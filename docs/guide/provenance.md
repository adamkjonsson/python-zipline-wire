# Provenance

A capture-sourced file can say three things about where its contents came from
that a transport stream cannot say on its own: which bytes of the capture
reached no record, when a coalesced record *began*, and when the connection
opened.  All three exist because the alternative is losing something quietly.
This page is about a capture conversion; a conversion of a `.zpf` of packets
cites its input packets in `spans` and owes the coverage guarantee, which
{doc}`converting-packets` works through.

## The accounting rule

Every byte a conversion reads is either written to a record or counted:

```python
stats.payload_bytes            # written
stats.overlap_bytes            # discarded as an already-accepted retransmit
stats.late_bytes               # arrived after its gap had been committed
stats.checksum_dropped_bytes   # discarded with its packet, under checksum="drop"
```

Nothing else can happen to a stream byte.  The three discard counters are
then *cited* wherever their position in the capture can be named:

```python
stats.undecoded_regions  # Undecoded blocks written
stats.unlocatable_bytes  # discarded bytes whose capture range cannot be named
```

so that:

```
cited bytes + unlocatable_bytes == overlap_bytes + late_bytes + checksum_dropped_bytes
```

That identity is asserted by the test suite on every fixture, under both
checksum policies.

## Undecoded blocks

An overlapping retransmit exists in the capture and reaches no record.
Nothing in the format expresses that except an `Undecoded` block, which names
a byte range of an input that the producing stage did not turn into a record:

```python
import zpf

with zpf.open("capture.zpf") as reader:
    for block in reader.undecoded:
        print(block.reason, block.off_start, block.off_end)
```

```
overlap-discarded 10711 10998
overlap-discarded 13938 14330
```

Because the input is a capture rather than another `.zpf`, the offsets are
**byte offsets into the capture file** and can be read directly:

```python
capture = open("capture.pcap", "rb").read()
for block in reader.undecoded:
    print(capture[block.off_start:block.off_end])
```

```
b'There is a flower within...'
```

Those are the exact bytes the reassembler dropped.

### The reasons

| Constant | `reason` | Meaning |
|----------|----------|---------|
| `REASON_OVERLAP` | `overlap-discarded` | A retransmit of a range already accepted |
| `REASON_DUPLICATE` | `duplicate-discarded` | A copy of a transmission already accepted — the capture point saw it twice; the sender sent once |
| `REASON_LATE` | `late-arrival` | Bytes that arrived after their gap had been committed, for a reason the Timestamps option could not name |
| `REASON_LATE_REORDERED` | `late-reordered` | Late, and the original: delayed by the network — a wider window would have kept it |
| `REASON_LATE_RETRANSMITTED` | `late-retransmitted` | Late, and a resend of an original that was lost — nothing would have kept it |
| `REASON_PAWS` | `paws-rejected` | An old segment from before a sequence wrap, dropped whole as a receiver drops it |
| `REASON_CHECKSUM` | `bad-checksum` | A TCP segment discarded because its checksum did not verify, under `checksum="drop"` |

All are `reason_class="bytes"` — the *bytes-exist* class, meaning a consumer
may follow the reference and fetch them.  The distinction matters: an overlap
or duplicate discard lost nothing, because the same bytes are in a record
already, a bad-checksum or PAWS discard lost nothing the receiver had either,
while a late arrival is data the policy caused you to lose — and the three
`late-` reasons say whether a different policy would have kept it.  See
{doc}`reassembly` for how each is decided.

```python
lost = [b for b in reader.undecoded if b.reason.startswith("late-")]
```

Match on the prefix, or on all three constants: since `0.3.0` a late byte
that the Timestamps option could classify is cited `late-reordered` or
`late-retransmitted` rather than `late-arrival`.

### Why a gap gets no block

A missing segment is a *hole*, and against a capture source the specification
bars a hole-class block outright.  A transport stream's own offsets already
carry the extent of what is missing — `seq_start` is the absolute wire
sequence number, so a gap is visible as arithmetic:

```python
sent = [r for r in session.records()
        if r.sender_pid == pid and r.seq_start is not None]

for before, after in zip(sent, sent[1:]):
    expected = (before.seq_start + len(before.payload)) % (1 << 32)
    if after.seq_start != expected:
        print(f"gap of {(after.seq_start - expected) % (1 << 32)} bytes")
```

Two details in that snippet are load-bearing.

**Take the modulo.**  Sequence numbers wrap at 32 bits, and a long-lived
stream will wrap.

**The SYN record needs no special case.**  It sits at `isn + 1` with an empty
payload, so the walk expects the first data record at `isn + 1` as well, and
finds it there.  (It did need one once: a SYN record placed at the `isn`
itself made the walk report a phantom one-byte gap after every handshake —
see below.)

Done that way, the count matches what the conversion reported — six gaps on
`packet_loss.pcap`, from both directions, exactly `stats.gaps`, with or
without the handshake records in the walk.

Declaring it again would be a second account of the same missing bytes with no
rule for which to believe.  So `Undecoded` covers the opposite case — bytes
that *are* in the capture and did not reach the output.

### When a range cannot be named

A datagram reassembled from several IP fragments occupies several
discontiguous ranges of the capture, and one block names one range.  Rather
than cite the first fragment's offset — which would name bytes that are partly
IP headers — the conversion declines and counts:

```python
stats.unlocatable_bytes      # discarded, but not citable
```

This is a limit of a single-range block, not of the capture reader: the
contributing records are known, and a future version could emit one block per
fragment.

## `ts_first`

A coalesced record is stamped with the time of the **last** packet that
contributed bytes — the moment the run became complete.  That leaves the time
it *started* unrecoverable, so a record that coalesced more than one packet
also carries `ts_first`:

```python
for record in session.records():
    if record.ts_first is not None:
        span = record.timestamp - record.ts_first
        print(f"{len(record.payload)} bytes assembled over {span} ticks")
```

A single-segment record omits it, because it would only repeat `timestamp`.

The usual way to express this would be `spans`, but a span must reference a
`zpf-input` source and ours is a capture — so `ts_first` is the only place a
capture-sourced file can record a run's beginning.

## The handshake

When the SYN is captured, each direction gets an empty record carrying the
`SYN` flag at the stream origin — `isn + 1`, not the `isn` itself:

```python
import zpf

for record in session.records():
    if record.flags & zpf.RecordFlags.SYN:
        print(record.sender_pid, record.seq_start, record.timestamp)
```

`isn` on the participant says where a stream begins in sequence space, but not
when; the first data record carries its own arrival time.  Without these
records the moment the connection opened is nowhere in the file.

The record shares its `seq_start` with the first data record, and that is the
specification's shape rather than a coincidence: the SYN consumes a sequence
number but delivers no byte, so the stream's first byte *is* `isn + 1`, and a
record placed at the `isn` would sit one below the origin, in an offset space
that has no negative offsets.  Two records at one `seq_start` are stored in
the order they were produced; the SYN comes first.  A record at the `isn`
was what this project wrote before python-zipline#63: the modular subtraction
absorbed the negative offset rather than reporting it, the record landed at
offset 2³²−1, and the stream measured that many bytes.  The writer now refuses
it, and `FileReader.unplaceable` is where such a record would show.

Only the first SYN of a direction gets one.  A retransmitted SYN re-opens
nothing.

A capture that starts mid-connection has no handshake to report, so it gets no
SYN records — and correctly no `isn` either.

## The capture digest

The Source Descriptor records what the file was derived from:

```python
with zpf.open("capture.zpf") as reader:
    for source in reader.sources.values():
        print(source.kind, source.uri, source.digest, source.link_type, source.comment)
```

```
capture capture.pcap sha256:9f2c… 1 None
```

The comment carries the capture's snaplen when it had one — `snaplen=262144` —
and is `None` otherwise.  It belongs here because it is what explains payloads
shorter than what was sent; the Source Descriptor has no field of its own for
it yet.  `ConversionStats.truncated` counts the packets it actually cut.

The digest is the dependency edge: it is how a consumer confirms a `.zpf`
still matches the capture it came from.  Compute it yourself with
{func}`~zpfwire.convert.describe_source`:

```python
from zpfwire import describe_source

digest, uri = describe_source("capture.pcap")
```

A conversion from an unnamed stream records a digest with no `uri`, which is
honest for input that has no name.

## What is deliberately absent

**`content_type`** is forbidden at the transport layer — a byte run has no
media type — and the writer raises if you try.

**`spans`** cannot be used, because every span must reference a `zpf-input`
source and ours is a capture.  This is why `ts_first` exists.

**`Discontinuity`** blocks belong to decoded layers.  A transport stream
expresses its gaps in its offsets, as above.
