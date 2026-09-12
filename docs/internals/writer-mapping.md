# Writing the file

{doc}`../reference/zpf-mapping` lists what ends up in the output.  This page
is about the parts that were decisions, and why they came out the way they
did.

## Validation is not reimplemented

`zpf`'s writer runs its conformance checker *before* bytes reach the sink, so
a violation raises `zpf.SemanticError` at the offending call rather than
producing a bad file.  zpfwire relies on that entirely — there is no
second implementation of the spec's rules here, and there should not be.

The practical consequence for a contributor: if you write something
non-conformant, you will find out at the call site with a useful message.
Trust it rather than pre-checking.

## `Undecoded`, and why it needs `payload_offset`

An overlapping retransmit exists in the capture and reaches no record, and
nothing else in the format can express that.  Against a **capture** source the
block's offsets are byte offsets into the capture file, and
`session_id`/`participant_id` must both be written `0` — there is no input
`.zpf`, so there is no id namespace to name.

Producing those offsets is the whole reason `PacketView.payload_offset`
exists:

```python
packet.source_records[0].data_offset + packet.payload_offset
```

It cannot be `len(frame) - len(payload)`.  That assumes the payload runs to
the end of the frame, which stopped being true once packeteer began trimming
Ethernet padding — on a padded frame the subtraction lands inside the padding
and names the wrong bytes with no error.

Because the reassembler only ever trims *leading* bytes, a discard is always a
prefix of some segment's payload, so its file range is
`payload_offset + skip` for a known `skip`.

### The class rule

Only the **bytes-exist** class may be declared against a capture source.  A
hole — a gap — must not be, and this is not a technicality: a transport
stream's offsets are hole-inclusive, so a missing segment already occupies a
range no record covers.  Declaring it again would be two accounts of the same
missing bytes with no rule for which to believe.

So `_count_repeat` splits a discard by whether it falls inside a committed
gap, and cites both halves with different reasons — `late-arrival` for bytes
we refused to write, `overlap-discarded` for a retransmit of bytes already
accepted — but never cites the hole itself.  A third reason, `bad-checksum`,
comes from `convert.py` rather than the reassembler: under `checksum="drop"`
a packet that failed its checksum is discarded whole before it reaches a
flow, and its payload is cited the same way.

### When it cannot be done

A datagram reassembled from several IP fragments occupies several
discontiguous ranges, and a block names one.  Rather than cite the first
fragment's offset, which would name IP headers, the conversion declines:

```python
if off_start is None or self._writer is None or self._source is None:
    self._stats.unlocatable_bytes += length
    return
```

The accounting identity the tests assert is what keeps that honest:

```
cited bytes + unlocatable_bytes == overlap_bytes + late_bytes + checksum_dropped_bytes
```

## `ts_first` rather than `spans`

The natural way to say when a coalesced record began would be a `spans` entry.
It is unavailable: every span must reference a `zpf-input` source, and ours is
a capture.  `ts_first` is therefore the only place a capture-sourced file can
record a run's start time — which is precisely the argument that got it added
to the ergonomic writer upstream.

It is written only when the run coalesced more than one packet.  For a single
segment it would repeat `timestamp`.

## What a sequenced session declares, and what it used to

A session is **hint-ful** when its records carry `seq`/`ack`, and a hint-ful
session's causal order follows from the records themselves.  A TCP session is
hint-ful — except when it has no records at all.  A conversation of pure
acknowledgements produces none, and three of the four sessions in
`http_example.pcapng` are exactly that.

Under spec `0.16` this was the subtlest thing in the writer.  A hint-less
session had to record what its order rested on, in `sequenced_basis`; the flag
is written on the Session Descriptor *before* any record exists, so a producer
could not know which kind of session it had when it had to decide.  We declared
`sequenced_basis="clock"` on every sequenced session — redundant for the
hint-ful ones, correct for the rest — resting on the `SINGLE_CLOCK` file flag,
one capture being one tap.

**Spec `0.19` deleted both options**, and with them the whole problem.
`SEQUENCED` is a bare assertion: a reader cannot check a basis any more than it
can check the order, so trusting the producer for one and not the other bought
nothing.  `begin_session` therefore passes `sequenced=` and `linearize=` and
nothing else.

## What answers the forensic question now

The account of the file moved to its build provenance, and `zpf.create()`
carries all of it:

| Field | What we write |
| --- | --- |
| `creator` | `zpfwire <version>` |
| `produced_by` | the same — permitted on a capture-sourced file, required only once a `zpf-input` Source appears |
| `produced_at` | the conversion's wall-clock time, or whatever `produced_at=` pinned |

`produced_at` is the only part of the output that is not a function of the
input, so it is the only thing between two conversions of one capture and
byte-identical results.  `_produced_at` in `convert.py` resolves the three
answers: `"now"` stamps, a value pins, `None` omits.

One capture file is still one tap, so every timestamp in the output was stamped
against one clock — that is what lets a later stage sequence regrouped one-way
streams by time.  The file no longer has a field in which to say so.

## Extending to another transport

A new transport is a `FlowTracker` subclass and one entry in
`convert._TRACKERS`:

```python
_TRACKERS: dict[str, type[FlowTracker]] = {"tcp": TcpFlow, "udp": UdpFlow}
```

The base class gives you participant declaration, the session, the stats, the
options, and `undecoded()`.  What a subclass must provide is `packet()` and
`finish()`.

Three things to get right, in rough order of how easy they are to get wrong:

1. **Ascending `seq_start` per participant**, if your records carry one.
2. **Declare participants before recording from them** — use
   `self.participant(endpoint, **declaration)`, which declares on first sight.
3. **Count everything you drop**, and cite it when you can name its place in
   the capture.

`UdpFlow` is some fifty lines and is the honest example of how little the
base class leaves you to do.
