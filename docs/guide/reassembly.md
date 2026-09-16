# Reassembly policy

{class}`~zpfwire.options.ReassemblyOptions` decides how TCP segments become
records.  It is not a set of tuning knobs: together these settings decide
**which bytes reach the output and which are thrown away**.

```python
from zpfwire import ReassemblyOptions

options = ReassemblyOptions(
    overlap="favor-old",
    reorder_window=262_144,
    flush_timeout=5.0,
    session_timeout=300.0,
    coalesce=True,
)
stats = zpfwire.capture_to_zpf("capture.pcap", "out.zpf", options=options)
```

The defaults above are what you get by passing nothing.

## Why the policy is visible at all

The specification makes two rules that a reassembler cannot route around:

1. **Records must be stored in ascending sequence order per participant**, so
   a reader can merge both directions in one streaming pass without sorting.
2. **Committing a gap is irreversible.** Once a record has been written past
   missing bytes, those bytes may never be written — even if they arrive
   later.

Together these mean a reassembler cannot simply wait forever for a missing
segment, and cannot go back once it stops waiting.  Something must decide when
to give up, and that decision destroys data.  So it is a declared option
rather than an implementation detail, and its digest is recorded on the file's
decoder descriptor:

```python
options.params_digest()      # 'sha256:1f3a…'
```

Same capture digest, same decoder version, same params digest ⇒ same output.
That is the reproducibility contract, and it is why every field here is
hashed.

## The settings

### `reorder_window` — how much to hold

Bytes a direction may hold out of order before the oldest gap is committed.

```python
ReassemblyOptions(reorder_window=0)          # never wait; commit every gap at once
ReassemblyOptions(reorder_window=1 << 20)    # hold up to a megabyte
```

Out-of-order segments are buffered until the bytes before them arrive.  When
the buffer exceeds this many bytes, the reassembler stops waiting for the
missing range, writes what it has, and the gap becomes permanent.

`0` disables buffering entirely: any segment that is not the next one commits
a gap immediately.  That is occasionally what you want — it makes the
conversion strictly streaming — but on a capture with ordinary reordering it
throws away a great deal.

### `flush_timeout` — how long to wait

Seconds a gap may stay unfilled before it is committed, measured in **capture
time**, not wall-clock.

```python
ReassemblyOptions(flush_timeout=30.0)        # patient
```

A retransmission typically arrives within a round-trip or two, so the default
of five seconds recovers almost all real loss.  Raising it costs memory and
recovers correspondingly less.

Because the clock is the capture's own, this behaves identically whether you
convert a capture live or five years later.

### `overlap` — which copy wins

When retransmitted bytes disagree with bytes already accepted, `"favor-old"`
keeps what was seen first, as most receiving stacks do.  It is the only
policy, and the reason is structural rather than a gap: the converter writes
in one pass, so once a record is out, a later copy of its bytes cannot replace
them.  Any rule that prefers a later copy — the retransmission, or the copy
the peer's acknowledgement turns out to echo — means holding every run until
the choice can be made, which is a different reassembler.  (A `"favor-new"`
was offered until 0.2.0; it was never read, and was withdrawn rather than
left to put a policy in the digest that no code applied.)

Disagreeing retransmits are rare in healthy traffic and are a classic evasion
technique in unhealthy traffic: a sender that knows a monitor prefers one copy
can hide bytes in the other.  If you are analysing traffic adversarially, this
is the setting to know about, and the digest is what lets you prove which rule
the file was built under — even while there is only one.

### `session_timeout` — when a conversation is over

Seconds of silence after which a session is closed with reason `"timeout"`.  A
later packet between the same endpoints opens a **new** session.

```python
ReassemblyOptions(session_timeout=60.0)
```

This is what stops a long capture from producing one enormous session per
endpoint pair when a client reuses a port hours later.

### `coalesce` — record granularity

With `coalesce=True` (the default), contiguous bytes are joined into one
record, flushed on PSH, on a gap, on FIN or RST, at a timeout, and at the end
of the capture.  With `coalesce=False`, every segment becomes its own record.

```python
ReassemblyOptions(coalesce=False)            # one record per segment
```

Both are conformant — a record is a run of stream bytes either way — and the
choice is about what you want to read afterwards.  Coalescing produces far
fewer, larger records that line up with application message boundaries where
the sender used PSH.  Not coalescing preserves the segmentation exactly as it
was on the wire, which matters if the segmentation itself is what you are
studying.

Coalescing also affects timestamps: a coalesced record is stamped with its
*last* contributing packet, and carries `ts_first` for its first.  See
{doc}`provenance`.

### `checksum` — trusting what the wire said

A packet whose transport checksum does not verify was corrupted in flight.  A
receiver drops it and takes the retransmission that follows; by default
`zpfwire` keeps it.

```python
ReassemblyOptions(checksum="drop")           # discard it, as a receiver would
```

The default is `"ignore"` for one reason: **checksum offload**.  A capture
taken on a sending host is tapped above the network card, before the hardware
fills the checksum in, so outbound packets routinely carry a wrong — often
zero — value for traffic that was perfectly correct on the wire.  Dropping
those by default would gut such a capture, so the policy is opt-in.

Where the checksums *are* trustworthy, `"drop"` is the more faithful reading,
and it changes what the file says.  A corrupt segment is usually retransmitted
cleanly, and the damaged copy arrives first — so `favor-old` keeps the bytes
no endpoint ever accepted, and cites the good retransmission as an overlap
discard:

```
$ zpfwire convert payload_corruption.pcap -o kept.zpf
payload      74065 bytes
overlap      9150 bytes (discarded)
bad cksum    11 packet(s)

$ zpfwire convert payload_corruption.pcap -o dropped.zpf --checksum drop
payload      74065 bytes
skipped      11 (bad-checksum)
bad cksum    11 packet(s)
dropped      9150 bytes (bad checksum)
```

The same number of bytes is written either way; eleven of them differ, and
under `"drop"` they are the ones the receiver actually saw.

The whole packet is discarded, not just its payload — a receiver that fails
the checksum has no reason to trust the header either, so the segment's flags
open and close nothing, and a corrupt packet never starts a session.  The
payload is cited as an `Undecoded` block with reason `bad-checksum`, and the
packet is tallied as a skip, so the accounting rule holds under either policy.

Two things are deliberately *not* read as failures: an IPv4 UDP datagram whose
checksum is `0`, which means *none was computed* (RFC 768) rather than a wrong
one, and any packet from a capture truncated by a snaplen, whose checksum
covers bytes that were not kept.  The second is decided here, from packeteer's
`datagram_truncated`: the value cannot be checked against bytes that are not
in the file, which is a different statement from its being wrong — so a
snaplen-limited capture reports no corruption at all, under either policy.

## Validation

Invalid options raise `ValueError` at construction, not at conversion:

```python
ReassemblyOptions(overlap="favour-old")
# ValueError: overlap must be one of favor-old, got 'favour-old'

ReassemblyOptions(flush_timeout=-1)
# ValueError: flush_timeout must not be negative
```

The accepted policies are in `OVERLAP_POLICIES` and `CHECKSUM_POLICIES`.

## What the Timestamps option decides

None of the settings above is an option for this: the reassembler reads the
TCP Timestamps option (RFC 7323) whenever a connection negotiated it, and
falls back to the conservative reading when it did not.  The option puts the
sender's clock on every segment, and the property reassembly cares about is
that **every transmission of a byte range gets its own value, and a copy of
one transmission does not**.

**A repeated segment is a copy, not a resend**, when it carries the same
TSval as the transmission it repeats and nothing from the peer arrived
between the two.  That is what a mirror port, a two-interface capture or a
veth pair produces: every packet twice, a microsecond apart, the sender
having sent once.  Such a copy is discarded and cited as
`duplicate-discarded`, counted in `stats.duplicates`, and — the part that
reaches the file — **does not set `retransmit`** on the record covering its
bytes.  The specification names that flag as the sender's act, and a mirror
is not the sender.

A repeat with a **later** TSval is a retransmission, cited
`overlap-discarded` and flagged as before.  So is a repeat with the *same*
TSval that has a packet from the peer between it and its original: a fast
retransmit is triggered by the peer's duplicate ACKs, and on a stack whose
timestamp tick is coarser than its round trip the resend can land inside the
original's tick — the ACKs between them are what tells it from a copy.

A repeat that **cannot be judged** is treated as a retransmission, which is
what the specification asks of a producer that cannot tell, and the reason
it could not be judged is counted:

```python
stats.ts_fallback["absent"]  # one side, or both, carried no option
stats.ts_fallback["stale"]   # the original had aged out of the reassembler's memory
```

The memory is bounded by `reorder_window` bytes, so a copy of something
older than that is `stale`; the newest transmission is never forgotten, so
the copy that follows its original is always judged.  A non-zero
`ts_fallback` means some `retransmit` flags in the file rest on the fallback
rather than on evidence — which is exactly what every file written before
this option was read rested on.

The one shape this cannot separate is a **one-way capture of a coarse-tick
stack**: with the peer's ACKs absent from the file and the resend inside its
original's tick, a fast retransmit looks like a copy.  See
{doc}`../reference/limits`.

## Reading what a policy cost

Four counters report what the policy threw away:

```python
stats.gaps             # records written past bytes that never arrived
stats.late_bytes       # bytes that arrived after their gap had closed
stats.overlap_bytes    # retransmits discarded as already-accepted
stats.duplicate_bytes  # copies of one transmission, seen twice by the capture point
```

`overlap_bytes` is normal — it is what reassembly is *for*, and those bytes
did reach the output the first time they were seen.  `duplicate_bytes` says
something about the capture rather than the connection: set
`stats.duplicates` beside `stats.packets` and it says how much of the file
is doubled.  `gaps` and `late_bytes` are the ones to watch: they mean the
policy stopped waiting.

```python
if not stats.lossless:
    print(f"{stats.gaps} gaps; raise reorder_window or flush_timeout")
```

A non-zero `late_bytes` is the specific signal that you were nearly patient
enough: the bytes did arrive, just after the reassembler had given up.
Raising `flush_timeout` will usually recover them.

## Where the policy is recorded

The decoder descriptor names the stage and its parameters:

```python
import zpf

with zpf.open("capture.zpf") as reader:
    for decoder in reader.decoders.values():
        print(decoder.name, decoder.version, decoder.params_digest)
```

```
tcp-reassembly 0.3.0 sha256:1f3a…
```

The name is `DECODER_NAME`.  Declaring it is a **should** in the
specification, and zpfwire takes it because this is the only place the policy
can be recorded — which is what makes a conversion reproducible, and what
tells a later reader why bytes are missing.
