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
    checksum="ignore",
    pure_acks=True,
    acked_hold=None,
    require_timestamps=False,
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
keeps what was seen first.  That is what a single-pass writer can always do,
and it is the default.

`"favor-acked"` keeps the copy the **receiver** kept.  The evidence is the
TCP Timestamps option: the peer's acknowledgement echoes, as TSecr, the TSval
of the transmission that advanced its window, and every transmission carries
its own TSval — so the first ack covering a range says which copy of it the
receiver accepted, in the receiver's own words.  A segment corrupted in
flight and resent clean is the case: the receiver drops the damaged copy on
its checksum and acks the resend, echoing the resend's clock.  On packeteer's
real capture of exactly that (`tcp_corrupt_ts.pcap`, five corruptions),
`favor-acked` writes the same bytes `checksum="drop"` writes — arrived at
from the receiver's side rather than ours, which matters because a capture
taken on a host with checksum offload has every checksum wrong and `"drop"`
would discard the whole stream.

What it costs, and why it could not be the default: the evidence arrives
*after* both copies, so every run is **held after it closes until the peer's
ack covers it**, and only then written.  By default the hold is bounded by
the two bounds the policy already has — `reorder_window` bytes of closed runs
per direction, `flush_timeout` seconds since a run closed — or, when
`acked_hold` is set, by that alone (below).  A run the bound releases, or
that the session ends on, is written as `favor-old` would have written it.
So is a range whose copies both lacked the option, whose covering ack did, or
whose ack echoed neither copy, as a cumulative ack that jumps over several
resends does — or both, as when a forgery carries the real segment's clock.  Every such byte is counted in `stats.acked_fallback_bytes`,
including a resend that arrives *after* its run was released (since `0.7.0`;
before, those were written as `favor-old` and counted nowhere), so a file's
digest never names a rule the file silently did not follow;
`stats.acked_swaps` counts the ranges where the receiver's choice was *not*
the first copy.  A one-way capture, with no acks
in it at all, falls back on every contested byte and says so.  Only
*disagreeing* copies are held against a run, so memory is bounded by real
disagreements, not by repeats.

A swapped-in copy is **a record of its own**, carrying `retransmit` — the
flag is the sender's act — and the resend's own `timestamp` and `ack`.  The
resend went out after the peer had answered the bytes around it, so in one
record with them it would straddle the peer's message and no causal position
for it would be valid; apart, every stamp on every record is true.  The loser
is cited as an `Undecoded` region wherever it lay in the capture.

A `"favor-new"` was offered until 0.2.0 and never read, for the reason that
makes `"favor-acked"` need the hold: a writer cannot prefer a later copy
against bytes already written.  It stays withdrawn — "the later copy" is not
a fact about the connection, and "the copy the receiver kept" is.

Disagreeing retransmits are rare in healthy traffic and are a classic evasion
technique in unhealthy traffic: a sender that knows a monitor prefers one copy
can hide bytes in the other.  If you are analysing traffic adversarially, this
is the setting to know about — `"favor-acked"` is the one that follows the
receiver rather than a rule the sender can predict — and the digest is what
lets you prove which rule the file was built under.

### `acked_hold` — how long `favor-acked` waits

Under `overlap="favor-acked"`, seconds a closed run may wait for the
receiver's covering ack.  `None`, the default, bounds the hold by
`flush_timeout` and `reorder_window`, which is right while a resend arrives
within them.  It often does not: a resend comes an RTO after the copy it
replaces, and an initial RTO of a second behind a bulk transfer puts
hundreds of kilobytes, and the evidence, past both bounds.

```python
ReassemblyOptions(overlap="favor-acked", acked_hold=10.0)
```

Set, it is the hold's only bound, so the memory it takes is the traffic it
spans.  Measured by the fidelity tool on a 1 MiB transfer at a 1 s RTO with a
fifth of its segments corrupted, the default hold keeps about 90 corrupted
copies a run, every byte of them in `acked_fallback_bytes`; a 10 s hold keeps
none.  Left out of `params_digest` while `None`, so a policy that does not
set it declares the digest it declared before the field existed.

### `require_timestamps` — RFC 7323's rule for a missing option

RFC 7323 §3.2: once both SYNs carried the Timestamps option, a receiver
SHOULD silently drop a non-RST segment that lacks it.  With
`require_timestamps=True` the reassembler does the same — the segment's
bytes, its ack and its flags — and cites its payload as `timestamp-missing`,
counted in `stats.ts_missing`.

```python
ReassemblyOptions(require_timestamps=True)
```

A segment forged by a third party usually lacks the option, so this keeps
strays out of the stream: they otherwise win under every policy, since the
first copy is kept and an ack covers a length, not content.  It is off by
default because a middlebox that strips options mid-connection would make it
drop real data.  A capture that began after the handshake never saw the
negotiation and drops nothing; none of the real Timestamps captures in the
test corpus loses a segment to it.  Left out of `params_digest` while off.

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
record.  A run ends:

- **at PSH**, where the pushed segment's bytes join it — in sequence order,
  so a segment held out of order ends its own run when it drains, not
  whichever run was open when it arrived;
- **when the peer answers it**: a peer segment carrying data, or a FIN,
  that acknowledges any of its bytes.  What the sender writes next was
  written after that answer, and in one record with the bytes before it
  would straddle the peer's message, which no causal order can place.  A
  pure ACK answers nothing a record can be ordered against, so a one-way
  transfer still coalesces;
- on a gap, on FIN or RST, at a timeout, and at the end of the capture.

With `coalesce=False`, every segment becomes its own record, including
those drained after a hole fills.  Both rules are `0.7.0`'s; before it a run
ended only at the arriving packet's PSH, and a backlog drained after a hole
was one record however many pushed segments it held.

A FIN ends the record that ends where it sits.  When that record was already
written — a pushed last segment, then a bare FIN, the usual close — the FIN
is a zero-length record at its sequence number, as a pure ACK is.

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

### `pure_acks` — storing what only acknowledges

A TCP segment carrying no bytes and no SYN, FIN or RST is a **pure ACK**.
Since `0.6.0` each one is stored as a zero-length record holding its `ack`,
as the specification advises since spec `0.23`.

```python
ReassemblyOptions(pure_acks=False)           # fold each ack into the next record
```

A pure ACK occupies no sequence number, so it has no end and no causal edge
runs from it; but its `ack` places it after the peer bytes it covers, which
is what it is stored for:

- **Order.**  Every pure ACK is an edge for the causal merge.  A peer that
  only acknowledges, the receiving side of an upload, otherwise leaves the
  merge nothing to place it by, and a `--sequenced` file's order rests on
  more evidence.
- **Time.**  A pure ACK's timestamp is when the receiver reacted.  Round-trip
  times and delayed-ACK behaviour can be read from the file.
- **Provenance.**  Over a `.zpf` input, a pure ACK's packet is cited by its
  record instead of being marked `skipped`; it did feed the reassembler.

It costs a record per pure ACK, and there are many.  `http_stream_1.pcap`,
a 4,140-packet HTTP capture, carries 2,060 pure ACKs beside 2,000 data
segments, so storing them doubles its records: 23% more output (543,900 →
667,500 bytes) and about 30% more conversion time (119 → 154 ms), almost all
of it in the `zpf` writer's per-record work.  Storing them changes no data
record: every fixture converts to what `pure_acks=False` writes, plus the
pure-ACK records.

That trade is deliberate.  The specification's own premise is that "a file
is read far more often than written" (*Sequenced files*), so a cost paid
once, when the file is written, buys information every reader gets: the
order and timing above, which a reader could not recover from a file
without them.  Opt out when a conversion's output is only an intermediate
step, or when size or throughput matters more than ordering detail; it
writes `0.5.0`'s bytes exactly.

`pure_acks=False` folds each `ack` into the sender's next data record
instead, which is what every release before `0.6.0` did, and writes exactly
what `0.5.0` wrote, Decoder `params_digest` included.  Where a pure ACK's
record is placed, and the one kind that cannot be stored, is in
{doc}`../internals/tcp-reassembler`.

### `checksum` — trusting what the wire said

A segment whose TCP checksum does not verify was corrupted in flight.  A
receiver drops it and takes the retransmission that follows; by default
`zpfwire` keeps it.  The policy applies to **TCP only** — see *UDP is always
kept*, below.

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
overlap      9150 bytes (retransmitted, discarded)
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

**UDP is always kept.**  A UDP datagram whose checksum fails is written
like any other, under either policy, and counted under `bad cksum`.  The
specification forbids a transport-layer stage to *withhold content* from a
stream whose offsets are not sequence-anchored: a TCP segment left out is a
sequence hole the offsets show, and its resend fills it, but a UDP stream's
offsets are the payloads that arrived, so a datagram left out would leave no
trace.  A consumer that wants corrupt datagrams gone has the count to know
they are there, and the input to find them in.

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
# ValueError: overlap must be one of favor-old, favor-acked, got 'favour-old'

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
TSval as the transmission it repeats, nothing from the peer arrived between
the two, and its bytes are the same.  The last clause is since `0.7.0`: a
copy is byte-identical by definition, and a segment forged with the right
clock is not one.  While a run still holds the accepted bytes they are
compared directly; once they are written, a copy has to be the same packet
as one remembered transmission, the same range with a CRC32 of the same
bytes.  That is what a mirror port, a two-interface capture or a
veth pair produces: every packet twice, a microsecond apart, the sender
having sent once.  Such a copy is discarded and cited as
`duplicate-discarded`, counted in `stats.duplicates`, and — the part that
reaches the file — **does not set `retransmit`** on the record covering its
bytes.  The specification names that flag as the sender's act, and a mirror
is not the sender.

A repeat with a **later** TSval is a retransmission, cited
`overlap-discarded`, and flags the record holding the bytes it repeats —
if that record is not yet written; a record cannot change once it is out,
and a resend usually comes an RTO later, so most resends flag nothing and
their citation is what records them.  Before `0.7.0` the flag went on
whichever run happened to be open, which could be a later record holding no
resent byte.  A copy *of a resend* is a copy too, judged against the resend
rather than the original it repeats.  So is a repeat with the *same*
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

**An old segment from before a wrap is rejected**, as a receiver rejects it:
RFC 7323's PAWS.  A segment that would contribute bytes but carries a TSval
older than the last one accepted in order is not new data — its sequence
numbers have come round again — and it is dropped whole, cited
`paws-rejected` and counted in `stats.paws_bytes`.  The clock it is compared
against moves only on in-order arrival, which is the receiver's own rule and
the reason a delayed original that finally fills a hole is *not* rejected
however many newer segments passed it.  A repeat of accepted bytes is never
judged by PAWS — it is a repeat, and judged as one above.

**A segment from the far side of a hole wider than 2³¹ bytes is recognised
as such.**  Serial arithmetic places anything more than 2³¹ away on the near
side, so without the option such a segment reads as old data, is discarded as
a retransmission the sender never made, and the rest of the direction is lost
behind it.  With it, a segment further behind than the largest window TCP can
advertise (2³⁰ bytes) whose TSval is *newer* than the last accepted in order
is from ahead.  It cannot join the session it belongs to — the format stores
records in serial order, and one that far past its predecessor precedes it —
so the session ends for `capture-gap`, the specification's own word for the
shape since `0.21`, and the segment opens the next on the same key; see
{doc}`converting`.  Counted in `stats.wrap_resolved`, since a file that
needed the rule is a file with a hole worth knowing about.

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

A non-zero `late_bytes` says the bytes did arrive, just after the
reassembler had given up — but that is two different stories, and where the
Timestamps option is present it tells them apart:

```python
stats.late_reordered_bytes      # the original, delayed by the network
stats.late_retransmitted_bytes  # a resend of an original that was lost
```

A late byte is compared against the clock of the first segment that overtook
its gap.  **Older** means it was sent *before* the bytes that passed it: the
original transmission, reordered on the way — and a wider `reorder_window`
or a longer `flush_timeout` would have kept it.  That is the tuning signal.
**Newer** means it was sent *after* them: the original never arrived and the
sender recovered it once the receiver's duplicate ACKs said so, by which time
the gap had been given up on.  No policy of ours could have kept those; they
are a fact about the network.  The comparison is against the *first* segment
past the gap rather than everything committed since, because a resend can be
slow to arrive too, and by then the sender has moved on.

What remains of `late_bytes` after both is late for a reason the option could
not name: no option on one side, or an arrival inside the same clock tick as
the segment that overtook it — which is what a delayed original that was a
burst-mate of the passer looks like, and on a path with no delay what a fast
retransmit can look like too, so nothing more is said.  Each late region's
`Undecoded` block carries the same verdict as its reason: `late-reordered`,
`late-retransmitted`, or plain `late-arrival`.

```python
if stats.late_reordered_bytes:
    print("raise reorder_window or flush_timeout")
elif stats.late_bytes:
    print("the late bytes were resends of losses; no window would have kept them")
```

## Where the policy is recorded

The decoder descriptor names the stage and its parameters:

```python
import zpf

with zpf.open("capture.zpf") as reader:
    for decoder in reader.decoders.values():
        print(decoder.name, decoder.version, decoder.params_digest)
```

```
tcp-reassembly 0.4.0 sha256:1f3a…
```

The name is `DECODER_NAME`.  Declaring it is a **should** in the
specification, and zpfwire takes it because this is the only place the policy
can be recorded — which is what makes a conversion reproducible, and what
tells a later reader why bytes are missing.
