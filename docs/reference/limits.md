# Limits

What the output does not carry, and what is not yet implemented.  Some of
these are permanent consequences of the format; others are work not yet done.
They are separated here because the difference matters when you are deciding
whether to wait.

## Permanent, by design

**No application decoding.** zpfwire produces a transport-layer file and
stops.  Decoded output is a *second* file, derived from this one by a decode
stage, and the clean transport-layer output here is its input.  This is the
whole architecture, not a gap.

**No `content_type` on records.** Forbidden at the transport layer — a byte
run has no media type.

**No `spans` on records.** A span must reference a `zpf-input` source, and a
capture-sourced file has none.  `ts_first` covers the one thing spans would
otherwise have carried.

**No `Discontinuity` blocks.** A transport stream expresses its gaps in its
offsets.  See {doc}`zpf-mapping`.

## Consequences of the reassembly policy

**Committed gaps are permanent.** Once a record is written past missing bytes,
those bytes may never be written, even if they arrive later.  This is the
specification's rule, and it is why the policy is a declared, hashed option.
Bytes lost this way are counted as `late_bytes` and cited as `late-arrival`
regions.

**A direction longer than 2 GiB is written as several sessions.**  The
format places a transport record by its `seq_start` against the stream
origin with serial arithmetic, which is decidable only within 2³¹: a record
further from the origin than that is "below" it, and python-zipline's writer
refuses it — so without help a capture of any TCP direction carrying more
than 2 GiB, an ordinary large download, could not be converted at all.
Until the format unwraps offsets along stored order
([zipline#146](https://github.com/adamkjonsson/zipline/issues/146)) zpfwire
ends the session at that point for `offset-limit` and continues the
direction in a new one, whose origin is its first byte; every record is
then placed, and `stats.offset_splits` says it happened.  What it costs: a
reader sees several sessions with one key where the wire had one
connection, and a segment reordered across the boundary — sent below 2 GiB,
arriving after the split — lands in the new session as a repeat rather than
in the old one where it belonged.  Both go with the shim.

**A hole wider than 2³¹ bytes in one direction splits the session.**  The
offset space is modular over 2³² and records are stored in serial order, so
two records of one participant cannot be more than 2³¹ apart with nothing
between them.  A segment from the far side of a hole that wide is recognised
by the Timestamps option — further behind than any window and carrying a
newer clock — and opens a new session, the old one ending for
`capture-gap`.  Without the option the shape is invisible: serial arithmetic
calls the segment old, it is discarded as a retransmission, and the rest of
the direction goes with it.  The zone between a window's width and 2³¹
behind is where a resend cannot be, so the rule is safe there; a hole
between 2³⁰ and 2³¹ wide is placed by serial arithmetic alone and needs no
rule, and is held and then committed as any gap is.

**Filtering below the flow level breaks streams.** A predicate that drops
segments from the middle of a connection produces gaps exactly as packet loss
would.  Filtering by address or port keeps whole conversations and is safe.

## Not yet implemented

**Sequenced UDP sessions.** A datagram carries no `seq`/`ack`, so a UDP
session is hint-less and its order would rest on the clock alone.  Defensible,
one capture being one tap, but a distinct claim from the one `--sequenced`
makes.  See {doc}`../guide/ordering`.

**A conversion run from the CLI is not byte-reproducible.**  The File Header
carries `produced_at`, a wall-clock stamp, so two conversions of one capture
differ by those bytes.  The API takes `produced_at=` to pin or omit it; the
command line has no flag for it, on the grounds that a caller who needs a
pinned stamp is scripting the conversion anyway.  The reproducibility of the
*decode* is a separate thing and is unaffected — it rests on the Decoder's
`params_digest`, which is a function of the options alone.

**SACK-aware loss inference.** TCP options are parsed and carried on every
{class}`~zpfwire.capture.PacketView` — `tcp_options.sack_blocks` tells you
which ranges the receiver actually got — but the reassembler does not consult
them.  It infers loss from arrival order and its timeouts alone, so a capture
with SACK information available is analysed as though it had none.

**A one-way capture of a coarse-tick stack cannot tell a fast retransmit
from a mirror copy.**  The reassembler reads the TCP Timestamps option to
separate the two — see {doc}`../guide/reassembly` — and the signal that
separates them on a stack whose timestamp tick is coarser than its round
trip (historically ~100 ms on some stacks, against a LAN round trip of well
under a millisecond) is the peer's duplicate ACKs sitting between the
original and the resend.  In a capture that holds only one direction those
ACKs are not in the file, and a fast retransmit that landed inside its
original's tick carries the same TSval with nothing visible between: the
rule calls it a duplicate and clears `retransmit` on a record whose bytes
the sender did in fact resend.  Linux ticks at 1 ms and a resend after a
dup-ACK round trip is safely apart, so the six real captures the rule was
built against never show the shape; it is recorded because the shape exists.
The Timestamps option itself is only present when both ends negotiated it,
and every rule that reads it degrades to the specification's conservative
reading — every repeat is a retransmission — when it is absent, and counts
that it did (`stats.ts_fallback`).

**A late byte in the same tick as the segment that overtook it is not
classified.**  A delayed original that was a burst-mate of the passer shares
its TSval, and so does a fast retransmit on a path whose round trip is
shorter than a tick; the option cannot tell them apart and the reassembler
leaves such a byte as plain `late-arrival` rather than guess.  On real
traffic with realistic delay this is the minority — 6 of 18 late regions in
`tcp_reorder_ts.pcap`, none in `tcp_gap_ts.pcap` — and it is the option's
granularity, not the tool's.

**`favor-acked` is evidence, not proof.**  RFC 7323 §4.3 lets a receiver's
`TS.Recent` advance from an old duplicate that lands inside its delayed-ACK
window, so a copy arriving there can steal the echo from the copy the
receiver actually kept.  It is nonetheless the receiver's own word, and
independent of the capture point, which the order copies arrived in is not.
And it needs both directions in the capture and the option negotiated;
without either, every contested byte is decided as `favor-old` and counted
as such — see {doc}`../guide/reassembly`.

**Byte ranges for discarded fragments.** A datagram reassembled from several
IP fragments occupies several discontiguous ranges of the capture, and an
`Undecoded` block names one range.  Rather than name the wrong bytes, a
discard from such a datagram is counted as `unlocatable_bytes` and not cited.
The contributing records are known, so emitting one block per fragment is
possible; it is not done.

## Bounded by memory

**Sequenced sessions buffer.** A causal order needs both directions in hand,
so `sequenced=True` holds each session until it ends — unbounded for the
session's lifetime.  This is why it is opt-in.  See {doc}`../guide/ordering`
for mitigations.

**Reassembly buffers per direction.** `reorder_window` bounds it: a direction
holds at most that many out-of-order bytes before committing a gap.  The
default is 256 KiB per direction.

**Reading is streaming.** The capture itself is read one packet at a time, so
a capture larger than memory is fine as long as the two limits above are.

## Interoperability

**The spec version is fixed by the `zpf` library**, not by zpfwire.  Check it
with `zpfwire --version`, which reports `zpf.SPEC_VERSION` rather than a
hard-coded number.  The format guarantees no upgrade path across a minor
version while it is below 1.0, so a file written against one minor may be
refused by a library implementing another.

**Neither sibling is on PyPI yet.**  `pyproject.toml` floors both, but with
nothing to resolve against, a floor is documentation as much as a
constraint: it names the oldest release the code runs on, which each
`CHANGELOG.md` entry names beside the release it was actually built
against, and it makes an older checkout fail at import rather than
somewhere subtler.  The numbers themselves live in `pyproject.toml` and the
changelog, not here, because a copy in prose is one no test can see.  Both
are installed editable from the checkouts beside this one, so what is
actually in use is whatever those checkouts are at.
