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

**No `spans` on a capture conversion's records.** A span must reference a
`zpf-input` source, and a capture-sourced file has none.  `ts_first` covers
the one thing spans would otherwise have carried.  A conversion of a `.zpf`
of packets is zpf-sourced, and its records do carry them.

**No `Discontinuity` blocks.** A transport stream expresses its gaps in its
offsets.  See {doc}`zpf-mapping`.

## Consequences of the reassembly policy

**Committed gaps are permanent.** Once a record is written past missing bytes,
those bytes may never be written, even if they arrive later.  This is the
specification's rule, and it is why the policy is a declared, hashed option.
Bytes lost this way are counted as `late_bytes` and cited as `late-arrival`
regions.

**A direction longer than 2 GiB is one session, placed at its true
offsets.**  Since spec `0.21` a transport record's offset is its
predecessor's plus the signed serial delta of their `seq_start`s, so a
stream is placed at any length and through a sequence wrap
([zipline#146](https://github.com/adamkjonsson/zipline/issues/146), filed
from this project).  Through `0.20` every record was measured against the
origin, which stopped at 2³¹, and `0.3.0` split such a direction into a new
session every 2 GiB to get past it; that split, its `offset-limit` reason
and its counter are gone.  A `--sequenced` conversion of such a direction
orders and verifies at any length too: since spec `0.22` an `ack` is
unwrapped along the acker's records the same way
([zipline#151](https://github.com/adamkjonsson/zipline/issues/151),
[python-zipline#75](https://github.com/adamkjonsson/python-zipline/issues/75),
both filed from this project).  `0.4.0` refused one whose peer only
acknowledged — an ordinary upload, whose server recorded nothing after its
SYN-ACK.  Since `0.6.0` that server's pure ACKs are records by default, and
under `--no-pure-acks` the shape is as it was.  The one shape one session cannot hold is the hole below.

**A hole wider than 2³¹ bytes in one direction splits the session.**  This
is the specification's stated exit for what it calls *the unmeasurable
hole* (spec `0.21`, §Referencing the source by stream offset, answering
[zipline#147](https://github.com/adamkjonsson/zipline/issues/147), filed
from this project): the offset space is modular over 2³² and records are
stored in serial order, so two records of one participant cannot be more
than 2³¹ apart with nothing between them, and a producer that knows the far
side is real ends the session at the hole and opens another on the same
key with no `isn`, writing `capture-gap` — the specification's word, not
ours, since `0.21` — so that a reader can tell a resumed conversation from
a new one.  A segment from the far side of a hole that wide is recognised
by the Timestamps option — further behind than any window and carrying a
newer clock — and opens the new session.  The stream still *ends* at the
hole rather than spanning it because the format has no representation for
the far side's true position: the `u64 offset` Record option that would
give it one is recorded upstream as the design if a capture with the shape
ever needs it, and is safe to add as a `1.x` minor, so there is nothing to
work around here.  Without the option the shape is invisible: serial arithmetic
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

**`favor-acked` trusts the peer's acks, and a forger can forge those too.**
The policy is a defence against copies that disagree, and holds up well
against a third party who forges *data*: since `0.7.0`, a copy of bytes
the receiver had already acknowledged is not contested (#62), an
acknowledgement of bytes never seen sent is not taken as proof the receiver
had them, and a forgery stamped with the right clock is not a copy (#61).
What it cannot tell is a forged *acknowledgement* that only covers bytes
already seen.  One such ack, from a forgery impersonating the other side,
releases a run still holding a forgery before the real segment arrives, and
the real copy then has nothing to be contested against.  The forged bytes
stay, and nothing counts them.  In the fidelity tool's stamped-stray cells
(three forgeries, each stamped with the impersonated side's clock and
carrying its ack), 8 of 224 `favor-acked` runs end this way; 162 are exact,
and in the other 54 every wrong byte is counted as a fallback.  A capture
alone cannot authenticate an acknowledgement; an RFC 5961 receiver with
its challenge ACKs does better, because it is in the conversation.

**Byte ranges for discarded fragments.** A datagram reassembled from several
IP fragments occupies several discontiguous ranges of the capture, and an
`Undecoded` block names one range.  Rather than name the wrong bytes, a
discard from such a datagram is counted as `unlocatable_bytes` and not cited.
The contributing records are known, so emitting one block per fragment is
possible; it is not done.

## A `.zpf` of packets as input

**A fragmented UDP datagram is not converted.**  Its fragments are separate
input records, and only a record carrying `seq_start` may cite several input
units (spec `0.22`); a UDP record has none.  The fragments are marked
`undecodable` and counted under `SKIP_FRAGMENTED_UDP`.  Whether the
permission should extend to a datagram reassembled from IP fragments, whose
offsets prove the join as sequence numbers do, is
[zipline#166](https://github.com/adamkjonsson/zipline/issues/166), filed from
this project.  Fragmented TCP is unaffected.

**Each input stream is read in stored order**, and the streams are merged by
timestamp.  A decryptor writes each tunnel direction in time order, which is
all this needs; a stage that stored one stream's packets out of time order
would have them reassembled in that order.  Two records in different streams
sharing a timestamp are taken in stream order, since a `.zpf` records no
order between them.

## Bounded by memory

**Sequenced sessions buffer.** A causal order needs both directions in hand,
so `sequenced=True` holds each session until it ends — unbounded for the
session's lifetime.  This is why it is opt-in.  See {doc}`../guide/ordering`
for mitigations.

**Reassembly buffers per direction.** `reorder_window` bounds it: a direction
holds at most that many out-of-order bytes before committing a gap.  The
default is 256 KiB per direction.

**Two small lists grow for a connection's lifetime.**  Every committed gap
is remembered, one small entry each, so a late arrival into it can be told
from a resend; it is never pruned, because a bound would reclassify a
segment arriving very late.  And a pure ACK whose sequence number is ahead
of its sender's placed bytes is held until those bytes are placed, a gap is
committed past it, or the session ends.  In ordinary traffic that is at
once, but a direction whose data stops being captured while its ACKs go on
holds every one of them.  Neither is bounded by `reorder_window` today.

**Reading is streaming.** The capture itself is read one packet at a time, so
a capture larger than memory is fine as long as the two limits above are.

## Interoperability

**The spec version is fixed by the `zpf` library**, not by zpfwire.  Check it
with `zpfwire --version`, which reports `zpf.SPEC_VERSION` rather than a
hard-coded number.  The format guarantees no upgrade path across a minor
version while it is below 1.0, so a file written against one minor may be
refused by a library implementing another.

**Neither sibling is on PyPI yet.**  `pyproject.toml` declares each as a
range closed above, since each is in `0.x` and any minor may break: the
floor names the oldest release the code runs on, the ceiling the newest
minor it was tested against.  `requirements.txt` installs the exact release
tags from GitHub, and a test holds those tags inside the ranges.  The
numbers live in `pyproject.toml`, `requirements.txt` and the changelog, not
here, because a copy in prose is one no test can see.  The sibling
checkouts are for co-development, in a second venv; see
{doc}`../introduction/installation`.
