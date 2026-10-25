# The TCP reassembler

`tcp.py` is the substance of the project: segments in, byte runs out.  Its
design is not free — two specification rules dictate most of it.

## The two rules

**Within one participant, records must be stored in ascending `seq_start`**,
in serial-number order, so a reader can merge both directions in one streaming
pass and never has to sort.  32-bit wrap is legal, so comparisons use RFC 1982
arithmetic throughout:

```python
def _delta(a: int, b: int) -> int:
    diff = (a - b) % _SEQ_MOD
    return diff - _SEQ_MOD if diff >= _SEQ_HALF else diff
```

Never compare sequence numbers with `<` in this module.

**Committing a gap is irreversible.**  Once a record has been written past
missing bytes, those bytes may never be written, even if they arrive later.

Together these forbid the easy implementation.  A reassembler cannot hold
everything until the end (that is not streaming), and it cannot write eagerly
and patch later (that is forbidden).  So it needs an explicit reorder buffer
with a bounded flush policy — and because that policy decides which bytes are
destroyed, it is a declared option whose digest is recorded on the file.

## Per-direction state

One `_Stream` per direction, keyed by the sender's endpoint:

| Field | Purpose |
|-------|---------|
| `isn`, `role` | From the handshake, if seen |
| `next_seq` | The next byte we expect; everything before it is committed |
| `pending` | Segments held because earlier bytes have not arrived, keyed by sequence |
| `pending_order`, `pending_anchor` | The keys of `pending` in serial order, as offsets from an anchor at or behind all of them, so the next held segment is the first entry |
| `pending_bytes`, `oldest_pending_ts` | What the flush policy measures |
| `run` | The record currently being accumulated |
| `committed_gaps` | Ranges we gave up on, each with the TSval of the first segment that overtook it, so late arrivals can be told from retransmits — and, by that clock, delayed originals from resends |
| `recent`, `recent_head`, `recent_bytes` | The transmissions accepted most recently, as `(seq, end, TSval, peer_count, pos)`, bounded by `reorder_window` bytes but never emptied; a list read from `recent_head` |
| `peer_count` | Packets seen from the other direction, whatever they carried |
| `ts_recent` | RFC 7323's `TS.Recent`: the TSval of the last segment accepted *in order at arrival* |

`committed_gaps` is the one that earns its keep.  Without it, bytes arriving
after their gap closed would be counted as ordinary duplicates — and a loss
caused by our own timeout would be indistinguishable from a harmless
retransmit.

`recent` is what lets a repeat be judged: the entry covering its range says
what TSval the bytes were first sent with and how many peer packets had been
seen by then.  It is bounded by `reorder_window` so memory is bounded by the
same number the hold is, and it never drops its newest entry, so the copy
that lands a microsecond after its original — the mirror-port shape — can
always be judged whatever the window.  A repeat of something older is
`stale`.

Neither structure is scanned on the paths that run per packet
([#43](https://github.com/adamkjonsson/python-zipline-wire/issues/43),
[#44](https://github.com/adamkjonsson/python-zipline-wire/issues/44)).
Both are kept in serial order, and both are searched by `bisect`. Serial
order is only an order within half the sequence space, so each keeps a way
to know it is still inside it:

- **`pending_order`** holds offsets from `pending_anchor`, which is set at
  `next_seq` when the buffer fills from empty, so it is at or behind every
  held segment. When `next_seq` runs more than `_MAX_WINDOW` past it, which
  takes a segment held across a gigabyte of progress, `_rebase_pending`
  moves it up.
- **`recent`** gives every entry an unwrapped position, `pos`, so its exact
  span is known. `_judge` bisects when that span is at most `_MAX_WINDOW`,
  which is the usual case, since `recent` holds `reorder_window` bytes. When
  committed gaps between entries stretch it further, `_judge` scans every
  entry, as it always did.

`tests/test_tcp_order.py` checks both against the implementations they
replaced, call for call.

## Accepting a segment

`_accept` handles four cases, in order:

```python
end = _advance(seq, len(data))
if _delta(end, stream.next_seq) <= 0:        # 1. entirely already seen
    self._count_repeat(...); return

if _delta(seq, stream.next_seq) < 0:         # 2. partially already seen
    overlap = _delta(stream.next_seq, seq)
    self._count_repeat(...)                  #    cite the leading trim
    data = data[overlap:]; seq = stream.next_seq
    self._mark_retransmit(stream)

if seq == stream.next_seq:                   # 3. contiguous
    self._append(...); self._drain(...)
else:                                        # 4. ahead — hold it
    self._hold(...); self._maybe_commit_gap(...)
```

Note that trimming is only ever *leading*.  That is what lets every discard
cite a byte range starting at the segment's payload offset, which is what
makes `Undecoded` blocks possible — see {doc}`writer-mapping`.

`_drain` then absorbs any held segments the new bytes made contiguous, which
is where reordering is actually undone.

### Judging a repeat

Every discard of already-seen bytes — cases 1 and 2 above, a repeat of a
held segment in `_hold`, and in `_drain` both the trim of a held segment and
a held segment the fill covered wholly — goes through `_judge`, which
returns one of four verdicts.  All five sites flag alike: until `0.5.0` the
last one discarded without flagging, by inheritance rather than decision
([#31](https://github.com/adamkjonsson/python-zipline-wire/issues/31)), and
the record covering its range is always the open run, since the fill was
appended in the same call.

| Verdict | When | Counted as | Cited as | Flags the run |
|---------|------|------------|----------|---------------|
| duplicate | both carried the option, same TSval, `peer_count` unchanged, range fully covered by `recent` | `duplicate_bytes` | `duplicate-discarded` | no |
| retransmit | option on both, and either a different TSval or a peer packet between | `overlap_bytes` | `overlap-discarded` | yes |
| `absent` | either side without the option | `overlap_bytes`, `ts_fallback["absent"]` | `overlap-discarded` | yes |
| `stale` | option on both, but the range is not covered by `recent` | `overlap_bytes`, `ts_fallback["stale"]` | `overlap-discarded` | yes |

The third clause of *duplicate* is the one that answers the coarse-tick
objection: a fast retransmit is triggered by the peer's duplicate ACKs, which
sit in the capture between the original and the resend, so `peer_count`
differs; a mirror copy follows its original with nothing between.  Content
is not compared — a resend carries the same bytes as its original unless one
was corrupted in flight, and corruption is the checksum policy's business.

`_judge` and `_late_reason` are the only places the Timestamps option is
*consulted*; `_tsval` is the only place it is *read*.  A repeat of a held
segment is judged against the `_Pending` directly rather than through
`recent`, since the held segment is the transmission the repeat may be a
copy of.

### PAWS, and the far side of a hole

Two rules from RFC 7323 read the option to decide *placement*, and neither
fires on any of the six real captures — which is the point: a rule that
emulates the receiver has to agree with what the receiver did.

**PAWS** sits in `_accept` after the wholly-behind branch and before the
trim: a segment that would contribute bytes, carrying a TSval older than
`ts_recent`, is an old segment from before a wrap and is dropped whole —
cited `paws-rejected`, counted `paws_bytes`, no flag.  It comes *after* the
repeat branch deliberately: a repeat is judged as a repeat, whatever its
clock, because the flag it may set is the sender's act and the receiver's
reason for dropping the copy changes nothing about that.  Because
`ts_recent` moves only on in-order arrival (below), a delayed original
filling a hole passes — its clock is older than the held segments' but not
older than the last in-order one — as it does on a real receiver.

**The far side of a hole** is `splits_before`, consulted by the conversion
loop before `packet()`, beside `expired()`.  `_delta` calls anything more
than 2³¹ away *behind*, so a segment from the far side of a hole that wide
would be discarded as a repeat and the direction lost.  Two facts identify
it: it is further behind than the largest window TCP can advertise
(`_MAX_WINDOW`, 2³⁰), so it is not a resend of anything; and its TSval is
newer than `ts_recent`, which an old segment's cannot be.  What the rule
*cannot* do is place it in this session — the writer stores records in
serial order and refuses one that far past its predecessor, since serially
it precedes — so the session ends for `capture-gap` and the segment opens
the next, on the same key with no `isn`.  `wrap_resolved` counts it.  The
`0.3.0` plan had the segment "held as ahead"; that is not representable, in
the buffer or in the format, and the split is what the format can say —
since spec `0.21` in as many words, the exit and the reason both being the
specification's own for what it calls *the unmeasurable hole*.

### Why a byte was late

A byte that lands inside a committed gap is compared, by TSval, against the
**first segment past that gap at the time it was committed** — the
`passer_tsval` on the `_Gap`, taken from the lowest-numbered held segment
when `_commit_gap` fires.  Older: sent before the bytes that overtook it,
so the original, delayed — `late-reordered`, the tuning signal.  Newer: sent
after them, so a resend — `late-retransmitted`.  Same tick, or no option:
plain `late-arrival`.

The reference is the first passer and *not* the newest TSval committed by
the time the late byte arrives, and `tcp_reorder_ts.pcap` is why: its
spurious resends take the same slow path as the originals they repeat, so by
their arrival the sender has committed 50 ms of newer segments.  Against
"everything committed" 8 of 10 read as reordered; against the segment that
overtook the gap, all 10 read as the resends they are.  The question is
about the sender's order, not the arrival's.

## Committing a gap

When the reorder window overflows or the oldest held segment goes stale:

```python
self._flush(stream)                                    # close the current run
stream.committed_gaps.append((stream.next_seq, target))
stream.next_seq = target                               # jump the hole
self._stats.gaps += 1
self._drain(stream, pkt)
```

The flush before the jump matters: the record that has been accumulating ends
*at* the hole, so the next record's `seq_start` is the far side of it.  That
is what makes the gap visible as arithmetic and is why no `Discontinuity`
block is needed.

The timeout is measured in **capture time**, not wall-clock, so a conversion
behaves identically whether it runs live or years later.

At end of capture, `_commit_remaining` drains whatever is still held rather
than dropping it, committing gaps as it goes.

## Record granularity

Both "one record per segment" and "coalesce contiguous bytes" are conformant
byte runs.  The default coalesces, flushing on PSH, on a gap, on FIN or RST,
at a timeout, and at end of capture.  `--no-coalesce` flushes every segment.

A run carries three hints, and all three are extremes over its contributing
packets rather than values from whichever packet happened to be appended last:

```python
ts        # the LAST packet contributing bytes — when the run became complete
ts_first  # the FIRST, written only when more than one packet contributed
ack       # the serial MAXIMUM of the contributors' acks
```

The `ts` rule is the specification's.  An acknowledgement can never precede
arrival of what it acknowledges, so the completion time is the meaningful one;
a retransmit contributing no accepted bytes does not move it.

The `ack` rule is this project's, and it exists because "last appended" is not
"last arrived": a segment held out of order arrives *before* the one that made
it contiguous but is appended *after* it, so a drained run would otherwise
carry the earlier packet's ack beside the later packet's timestamp — two hints
from two packets, by no rule.  Acks are cumulative, so one observed on any
contributor is still true when the run completes; the maximum is the strongest
statement the run can make that is certainly true, and it can never overstate.
It matters most under `--sequenced`, where the linearization releases a record
once every peer record it acks has been emitted, so an understated ack delays
a record for a reason that is not in the capture.  Serial, never `max()`: a
32-bit wrap in the middle of a run is exactly where a naive maximum inverts.

## The held run: `favor-acked`

Under `overlap="favor-acked"` a run is not written when it closes.  `_flush`
moves it onto `_Stream.unacked`, a deque in closing order — which is
ascending `seq_start` — and it is written by one of three things:

| Trigger | Where | Verdict for a contested range |
|---------|-------|-------------------------------|
| The peer's ack covers the run's end | `_settle`, from `packet()` on every peer packet carrying `ACK`, *before* that packet's own bytes are taken | the alternate's own evidence, below |
| `flush_timeout` since the run closed, or `unacked_bytes > reorder_window` | `_settle_stale`, on every packet and at `_flush` | fallback: `favor-old`, counted |
| Session end | `finish()`, after `_commit_remaining` and `_flush` | fallback: `favor-old`, counted |

**What is held against a run.**  A repeat judged a *retransmission* whose
bytes **differ** from what the run holds becomes an `_Alternate` on that run
— `(seq, end, tsval, data, ts, ack, payload_offset)` — via `_contested`,
which is consulted at every site `_discard` is, and answers *taken* (do not
count or cite yet: which copy loses is not known) or *not taken* (discard as
usual: the policy is `favor-old`, the verdict is a duplicate or a fallback —
no second clock to match an echo against — or the copies agree, where the
choice is moot).  A repeat of a *held* segment goes onto the `_Pending`'s
own alternates and is carried into the run with it, clipped by any trim.
Only disagreeing copies are kept, so memory is bounded by genuine
disagreements rather than by repeats.

**The evidence is per alternate, from the first ack covering *its* range**
— not the ack that releases the run.  The receiver echoes the TSval of
whatever *last* advanced its window, so by the time a coalesced run's end is
acknowledged the echo names a later segment than the resend that filled this
hole.  `_settle` therefore first walks every alternate of every held *and
open* run and stamps `decided`/`evidence` on those the ack covers, and only
then writes the runs whose end it covers.  The first implementation took the
evidence from the releasing ack and got 3 of `tcp_corrupt_ts`'s 5; this gets
all 5.

**Writing** (`_write`) resolves each alternate: swap when it is decided, the
echo equals the alternate's TSval and no kept contributor's — then the bytes
are spliced in, the displaced contributor(s) are cited as the losers and cut
out of `contributors` (`_without`), and the alternate joins them; otherwise
the alternate is the loser, cited, and counted as a fallback if it was
undecided or its ack carried no option.  The hints are then computed from
the contributors as finally chosen (`_hints`), which is why they moved from
incremental fields on `_Run` to a function: a swapped-in resend is the last
contributor and takes `ts` with it, and the copy it displaced stops counting
towards `ts_first`.  For `favor-old` the function returns exactly what the
incremental fields did — the sixteen pins are the proof.

**Interactions.**  `coalesce=False` closes a run per segment; each is held
and settled by the same rule, just more of them.  `--sequenced` is
unaffected: records still reach zpf in per-direction `seq_start` order, and
the linearisation is zpf's own buffer of built blocks — which is also why
the hold could not live there.  The idle `timeout` and the `splits_before`
reason both go through `finish()`.  A one-way capture never acks, so every
run waits out `flush_timeout` (measured by the packets that do arrive, or
the session's end) and falls back, counted.

## Two things that produce no record

**Pure acknowledgements.**  The specification permits zero-length ack-only
records, but they would multiply file size for information that only matters
once sessions are sequenced.  The consequence is real and worth knowing: a
conversation of nothing but acks produces a session with *no records at all*,
which makes it hint-less — see {doc}`writer-mapping`.

**A FIN on its own segment.**  When a FIN rides along with data the record
carries the flag; when it arrives alone, the direction's close is carried by
the Session End reason instead of an empty record.

A SYN *does* get a record, because it is the one event whose time would
otherwise be nowhere in the file.  It sits at `isn + 1` — the stream origin —
and **not** at the `isn`: the SYN consumes a sequence number but delivers no
byte, so a record at the `isn` is one below the origin, where the offset
`seq_start - (isn + 1)` is negative in a space that has none.  The modular
subtraction absorbs that rather than reporting it, putting the record at
offset 2³²−1 and making the stream measure that many bytes — which is what
this project shipped for months before python-zipline#63, and what the
writer now refuses.  Sharing the origin with the first data record is what
the specification asks for: two records at one `seq_start` are stored in the
order they were produced, and the SYN comes first.

Only the first SYN per direction gets one — a retransmitted SYN re-opens
nothing.

## Where to be careful

**Sequence comparisons.**  Use `_delta`, never `<`.  TSvals too: they are
32-bit and wrap, and `_delta` is the comparison for both.

**`ts_recent` moves only on in-order arrival.**  It is updated in `_accept`
when `seq == stream.next_seq` *as the segment arrives*, and never from a
segment drained out of the hold.  That is the receiver's rule (RFC 7323
§4.3, `SEG.SEQ <= Last.ACK.sent`): while a hole is open the receiver keeps
acknowledging the same byte, so `TS.Recent` stays at the last in-order
segment, and a delayed original that finally fills the hole — with a TSval
older than the segments that passed it — is *not* rejected.  A real receiver
kept exactly those segments in `tcp_reorder_ts.pcap` and D-SACKed their
resends; a reassembler that updated `ts_recent` from out-of-order data would
disagree with the stack it emulates.  PAWS and the far-side rule both read
it, and this is the invariant they rest on; the test that catches an
over-eager update is the delayed original behind a hole.

**The `_stamp` helper.**  Draining a held segment appends it with the *held*
packet's timestamp, flags and ack, not the arriving packet's, so a run's
hints reflect the packets that actually carried its bytes.  A synthetic
`PacketView` carries that metadata; it has `payload=b""` because the payload
travels separately.  `_commit_remaining` builds the same kind of view at end
of capture.  Both fold through `_append`, which is why the three-hint rule
above lives there and nowhere else.

**Citing discards.**  Every discard site must both count and cite.  Counting
without citing loses the byte range; citing without counting breaks the
accounting identity the tests assert.
