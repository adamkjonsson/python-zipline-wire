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
| `pending_bytes`, `oldest_pending_ts` | What the flush policy measures |
| `run` | The record currently being accumulated |
| `committed_gaps` | Ranges we gave up on, so late arrivals can be told from retransmits |

`committed_gaps` is the one that earns its keep.  Without it, bytes arriving
after their gap closed would be counted as ordinary duplicates — and a loss
caused by our own timeout would be indistinguishable from a harmless
retransmit.

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

A run carries two timestamps:

```python
ts        # the LAST packet contributing bytes — when the run became complete
ts_first  # the FIRST, written only when more than one packet contributed
```

The `ts` rule is the specification's.  An acknowledgement can never precede
arrival of what it acknowledges, so the completion time is the meaningful one;
a retransmit contributing no accepted bytes does not move it.

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
otherwise be nowhere in the file.  Only the first per direction — a second at
the same `seq_start` would break the ascending-order rule.

## Where to be careful

**Sequence comparisons.**  Use `_delta`, never `<`.

**The `_stamp` helper.**  Draining a held segment appends it with the *held*
packet's timestamp and flags, not the arriving packet's, so a run's `ts`
reflects when its bytes actually arrived.  A synthetic `PacketView` carries
that metadata; it has `payload=b""` because the payload travels separately.

**Citing discards.**  Every discard site must both count and cite.  Counting
without citing loses the byte range; citing without counting breaks the
accounting identity the tests assert.
