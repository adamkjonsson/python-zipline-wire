"""TCP order and timing, on top of :mod:`zpfwire.fidelity`.

The TCP truth, ledger, byte score and accounting are public since ``0.8.0``
(#63).  Order and timing are not: their definitions changed twice during
``0.7.0``, so they stay here, without a promise, until they have survived a
release unchanged.

- :func:`score_order` — each message's place in the file's timeline, against
  what it depends on, and its timing.
- :func:`measure` — :func:`zpfwire.fidelity.measure`, with the order scored.
"""

from __future__ import annotations

import bisect
import dataclasses
from dataclasses import dataclass

from zpfwire.fidelity import (
    DIRECTIONS,
    Direction,
    Entry,
    Ledger,
    Output,
    Run,
)
from zpfwire.fidelity import Measurement as Scored
from zpfwire.fidelity import measure as measure_bytes
from zpfwire.options import ReassemblyOptions

_WRAP = 2**32


# ── Order and timing ────────────────────────────────────────────────────


@dataclass(frozen=True)
class Timing:
    """When the file says a message was sent, against when it was.

    Read from the record holding the message's first byte.  A coalesced
    record is one unit, so its ``timestamp`` is when its *last* packet
    arrived and its ``ts_first`` when its first did: a message that does
    not start its record, or does not end it, is dated by its neighbours.

    Attributes:
        message: The message's index.
        recovered: Whether its first segment's original was lost and only a
            resend captured.  The true send time is then the resend's less
            the retransmission timeout — what packeteer schedules it at —
            and the record is expected to be late by about that much.
        correct: Whether the file holds the true byte there.  A forged first
            byte is timed too, and what it times is the forgery.
        starts_record: Whether the message's first byte is its record's.
        timestamp_error: The record's ``timestamp`` less the true send time,
            in microseconds.
        ts_first_error: The same for ``ts_first``, or ``None`` where the
            record carries none.

    """

    message: int
    recovered: bool
    correct: bool
    starts_record: bool
    timestamp_error: int
    ts_first_error: int | None


@dataclass(frozen=True)
class OrderScore:
    """Where each message's first byte falls in the session's timeline.

    packeteer emits messages strictly in order, but message order is not the
    causal order once a segment is lost: the generator keeps sending, and a
    receiver's acknowledgement stays at the hole, so a reply sent meanwhile
    acknowledges nothing of the message it follows.  What the wire
    establishes is narrower, and it is what neither the causal merge nor a
    sequenced session may break: message *j* **depends on** message *i*
    when the original transmission of *j*'s first segment acknowledged
    *i*'s first byte, or *i* is earlier in *j*'s own direction — closed
    transitively.  Only the original counts: a resend carries the ack of
    when it was resent, so a message whose original was lost has no ack
    evidence at all, rather than evidence from the wrong moment.

    Attributes:
        positions: Each message's first byte's position in the timeline,
            counting records with payload; ``None`` where the file does not
            hold that byte.
        inversions: Pairs where a message is placed before one it depends
            on: each a failure.  Pairs involving a forged first byte are not
            counted — the forgery's position is the forgery's.
        reordered: Pairs placed against plain message order, dependency or
            not.  Reported, not a failure.  Two messages whose first bytes
            share a record are not a pair: the record's offsets order them.
        forged: Messages whose first byte the file holds wrongly.
        timing: One sample per placed message.

    """

    positions: tuple[int | None, ...]
    inversions: int
    reordered: int
    forged: int
    timing: tuple[Timing, ...]

    @property
    def unplaced(self) -> int:
        """Messages whose first byte the file does not hold."""
        return sum(p is None for p in self.positions)


def dependencies(run: Run) -> list[set[int]]:
    """Return, for each message, the earlier messages it depends on.

    Args:
        run: The run.

    Returns:
        ``deps[j]``: the messages *j* depends on, transitively.  See
        :class:`OrderScore`.

    """
    messages = run.truth.messages
    deps: list[set[int]] = []
    for j, message in enumerate(messages):
        original = _original(run.ledger, message.direction, message.offset)
        acked = original.acked if original is not None else None
        direct = {
            i for i, earlier in enumerate(messages[:j])
            if earlier.direction == message.direction
            or (acked is not None and acked > earlier.offset)
        }
        closed = set(direct)
        for i in direct:
            closed |= deps[i]
        deps.append(closed)
    return deps


def _original(ledger: Ledger, direction: Direction, offset: int) -> Entry | None:
    """Return the captured original transmission carrying *offset*, if any."""
    originals = [e for e in ledger.data(direction)
                 if e.original and e.offset <= offset < e.end]
    return min(originals, key=lambda e: e.usec, default=None)


def score_order(run: Run, output: Output) -> OrderScore:
    """Score the order and timing of a converted run's messages.

    Args:
        run: The run.
        output: What its conversion holds.

    Returns:
        The score.

    """
    placed: dict[Direction, list[tuple[int, int, int]]] = {d: [] for d in DIRECTIONS}
    for position, (direction, offset, record) in enumerate(output.timeline):
        placed[direction].append((offset, offset + len(record.payload), position))
    for spans in placed.values():
        spans.sort()

    positions: list[int | None] = []
    timing = []
    rto = round(run.scenario.impairments.retransmission_timeout * 1_000_000)
    for message in run.truth.messages:
        spans = placed[message.direction]
        at = bisect.bisect_right(spans, (message.offset, _WRAP, 0)) - 1
        if at < 0 or not spans[at][0] <= message.offset < spans[at][1]:
            positions.append(None)
            continue
        start, _, position = spans[at]
        positions.append(position)
        segment = next(
            (s for s in run.ledger.segments if s.direction == message.direction
             and s.offset <= message.offset < s.offset + s.length),
            None,
        )
        if segment is None:  # a forged byte where nothing real was captured
            continue
        sent = segment.first_usec - rto if segment.sent_usec is None else segment.sent_usec
        record = output.timeline[position][2]
        held = record.payload[message.offset - start]
        timing.append(Timing(
            message=message.index,
            recovered=segment.sent_usec is None,
            correct=held == run.truth.streams[message.direction][message.offset],
            starts_record=start == message.offset,
            timestamp_error=output.usec(record.timestamp) - sent,
            ts_first_error=None if record.ts_first is None else output.usec(record.ts_first) - sent,
        ))

    forged = {t.message for t in timing if not t.correct}
    deps = dependencies(run)

    def placed_after(i: int, j: int) -> bool:
        a, b = positions[i], positions[j]
        return a is not None and b is not None and a > b

    pairs = [(i, j) for j in range(len(positions)) for i in range(j)]
    return OrderScore(
        positions=tuple(positions),
        inversions=sum(
            1 for i, j in pairs
            if i in deps[j] and i not in forged and j not in forged and placed_after(i, j)
        ),
        reordered=sum(1 for i, j in pairs if placed_after(i, j)),
        forged=len(forged),
        timing=tuple(timing),
    )


# ── A measurement ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class Measurement(Scored):
    """A :class:`zpfwire.fidelity.Measurement`, with the messages' order and timing.

    Attributes:
        order: The messages' order and timing.

    """

    order: OrderScore


def measure(
    run: Run, options: ReassemblyOptions | None = None, *, sequenced: bool = False,
) -> Measurement:
    """Convert a run, read it back, and score it, order and timing included.

    Args:
        run: The run.
        options: The reassembly policy; zpfwire's defaults when ``None``.
        sequenced: Whether to write the session in causal order.

    Returns:
        The measurement.

    Raises:
        Unclean: If the file does not read back clean.

    """
    scored = measure_bytes(run, options, sequenced=sequenced)
    fields = {f.name: getattr(scored, f.name) for f in dataclasses.fields(scored)}
    return Measurement(**fields, order=score_order(run, scored.conversion.output))
