"""TCP reassembly: segments in, byte runs out.

The output shape is fixed by the specification rather than by taste, and two
of its rules drive the whole design:

* Within one participant, records **must** be stored in ascending
  ``seq_start`` (serial-number order), so a reader can merge the two
  directions in one streaming pass and never has to sort.
* Committing a gap is **irreversible**. Once a record has been written past
  missing bytes, those bytes may never be written, even if they arrive later.

The second is why this module has an explicit reorder buffer with a bounded
flush policy instead of an incidental one: the policy decides which bytes are
thrown away, so it is a declared option
(:class:`~zpfwire.options.ReassemblyOptions`) whose digest is recorded on the
Decoder Descriptor.

Everything discarded is counted — retransmitted bytes as ``overlap_bytes``,
copies of one transmission as ``duplicate_bytes``, bytes that arrived after
their gap was committed as ``late_bytes`` — so a conversion never loses data
quietly.

The TCP Timestamps option (RFC 7323) is read where it can settle something
the reassembler would otherwise have to assume.  Every transmission of a byte
range carries its own TSval; a copy of one transmission does not.  That is
what separates a mirror port's duplicate from a retransmission, and the
specification's ``retransmit`` flag names the sender's act, so the
distinction reaches the file.  Where the option is absent the rule degrades
to the conservative reading the specification asks for — every repeat is a
retransmission — and says so in the stats.

Under ``overlap="favor-acked"`` the option decides one more thing: which of
two *disagreeing* copies of a range the receiver kept.  The evidence is the
TSecr on the peer's first acknowledgement covering the range — the TSval of
the transmission that advanced its window — and it arrives after both
copies.  So every run is held after it closes until the peer's ack covers
it, and only then written; see :meth:`TcpFlow._settle`.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import zpf
from packeteer.generate.tcp import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG
from zpf import RecordFlags, TcpRole

from zpfwire.capture import PacketView
from zpfwire.flow import (
    END_CAPTURE_END,
    END_TIMEOUT,
    REASON_DUPLICATE,
    REASON_LATE,
    REASON_LATE_REORDERED,
    REASON_LATE_RETRANSMITTED,
    REASON_OVERLAP,
    REASON_PAWS,
    FlowTracker,
)

__all__ = [
    "END_CAPTURE_GAP",
    "END_FIN",
    "END_RST",
    "TS_ABSENT",
    "TS_STALE",
    "TcpFlow",
]

_SEQ_MOD = 1 << 32
_SEQ_HALF = _SEQ_MOD >> 1
# The largest receive window TCP can advertise — a 16-bit window scaled by
# the maximum shift of 14 (RFC 7323 §2.3) — and so the furthest behind the
# next expected byte any retransmission can be.  A segment further behind
# than that is not a resend of anything; if its clock is newer than ours, it
# is from *ahead*, past the half-space edge serial arithmetic cannot cross.
_MAX_WINDOW = 1 << 30

END_FIN = "fin"
"""Session End reason when both directions closed cleanly."""

END_RST = "rst"
"""Session End reason when either direction reset the connection."""

END_CAPTURE_GAP = "capture-gap"
"""Session End reason when the capture skipped further than a session can span.

The specification's own value for *the unmeasurable hole* (`spec 0.21,
§Referencing the source by stream offset
<https://github.com/adamkjonsson/zipline/blob/v0.21/docs/
zipline-payload-format.md#referencing-the-source-by-stream-offset>`__): a
hole of 2**31 bytes or more between two consecutive records of one
participant has no representation within one stream — a record 2**31 + *x*
past its predecessor is, in serial arithmetic, 2**31 − *x* before it, and
the ordering rule refuses the pair.  A producer that knows the far side is
real ends the session at the hole and opens another on the same key with no
``isn``, so the stream resumes at its first captured byte, and **SHOULD**
write this reason, so that a consumer can tell a resumed conversation from a
new one.  This reason on the old session therefore says the connection did
not end: the file merely could not follow it across the hole.  The far side
is recognised by the TCP Timestamps option; see
:meth:`TcpFlow.splits_before`.
"""

TS_ABSENT = "absent"
"""Fallback key: a repeat could not be judged because one side lacked the option."""

TS_STALE = "stale"
"""Fallback key: a repeat could not be judged because its original had aged out."""

_DUPLICATE = "duplicate"
_RETRANSMIT = "retransmit"
_FAVOR_ACKED = "favor-acked"

_FLAG_MAP = (
    (TCP_PSH, RecordFlags.PSH),
    (TCP_FIN, RecordFlags.FIN),
    (TCP_RST, RecordFlags.RST),
    (TCP_URG, RecordFlags.URG),
)


def _advance(seq: int, count: int) -> int:
    """Return *seq* plus *count*, wrapping in the 32-bit sequence space."""
    return (seq + count) % _SEQ_MOD


def _delta(a: int, b: int) -> int:
    """Return ``a - b`` as a signed distance, per RFC 1982.

    Well defined for any two sequence numbers within 2**31 of each other,
    which is vastly more than any in-flight window.
    """
    diff = (a - b) % _SEQ_MOD
    return diff - _SEQ_MOD if diff >= _SEQ_HALF else diff


def _tsval(pkt: PacketView) -> int | None:
    """Return the segment's TSval, or ``None`` when it carries no Timestamps option.

    The one place the option is read, so every rule that consults it degrades
    through the same door when it is absent.
    """
    options = pkt.tcp_options
    if options is None or options.timestamps is None:
        return None
    return options.timestamps[0]


@dataclass
class _Pending:
    """A segment held back because earlier bytes have not arrived."""

    data: bytes
    flags: int
    ack: int
    ts: int
    payload_offset: int | None = None
    tsval: int | None = None
    # The peer packets seen when it arrived; see _Sent.
    peer_count: int = 0
    # Disagreeing copies that arrived while it waited (favor-acked only).
    alternates: list[_Alternate] = field(default_factory=list)


@dataclass(frozen=True)
class _Contribution:
    """One transmission whose bytes are in a run, with what the hints need of it."""

    seq: int
    end: int
    tsval: int | None
    ts: int
    ack: int
    payload_offset: int | None


@dataclass
class _Alternate:
    """A copy of part of a run that arrived with different bytes (favor-acked only).

    Only a *disagreeing* copy is kept — where two copies agree the choice is
    moot — so memory is bounded by genuine disagreements, not by repeats.

    The evidence is taken from the **first peer ack covering this range**,
    not the ack that releases the run: the receiver echoes the TSval of what
    *last* advanced its window, so by the time a coalesced run's end is
    acknowledged the echo may name a later segment than the one that filled
    this hole.  ``decided`` says an ack covered the range; ``evidence`` is
    what it echoed, ``None`` when it carried no option.
    """

    seq: int
    end: int
    tsval: int
    data: bytes
    ts: int
    ack: int
    payload_offset: int | None
    decided: bool = False
    evidence: int | None = None


@dataclass(frozen=True)
class _Gap:
    """A range this direction gave up on, and the clock of what overtook it."""

    start: int
    end: int
    passer_tsval: int | None


@dataclass(frozen=True)
class _Sent:
    """One transmission this direction accepted, remembered to judge its repeats.

    A repeat of ``[seq, end)`` is a copy of *this* transmission — the same
    packet seen twice by the capture point — when it carries the same TSval
    and nothing from the peer arrived in between.  A fast retransmit is
    triggered by the peer's duplicate ACKs, which sit in the capture between
    the original and the resend, and a mirror copy follows its original with
    nothing between them; ``peer_count`` is what makes that comparable.
    """

    seq: int
    end: int
    tsval: int | None
    peer_count: int


@dataclass
class _Run:
    """Contiguous bytes accumulating towards one record."""

    seq_start: int
    data: bytearray = field(default_factory=bytearray)
    # The transmissions whose bytes these are, in the order appended.  The
    # three hints are computed from them when the run is written — see
    # _hints — so that a copy swapped in under favor-acked, or the one it
    # displaced, moves them the way the specification's rules say.
    contributors: list[_Contribution] = field(default_factory=list)
    # Disagreeing copies of parts of this run, awaiting the peer's verdict.
    alternates: list[_Alternate] = field(default_factory=list)
    flags: int = 0
    retransmit: bool = False
    # Capture time when the run closed; what the favor-acked hold is timed from.
    closed_ts: int = 0
    # Packets whose flags, not bytes, reached the run — a FIN or RST with no
    # payload — named so a `.zpf` input can cite them; see RecordSink.record.
    flag_origins: list[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        """Return one past the run's last sequence number."""
        return _advance(self.seq_start, len(self.data))


@dataclass
class _Stream:
    """One direction of a TCP connection."""

    endpoint: str
    isn: int | None = None
    role: TcpRole | None = None
    next_seq: int | None = None
    declared: bool = False
    syn_written: bool = False
    fin: bool = False
    rst: bool = False
    pending: dict[int, _Pending] = field(default_factory=dict)
    pending_bytes: int = 0
    oldest_pending_ts: int | None = None
    run: _Run | None = None
    # (start, end, passer) — the third is the TSval of the first segment past
    # the gap when it was committed: the clock reading of what overtook the
    # missing bytes, against which a late arrival says whether it was sent
    # before them (the original, delayed) or after (a resend).
    committed_gaps: list[_Gap] = field(default_factory=list)
    # The transmissions accepted most recently, oldest first, bounded by
    # `reorder_window` bytes — but never emptied, so the copy that lands a
    # microsecond after its original can always be judged.  A repeat of
    # something older than the deque cannot be, and is counted as such.
    recent: deque[_Sent] = field(default_factory=deque)
    recent_bytes: int = 0
    # Packets seen from the other direction, whatever they carried.
    peer_count: int = 0
    # RFC 7323 §4.3's TS.Recent: the TSval of the last segment accepted *in
    # order* at arrival, never one drained from the hold.  That is the
    # receiver's own rule (SEG.SEQ <= Last.ACK.sent): while a hole is open the
    # value stays at the last in-order segment, which is why a delayed
    # original behind the hole, with an older TSval, is not rejected — a real
    # receiver kept it, and D-SACKed the resend.
    ts_recent: int | None = None
    # favor-acked: runs that have closed and wait for the peer's ack to cover
    # them, oldest first — so records still reach the writer in seq order.
    unacked: deque[_Run] = field(default_factory=deque)
    unacked_bytes: int = 0


class TcpFlow(FlowTracker):
    """Writes one TCP conversation as a session of reassembled byte runs."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._streams: dict[str, _Stream] = {}
        self._split_reason: str | None = None
        self._acked = self._options.overlap == _FAVOR_ACKED

    # ── driving ─────────────────────────────────────────────────────────

    def packet(self, pkt: PacketView) -> None:
        """Take one segment of this conversation."""
        self.last_ts = pkt.ts_ticks
        stream = self._stream(pkt.src_endpoint)
        for other in self._streams.values():
            if other is not stream:
                other.peer_count += 1
                # This packet's ack settles the peer's held runs — before its
                # own bytes are taken, since what it acknowledges arrived
                # before it was sent.
                if self._acked and pkt.tcp_flags & TCP_ACK:
                    self._settle(other, pkt.ack, _tsecr(pkt))
        if self._acked:
            for held_stream in self._streams.values():
                self._settle_stale(held_stream, pkt.ts_ticks)

        syn = bool(pkt.tcp_flags & TCP_SYN)
        if syn:
            self._handshake(stream, pkt)
            tsval = _tsval(pkt)
            if tsval is not None and stream.ts_recent is None:
                stream.ts_recent = tsval
        self._declare(stream)
        if syn:
            self._syn_record(stream, pkt)

        if pkt.payload:
            self._accept(stream, pkt.seq, pkt.payload, pkt)

        closing = bool(pkt.tcp_flags & (TCP_FIN | TCP_RST))
        if closing:
            stream.fin = stream.fin or bool(pkt.tcp_flags & TCP_FIN)
            stream.rst = stream.rst or bool(pkt.tcp_flags & TCP_RST)
            self._attach_flags(stream, pkt, origin=pkt.payload_offset)

        # A run ends where the sender said it did (PSH), where the connection
        # ends, or at every segment when coalescing is off.
        pushed = bool(pkt.tcp_flags & TCP_PSH) and bool(pkt.payload)
        if closing or pushed or not self._options.coalesce:
            self._flush(stream)

    def finish(self) -> str:
        """Flush every held-back byte and report why the session ended.

        Returns:
            ``"rst"``, ``"fin"``, ``"timeout"`` or ``"capture-end"``.

        """
        for stream in self._streams.values():
            self._commit_remaining(stream)
            self._flush(stream)
            # Whatever the peer never acknowledged is written on the
            # fallback: the evidence did not arrive, and that is counted.
            while stream.unacked:
                self._write(stream, self._release_run(stream))
        self._declare_silent_peer()

        if any(s.rst for s in self._streams.values()):
            return END_RST
        if self._streams and all(s.fin for s in self._streams.values()) and len(self._streams) > 1:
            return END_FIN
        if self._split_reason is not None:
            return self._split_reason
        return END_TIMEOUT if self.timed_out else END_CAPTURE_END

    # ── participants ────────────────────────────────────────────────────

    def _stream(self, endpoint: str) -> _Stream:
        stream = self._streams.get(endpoint)
        if stream is None:
            stream = _Stream(endpoint=endpoint)
            self._streams[endpoint] = stream
        return stream

    def _handshake(self, stream: _Stream, pkt: PacketView) -> None:
        """Record what a SYN tells us, if this is the first one we have seen.

        The ``isn`` fixes the stream's absolute origin, and the specification
        requires it exactly when the handshake was observed — so it has to be
        known before the participant is declared, which is why declaration is
        lazy and per-sender.
        """
        if stream.declared or stream.isn is not None:
            return
        stream.isn = pkt.seq
        stream.role = TcpRole.RESPONDER if pkt.tcp_flags & TCP_ACK else TcpRole.INITIATOR
        # The SYN itself consumes one sequence number; data starts after it.
        stream.next_seq = _advance(pkt.seq, 1)

    def _syn_record(self, stream: _Stream, pkt: PacketView) -> None:
        """Write the handshake itself as an empty record carrying ``SYN``.

        The connection's opening is the one event whose *time* the file would
        otherwise lose: ``isn`` says where the stream begins in sequence space
        but not when, and the first data record is stamped with its own
        arrival. Only the first SYN of a direction gets one — a retransmitted
        SYN re-opens nothing.

        The record sits at ``isn + 1``, the stream origin, and **not** at the
        ``isn``: the SYN consumes a sequence number but delivers no byte, so a
        record at the ``isn`` sits one below the origin, where the offset
        ``seq_start - (isn + 1)`` is negative in a space that has no negative
        offsets. The subtraction is modular and absorbs it rather than
        reporting it, putting the record at offset 2**32 - 1 and making the
        stream measure that many bytes. Sharing the origin with the first data
        record is what the specification asks for: the two are stored in the
        order they were produced, and the SYN comes first.
        """
        if stream.syn_written or stream.isn is None or pkt.seq != stream.isn:
            return
        stream.syn_written = True
        self.sink.record(
            self.participant(stream.endpoint),
            ts=pkt.ts_ticks,
            payload=b"",
            origins=(pkt.payload_offset,),
            hints=zpf.Hints(
                seq_start=_advance(stream.isn, 1),
                # The one place the ACK flag is consulted, and deliberately so:
                # the opening SYN of a connection has nothing to acknowledge
                # yet, so its ack field is not a number that was understated —
                # it is a number that does not exist.  A data segment always
                # has something to acknowledge whatever its flags say, which is
                # why _append reads every contributor's ack without asking.
                ack=pkt.ack if pkt.tcp_flags & TCP_ACK else None,
            ),
            flags=RecordFlags.SYN,
        )
        self._stats.records += 1

    def _declare(self, stream: _Stream) -> None:
        if stream.declared:
            return
        declaration: dict[str, object] = {}
        if stream.isn is not None:
            declaration["isn"] = stream.isn
        if stream.role is not None:
            declaration["tcp_role"] = stream.role
        self.participant(stream.endpoint, **declaration)
        stream.declared = True

    def _declare_silent_peer(self) -> None:
        """Declare the far endpoint even if it never sent anything.

        The conversation had two ends whether or not both spoke; a session
        that named only the talker would describe the capture rather than the
        connection. It gets no ``isn``, since no handshake was seen from it.
        """
        for endpoint in (self.key.a, self.key.b):
            if not self.declared(endpoint):
                self.participant(endpoint)

    # ── reassembly ──────────────────────────────────────────────────────

    def _accept(self, stream: _Stream, seq: int, data: bytes, pkt: PacketView) -> None:
        """Take the payload of one segment into the stream."""
        if stream.next_seq is None:
            # Mid-stream capture: no handshake was seen, so this segment
            # defines where our view of the stream begins.
            stream.next_seq = seq

        end = _advance(seq, len(data))
        tsval = _tsval(pkt)
        if _delta(end, stream.next_seq) <= 0:
            self._count_repeat(stream, seq, end, pkt.payload_offset, data,
                               tsval=tsval, peer_count=stream.peer_count, pkt=pkt)
            return

        # PAWS (RFC 7323 §5.3): a segment that would contribute bytes but
        # carries a clock older than the last one accepted in order is an old
        # segment from before a wrap, and a receiver drops it whole.  Judged
        # only here — a segment wholly behind is a repeat and has already been
        # judged as one above, where the flag it may set is the sender's act
        # whatever the receiver did with the copy.
        if (
            tsval is not None
            and stream.ts_recent is not None
            and _delta(tsval, stream.ts_recent) < 0
        ):
            self._stats.paws_bytes += len(data)
            self.undecoded(pkt.payload_offset, len(data), reason=REASON_PAWS)
            return

        payload_offset = pkt.payload_offset
        if _delta(seq, stream.next_seq) < 0:
            overlap = _delta(stream.next_seq, seq)
            # Only ever a leading trim, so the discarded bytes start where the
            # segment's payload starts.
            self._count_repeat(stream, seq, stream.next_seq, pkt.payload_offset, data[:overlap],
                               tsval=tsval, peer_count=stream.peer_count, pkt=pkt)
            data = data[overlap:]
            seq = stream.next_seq
            if payload_offset is not None:
                payload_offset += overlap

        if seq == stream.next_seq:
            # In order at arrival: the one case that moves TS.Recent.
            if tsval is not None and (
                stream.ts_recent is None or _delta(tsval, stream.ts_recent) >= 0
            ):
                stream.ts_recent = tsval
            self._append(stream, seq, data, pkt, tsval=tsval, peer_count=stream.peer_count,
                         payload_offset=payload_offset)
            self._drain(stream, pkt)
        else:
            self._hold(stream, seq, data, pkt, tsval=tsval)
            self._maybe_commit_gap(stream, pkt)

    def _append(
        self,
        stream: _Stream,
        seq: int,
        data: bytes,
        pkt: PacketView,
        *,
        tsval: int | None,
        peer_count: int,
        payload_offset: int | None,
        alternates: list[_Alternate] | None = None,
    ) -> None:
        if stream.run is None:
            stream.run = _Run(seq_start=seq)
        end = _advance(seq, len(data))
        stream.run.data.extend(data)
        stream.run.contributors.append(_Contribution(
            seq=seq, end=end, tsval=tsval, ts=pkt.ts_ticks, ack=pkt.ack,
            payload_offset=payload_offset,
        ))
        if alternates:
            stream.run.alternates.extend(alternates)
            stream.run.retransmit = True
        self._remember(stream, seq, end, tsval, peer_count)
        self._attach_flags(stream, pkt)
        stream.next_seq = end

    def _hold(
        self, stream: _Stream, seq: int, data: bytes, pkt: PacketView, *, tsval: int | None,
    ) -> None:
        if seq in stream.pending:
            # A repeat of something already waiting.  The held segment is the
            # transmission this one may be a copy of, so it is judged against
            # that directly rather than through `recent`.
            held = stream.pending[seq]
            if tsval is None or held.tsval is None:
                verdict = TS_ABSENT
            elif (
                tsval == held.tsval
                and stream.peer_count == held.peer_count
                and len(data) == len(held.data)
            ):
                verdict = _DUPLICATE
            else:
                verdict = _RETRANSMIT
            if (
                self._acked
                and verdict == _RETRANSMIT
                and len(data) == len(held.data)
                and data != held.data
            ):
                # A disagreeing copy of something not yet in a run: it waits
                # with the held segment and is carried into the run with it.
                # Both TSvals are known, since the verdict needed them.
                assert tsval is not None
                held.alternates.append(_Alternate(
                    seq=seq, end=_advance(seq, len(data)), tsval=tsval, data=data,
                    ts=pkt.ts_ticks, ack=pkt.ack, payload_offset=pkt.payload_offset,
                ))
                return
            self._discard(stream, verdict, pkt.payload_offset, 0, len(data))
            return
        stream.pending[seq] = _Pending(data=data, flags=pkt.tcp_flags, ack=pkt.ack,
                                       ts=pkt.ts_ticks, payload_offset=pkt.payload_offset,
                                       tsval=tsval, peer_count=stream.peer_count)
        stream.pending_bytes += len(data)
        if stream.oldest_pending_ts is None:
            stream.oldest_pending_ts = pkt.ts_ticks

    def _drain(self, stream: _Stream, pkt: PacketView) -> None:
        """Absorb held segments that the newly-arrived bytes made contiguous."""
        while stream.pending:
            seq = self._next_pending(stream)
            held = stream.pending[seq]
            end = _advance(seq, len(held.data))
            if _delta(end, stream.next_seq) <= 0:
                # Wholly superseded by what filled the hole.  The fill is the
                # later arrival, so the held segment is the original and the
                # fill the repeat; the verdict is the same either way round.
                # A retransmission flags the record covering the range, as at
                # the other four sites, by decision (#31): the sender sent
                # these bytes twice, once alone and once inside the fill.
                # That record is always the open run.  The fill was appended
                # in this same call, by _accept just before it drains or by an
                # earlier pass of this loop, _commit_gap flushes *before* it
                # drains, and _append never flushes; a held segment sits past
                # the hole, so its range starts inside the run.
                assert stream.run is not None, "a superseded held segment lies in the open run"
                self._release(stream, seq)
                verdict = self._judge(stream, seq, end, held.tsval, held.peer_count)
                if not self._contested(stream, verdict, seq, end, held.data, held):
                    self._discard(stream, verdict, held.payload_offset, 0, len(held.data))
                continue
            if _delta(seq, stream.next_seq) > 0:
                return
            trim = _delta(stream.next_seq, seq)
            self._release(stream, seq)
            if trim:
                verdict = self._judge(stream, seq, stream.next_seq, held.tsval, held.peer_count)
                if not self._contested(stream, verdict, seq, stream.next_seq,
                                       held.data[:trim], held):
                    self._discard(stream, verdict, held.payload_offset, 0, trim)
            self._append(
                stream,
                stream.next_seq,
                held.data[trim:],
                _stamp(pkt, held),
                tsval=held.tsval,
                peer_count=held.peer_count,
                payload_offset=None if held.payload_offset is None else held.payload_offset + trim,
                alternates=_clip(held.alternates, stream.next_seq, end),
            )
        stream.oldest_pending_ts = None

    def _release(self, stream: _Stream, seq: int) -> None:
        held = stream.pending.pop(seq)
        stream.pending_bytes -= len(held.data)

    def _next_pending(self, stream: _Stream) -> int:
        assert stream.next_seq is not None
        return min(stream.pending, key=lambda s: _delta(s, stream.next_seq))  # type: ignore[arg-type]

    # ── gaps ────────────────────────────────────────────────────────────

    def splits_before(self, pkt: PacketView) -> bool:
        """Say whether *pkt* is from past the wrap, where this session cannot follow.

        ``_delta`` places anything more than 2**31 away on the near side, so a
        segment from more than 2 GB further along the stream — the far side of
        a hole in the capture that big — looks like old data and, as old data,
        would be discarded as a repeat: counted as a retransmission the sender
        never made, with the rest of the direction lost behind it.  Two facts
        separate the two.  A resend is never further behind than the largest
        window TCP can advertise, so a segment further behind than that is
        not one.  And the Timestamps option is a per-sender clock that the
        sequence number is not: a segment from ahead carries a TSval newer
        than the last one accepted in order, which an old segment cannot.

        Both together, and the segment is from ahead — but not somewhere this
        session can put it.  Records are stored in serial order, so a record
        more than 2**31 past its predecessor with nothing between *precedes*
        it, and the writer refuses it.  What the format can say — and, since
        spec 0.21, says in as many words — is that one session ended here,
        for :data:`END_CAPTURE_GAP`, and another began on the same key with
        no ``isn``.

        Args:
            pkt: The segment about to be delivered.

        Returns:
            ``True`` when the caller should close this session and open a
            new one with *pkt*.

        """
        if not pkt.payload:
            return False
        stream = self._streams.get(pkt.src_endpoint)
        if stream is None or stream.next_seq is None:
            return False
        tsval = _tsval(pkt)
        behind = -_delta(pkt.seq, stream.next_seq)
        if (
            tsval is not None
            and stream.ts_recent is not None
            and behind > _MAX_WINDOW
            and _delta(tsval, stream.ts_recent) > 0
        ):
            self._split_reason = END_CAPTURE_GAP
            self._stats.wrap_resolved += 1
            return True
        return False

    def _maybe_commit_gap(self, stream: _Stream, pkt: PacketView) -> None:
        """Give up on missing bytes once the policy says to stop waiting."""
        over_window = stream.pending_bytes > self._options.reorder_window
        stale = (
            stream.oldest_pending_ts is not None
            and (pkt.ts_ticks - stream.oldest_pending_ts) / self._tick_hz
            > self._options.flush_timeout
        )
        if over_window or stale:
            self._commit_gap(stream, pkt)

    def _commit_gap(self, stream: _Stream, pkt: PacketView) -> None:
        assert stream.next_seq is not None
        target = self._next_pending(stream)
        if _delta(target, stream.next_seq) <= 0:  # pragma: no cover - drained already
            return
        self._flush(stream)
        # The lowest-numbered held segment is the first the sender put on the
        # wire past the hole, so its TSval is the earliest clock reading among
        # everything that overtook the missing bytes.
        stream.committed_gaps.append(
            _Gap(stream.next_seq, target, stream.pending[target].tsval),
        )
        stream.next_seq = target
        self._stats.gaps += 1
        stream.oldest_pending_ts = None
        self._drain(stream, pkt)

    def _commit_remaining(self, stream: _Stream) -> None:
        """At end of capture, take whatever is still held rather than drop it."""
        while stream.pending:
            assert stream.next_seq is not None
            target = self._next_pending(stream)
            held = stream.pending[target]
            if _delta(target, stream.next_seq) > 0:
                self._flush(stream)
                stream.committed_gaps.append(_Gap(stream.next_seq, target, held.tsval))
                stream.next_seq = target
                self._stats.gaps += 1
            self._release(stream, target)
            trim = max(0, _delta(stream.next_seq, target))
            self._append(
                stream,
                stream.next_seq,
                held.data[trim:],
                PacketView(
                    packet_num=0, ts_ticks=held.ts, protocol="tcp",
                    src="", dst="", src_port=0, dst_port=0,
                    payload=b"", seq=target, ack=held.ack, tcp_flags=held.flags,
                ),
                tsval=held.tsval,
                peer_count=held.peer_count,
                payload_offset=None if held.payload_offset is None else held.payload_offset + trim,
                alternates=_clip(held.alternates, stream.next_seq,
                                 _advance(target, len(held.data))),
            )

    def _count_repeat(
        self,
        stream: _Stream,
        seq: int,
        end: int,
        payload_offset: int | None,
        data: bytes,
        *,
        tsval: int | None,
        peer_count: int,
        pkt: PacketView,
    ) -> None:
        """Attribute already-seen bytes to a committed gap, a copy, or a resend.

        Bytes that fall inside a gap this stream already gave up on are not
        repeats — they are data the policy caused us to lose, and the
        specification forbids writing them now. They are counted separately so
        that a loss caused by our own timeouts is never mistaken for a
        harmless duplicate — and, where the option allows, by *why* they were
        late: a TSval older than everything committed past the gap is the
        original transmission, delayed, which a wider ``reorder_window`` or a
        longer ``flush_timeout`` would have saved; a newer one is a resend
        that recovered the loss after the hole was given up on, which no
        policy of ours could have kept.  Same discard, different story, and
        only the first is about us.

        What remains repeats bytes this direction accepted, and is judged by
        the Timestamps option — see :meth:`_judge`.  Every kind exists in the
        capture and reaches no record, so every kind is cited as an Undecoded
        region; only the reason differs. The ranges are taken relative to
        *seq*, which is where this segment's payload begins.
        """
        length = _delta(end, seq)
        if length <= 0:
            return
        for gap in stream.committed_gaps:
            gap_start, gap_end = gap.start, gap.end
            overlap_start = max(_delta(seq, gap_start), 0)
            overlap_end = min(_delta(end, gap_start), _delta(gap_end, gap_start))
            if overlap_end > overlap_start:
                late = overlap_end - overlap_start
                late_reason = _late_reason(tsval, gap.passer_tsval)
                self._stats.late_bytes += late
                if late_reason == REASON_LATE_REORDERED:
                    self._stats.late_reordered_bytes += late
                elif late_reason == REASON_LATE_RETRANSMITTED:
                    self._stats.late_retransmitted_bytes += late
                self._cite(payload_offset, _delta(gap_start, seq) + overlap_start,
                           late, late_reason)
        for start, stop in self._unclaimed(stream, seq, end):
            lo, hi = _advance(seq, start), _advance(seq, stop)
            verdict = self._judge(stream, lo, hi, tsval, peer_count)
            if self._contested(stream, verdict, lo, hi, data[start:stop], pkt,
                               skip=start):
                continue
            self._discard(stream, verdict, payload_offset, start, stop - start)

    def _cite(self, payload_offset: int | None, skip: int, length: int, reason: str) -> None:
        """Declare a sub-range of one segment's payload as undecoded."""
        start = None if payload_offset is None else payload_offset + skip
        self.undecoded(start, length, reason=reason)

    def _unclaimed(self, stream: _Stream, seq: int, end: int) -> list[tuple[int, int]]:
        """Return the parts of ``[seq, end)`` no committed gap claimed, relative to *seq*."""
        length = _delta(end, seq)
        claimed = sorted(
            (max(_delta(gap.start, seq), 0), min(_delta(gap.end, seq), length))
            for gap in stream.committed_gaps
        )
        parts: list[tuple[int, int]] = []
        cursor = 0
        for start, stop in claimed:
            if stop <= cursor or start >= length:
                continue
            if start > cursor:
                parts.append((cursor, start))
            cursor = max(cursor, stop)
        if cursor < length:
            parts.append((cursor, length))
        return parts

    # ── repeats ─────────────────────────────────────────────────────────

    def _remember(
        self, stream: _Stream, seq: int, end: int, tsval: int | None, peer_count: int,
    ) -> None:
        """Record an accepted transmission so a later repeat of it can be judged."""
        stream.recent.append(_Sent(seq=seq, end=end, tsval=tsval, peer_count=peer_count))
        stream.recent_bytes += _delta(end, seq)
        while len(stream.recent) > 1 and stream.recent_bytes > self._options.reorder_window:
            oldest = stream.recent.popleft()
            stream.recent_bytes -= _delta(oldest.end, oldest.seq)

    def _judge(
        self, stream: _Stream, seq: int, end: int, tsval: int | None, peer_count: int,
    ) -> str:
        """Say whether a repeat of ``[seq, end)`` is a copy or a resend.

        A **duplicate** is the same transmission seen twice — a mirror port, a
        two-interface capture, a veth pair — and takes all three of: both it
        and the transmission it repeats carried the option; the TSvals are
        equal; and no packet from the peer arrived between the two.  The
        third clause is what separates a copy from a fast retransmit on a
        stack whose timestamp tick is coarser than its round trip: the
        resend is triggered by the peer's duplicate ACKs, and they sit in the
        capture between original and resend, while a copy follows its
        original with nothing between.

        Anything else is a **retransmission** — the reading RFC 7323 supports
        and the one the specification asks a producer to fall back to.  The
        two fallbacks are named so they can be counted: :data:`TS_ABSENT`
        when either side lacks the option, :data:`TS_STALE` when the
        transmission repeated has aged out of ``recent``.

        The one case this cannot separate is a one-way capture of a
        coarse-tick stack: with the peer's ACKs absent from the file and the
        resend inside its original's tick, a fast retransmit looks exactly like
        a copy.  The rule then calls it a duplicate, which is the wrong way
        round for the specification's SHOULD, and is recorded as a limit.
        """
        if tsval is None:
            return TS_ABSENT
        covered = 0
        length = _delta(end, seq)
        for sent in stream.recent:
            lo = max(_delta(sent.seq, seq), 0)
            hi = min(_delta(sent.end, seq), length)
            if hi <= lo:
                continue
            if sent.tsval is None:
                return TS_ABSENT
            if sent.tsval != tsval or sent.peer_count != peer_count:
                return _RETRANSMIT
            covered += hi - lo
        return _DUPLICATE if covered >= length else TS_STALE

    def _contested(
        self,
        stream: _Stream,
        verdict: str,
        seq: int,
        end: int,
        data: bytes,
        source: PacketView | _Pending,
        *,
        skip: int = 0,
    ) -> bool:
        """Under favor-acked, hold a disagreeing resend against the runs it repeats.

        Returns ``True`` when the range was taken up as an alternate — and so
        must not be counted or cited now, since which copy loses is not yet
        known — and ``False`` when the caller should discard it as usual:
        the policy is ``favor-old``, the verdict is not a retransmission (a
        duplicate or an unjudgeable repeat has no second clock to match an
        echo against), or the copies agree byte-for-byte, where the choice is
        moot.  A part of the range that no open or held run covers has
        already been settled by the peer's ack, and is discarded too.
        """
        if not self._acked or verdict != _RETRANSMIT:
            return False
        tsval = source.tsval if isinstance(source, _Pending) else _tsval(source)
        assert tsval is not None  # a retransmission verdict needed it
        ts = source.ts if isinstance(source, _Pending) else source.ts_ticks
        payload_offset = source.payload_offset
        if payload_offset is not None:
            payload_offset += skip
        taken = False
        for run in self._covering_runs(stream, seq, end):
            offset = _delta(run.seq_start, seq)
            a, b = max(offset, 0), min(offset + len(run.data), len(data))
            if b <= a:
                continue
            kept = bytes(run.data[a - offset:b - offset])
            copy = data[a:b]
            run.retransmit = True
            if kept == copy:
                self._stats.overlap_bytes += b - a
                self._cite(payload_offset, a, b - a, REASON_OVERLAP)
            else:
                run.alternates.append(_Alternate(
                    seq=_advance(seq, a), end=_advance(seq, b), tsval=tsval, data=copy,
                    ts=ts, ack=source.ack,
                    payload_offset=None if payload_offset is None else payload_offset + a,
                ))
            taken = True
        return taken

    def _covering_runs(self, stream: _Stream, seq: int, end: int) -> list[_Run]:
        """Return the open and held runs of *stream* that overlap ``[seq, end)``."""
        runs = [*stream.unacked]
        if stream.run is not None:
            runs.append(stream.run)
        return [
            run for run in runs
            if _delta(end, run.seq_start) > 0 and _delta(run.end, seq) > 0
        ]

    def _discard(
        self,
        stream: _Stream,
        verdict: str,
        payload_offset: int | None,
        skip: int,
        length: int,
    ) -> None:
        """Count and cite a repeated range under its verdict, and flag the run if a resend."""
        if verdict == _DUPLICATE:
            self._stats.duplicate_bytes += length
            self._stats.duplicates += 1
            self._cite(payload_offset, skip, length, REASON_DUPLICATE)
            return
        if verdict != _RETRANSMIT:
            self._stats.ts_fallback[verdict] += 1
        self._stats.overlap_bytes += length
        self._cite(payload_offset, skip, length, REASON_OVERLAP)
        if stream.run is not None:
            stream.run.retransmit = True

    # ── emission ────────────────────────────────────────────────────────

    def _attach_flags(
        self, stream: _Stream, pkt: PacketView, *, origin: int | None = None,
    ) -> None:
        """OR *pkt*'s flags into the open run, naming *origin* when its flags alone reach it."""
        if stream.run is not None:
            stream.run.flags |= pkt.tcp_flags
            if origin is not None:
                stream.run.flag_origins.append(origin)

    def _flush(self, stream: _Stream) -> None:
        """Close the accumulated run: write it, or hold it for the peer's ack."""
        run = stream.run
        stream.run = None
        if run is None or not run.data:
            return
        if self._acked:
            run.closed_ts = self.last_ts
            stream.unacked.append(run)
            stream.unacked_bytes += len(run.data)
            # The byte bound is checked the moment it can be exceeded, so the
            # hold never holds more than the window between two packets.
            self._settle_stale(stream, self.last_ts)
            return
        self._write(stream, run)

    def _settle(self, stream: _Stream, ack: int, tsecr: int | None) -> None:
        """Write every held run of *stream* that the peer's *ack* covers.

        The peer's TSecr is the TSval of the transmission that advanced its
        window — the copy it kept — and each alternate on a covered run is
        judged against it: an alternate whose TSval the peer echoed, where no
        kept contributor's was, is swapped in.  Runs are written in the order
        they closed, which is ascending ``seq_start``.

        The evidence is strong, not proof: RFC 7323 §4.3 also lets
        ``TS.Recent`` advance from an old duplicate landing inside the
        delayed-ACK window (``SEG.TSval >= TS.Recent`` and ``SEG.SEQ <=
        Last.ACK.sent``), so a copy arriving there can steal the echo from
        the copy the receiver actually kept.  It is nonetheless evidence from
        the receiver itself, and independent of the capture point, which the
        order copies arrived in is not.
        """
        runs = [*stream.unacked]
        if stream.run is not None:
            runs.append(stream.run)
        for run in runs:
            for alt in run.alternates:
                if not alt.decided and _delta(ack, alt.end) >= 0:
                    alt.decided = True
                    alt.evidence = tsecr
        while stream.unacked and _delta(ack, stream.unacked[0].end) >= 0:
            self._write(stream, self._release_run(stream))

    def _settle_stale(self, stream: _Stream, now: int) -> None:
        """Write held runs the bounds say have waited long enough, on the fallback.

        The two bounds are the policy's own: a run whose ack has not come
        within ``flush_timeout`` of its closing, or the oldest run once the
        hold exceeds ``reorder_window`` bytes, is written as ``favor-old``
        would have written it, and every contested byte in it is counted as a
        fallback.  A one-way capture, where no ack ever comes, writes every
        run this way.
        """
        while stream.unacked and (
            (now - stream.unacked[0].closed_ts) / self._tick_hz > self._options.flush_timeout
            or stream.unacked_bytes > self._options.reorder_window
        ):
            self._write(stream, self._release_run(stream))

    def _release_run(self, stream: _Stream) -> _Run:
        run = stream.unacked.popleft()
        stream.unacked_bytes -= len(run.data)
        return run

    def _write(self, stream: _Stream, run: _Run) -> None:
        """Resolve a run's alternates and write it as one record.

        Each alternate carries its own verdict, taken from the first peer ack
        that covered its range (see :class:`_Alternate`).  One with no
        verdict — the run is being written because a bound expired or the
        session ended — or whose ack carried no option loses on the
        fallback, and is counted as such.
        """
        for alt in run.alternates:
            kept = _within(run.contributors, alt.seq, alt.end)
            evidence = alt.evidence
            swap = (
                alt.decided
                and evidence is not None
                and alt.tsval == evidence
                and all(c.tsval != evidence for c in kept)
            )
            if swap:
                offset = _delta(alt.seq, run.seq_start)
                run.data[offset:offset + len(alt.data)] = alt.data
                for c in kept:
                    a = max(_delta(alt.seq, c.seq), 0)
                    b = min(_delta(alt.end, c.seq), _delta(c.end, c.seq))
                    self._stats.overlap_bytes += b - a
                    self._cite(c.payload_offset, a, b - a, REASON_OVERLAP)
                run.contributors = _without(run.contributors, alt.seq, alt.end)
                run.contributors.append(_Contribution(
                    seq=alt.seq, end=alt.end, tsval=alt.tsval, ts=alt.ts, ack=alt.ack,
                    payload_offset=alt.payload_offset,
                ))
                self._stats.acked_swaps += 1
            else:
                if not alt.decided or evidence is None:
                    self._stats.acked_fallback_bytes += len(alt.data)
                self._stats.overlap_bytes += len(alt.data)
                self._cite(alt.payload_offset, 0, len(alt.data), REASON_OVERLAP)

        flags = RecordFlags(0)
        for tcp_bit, record_bit in _FLAG_MAP:
            if run.flags & tcp_bit:
                flags |= record_bit
        if run.retransmit:
            flags |= RecordFlags.RETRANSMIT

        ts, ts_first, ack = _hints(run)
        self.sink.record(
            self.participant(stream.endpoint),
            ts=ts,
            payload=bytes(run.data),
            origins=[*(c.payload_offset for c in run.contributors), *run.flag_origins],
            hints=zpf.Hints(seq_start=run.seq_start, ack=ack),
            flags=flags,
            # Only worth stating when the run coalesced more than one packet;
            # for a single segment it would repeat `ts`.
            ts_first=ts_first if ts_first != ts else None,
        )
        self._stats.records += 1
        self._stats.payload_bytes += len(run.data)


def _tsecr(pkt: PacketView) -> int | None:
    """Return the segment's TSecr, or ``None`` when it carries no Timestamps option."""
    options = pkt.tcp_options
    if options is None or options.timestamps is None:
        return None
    return options.timestamps[1]


def _hints(run: _Run) -> tuple[int, int, int | None]:
    """Return a run's ``(ts, ts_first, ack)`` from the transmissions that made it.

    All three are extremes over the run's contributing packets, not the
    packet that happened to be appended last: a segment held out of order
    arrives *before* the one that made it contiguous but is appended after
    it, and taking its time would stamp the run as complete before its last
    packet arrived — and leave ``ts_first`` later than ``ts``.

    ``ts`` is the specification's rule — the time of the LAST packet that
    contributed bytes, the moment the unit became complete — and ``ts_first``
    the time it began, which spans could carry but ours cannot since they
    must reference a zpf-input source.  The ack is the serial MAXIMUM rather
    than the last arrival's, which for a drained run is the earlier packet's
    and for any other the later one's — a value taken from no rule.  Acks are
    cumulative, so one observed on any contributor is still true when the run
    completes, and the maximum is the strongest statement the run can make
    that is certainly true.  Taking the ack of the packet that supplies
    ``ts`` would keep the two hints on one packet at the cost of throwing
    away a real edge whenever the last contributor's ack is the lower one,
    which a delayed ack makes common.  It matters most under ``sequenced``:
    the linearization releases a record once every peer record it acks has
    been emitted, so understating one delays a record for a reason that is
    not in the capture.

    Computed at write time so that a copy swapped in under favor-acked — a
    resend, later than the copy it displaces — moves ``ts`` the way the rule
    says, and the displaced copy stops counting.
    """
    ts = max(c.ts for c in run.contributors)
    ts_first = min(c.ts for c in run.contributors)
    ack: int | None = None
    for c in run.contributors:
        if ack is None or _delta(c.ack, ack) > 0:
            ack = c.ack
    return ts, ts_first, ack


def _within(contributors: list[_Contribution], seq: int, end: int) -> list[_Contribution]:
    """Return the contributors overlapping ``[seq, end)``."""
    return [c for c in contributors if _delta(end, c.seq) > 0 and _delta(c.end, seq) > 0]


def _without(contributors: list[_Contribution], seq: int, end: int) -> list[_Contribution]:
    """Return *contributors* with ``[seq, end)`` cut out of each, splitting where needed."""
    kept: list[_Contribution] = []
    for c in contributors:
        if _delta(end, c.seq) <= 0 or _delta(c.end, seq) <= 0:
            kept.append(c)
            continue
        if _delta(seq, c.seq) > 0:
            kept.append(_Contribution(c.seq, seq, c.tsval, c.ts, c.ack, c.payload_offset))
        if _delta(c.end, end) > 0:
            offset = _delta(end, c.seq)
            kept.append(_Contribution(
                end, c.end, c.tsval, c.ts, c.ack,
                None if c.payload_offset is None else c.payload_offset + offset,
            ))
    return kept


def _clip(alternates: list[_Alternate], seq: int, end: int) -> list[_Alternate]:
    """Return the parts of *alternates* that fall inside ``[seq, end)``."""
    clipped: list[_Alternate] = []
    for alt in alternates:
        a = max(_delta(seq, alt.seq), 0)
        b = min(_delta(end, alt.seq), len(alt.data))
        if b <= a:
            continue
        clipped.append(_Alternate(
            seq=_advance(alt.seq, a), end=_advance(alt.seq, b), tsval=alt.tsval,
            data=alt.data[a:b], ts=alt.ts, ack=alt.ack,
            payload_offset=None if alt.payload_offset is None else alt.payload_offset + a,
        ))
    return clipped


def _late_reason(tsval: int | None, passer_tsval: int | None) -> str:
    """Say why a byte arriving inside a committed gap was late, if the option can.

    The comparison is against the clock of the *first segment that overtook
    the gap*, not against everything committed since: a resend can itself be
    delayed on the way in — in ``tcp_reorder_ts.pcap`` it takes the same slow
    path as the original it repeats — and by its arrival the sender has
    committed plenty that is newer.  What the split asks is whether the byte
    was *sent* before the bytes that passed it, which makes it the original,
    or after, which makes it a response to their arrival.
    """
    if tsval is None or passer_tsval is None:
        return REASON_LATE
    order = _delta(tsval, passer_tsval)
    if order < 0:
        return REASON_LATE_REORDERED
    if order > 0:
        return REASON_LATE_RETRANSMITTED
    # Inside one tick of the segment that overtook it: sent in the same burst,
    # which only an original can be — but a fast retransmit on a path with no
    # delay can share the tick too, so the option cannot say, and neither do we.
    return REASON_LATE


def _stamp(pkt: PacketView, held: _Pending) -> PacketView:
    """Re-key a held segment's metadata onto a packet view for appending."""
    return PacketView(
        packet_num=pkt.packet_num,
        ts_ticks=held.ts,
        protocol="tcp",
        src=pkt.src,
        dst=pkt.dst,
        src_port=pkt.src_port,
        dst_port=pkt.dst_port,
        payload=b"",
        seq=pkt.seq,
        ack=held.ack,
        tcp_flags=held.flags,
    )
