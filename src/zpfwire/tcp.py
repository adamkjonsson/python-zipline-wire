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

A segment carrying only an ``ack`` is written too, by default since
``0.6.0`` (#37): a zero-length record at its wire sequence number, placed
once nothing of its sender's will be stored below that number; see
:meth:`TcpFlow._pure_ack`.
"""

from __future__ import annotations

import bisect
import itertools
import zlib
from collections import deque
from collections.abc import Iterable
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
    REASON_TS_MISSING,
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
# Discarded resends remembered per direction, to judge their copies (#56).  A
# mirror's copy arrives within microseconds; this many resends cannot pass in
# that time.
_RESENDS_KEPT = 64
# Released favor-acked segments remembered per direction, to tell whether a
# resend arriving after its run was written disagreed with it (#54).  At
# 1,448 bytes a segment this reaches about 95 MB back, past any RTO's worth
# of traffic, for a dictionary of this many small entries.
_RELEASED_KEPT = 65_536

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
# Verdicts on a repeat that carries its own clock, so that the peer's echo can
# still choose between it and the copy kept: a resend, and a repeat whose
# original has aged out of `recent` — a resend by the conservative reading,
# and the usual verdict on one a whole RTO behind a bulk transfer (#54).
_CONTESTABLE = frozenset({_RETRANSMIT, TS_STALE})
_FAVOR_ACKED = "favor-acked"

_FLAG_MAP = (
    (TCP_PSH, RecordFlags.PSH),
    (TCP_FIN, RecordFlags.FIN),
    (TCP_RST, RecordFlags.RST),
    (TCP_URG, RecordFlags.URG),
)


def _record_flags(tcp_flags: int) -> RecordFlags:
    """Return the record flags that the TCP flags in *tcp_flags* carry over."""
    flags = RecordFlags(0)
    for tcp_bit, record_bit in _FLAG_MAP:
        if tcp_flags & tcp_bit:
            flags |= record_bit
    return flags


# Every 8-bit combination, worked out once: `RecordFlags` is a `Flag` enum,
# whose `|` runs in Python, and doing it per record was about a seventh of
# the in-order path (#46).
_RECORD_FLAGS = tuple(_record_flags(bits) for bits in range(256))


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
    # Whether it was resent while it waited: its record will carry
    # ``retransmit`` once it has one (#59).
    resent: bool = False


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

    ``pos`` is ``seq`` unwrapped: a count that does not wrap at 2**32, so the
    span of everything remembered is known exactly — see :meth:`TcpFlow._judge`.
    """

    seq: int
    end: int
    tsval: int | None
    peer_count: int
    pos: int


@dataclass(frozen=True)
class _PureAck:
    """A segment that carried only an ``ack``, waiting for its place in the stream.

    Stored as a zero-length record at ``seq``, the sender's sequence number
    on the wire (#37).  ``origin`` is the packet's ``payload_offset``, so a
    ``.zpf`` input can cite it.
    """

    seq: int
    ts: int
    ack: int
    origin: int | None


@dataclass(frozen=True)
class _TrailingFin:
    """A FIN to store straight after a held run, as a zero-length record (#60).

    Under favor-acked the last run may still be held when its FIN arrives.
    Written at once, the FIN would precede that run; carried on it, the
    record would differ from favor-old's, which wrote the run already.  So
    it waits in the run's trailing list, in arrival order among the pure
    ACKs, and is written as favor-old writes it.
    """

    seq: int
    flags: int
    origin: int | None
    ts: int
    ack: int


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
    # Ranges of this run the sender resent, whose repeats were discarded:
    # the records holding them carry ``retransmit`` (#59).
    resent: list[tuple[int, int]] = field(default_factory=list)
    # Capture time when the run closed; what the favor-acked hold is timed from.
    closed_ts: int = 0
    # Packets whose flags, not bytes, reached the run — a FIN or RST with no
    # payload — named so a `.zpf` input can cite them; see RecordSink.record.
    flag_origins: list[int] = field(default_factory=list)
    # Pure ACKs to store straight after this run's record: their sequence
    # number lies at or past its start, so they cannot be stored before it.
    trailing_acks: list[_PureAck | _TrailingFin] = field(default_factory=list)

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
    # Whether this direction's SYN carried the Timestamps option: with the
    # peer's, what RFC 7323 calls negotiating it.
    syn_timestamps: bool = False
    fin: bool = False
    rst: bool = False
    pending: dict[int, _Pending] = field(default_factory=dict)
    pending_bytes: int = 0
    # The keys of `pending` in serial order, as offsets from `pending_anchor`,
    # so the next held segment is the first entry rather than a scan (#44).
    # The anchor sits at or behind every held segment and `next_seq`; see
    # _rebase_pending for why that keeps the order exact.
    pending_order: list[int] = field(default_factory=list)
    pending_anchor: int = 0
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
    # something older cannot be, and is counted as such.  A list read from
    # `recent_head`, not a deque, because _judge bisects it and a deque's
    # middle is a walk (#43); the evicted prefix is dropped in batches.
    recent: list[_Sent] = field(default_factory=list)
    recent_head: int = 0
    recent_bytes: int = 0
    # Repeats judged retransmissions and discarded: transmissions too, whose
    # own copies a mirror shows a microsecond later (#56).  `recent` holds
    # only what was accepted, so without these a copy of a discarded resend
    # is judged against the original's clock, and taken for another resend.
    # The copy follows at once, so a short memory serves.
    resends: deque[_Sent] = field(default_factory=lambda: deque(maxlen=_RESENDS_KEPT))
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
    # favor-acked: the segments of runs a bound released before the peer's
    # ack covered them, as written: ``(seq, end) -> crc32``, oldest first.  A
    # disagreeing resend that arrives after its run was released is a
    # fallback as surely as one that arrived before, and only these can show
    # it disagrees (#54).  A digest per segment rather than its bytes, so a
    # resend a whole RTO behind is still within reach; see _RELEASED_KEPT.
    released: dict[tuple[int, int], int] = field(default_factory=dict)
    # Where the FIN sits: one past the last byte of the segment carrying it.
    # The FIN occupies that sequence number, so once every byte before it is
    # in, the next one the sender can use is one further on.
    fin_seq: int | None = None
    # A FIN that arrived with no payload while bytes before it were still
    # missing: ``(flags, origin, ts, ack)``.  A FIN ends the record that ends
    # where it sits, so it waits for that record rather than marking
    # whichever run is open; see TcpFlow._append and finish.
    fin_deferred: tuple[int, int | None, int, int] | None = None
    # Whether a record carries this direction's FIN yet: once, so that a
    # resent or mirrored FIN does not close the stream twice (#60).
    fin_placed: bool = False
    # Pure ACKs whose sequence number is ahead of where this direction's
    # bytes have been placed; see TcpFlow._release_acks.
    held_acks: list[_PureAck] = field(default_factory=list)


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
        if self._options.require_timestamps and self._unstamped(pkt):
            # Dropped whole, as the receiver drops it: its bytes, its ack and
            # its flags never happened (#57).
            self._stats.ts_missing += 1
            self._stats.ts_missing_bytes += len(pkt.payload)
            self.undecoded(pkt.payload_offset, len(pkt.payload), reason=REASON_TS_MISSING)
            return
        for other in self._streams.values():
            if other is not stream:
                other.peer_count += 1
                if pkt.tcp_flags & TCP_ACK:
                    self._answered(other, pkt)
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
        elif (
            self._options.pure_acks
            and pkt.tcp_flags & TCP_ACK
            and not pkt.tcp_flags & (TCP_SYN | TCP_FIN | TCP_RST)
        ):
            self._pure_ack(stream, pkt)

        closing = bool(pkt.tcp_flags & (TCP_FIN | TCP_RST))
        if closing:
            self._close(stream, pkt)

        # A run ends where the connection does.  Where the sender said it did
        # (PSH), or at every segment when coalescing is off, it ends as the
        # segment's bytes join it, in sequence order — see _drain (#53).
        if closing:
            self._flush(stream)

    def _close(self, stream: _Stream, pkt: PacketView) -> None:
        """Take a FIN or RST: what it says about the stream, and which record it marks."""
        stream.fin = stream.fin or bool(pkt.tcp_flags & TCP_FIN)
        stream.rst = stream.rst or bool(pkt.tcp_flags & TCP_RST)
        first_fin = bool(pkt.tcp_flags & TCP_FIN) and stream.fin_seq is None
        if first_fin:
            stream.fin_seq = _advance(pkt.seq, len(pkt.payload))
            if stream.next_seq is None:
                # A direction first seen at its FIN — a capture that
                # caught only the teardown — begins there, as it would
                # at a first data segment or pure ACK.
                stream.next_seq = stream.fin_seq
        if not pkt.tcp_flags & TCP_FIN:
            self._attach_flags(stream, pkt.tcp_flags, origin=pkt.payload_offset)
        elif stream.fin_placed:
            pass  # a resend or a copy of a FIN already placed
        elif stream.next_seq == stream.fin_seq:
            self._place_fin(stream, pkt.tcp_flags, pkt.payload_offset,
                            ts=pkt.ts_ticks, ack=pkt.ack)
        elif stream.next_seq is not None and _delta(stream.fin_seq, stream.next_seq) > 0:
            # Bytes before the FIN are still missing: it ends the record
            # that will end where it sits, not the run open now.  A FIN
            # with payload held behind the hole carries its own flags.
            if not pkt.payload:
                stream.fin_deferred = (pkt.tcp_flags, pkt.payload_offset, pkt.ts_ticks, pkt.ack)
        else:
            # The stream already runs past where the FIN sits — a forged
            # segment reached beyond it — so no record can end there, and
            # none may be written below what is out.  It marks the open
            # run, as it did before 0.7.0.
            self._attach_flags(stream, pkt.tcp_flags, origin=pkt.payload_offset)
        # After the FIN is placed: an ACK sent after it sits one past it.
        if first_fin and stream.held_acks:
            self._release_acks(stream)

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
            # A FIN whose preceding bytes never all came: nothing will end
            # where it sits, so it is a record of its own, before the ACKs
            # that followed it (#60).
            if (
                stream.fin_deferred is not None
                and not stream.fin_placed
                and stream.fin_seq is not None
                and stream.next_seq is not None
                and _delta(stream.fin_seq, stream.next_seq) >= 0
            ):
                flags, origin, ts, ack = stream.fin_deferred
                stream.fin_deferred = None
                self._write_fin(stream, flags, origin, ts=ts, ack=ack)
            # Pure ACKs still ahead of every placed byte: nothing more of
            # this direction will be stored, so they go last, in order.
            if stream.held_acks:
                assert stream.next_seq is not None
                frontier = self._frontier(stream)
                for held in sorted(stream.held_acks, key=lambda a: _delta(a.seq, frontier)):
                    self._write_ack(stream, held)
                stream.held_acks.clear()
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
        stream.syn_timestamps = _tsval(pkt) is not None
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

    # ── pure ACKs ───────────────────────────────────────────────────────

    def _pure_ack(self, stream: _Stream, pkt: PacketView) -> None:
        """Store a segment that carried only an ``ack`` as a zero-length record (#37).

        Its record sits at its own sequence number, so it has to be stored
        where that number falls among this direction's records, which are
        stored in serial order.  That is only certain once nothing of this
        direction will be stored below it, which is the frontier
        (:meth:`_frontier`).  At the frontier it is placed now; ahead of it,
        held until the frontier passes it; behind it, it would have to come
        before records already placed, so it is not stored and its ``ack``
        is left to the next data record, as when the option is off.

        A direction that has sent nothing yet begins at the pure ACK, as it
        would at a first data segment: the ACK says the sender had nothing
        unsent below it.
        """
        if stream.next_seq is None:
            stream.next_seq = pkt.seq
        held = _PureAck(seq=pkt.seq, ts=pkt.ts_ticks, ack=pkt.ack, origin=pkt.payload_offset)
        if _delta(held.seq, self._frontier(stream)) < 0:
            self._stats.pure_acks_unstored += 1
            return
        stream.held_acks.append(held)
        self._release_acks(stream)

    def _frontier(self, stream: _Stream) -> int:
        """Return the lowest sequence number this direction may still store a record at.

        Every byte below ``next_seq`` has been placed or given up on, so no
        record of this direction will start below it again.  A FIN takes one
        more number, and once everything before it is in, the sender's next
        segment, and so its next pure ACK, sits one past it.
        """
        assert stream.next_seq is not None
        if stream.fin_seq is not None and stream.next_seq == stream.fin_seq:
            return _advance(stream.fin_seq, 1)
        return stream.next_seq

    def _release_acks(self, stream: _Stream) -> None:
        """Place every held pure ACK the frontier has reached, in serial order.

        Called wherever the frontier moves, and always before a run is
        opened past it, so an ACK is never placed after a record that starts
        beyond its sequence number.
        """
        frontier = self._frontier(stream)
        ready = [held for held in stream.held_acks if _delta(held.seq, frontier) <= 0]
        if not ready:
            return
        stream.held_acks = [held for held in stream.held_acks if _delta(held.seq, frontier) > 0]
        for held in sorted(ready, key=lambda a: _delta(a.seq, frontier)):
            self._place_ack(stream, held)

    def _place_ack(self, stream: _Stream, held: _PureAck) -> None:
        """Store *held* now, or straight after the run that must precede it.

        An open run, or one held for the peer's ack, starts at or before
        the ACK's sequence number and has not been written yet, so the ACK
        goes after it: a zero-length record covers no byte, so following a
        run that ends past it overlaps nothing, and the run's boundaries
        are those it would have had without the ACK.
        """
        if stream.run is not None:
            stream.run.trailing_acks.append(held)
        elif stream.unacked:
            stream.unacked[-1].trailing_acks.append(held)
        else:
            self._write_ack(stream, held)

    def _write_ack(self, stream: _Stream, held: _PureAck) -> None:
        """Write a pure ACK as a zero-length record carrying its ``ack``.

        It sits at its sequence number from the wire, including after a FIN,
        where that number is one past the FIN's: the FIN occupies a sequence
        number, as the specification's table of record ends says.  The
        causal merge depends on it.  Two final ACKs each acknowledge the
        other side's FIN, and the merge judges whether a peer has sent up to
        an acknowledged position by where its records sit; a final ACK moved
        back onto its FIN's number reads as not yet past it, and the two wait
        on each other.  So a stream with a final pure ACK reaches one
        position past its last byte, the FIN's.  Whether its extent should
        count that position is a question for the specification
        (zipline#168).
        """
        self.sink.record(
            self.participant(stream.endpoint),
            ts=held.ts,
            payload=b"",
            origins=(held.origin,),
            hints=zpf.Hints(seq_start=held.seq, ack=held.ack),
        )
        self._stats.records += 1
        self._stats.pure_acks += 1

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
            self._append(stream, seq, data, ts=pkt.ts_ticks, ack=pkt.ack, flags=pkt.tcp_flags,
                         tsval=tsval, peer_count=stream.peer_count,
                         payload_offset=payload_offset)
            self._drain(stream, ends_previous=self._ends_run(pkt.tcp_flags))
        else:
            self._hold(stream, seq, data, pkt, tsval=tsval)
            self._maybe_commit_gap(stream, pkt)

    def _append(
        self,
        stream: _Stream,
        seq: int,
        data: bytes,
        *,
        ts: int,
        ack: int,
        flags: int,
        tsval: int | None,
        peer_count: int,
        payload_offset: int | None,
        alternates: list[_Alternate] | None = None,
        resent: bool = False,
    ) -> None:
        """Add one segment's bytes to the open run, starting one if needed.

        *resent* says the segment was resent while it was held, and flags
        the record its bytes land in (#59).
        """
        if stream.run is None:
            stream.run = _Run(seq_start=seq)
        end = _advance(seq, len(data))
        stream.run.data.extend(data)
        stream.run.contributors.append(_Contribution(
            seq=seq, end=end, tsval=tsval, ts=ts, ack=ack,
            payload_offset=payload_offset,
        ))
        if alternates:
            stream.run.alternates.extend(alternates)
        if resent:
            stream.run.resent.append((seq, end))
        if flags & TCP_FIN:
            stream.fin_placed = True
        if stream.fin_deferred is not None and end == stream.fin_seq:
            fin_flags, origin, _, _ = stream.fin_deferred
            stream.fin_deferred = None
            stream.fin_placed = True
            self._attach_flags(stream, fin_flags, origin=origin)
        self._remember(stream, seq, end, tsval, peer_count)
        self._attach_flags(stream, flags)
        stream.next_seq = end
        if stream.held_acks:
            self._release_acks(stream)

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
            # The record these bytes will be in does not exist yet: the held
            # segment carries the resend to it.
            if verdict != _DUPLICATE:
                held.resent = True
            self._discard(stream, verdict, pkt.payload_offset, 0, len(data), resent=None)
            return
        assert stream.next_seq is not None
        if not stream.pending:
            stream.pending_anchor = stream.next_seq
        else:
            self._rebase_pending(stream)
        # A segment is only held ahead of `next_seq`, so its offset from an
        # anchor at or behind `next_seq` is its distance in serial order.
        bisect.insort(stream.pending_order, (seq - stream.pending_anchor) % _SEQ_MOD)
        stream.pending[seq] = _Pending(data=data, flags=pkt.tcp_flags, ack=pkt.ack,
                                       ts=pkt.ts_ticks, payload_offset=pkt.payload_offset,
                                       tsval=tsval, peer_count=stream.peer_count)
        stream.pending_bytes += len(data)
        if stream.oldest_pending_ts is None:
            stream.oldest_pending_ts = pkt.ts_ticks

    def _drain(self, stream: _Stream, *, ends_previous: bool) -> None:
        """Absorb held segments that the newly-arrived bytes made contiguous.

        A run ends where a segment's bytes join it and the segment says so —
        at its PSH, or at once when coalescing is off — in sequence order,
        not arrival order (#53).  So a drained backlog is written as the
        records the same segments make in order, and a segment held with a
        PSH ends nothing until its bytes are placed.  The run is closed
        lazily, just before the next segment is appended, because a
        superseded held segment, or the trimmed head of one, belongs to the
        open run and must still find it open; and once more after the last.

        Args:
            stream: The direction to drain.
            ends_previous: Whether the segment appended just before — the
                fill — ends its run.  ``False`` from :meth:`_commit_gap`,
                which flushed before the hole it gave up on.

        """
        while stream.pending:
            seq = self._next_pending(stream)
            held = stream.pending[seq]
            end = _advance(seq, len(held.data))
            if _delta(end, stream.next_seq) <= 0:
                # Wholly superseded by what filled the hole.  The fill is the
                # later arrival, so the held segment is the original and the
                # fill the repeat; the verdict is the same either way round.
                # A retransmission flags the record covering the range, as at
                # the other four sites, by decision (#31, #59): the sender sent
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
                    self._discard(stream, verdict, held.payload_offset, 0, len(held.data),
                                  resent=(seq, end))
                continue
            if _delta(seq, stream.next_seq) > 0:
                break
            trim = _delta(stream.next_seq, seq)
            self._release(stream, seq)
            if trim:
                verdict = self._judge(stream, seq, stream.next_seq, held.tsval, held.peer_count)
                if not self._contested(stream, verdict, seq, stream.next_seq,
                                       held.data[:trim], held):
                    self._discard(stream, verdict, held.payload_offset, 0, trim,
                                  resent=(seq, stream.next_seq))
            if ends_previous:
                self._flush(stream)
            ends_previous = self._ends_run(held.flags)
            self._append(
                stream,
                stream.next_seq,
                held.data[trim:],
                ts=held.ts,
                ack=held.ack,
                flags=held.flags,
                tsval=held.tsval,
                peer_count=held.peer_count,
                payload_offset=None if held.payload_offset is None else held.payload_offset + trim,
                alternates=_clip(held.alternates, stream.next_seq, end),
                resent=held.resent,
            )
        else:
            stream.oldest_pending_ts = None
        if ends_previous:
            self._flush(stream)

    def _release(self, stream: _Stream, seq: int) -> None:
        held = stream.pending.pop(seq)
        stream.pending_bytes -= len(held.data)
        order = stream.pending_order
        del order[bisect.bisect_left(order, (seq - stream.pending_anchor) % _SEQ_MOD)]

    def _next_pending(self, stream: _Stream) -> int:
        """Return the held segment that comes first in serial order."""
        self._rebase_pending(stream)
        return (stream.pending_anchor + stream.pending_order[0]) % _SEQ_MOD

    def _rebase_pending(self, stream: _Stream) -> None:
        """Move the anchor up when `next_seq` has left it far behind.

        Ordering by offset from the anchor is ordering by ``_delta`` from
        ``next_seq``, which is what serial order means here, for as long as
        the anchor sits at or behind every held segment and less than 2**31
        behind ``next_seq``.  The first holds by construction: the anchor is
        set at ``next_seq`` when the buffer fills from empty, and a segment
        is held only ahead of ``next_seq``.  The second needs this: a stream
        that moves on while one segment stays held drags the distance out,
        so once it passes ``_MAX_WINDOW`` the anchor moves up to whichever is
        earlier, ``next_seq`` or the first held segment.  Every offset
        shrinks by the same amount and the order is unchanged.  It is O(held)
        and happens about once per gigabyte a held segment survives.
        """
        assert stream.next_seq is not None
        if not stream.pending_order or (
            _delta(stream.next_seq, stream.pending_anchor) <= _MAX_WINDOW
        ):
            return
        first = (stream.pending_anchor + stream.pending_order[0]) % _SEQ_MOD
        anchor = first if _delta(first, stream.next_seq) < 0 else stream.next_seq
        shift = (anchor - stream.pending_anchor) % _SEQ_MOD
        stream.pending_order[:] = [offset - shift for offset in stream.pending_order]
        stream.pending_anchor = anchor

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
            self._commit_gap(stream)

    def _commit_gap(self, stream: _Stream) -> None:
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
        if stream.held_acks:
            self._release_acks(stream)
        self._drain(stream, ends_previous=False)

    def _unstamped(self, pkt: PacketView) -> bool:
        """Say whether RFC 7323 §3.2 has a receiver drop *pkt* (#57).

        Both SYNs must have carried the Timestamps option — a capture that
        began mid-connection never saw them, and nothing is dropped — and
        the segment must lack it and be neither a SYN nor an RST, which the
        RFC exempts.
        """
        if pkt.tcp_flags & (TCP_SYN | TCP_RST) or _tsval(pkt) is not None:
            return False
        streams = self._streams.values()
        return len(streams) == 2 and all(s.syn_timestamps for s in streams)

    def _answered(self, stream: _Stream, pkt: PacketView) -> None:
        """Close *stream*'s open run if *pkt*, from the peer, answers part of it (#55).

        A peer segment carrying data — or a FIN, which takes a sequence
        number as data does — that acknowledges bytes of the open run was
        sent after those bytes arrived.  Anything this direction sends next
        was sent after it, and is captured after it, whichever side of the
        link the capture was taken on.  Joined to the run, such bytes would
        make a record that straddles the peer's message: its early bytes
        before it, its late ones after it.  Records are units, so no
        position for that record is valid, and the causal merge, ordering
        a peer record after one only once its ack covers the whole,
        places it after the message that answered its first bytes.

        A pure ACK answers nothing a record can be ordered against — a
        zero-length record covers no byte — so it does not close the run,
        and a one-way transfer still coalesces.
        """
        run = stream.run
        if run is None or not run.data:
            return
        if not (pkt.payload or pkt.tcp_flags & TCP_FIN):
            return
        if _delta(pkt.ack, run.seq_start) > 0:
            self._flush(stream)

    def _place_fin(
        self, stream: _Stream, flags: int, origin: int | None, *, ts: int, ack: int,
    ) -> None:
        """Put a FIN on the record that ends where it sits, or write it as its own (#60).

        Every byte before it is placed, so that record is the open run.
        Otherwise the last run is closed — a PSH flushed it, the usual way a
        sender closes — and the FIN is a zero-length record at its sequence
        number, as a pure ACK is: written now, or under favor-acked straight
        after the run still held.
        """
        stream.fin_placed = True
        if stream.run is not None:
            self._attach_flags(stream, flags, origin=origin)
        elif stream.unacked:
            assert stream.fin_seq is not None
            stream.unacked[-1].trailing_acks.append(
                _TrailingFin(stream.fin_seq, flags, origin, ts, ack),
            )
        else:
            self._write_fin(stream, flags, origin, ts=ts, ack=ack)

    def _write_fin(
        self, stream: _Stream, flags: int, origin: int | None, *, ts: int, ack: int,
    ) -> None:
        """Write a FIN that no run carries as a zero-length record at its number."""
        assert stream.fin_seq is not None
        stream.fin_placed = True
        self.sink.record(
            self.participant(stream.endpoint),
            ts=ts,
            payload=b"",
            origins=(origin,),
            hints=zpf.Hints(seq_start=stream.fin_seq, ack=ack),
            flags=_RECORD_FLAGS[flags & 0xFF],
        )
        self._stats.records += 1

    def _ends_run(self, flags: int) -> bool:
        """Say whether a segment with *flags* closes the run it joins."""
        return bool(flags & TCP_PSH) or not self._options.coalesce

    def _commit_remaining(self, stream: _Stream) -> None:
        """At end of capture, take whatever is still held rather than drop it.

        Runs end at each held segment's PSH, or at every segment when
        coalescing is off, as in :meth:`_drain` (#53).
        """
        ends_previous = False
        while stream.pending:
            assert stream.next_seq is not None
            target = self._next_pending(stream)
            held = stream.pending[target]
            if _delta(target, stream.next_seq) > 0:
                self._flush(stream)
                stream.committed_gaps.append(_Gap(stream.next_seq, target, held.tsval))
                stream.next_seq = target
                self._stats.gaps += 1
                if stream.held_acks:
                    self._release_acks(stream)
            self._release(stream, target)
            trim = max(0, _delta(stream.next_seq, target))
            if ends_previous:
                self._flush(stream)
            ends_previous = self._ends_run(held.flags)
            self._append(
                stream,
                stream.next_seq,
                held.data[trim:],
                ts=held.ts,
                ack=held.ack,
                flags=held.flags,
                tsval=held.tsval,
                peer_count=held.peer_count,
                payload_offset=None if held.payload_offset is None else held.payload_offset + trim,
                alternates=_clip(held.alternates, stream.next_seq,
                                 _advance(target, len(held.data))),
                resent=held.resent,
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
        gaps = self._gaps_from(stream, seq)
        for gap in gaps:
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
        for start, stop in self._unclaimed(gaps, seq, end):
            lo, hi = _advance(seq, start), _advance(seq, stop)
            verdict = self._judge(stream, lo, hi, tsval, peer_count)
            if verdict in _CONTESTABLE:
                assert tsval is not None  # either verdict needed it
                stream.resends.append(_Sent(lo, hi, tsval, peer_count, 0))
            if self._contested(stream, verdict, lo, hi, data[start:stop], pkt,
                               skip=start):
                continue
            self._discard(stream, verdict, payload_offset, start, stop - start,
                          resent=(lo, hi))

    def _cite(self, payload_offset: int | None, skip: int, length: int, reason: str) -> None:
        """Declare a sub-range of one segment's payload as undecoded."""
        start = None if payload_offset is None else payload_offset + skip
        self.undecoded(start, length, reason=reason)

    def _gaps_from(self, stream: _Stream, seq: int) -> list[_Gap]:
        """Return the committed gaps that end past *seq*, oldest first.

        Gaps are committed at ``next_seq``, which only moves forward, so the
        list is ascending and its gaps do not overlap: once one ends at or
        before *seq*, every older one does too, and none of them can hold a
        byte of a repeat starting there.  So the walk is from the newest,
        and costs the gaps a repeat can reach rather than every gap the
        connection ever committed (#45).

        Stopping there is also what keeps an old gap from claiming bytes it
        has nothing to do with.  A gap is kept as wire sequence numbers,
        which come round again every 2**32 bytes; a direction 4 GiB past a
        loss is carrying the lost range's own numbers again, and a scan of
        every gap would read a resend there as a late arrival into the old
        hole.  The walk stops at the newest gap behind *seq*, long before it.
        """
        gaps = stream.committed_gaps
        first = len(gaps)
        while first and _delta(gaps[first - 1].end, seq) > 0:
            first -= 1
        return gaps[first:]

    def _unclaimed(self, gaps: list[_Gap], seq: int, end: int) -> list[tuple[int, int]]:
        """Return the parts of ``[seq, end)`` none of *gaps* claimed, relative to *seq*.

        *gaps* is ascending and non-overlapping, as :meth:`_gaps_from` returns
        them, so what they claim is already in order.
        """
        length = _delta(end, seq)
        claimed = (
            (max(_delta(gap.start, seq), 0), min(_delta(gap.end, seq), length))
            for gap in gaps
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
        # Every distance here runs forward — accepted transmissions only move
        # on, and a length is never negative — so the plain modular distance
        # is exact, and this path runs for every byte accepted.
        recent = stream.recent
        if recent:
            last = recent[-1]
            pos = last.pos + (seq - last.seq) % _SEQ_MOD
        else:
            pos = 0
        recent.append(_Sent(seq, end, tsval, peer_count, pos))
        stream.recent_bytes += (end - seq) % _SEQ_MOD
        window = self._options.reorder_window
        if stream.recent_bytes <= window:
            return
        head = stream.recent_head
        while stream.recent_bytes > window and len(recent) - head > 1:
            oldest = recent[head]
            head += 1
            stream.recent_bytes -= (oldest.end - oldest.seq) % _SEQ_MOD
        if head >= 64 and head * 2 >= len(recent):
            del recent[:head]
            head = 0
        stream.recent_head = head

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

        ``recent`` is ascending, so the transmissions overlapping the range
        are a contiguous run of it, found by bisection rather than a scan
        (#43).  That needs ``_delta`` from *seq* to be monotone along it,
        which it is while the whole of ``recent`` spans no more than
        ``_MAX_WINDOW``: the usual case, since it holds ``reorder_window``
        bytes.  Committed gaps between its entries can stretch it further,
        and then every entry is scanned, as before.  Either way the same
        transmissions are visited in the same order, so the verdict cannot
        differ between the two.
        """
        if tsval is None:
            return TS_ABSENT
        # A copy of a resend that was itself discarded: the same three
        # clauses, against the resend rather than the copy that was kept.
        for sent in stream.resends:
            if (
                sent.tsval == tsval
                and sent.peer_count == peer_count
                and _delta(seq, sent.seq) >= 0
                and _delta(sent.end, end) >= 0
            ):
                return _DUPLICATE
        covered = 0
        length = _delta(end, seq)
        recent, head = stream.recent, stream.recent_head
        if head == len(recent):
            # Nothing accepted yet: a segment wholly behind the handshake.
            return TS_STALE
        first, last = recent[head], recent[-1]
        if last.pos + _delta(last.end, last.seq) - first.pos <= _MAX_WINDOW:
            start = bisect.bisect_right(recent, 0, head, len(recent),
                                        key=lambda sent: _delta(sent.end, seq))
            contiguous = True
        else:
            start, contiguous = head, False
        for index in range(start, len(recent)):
            sent = recent[index]
            lo = max(_delta(sent.seq, seq), 0)
            hi = min(_delta(sent.end, seq), length)
            if hi <= lo:
                if contiguous:
                    break
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
        the policy is ``favor-old``, the repeat is a duplicate or carries no
        option (neither has a second clock to match an echo against — a
        stale repeat does, and is contested like a resend), or the copies
        agree byte-for-byte, where the choice is moot.  A part of the range
        that no open or held run covers has already been settled by the
        peer's ack, and is discarded too — or was released by a bound before
        the ack came, and then a copy that disagrees with what was written is
        counted as a fallback (#54).
        """
        if not self._acked or verdict not in _CONTESTABLE:
            return False
        digest = stream.released.get((seq, end))
        if digest is not None and digest != zlib.crc32(data):
            self._stats.acked_fallback_bytes += len(data)
        tsval = source.tsval if isinstance(source, _Pending) else _tsval(source)
        assert tsval is not None  # either verdict needed it
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
            if kept == copy:
                run.resent.append((_advance(seq, a), _advance(seq, b)))
                self._stats.overlap_bytes += b - a
                self._cite(payload_offset, a, b - a, REASON_OVERLAP)
            else:
                # A disagreeing copy is a resend of these bytes, and flags the
                # record that ends up holding them; see _write.
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
        *,
        resent: tuple[int, int] | None,
    ) -> None:
        """Count and cite a repeated range under its verdict, and flag the record if a resend.

        A resend flags the record that holds its range (#59): whichever open
        or held run covers *resent*, the ``[seq, end)`` it repeated.  Bytes
        already written flag nothing — a record cannot change once it is
        out — and their ``overlap-discarded`` citation is what says the
        sender resent them.  ``None`` when the caller carries the flag
        itself, to a record that does not exist yet.
        """
        if verdict == _DUPLICATE:
            self._stats.duplicate_bytes += length
            self._stats.duplicates += 1
            self._cite(payload_offset, skip, length, REASON_DUPLICATE)
            return
        if verdict != _RETRANSMIT:
            self._stats.ts_fallback[verdict] += 1
        self._stats.overlap_bytes += length
        self._cite(payload_offset, skip, length, REASON_OVERLAP)
        if resent is not None:
            for run in self._covering_runs(stream, *resent):
                run.resent.append(resent)

    # ── emission ────────────────────────────────────────────────────────

    def _attach_flags(
        self, stream: _Stream, flags: int, *, origin: int | None = None,
    ) -> None:
        """OR TCP *flags* into the open run, naming *origin* when the flags alone reach it."""
        if stream.run is not None:
            stream.run.flags |= flags
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

        By default the bounds are the policy's own: a run whose ack has not
        come within ``flush_timeout`` of its closing, or the oldest run once
        the hold exceeds ``reorder_window`` bytes.  With ``acked_hold`` set,
        it is the one bound, in seconds (#32).  A released run is written as
        ``favor-old`` would have written it, and every contested byte in it
        is counted as a fallback — including bytes contested only later, by
        a resend that arrives after the release (#54), which is why the run
        is remembered as written.  A one-way capture, where no ack ever
        comes, writes every run this way.
        """
        hold = self._options.acked_hold
        timeout = self._options.flush_timeout if hold is None else hold
        while stream.unacked and (
            (now - stream.unacked[0].closed_ts) / self._tick_hz > timeout
            or (hold is None and stream.unacked_bytes > self._options.reorder_window)
        ):
            run = self._release_run(stream)
            self._write(stream, run)
            self._remember_released(stream, run)

    def _remember_released(self, stream: _Stream, run: _Run) -> None:
        """Keep a digest of each segment of a released run, as written (#54).

        A resend repeats its original's boundaries, so it is judged against
        the segment it resends; one that does not line up with a remembered
        segment cannot be judged, and is not counted.
        """
        for c in run.contributors:
            offset = _delta(c.seq, run.seq_start)
            data = run.data[offset:offset + _delta(c.end, c.seq)]
            stream.released[c.seq, c.end] = zlib.crc32(data)
        while len(stream.released) > _RELEASED_KEPT:
            del stream.released[next(iter(stream.released))]

    def _release_run(self, stream: _Stream) -> _Run:
        run = stream.unacked.popleft()
        stream.unacked_bytes -= len(run.data)
        return run

    def _write(self, stream: _Stream, run: _Run) -> None:
        """Resolve a run's alternates and write it as its records.

        Each alternate carries its own verdict, taken from the first peer ack
        that covered its range (see :class:`_Alternate`).  One with no
        verdict — the run is being written because a bound expired or the
        session ended — or whose ack carried no option loses on the
        fallback, and is counted as such.

        A copy swapped in is a record of its own (#55).  It is a resend,
        sent after the peer answered the bytes around it, so in one record
        with them it would straddle the peer's message: its time, the last
        contributor's, would date the whole run after the message that
        acknowledged its start.  Apart, each record's ``ts``, ``ack`` and
        flags are its own, and all of them true.  A run with no swap is one
        record, as before.
        """
        swapped: list[tuple[int, int]] = []
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
                swapped.append((alt.seq, alt.end))
                self._stats.acked_swaps += 1
            else:
                # No verdict, or one naming neither copy — a cumulative ack
                # that jumped over several resends echoes only the last
                # filler's clock — leaves the choice to favor-old (#54).
                if (
                    not alt.decided
                    or evidence is None
                    or (alt.tsval != evidence and all(c.tsval != evidence for c in kept))
                ):
                    self._stats.acked_fallback_bytes += len(alt.data)
                self._stats.overlap_bytes += len(alt.data)
                self._cite(alt.payload_offset, 0, len(alt.data), REASON_OVERLAP)

        pieces = _pieces(run, swapped)
        trailing = list(run.trailing_acks)
        for index, (seq, end) in enumerate(pieces):
            last = index == len(pieces) - 1
            offset = _delta(seq, run.seq_start)
            data = bytes(run.data[offset:offset + _delta(end, seq)])
            contributors = _inside(run.contributors, seq, end)
            # The run's TCP flags — a PSH or FIN — belong to its end.
            flags = _RECORD_FLAGS[run.flags & 0xFF] if last else RecordFlags(0)
            # A range resent, and a disagreeing copy swapped in or not, flag
            # the record holding them (#59).
            ranges = [*run.resent, *((alt.seq, alt.end) for alt in run.alternates)]
            if any(_delta(b, seq) > 0 and _delta(end, a) > 0 for a, b in ranges):
                flags |= RecordFlags.RETRANSMIT
            ts, ts_first, ack = _hints(contributors)
            self.sink.record(
                self.participant(stream.endpoint),
                ts=ts,
                payload=data,
                origins=[*(c.payload_offset for c in contributors),
                         *(run.flag_origins if last else ())],
                hints=zpf.Hints(seq_start=seq, ack=ack),
                flags=flags,
                # Only worth stating when the run coalesced more than one packet;
                # for a single segment it would repeat `ts`.
                ts_first=ts_first if ts_first != ts else None,
            )
            self._stats.records += 1
            self._stats.payload_bytes += len(data)
            # What trails the run follows the piece it falls in: records are
            # stored in serial order, and a pure ACK inside the run's range
            # would precede a later piece's start (#55).  They are ascending,
            # released as the frontier passed them.
            while trailing and (last or _delta(trailing[0].seq, pieces[index + 1][0]) < 0):
                held = trailing.pop(0)
                if isinstance(held, _TrailingFin):
                    self._write_fin(stream, held.flags, held.origin, ts=held.ts, ack=held.ack)
                else:
                    self._write_ack(stream, held)


def _tsecr(pkt: PacketView) -> int | None:
    """Return the segment's TSecr, or ``None`` when it carries no Timestamps option."""
    options = pkt.tcp_options
    if options is None or options.timestamps is None:
        return None
    return options.timestamps[1]


def _hints(contributors: list[_Contribution]) -> tuple[int, int, int | None]:
    """Return a record's ``(ts, ts_first, ack)`` from the transmissions that made it.

    All three are extremes over the run's contributing packets, not the
    packet that happened to be appended last: a segment held out of order
    arrives *before* the one that made it contiguous but is appended after
    it, and taking its time would stamp the run as complete before its last
    packet arrived — and leave ``ts_first`` later than ``ts``.

    ``ts`` is the specification's rule — the time of the LAST packet that
    contributed bytes, the moment the unit became complete — and ``ts_first``
    the time it began, which spans would carry if they could name a
    capture: they may only name a zpf-input source, so a capture conversion
    has no other way to say it, and a ``.zpf`` input's records state both.
    The ack is the serial MAXIMUM rather
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
    ts = max(c.ts for c in contributors)
    ts_first = min(c.ts for c in contributors)
    return ts, ts_first, _serial_max(c.ack for c in contributors)


def _pieces(run: _Run, swapped: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Return the ``(seq, end)`` of each record a run is written as.

    The whole run, unless a copy was swapped in; then each swapped range is
    a piece, and so is each stretch between them.
    """
    cuts = sorted({_delta(edge, run.seq_start) for seq, end in swapped for edge in (seq, end)})
    bounds = [0, *(cut for cut in cuts if 0 < cut < len(run.data)), len(run.data)]
    return [
        (_advance(run.seq_start, a), _advance(run.seq_start, b))
        for a, b in itertools.pairwise(bounds)
    ]


def _inside(contributors: list[_Contribution], seq: int, end: int) -> list[_Contribution]:
    """Return the parts of *contributors* that fall inside ``[seq, end)``."""
    parts: list[_Contribution] = []
    for c in contributors:
        a = max(_delta(seq, c.seq), 0)
        b = min(_delta(end, c.seq), _delta(c.end, c.seq))
        if b <= a:
            continue
        parts.append(_Contribution(
            _advance(c.seq, a), _advance(c.seq, b), c.tsval, c.ts, c.ack,
            None if c.payload_offset is None else c.payload_offset + a,
        ))
    return parts


def _serial_max(acks: Iterable[int]) -> int:
    """Return the furthest of *acks* in serial order (RFC 1982)."""
    best: int | None = None
    for ack in acks:
        if best is None or _delta(ack, best) > 0:
            best = ack
    assert best is not None, "a run has at least one contributor"
    return best


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
