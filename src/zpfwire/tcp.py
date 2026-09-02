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

Everything discarded is counted — overlapping retransmits as
``overlap_bytes``, bytes that arrived after their gap was committed as
``late_bytes`` — so a conversion never loses data quietly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from packeteer.generate.tcp import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG
from zpf import RecordFlags, TcpRole

from zpfwire.capture import PacketView
from zpfwire.flow import (
    END_CAPTURE_END,
    END_TIMEOUT,
    REASON_LATE,
    REASON_OVERLAP,
    FlowTracker,
)

__all__ = ["END_FIN", "END_RST", "TcpFlow"]

_SEQ_MOD = 1 << 32
_SEQ_HALF = _SEQ_MOD >> 1

END_FIN = "fin"
"""Session End reason when both directions closed cleanly."""

END_RST = "rst"
"""Session End reason when either direction reset the connection."""

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


@dataclass
class _Pending:
    """A segment held back because earlier bytes have not arrived."""

    data: bytes
    flags: int
    ack: int
    ts: int
    payload_offset: int | None = None


@dataclass
class _Run:
    """Contiguous bytes accumulating towards one record."""

    seq_start: int
    data: bytearray = field(default_factory=bytearray)
    # The specification stamps a reassembled record with the time of the LAST
    # packet that contributed bytes, in capture order — the moment the unit
    # became complete — because an ack can never precede arrival of what it
    # acknowledges.  Both stamps are set from the first packet appended and
    # widened from there; see _append.
    ts: int = 0
    # When a run coalesces several segments, the time it *began* is otherwise
    # unrecoverable: spans could carry it, but they must reference a zpf-input
    # source and ours is a capture, so ts_first is the only place it fits.
    ts_first: int = 0
    ack: int | None = None
    flags: int = 0
    retransmit: bool = False


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
    committed_gaps: list[tuple[int, int]] = field(default_factory=list)


class TcpFlow(FlowTracker):
    """Writes one TCP conversation as a session of reassembled byte runs."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._streams: dict[str, _Stream] = {}

    # ── driving ─────────────────────────────────────────────────────────

    def packet(self, pkt: PacketView) -> None:
        """Take one segment of this conversation."""
        self.last_ts = pkt.ts_ticks
        stream = self._stream(pkt.src_endpoint)

        syn = bool(pkt.tcp_flags & TCP_SYN)
        if syn:
            self._handshake(stream, pkt)
        self._declare(stream)
        if syn:
            self._syn_record(stream, pkt)

        if pkt.payload:
            self._accept(stream, pkt.seq, pkt.payload, pkt)

        closing = bool(pkt.tcp_flags & (TCP_FIN | TCP_RST))
        if closing:
            stream.fin = stream.fin or bool(pkt.tcp_flags & TCP_FIN)
            stream.rst = stream.rst or bool(pkt.tcp_flags & TCP_RST)
            self._attach_flags(stream, pkt)

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
        self._declare_silent_peer()

        if any(s.rst for s in self._streams.values()):
            return END_RST
        if self._streams and all(s.fin for s in self._streams.values()) and len(self._streams) > 1:
            return END_FIN
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
        self.session.record(
            self.participant(stream.endpoint),
            ts=pkt.ts_ticks,
            payload=b"",
            seq_start=_advance(stream.isn, 1),
            ack=pkt.ack if pkt.tcp_flags & TCP_ACK else None,
            flags=RecordFlags.SYN,
            decoder=self._decoder,
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
        if _delta(end, stream.next_seq) <= 0:
            self._count_repeat(stream, seq, end, pkt.payload_offset)
            return

        if _delta(seq, stream.next_seq) < 0:
            overlap = _delta(stream.next_seq, seq)
            # Only ever a leading trim, so the discarded bytes start where the
            # segment's payload starts.
            self._count_repeat(stream, seq, stream.next_seq, pkt.payload_offset)
            data = data[overlap:]
            seq = stream.next_seq
            self._mark_retransmit(stream)

        if seq == stream.next_seq:
            self._append(stream, seq, data, pkt)
            self._drain(stream, pkt)
        else:
            self._hold(stream, seq, data, pkt)
            self._maybe_commit_gap(stream, pkt)

    def _append(self, stream: _Stream, seq: int, data: bytes, pkt: PacketView) -> None:
        if stream.run is None:
            stream.run = _Run(seq_start=seq, ts=pkt.ts_ticks, ts_first=pkt.ts_ticks)
        stream.run.data.extend(data)
        # Both stamps are extremes over the run's contributing packets, not
        # the packet that happened to be appended last: a segment held out of
        # order arrives *before* the one that made it contiguous but is
        # appended after it, and taking its time would stamp the run as
        # complete before its last packet arrived — and leave ts_first, set
        # from the earlier append, later than ts.
        stream.run.ts = max(stream.run.ts, pkt.ts_ticks)
        stream.run.ts_first = min(stream.run.ts_first, pkt.ts_ticks)
        stream.run.ack = pkt.ack
        self._attach_flags(stream, pkt)
        stream.next_seq = _advance(seq, len(data))

    def _hold(self, stream: _Stream, seq: int, data: bytes, pkt: PacketView) -> None:
        if seq in stream.pending:
            # A duplicate of something already waiting.
            self._stats.overlap_bytes += len(data)
            self.undecoded(pkt.payload_offset, len(data), reason=REASON_OVERLAP)
            self._mark_retransmit(stream)
            return
        stream.pending[seq] = _Pending(data=data, flags=pkt.tcp_flags, ack=pkt.ack,
                                       ts=pkt.ts_ticks, payload_offset=pkt.payload_offset)
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
                self._release(stream, seq)
                self._stats.overlap_bytes += len(held.data)
                self.undecoded(held.payload_offset, len(held.data), reason=REASON_OVERLAP)
                continue
            if _delta(seq, stream.next_seq) > 0:
                return
            trim = _delta(stream.next_seq, seq)
            self._release(stream, seq)
            if trim:
                self._stats.overlap_bytes += trim
                self.undecoded(held.payload_offset, trim, reason=REASON_OVERLAP)
                self._mark_retransmit(stream)
            self._append(
                stream,
                stream.next_seq,
                held.data[trim:],
                _stamp(pkt, held),
            )
        stream.oldest_pending_ts = None

    def _release(self, stream: _Stream, seq: int) -> None:
        held = stream.pending.pop(seq)
        stream.pending_bytes -= len(held.data)

    def _next_pending(self, stream: _Stream) -> int:
        assert stream.next_seq is not None
        return min(stream.pending, key=lambda s: _delta(s, stream.next_seq))  # type: ignore[arg-type]

    # ── gaps ────────────────────────────────────────────────────────────

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
        stream.committed_gaps.append((stream.next_seq, target))
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
                stream.committed_gaps.append((stream.next_seq, target))
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
            )

    def _count_repeat(
        self,
        stream: _Stream,
        seq: int,
        end: int,
        payload_offset: int | None,
    ) -> None:
        """Attribute already-seen bytes to overlap, or to a committed gap.

        Bytes that fall inside a gap this stream already gave up on are not
        retransmits — they are data the policy caused us to lose, and the
        specification forbids writing them now. They are counted separately so
        that a loss caused by our own timeouts is never mistaken for a
        harmless duplicate.

        Both kinds exist in the capture and reach no record, so both are cited
        as Undecoded regions; only the reason differs. The ranges are taken
        relative to *seq*, which is where this segment's payload begins.
        """
        length = _delta(end, seq)
        if length <= 0:
            return
        late = 0
        for gap_start, gap_end in stream.committed_gaps:
            overlap_start = max(_delta(seq, gap_start), 0)
            overlap_end = min(_delta(end, gap_start), _delta(gap_end, gap_start))
            if overlap_end > overlap_start:
                late += overlap_end - overlap_start
                self._cite(payload_offset, _delta(gap_start, seq) + overlap_start,
                           overlap_end - overlap_start, REASON_LATE)
        self._stats.late_bytes += late
        self._stats.overlap_bytes += length - late
        if length - late:
            self._cite_remainder(stream, seq, end, payload_offset)
            self._mark_retransmit(stream)

    def _cite(self, payload_offset: int | None, skip: int, length: int, reason: str) -> None:
        """Declare a sub-range of one segment's payload as undecoded."""
        start = None if payload_offset is None else payload_offset + skip
        self.undecoded(start, length, reason=reason)

    def _cite_remainder(
        self,
        stream: _Stream,
        seq: int,
        end: int,
        payload_offset: int | None,
    ) -> None:
        """Cite the parts of ``[seq, end)`` that no committed gap claimed."""
        length = _delta(end, seq)
        claimed = sorted(
            (max(_delta(gap_start, seq), 0), min(_delta(gap_end, seq), length))
            for gap_start, gap_end in stream.committed_gaps
        )
        cursor = 0
        for start, stop in claimed:
            if stop <= cursor or start >= length:
                continue
            if start > cursor:
                self._cite(payload_offset, cursor, start - cursor, REASON_OVERLAP)
            cursor = max(cursor, stop)
        if cursor < length:
            self._cite(payload_offset, cursor, length - cursor, REASON_OVERLAP)

    def _mark_retransmit(self, stream: _Stream) -> None:
        if stream.run is not None:
            stream.run.retransmit = True

    # ── emission ────────────────────────────────────────────────────────

    def _attach_flags(self, stream: _Stream, pkt: PacketView) -> None:
        if stream.run is not None:
            stream.run.flags |= pkt.tcp_flags

    def _flush(self, stream: _Stream) -> None:
        """Write the accumulated run as one record."""
        run = stream.run
        stream.run = None
        if run is None or not run.data:
            return

        flags = RecordFlags(0)
        for tcp_bit, record_bit in _FLAG_MAP:
            if run.flags & tcp_bit:
                flags |= record_bit
        if run.retransmit:
            flags |= RecordFlags.RETRANSMIT

        self.session.record(
            self.participant(stream.endpoint),
            ts=run.ts,
            payload=bytes(run.data),
            seq_start=run.seq_start,
            ack=run.ack,
            flags=flags,
            decoder=self._decoder,
            # Only worth stating when the run coalesced more than one packet;
            # for a single segment it would repeat `ts`.
            ts_first=run.ts_first if run.ts_first != run.ts else None,
        )
        self._stats.records += 1
        self._stats.payload_bytes += len(run.data)


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
