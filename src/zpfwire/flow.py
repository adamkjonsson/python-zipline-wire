"""Grouping packets into the conversations that become zipline sessions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

import zpf

from zpfwire.capture import PacketView, format_endpoint

if TYPE_CHECKING:  # pragma: no cover
    from zpf import (
        DecoderHandle,
        FileWriter,
        Hints,
        ParticipantHandle,
        RecordFlags,
        SessionWriter,
        SourceHandle,
    )

    from zpfwire.options import ReassemblyOptions
    from zpfwire.stats import ConversionStats

__all__ = [
    "END_CAPTURE_END",
    "END_TIMEOUT",
    "REASON_CHECKSUM",
    "REASON_DUPLICATE",
    "REASON_LATE",
    "REASON_LATE_REORDERED",
    "REASON_LATE_RETRANSMITTED",
    "REASON_OVERLAP",
    "REASON_PAWS",
    "REASON_TS_MISSING",
    "CaptureSink",
    "FlowKey",
    "FlowTracker",
    "RecordSink",
    "cite_undecoded",
]

REASON_OVERLAP = "overlap-discarded"
"""Undecoded reason for retransmitted bytes dropped because the range was already accepted.

The sender resent; the record covering the range carries ``retransmit``.
"""

REASON_DUPLICATE = "duplicate-discarded"
"""Undecoded reason for a copy of a transmission already accepted.

The capture point saw one packet twice — a mirror port, a two-interface
capture — and the sender resent nothing, so no record carries ``retransmit``
on its account.  Told apart from :data:`REASON_OVERLAP` by the TCP Timestamps
option; see :class:`~zpfwire.tcp.TcpFlow`.
"""

REASON_LATE = "late-arrival"
"""Undecoded reason for bytes that arrived after their gap had been committed.

The bare reason: used when the TCP Timestamps option cannot say *why* they
were late — absent, or the arrival shares a clock tick with everything
committed past it.  Where it can, one of the two below is written instead.
"""

REASON_LATE_REORDERED = "late-reordered"
"""Undecoded reason for a late arrival that was the original transmission, delayed.

Its TSval is older than everything committed past its gap: the network
reordered it, and a wider ``reorder_window`` or a longer ``flush_timeout``
would have kept it.  A tuning signal about our own policy.
"""

REASON_LATE_RETRANSMITTED = "late-retransmitted"
"""Undecoded reason for a late arrival that was a resend of lost bytes.

Its TSval is newer than everything committed past its gap: the original was
lost and the sender recovered it after the hole had been given up on.  A
fact about the network, which no policy of ours could have changed.
"""

REASON_PAWS = "paws-rejected"
"""Undecoded reason for a segment whose timestamp says it is from before a wrap.

RFC 7323 §5.3: a segment carrying a TSval older than the last one the
receiver accepted in order is an old segment whose sequence numbers have
come round again, and a receiver drops it whole.  Applied only to segments
that would otherwise contribute bytes; a repeat of accepted bytes is judged
as a repeat, whatever its clock.
"""

REASON_CHECKSUM = "bad-checksum"
"""Undecoded reason for a TCP segment discarded because its checksum did not verify.

Written only under ``checksum="drop"``, and never for UDP, which is kept: a UDP
stream's offsets could not show a datagram missing.  Doubles as the skip key
for the same packets, since a packet dropped before it reaches a session is
skipped in exactly the sense the tally means.
"""

REASON_TS_MISSING = "timestamp-missing"
"""Undecoded reason for a segment without the Timestamps option on a connection that negotiated it.

RFC 7323 §3.2: once both SYNs carried the option, a receiver SHOULD silently
drop a non-RST segment that lacks it — which is what a segment forged by a
third party without it is.  Written only under ``require_timestamps``,
which is off by default: a middlebox stripping options mid-connection would
make the rule drop real data (#57).
"""

_BYTES_EXIST = "bytes"
"""The only ``reason_class`` a capture-sourced Undecoded block may carry."""

END_CAPTURE_END = "capture-end"
"""Session End reason for a flow still open when the capture ran out."""

END_TIMEOUT = "timeout"
"""Session End reason for a flow that fell silent for longer than allowed."""


@dataclass(frozen=True, order=True)
class FlowKey:
    """Identifies one conversation, independently of direction.

    A zipline session holds *both* directions of a connection, so the key has
    to be direction-free: the two endpoints are sorted, and a packet from
    either side yields the same key.

    packeteer's :func:`packeteer.parse.info._session_key` builds a similar
    tuple but deliberately keeps it directional — it only counts half-flows —
    so this is not shared with it.

    Attributes:
        protocol: ``"tcp"`` or ``"udp"``.
        a: The lower of the two endpoints, as ``ip:port``.
        b: The higher of the two endpoints.

    """

    protocol: str
    a: str
    b: str

    @classmethod
    def of(cls, pkt: PacketView) -> FlowKey:
        """Build the key for the conversation *pkt* belongs to.

        Args:
            pkt: Any packet of the conversation, in either direction.

        Returns:
            The direction-free key.

        """
        first = (pkt.src, pkt.src_port)
        second = (pkt.dst, pkt.dst_port)
        low, high = (first, second) if first <= second else (second, first)
        return cls(
            protocol=pkt.protocol,
            a=format_endpoint(*low),
            b=format_endpoint(*high),
        )

    @property
    def text(self) -> str:
        """A human-readable flow key, e.g. ``10.0.0.1:51000 <-> 10.0.0.2:80``."""
        return f"{self.a} <-> {self.b}"

    def peer_of(self, endpoint: str) -> str:
        """Return the other endpoint of this conversation.

        Args:
            endpoint: One of the two endpoints.

        Returns:
            The opposite endpoint.

        Raises:
            KeyError: If *endpoint* is not part of this flow.

        """
        if endpoint == self.a:
            return self.b
        if endpoint == self.b:
            return self.a
        raise KeyError(f"{endpoint} is not an endpoint of {self.text}")


def cite_undecoded(
    writer: FileWriter | None,
    source: SourceHandle | None,
    off_start: int | None,
    length: int,
    *,
    reason: str,
    decoder: DecoderHandle | None,
    stats: ConversionStats,
) -> None:
    """Declare capture bytes that reached no record.

    Bytes that exist in the capture and reach no record are something nothing
    else in a `.zpf` can express — a transport stream's gaps are visible in
    its offsets, but bytes deliberately dropped are not.  Only the
    *bytes-exist* class may be declared against a capture source; a hole must
    not be, so no caller here passes one.

    Args:
        writer: The file being written, or ``None`` when there is none.
        source: The capture the region belongs to.
        off_start: Byte offset of the region in the capture file, or ``None``
            when it cannot be located — a datagram reassembled from several
            fragments occupies discontiguous ranges, which one block cannot
            name.
        length: How many bytes the region covers.
        reason: Why the region went undecoded; see :data:`REASON_OVERLAP`,
            :data:`REASON_DUPLICATE`, :data:`REASON_LATE` and its two
            refinements, :data:`REASON_PAWS` and :data:`REASON_CHECKSUM`.
        decoder: The stage that discarded the bytes.
        stats: Tally to record the block, or the failure to place it, in.

    """
    if length <= 0:
        return
    if off_start is None or writer is None or source is None:
        stats.unlocatable_bytes += length
        return
    writer.undecoded(
        source,
        # Against a capture source there is no input .zpf, so there is no
        # id namespace to name: the spec requires both written as 0.
        session_id=0,
        pid=0,
        off_start=off_start,
        off_end=off_start + length,
        reason=reason,
        reason_class=_BYTES_EXIST,
        decoder=decoder,
    )
    stats.undecoded_regions += 1


class RecordSink(ABC):
    """Where one tracker's session is written.

    A tracker decides what the records of a conversation are; the sink
    decides what writing one means, which depends on what the conversion
    reads.  Over a capture it is a session of the output file, with
    Undecoded blocks at capture byte offsets (:class:`CaptureSink`).  Over a
    ``.zpf`` of packets it is a session of a sessionization stage, whose
    records cite the input records they came from
    (:class:`zpfwire.packets.PacketSink`).

    A tracker locates the bytes it handles by the
    :attr:`~zpfwire.capture.PacketView.payload_offset` of the packet they
    came from, plus how far into the payload they sit.  That is the whole of
    what a sink is told about where bytes came from, so each input gives the
    number its own meaning: a byte offset into the capture file, or a slot in
    a space that names one input packet.
    """

    @abstractmethod
    def participant(self, endpoint: str, **declaration: object) -> ParticipantHandle:
        """Declare a participant of this session.

        Args:
            endpoint: The participant's ``ip:port``.
            **declaration: ``isn`` and ``tcp_role``, where known.

        Returns:
            The participant handle.

        """

    @abstractmethod
    def record(
        self,
        sender: ParticipantHandle,
        *,
        ts: int,
        payload: bytes,
        origins: Sequence[int | None],
        hints: Hints | None = None,
        flags: RecordFlags | int = 0,
        ts_first: int | None = None,
    ) -> None:
        """Write one transport-layer record.

        Args:
            sender: The participant that sent the bytes.
            ts: The record's timestamp, in ticks.
            payload: The record's bytes.
            origins: The ``payload_offset`` of every packet the record was
                built from, its flags included.  A capture conversion has
                nothing to cite them as; a ``.zpf`` input cites each packet.
            hints: ``seq_start`` and ``ack``, for TCP.
            flags: The record's flags.
            ts_first: When the first contributing packet arrived, where it
                differs from ``ts``.

        """

    @abstractmethod
    def undecoded(self, off_start: int | None, length: int, *, reason: str) -> None:
        """Declare input bytes that reached no record.

        Args:
            off_start: Where the region starts, as a ``payload_offset`` plus
                how far into that payload, or ``None`` when it cannot be
                located.
            length: How many bytes the region covers.
            reason: Why the region went undecoded; see :data:`REASON_OVERLAP`
                and the reasons beside it.

        """

    @abstractmethod
    def end(self, reason: str) -> None:
        """End the session.

        Args:
            reason: How it ended, from the specification's open vocabulary.

        """


class CaptureSink(RecordSink):
    """A capture conversion's session: records in the output file, discards at capture offsets.

    Attributes:
        session: The output session being written.

    """

    def __init__(
        self,
        session: SessionWriter,
        *,
        writer: FileWriter,
        source: SourceHandle,
        decoder: DecoderHandle,
        stats: ConversionStats,
    ) -> None:
        """Bind a sink to one output session.

        Args:
            session: The output session.
            writer: The output file, which Undecoded blocks are written to.
            source: The capture, which Undecoded blocks name.
            decoder: The reassembler declared on the output, which every
                record and Undecoded block names.
            stats: Tally of what was written.

        """
        self.session = session
        self._writer = writer
        self._source = source
        self._decoder = decoder
        self._stats = stats

    def participant(self, endpoint: str, **declaration: object) -> ParticipantHandle:
        """Declare a participant of the output session.

        Args:
            endpoint: The participant's ``ip:port``.
            **declaration: ``isn`` and ``tcp_role``, where known.

        Returns:
            The participant handle.

        """
        return self.session.participant(endpoint, **declaration)  # type: ignore[arg-type]

    def record(
        self,
        sender: ParticipantHandle,
        *,
        ts: int,
        payload: bytes,
        origins: Sequence[int | None],
        hints: Hints | None = None,
        flags: RecordFlags | int = 0,
        ts_first: int | None = None,
    ) -> None:
        """Write one record to the output session; *origins* are not cited.

        A capture-sourced record carries no ``spans``: a span names a range
        of an input ``.zpf``, and a capture is not one.

        Args:
            sender: The participant that sent the bytes.
            ts: The record's timestamp, in ticks.
            payload: The record's bytes.
            origins: Unused here.
            hints: ``seq_start`` and ``ack``, for TCP.
            flags: The record's flags.
            ts_first: When the first contributing packet arrived.

        """
        del origins
        self.session.record(
            sender,
            ts=ts,
            payload=payload,
            hints=hints,
            flags=flags,
            decoded=zpf.Decoded(decoder=self._decoder),
            ts_first=ts_first,
        )

    def undecoded(self, off_start: int | None, length: int, *, reason: str) -> None:
        """Declare capture bytes that reached no record; see :func:`cite_undecoded`.

        Args:
            off_start: Byte offset of the region in the capture file, or
                ``None`` when it cannot be located.
            length: How many bytes the region covers.
            reason: Why the region went undecoded.

        """
        cite_undecoded(
            self._writer, self._source, off_start, length,
            reason=reason, decoder=self._decoder, stats=self._stats,
        )

    def end(self, reason: str) -> None:
        """End the output session.

        Args:
            reason: How it ended.

        """
        self.session.end(reason=reason)


class FlowTracker(ABC):
    """Turns one conversation's packets into one session's records.

    Subclasses differ only in what a record *is* for their transport — a UDP
    datagram, or a run of reassembled TCP bytes — so the sink wiring,
    participant bookkeeping and end-reason handling live here.  A subclass
    writes through :attr:`sink`, so the same tracker converts a capture and
    a ``.zpf`` of packets alike.

    Attributes:
        key: The conversation this tracker is responsible for.
        sink: Where the session is written.
        last_ts: Capture timestamp of the most recent packet seen, in ticks.
        timed_out: Whether the flow was closed by the idle timeout.

    """

    def __init__(
        self,
        key: FlowKey,
        sink: RecordSink,
        *,
        options: ReassemblyOptions,
        stats: ConversionStats,
        tick_hz: int,
    ) -> None:
        """Start tracking one conversation.

        Args:
            key: The conversation.
            sink: Where its session is written.
            options: The reassembly policy.
            stats: Tally of what the conversion did.
            tick_hz: Ticks per second of every timestamp it sees.

        """
        self.key = key
        self.sink = sink
        self.last_ts = 0
        self.timed_out = False
        self._options = options
        self._stats = stats
        self._tick_hz = tick_hz
        self._participants: dict[str, ParticipantHandle] = {}

    def undecoded(self, off_start: int | None, length: int, *, reason: str) -> None:
        """Declare input bytes that this stage did not turn into a record.

        The tracker-bound form of :meth:`RecordSink.undecoded`.

        Args:
            off_start: Where the region starts, as a ``payload_offset`` plus
                how far into that payload, or ``None`` when it cannot be
                located.
            length: How many bytes the region covers.
            reason: Why the region went undecoded; see :data:`REASON_OVERLAP`,
                :data:`REASON_DUPLICATE` and :data:`REASON_LATE`.

        """
        self.sink.undecoded(off_start, length, reason=reason)

    def expired(self, now_ticks: int) -> bool:
        """Report whether this flow has been silent for longer than allowed.

        Args:
            now_ticks: Current capture time, in ticks.

        Returns:
            ``True`` when the idle timeout has elapsed.

        """
        return (now_ticks - self.last_ts) / self._tick_hz > self._options.session_timeout

    def time_out(self) -> None:
        """Record that this flow is being closed by the idle timeout."""
        self.timed_out = True

    def splits_before(self, pkt: PacketView) -> bool:
        """Report whether *pkt* must open a new session rather than join this one.

        The base tracker never splits; a transport whose session cannot
        represent what comes next says so here.  When it answers ``True`` the
        caller closes this flow and begins another, and *pkt* is the new
        flow's first packet.

        Args:
            pkt: The packet about to be delivered.

        Returns:
            ``True`` to end this session before *pkt*.

        """
        return False

    @abstractmethod
    def packet(self, pkt: PacketView) -> None:
        """Take one packet of this conversation."""

    @abstractmethod
    def finish(self) -> str:
        """Flush anything held back and return the Session End reason.

        Returns:
            A reason from the spec's open vocabulary, such as ``"fin"``.

        """

    def participant(self, endpoint: str, **declaration: object) -> ParticipantHandle:
        """Return the handle for *endpoint*, declaring it on first sight.

        Declaring lazily is what lets the converter stay single-pass: a
        direction's first packet always precedes any record from it, so
        per-participant metadata that has to be fixed at declaration time —
        notably a TCP stream's ``isn`` — is known by then when it is knowable
        at all.

        ``adjacency`` is deliberately left at the writer's default,
        ``contiguous``.  On a transport-layer participant the field says
        nothing — offsets come from sequence numbers, so stored neighbours
        join by construction — and the specification forbids a writer to set
        ``units`` there (spec 0.21).  Every participant this project writes
        is transport-layer, so there is nothing to pass.

        Args:
            endpoint: The participant's ``ip:port``.
            **declaration: Extra arguments for the Participant Descriptor,
                used only when the participant is being declared now.

        Returns:
            The participant handle.

        """
        handle = self._participants.get(endpoint)
        if handle is None:
            handle = self.sink.participant(endpoint, **declaration)
            self._participants[endpoint] = handle
        return handle

    def declared(self, endpoint: str) -> bool:
        """Report whether *endpoint* has already been declared."""
        return endpoint in self._participants
