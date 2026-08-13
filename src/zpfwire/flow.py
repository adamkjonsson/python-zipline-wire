"""Grouping packets into the conversations that become zipline sessions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from zpfwire.capture import PacketView, format_endpoint

if TYPE_CHECKING:  # pragma: no cover
    from zpf import DecoderHandle, FileWriter, ParticipantHandle, SessionWriter, SourceHandle

    from zpfwire.options import ReassemblyOptions
    from zpfwire.stats import ConversionStats

__all__ = [
    "END_CAPTURE_END",
    "END_TIMEOUT",
    "REASON_LATE",
    "REASON_OVERLAP",
    "FlowKey",
    "FlowTracker",
]

REASON_OVERLAP = "overlap-discarded"
"""Undecoded reason for bytes dropped because that range was already accepted."""

REASON_LATE = "late-arrival"
"""Undecoded reason for bytes that arrived after their gap had been committed."""

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


class FlowTracker(ABC):
    """Turns one conversation's packets into one session's records.

    Subclasses differ only in what a record *is* for their transport — a UDP
    datagram, or a run of reassembled TCP bytes — so the writer wiring,
    participant bookkeeping and end-reason handling live here.

    Attributes:
        key: The conversation this tracker is responsible for.
        session: The session being written.
        last_ts: Capture timestamp of the most recent packet seen, in ticks.
        timed_out: Whether the flow was closed by the idle timeout.

    """

    def __init__(
        self,
        key: FlowKey,
        session: SessionWriter,
        *,
        decoder: DecoderHandle | None,
        options: ReassemblyOptions,
        stats: ConversionStats,
        tick_hz: int,
        writer: FileWriter | None = None,
        source: SourceHandle | None = None,
    ) -> None:
        self.key = key
        self.session = session
        self.last_ts = 0
        self.timed_out = False
        self._decoder = decoder
        self._options = options
        self._stats = stats
        self._tick_hz = tick_hz
        self._writer = writer
        self._source = source
        self._participants: dict[str, ParticipantHandle] = {}

    def undecoded(self, off_start: int | None, length: int, *, reason: str) -> None:
        """Declare capture bytes that this stage did not turn into a record.

        An overlapping retransmit exists in the capture and reaches no record,
        and nothing else in a `.zpf` can say so — a transport stream's gaps are
        already visible in its offsets, but bytes deliberately dropped are not.
        Only the *bytes-exist* class may be declared against a capture source;
        a hole must not be, so no caller here passes one.

        Args:
            off_start: Byte offset of the region in the capture file, or
                ``None`` when it cannot be located — a datagram reassembled
                from several fragments occupies discontiguous ranges, which one
                block cannot name.
            length: How many bytes the region covers.
            reason: Why the region went undecoded; see :data:`REASON_OVERLAP`
                and :data:`REASON_LATE`.

        """
        if length <= 0:
            return
        if off_start is None or self._writer is None or self._source is None:
            self._stats.unlocatable_bytes += length
            return
        self._writer.undecoded(
            self._source,
            # Against a capture source there is no input .zpf, so there is no
            # id namespace to name: the spec requires both written as 0.
            session_id=0,
            pid=0,
            off_start=off_start,
            off_end=off_start + length,
            reason=reason,
            reason_class=_BYTES_EXIST,
            decoder=self._decoder,
        )
        self._stats.undecoded_regions += 1

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

        Args:
            endpoint: The participant's ``ip:port``.
            **declaration: Extra arguments for the Participant Descriptor,
                used only when the participant is being declared now.

        Returns:
            The participant handle.

        """
        handle = self._participants.get(endpoint)
        if handle is None:
            handle = self.session.participant(endpoint, **declaration)  # type: ignore[arg-type]
            self._participants[endpoint] = handle
        return handle

    def declared(self, endpoint: str) -> bool:
        """Report whether *endpoint* has already been declared."""
        return endpoint in self._participants
