"""UDP flows: one datagram, one record."""

from __future__ import annotations

from zpf import RecordFlags

from zpfwire.capture import PacketView
from zpfwire.flow import END_CAPTURE_END, END_TIMEOUT, FlowTracker

__all__ = ["UdpFlow"]


class UdpFlow(FlowTracker):
    """Writes one UDP conversation as a session of message records.

    UDP needs no reassembly: a datagram is already the unit the application
    sent, so each becomes exactly one record carrying the ``message`` flag —
    which is what the specification asks of a message-oriented transport at
    the transport layer.

    There are no sequence numbers, so records carry no ``seq_start`` or
    ``ack`` and participants carry no ``isn``.  Ordering within a participant
    is therefore capture order, which the specification names as the rule for
    streams without sequence numbers.

    A datagram the capture point saw twice cannot be discarded, as a TCP
    segment's copy is: a datagram left out of a stream without sequence
    numbers would leave no trace.  So it is written, and since spec ``0.24``
    marked ``copy`` (zipline#169), when the evidence allows it (#77): it
    repeats its participant's preceding datagram frame for frame, under the
    same non-zero IP identification
    (:attr:`~zpfwire.capture.PacketView.datagram_digest`).  A sender that
    resends gives the datagram a new identification, and a mirror port does
    not.  A repeat that cannot be told from a resend is written unmarked.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        # Each participant's preceding datagram, as its digest: what a copy
        # would repeat.
        self._previous: dict[str, bytes | None] = {}

    def packet(self, pkt: PacketView) -> None:
        """Write one datagram as one record, flagged ``copy`` when it is one."""
        self.last_ts = pkt.ts_ticks
        sender = self.participant(pkt.src_endpoint)
        # Declare the peer too, so the session describes the conversation and
        # not just the half of it that happened to speak.
        self.participant(pkt.dst_endpoint)

        flags = RecordFlags.MESSAGE
        digest = pkt.datagram_digest
        if digest is not None and self._previous.get(pkt.src_endpoint) == digest:
            flags |= RecordFlags.COPY
            self._stats.copies += 1
        self._previous[pkt.src_endpoint] = digest
        self.sink.record(
            sender,
            ts=pkt.ts_ticks,
            payload=pkt.payload,
            origins=(pkt.payload_offset,),
            flags=flags,
        )
        self._stats.records += 1
        self._stats.payload_bytes += len(pkt.payload)

    def finish(self) -> str:
        """Close the flow.

        Nothing is ever held back, so there is nothing to flush.

        Returns:
            The Session End reason.

        """
        return END_TIMEOUT if self.timed_out else END_CAPTURE_END
