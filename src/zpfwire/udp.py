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
    """

    def packet(self, pkt: PacketView) -> None:
        """Write one datagram as one record."""
        self.last_ts = pkt.ts_ticks
        sender = self.participant(pkt.src_endpoint)
        # Declare the peer too, so the session describes the conversation and
        # not just the half of it that happened to speak.
        self.participant(pkt.dst_endpoint)

        self.sink.record(
            sender,
            ts=pkt.ts_ticks,
            payload=pkt.payload,
            origins=(pkt.payload_offset,),
            flags=RecordFlags.MESSAGE,
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
