"""Looking at a capture without converting it."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from zpfwire.capture import CaptureReader, PacketView
from zpfwire.flow import FlowKey

__all__ = ["FlowSummary", "survey"]


@dataclass
class FlowSummary:
    """What one conversation looks like, before anything is written.

    Attributes:
        key: The conversation.
        packets: Packets seen, both directions.
        payload_bytes: Transport payload bytes seen, before reassembly — so
            retransmits are still counted here.
        first_ts: Timestamp of the first packet, in ticks.
        last_ts: Timestamp of the last packet, in ticks.
        endpoints: Which endpoints actually sent something.

    """

    key: FlowKey
    packets: int = 0
    payload_bytes: int = 0
    first_ts: int = 0
    last_ts: int = 0
    endpoints: set[str] = field(default_factory=set)

    def duration(self, tick_hz: int) -> float:
        """Return how long the conversation lasted, in seconds."""
        return (self.last_ts - self.first_ts) / tick_hz


def survey(
    reader: CaptureReader,
    *,
    packet_filter: Callable[[PacketView], bool] | None = None,
) -> list[FlowSummary]:
    """Report the conversations a capture holds.

    This is what a conversion *would* turn into sessions, without writing
    anything — useful for sizing up a capture, or for checking a filter
    before committing to the output.

    Args:
        reader: The capture to look at.
        packet_filter: Called per packet; return ``False`` to exclude it.

    Returns:
        One summary per conversation, in first-seen order.

    """
    flows: dict[FlowKey, FlowSummary] = {}
    for pkt in reader:
        if packet_filter is not None and not packet_filter(pkt):
            continue
        key = FlowKey.of(pkt)
        summary = flows.get(key)
        if summary is None:
            summary = FlowSummary(key=key, first_ts=pkt.ts_ticks)
            flows[key] = summary
        summary.packets += 1
        summary.payload_bytes += len(pkt.payload)
        summary.last_ts = pkt.ts_ticks
        summary.endpoints.add(pkt.src_endpoint)
    return list(flows.values())
