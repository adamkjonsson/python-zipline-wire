"""Reusing packeteer's packet filter against :class:`~zpfwire.capture.PacketView`.

packeteer already implements filtering with validated semantics — CIDR ranges,
IPv4 and IPv6, and ``!`` negation — so this module adapts to it rather than
implementing a second dialect of the same flags.

:meth:`packeteer.filter.PacketFilter.matches` expects a packet-spec dict, but
it reads only five keys, so a small projection of a ``PacketView`` satisfies
it exactly.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from packeteer.filter import PacketFilter

from zpfwire.capture import PacketView

__all__ = ["matcher", "spec_of"]


def spec_of(pkt: PacketView) -> dict[str, Any]:
    """Project a packet view into the subset of a packet spec that filtering reads.

    Args:
        pkt: The packet to project.

    Returns:
        A dict with the ``network`` and ``transport`` keys
        :meth:`PacketFilter.matches` consults.

    """
    return {
        "network": {"protocol": pkt.protocol, "src": pkt.src, "dst": pkt.dst},
        "transport": {"src_port": pkt.src_port, "dst_port": pkt.dst_port},
    }


def matcher(packet_filter: PacketFilter | None) -> Callable[[PacketView], bool] | None:
    """Turn a :class:`PacketFilter` into a predicate over packet views.

    Args:
        packet_filter: The filter, or ``None``.

    Returns:
        A predicate, or ``None`` when there is nothing to filter on — which
        lets a caller skip the per-packet projection entirely.

    """
    if packet_filter is None or packet_filter.is_empty():
        return None
    return lambda pkt: packet_filter.matches(spec_of(pkt))
