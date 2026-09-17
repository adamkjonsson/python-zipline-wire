"""Turn network captures into Zipline Payload Format (`.zpf`) files.

``zpfwire`` is glue: :mod:`packeteer` parses the capture, :mod:`zpf` writes the
format, and this package does the part neither can — grouping packets into
conversations, reassembling TCP byte streams, and mapping the result onto the
specification's session/participant/record model.

The output of a conversion is a **capture-sourced, transport-layer** file.

Example:
    >>> import zpfwire
    >>> stats = zpfwire.capture_to_zpf("capture.pcap", "capture.zpf")
    >>> print(stats.summary())

"""

from __future__ import annotations

from zpfwire.capture import (
    TICK_HZ_NS,
    TICK_HZ_US,
    CaptureReader,
    PacketView,
    SkipReason,
    format_endpoint,
)
from zpfwire.convert import capture_to_zpf, convert, describe_source
from zpfwire.filter import matcher, spec_of
from zpfwire.flow import (
    END_CAPTURE_END,
    END_TIMEOUT,
    REASON_CHECKSUM,
    REASON_DUPLICATE,
    REASON_LATE,
    REASON_LATE_REORDERED,
    REASON_LATE_RETRANSMITTED,
    REASON_OVERLAP,
    REASON_PAWS,
    FlowKey,
    FlowTracker,
    cite_undecoded,
)
from zpfwire.options import (
    CHECKSUM_POLICIES,
    DECODER_NAME,
    OVERLAP_POLICIES,
    ReassemblyOptions,
    tool_version,
)
from zpfwire.stats import ConversionStats
from zpfwire.survey import FlowSummary, survey
from zpfwire.tcp import (
    END_CAPTURE_GAP,
    END_FIN,
    END_OFFSET_LIMIT,
    END_RST,
    TS_ABSENT,
    TS_STALE,
    TcpFlow,
)
from zpfwire.udp import UdpFlow

__version__ = tool_version()

__all__ = [
    "CHECKSUM_POLICIES",
    "DECODER_NAME",
    "END_CAPTURE_END",
    "END_CAPTURE_GAP",
    "END_FIN",
    "END_OFFSET_LIMIT",
    "END_RST",
    "END_TIMEOUT",
    "OVERLAP_POLICIES",
    "REASON_CHECKSUM",
    "REASON_DUPLICATE",
    "REASON_LATE",
    "REASON_LATE_REORDERED",
    "REASON_LATE_RETRANSMITTED",
    "REASON_OVERLAP",
    "REASON_PAWS",
    "TICK_HZ_NS",
    "TICK_HZ_US",
    "TS_ABSENT",
    "TS_STALE",
    "CaptureReader",
    "ConversionStats",
    "FlowKey",
    "FlowSummary",
    "FlowTracker",
    "PacketView",
    "ReassemblyOptions",
    "SkipReason",
    "TcpFlow",
    "UdpFlow",
    "__version__",
    "capture_to_zpf",
    "cite_undecoded",
    "convert",
    "describe_source",
    "format_endpoint",
    "matcher",
    "spec_of",
    "survey",
    "tool_version",
]
