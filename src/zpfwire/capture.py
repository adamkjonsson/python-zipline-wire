"""Reading a capture file into a stream of transport-layer packet views.

This is the seam against packeteer.  Everything that knows about link layers,
IP headers, or pcap framing lives here; the rest of :mod:`zpfwire` sees only
:class:`PacketView` objects.

Why the layer walk is done by hand
----------------------------------

The obvious entry point is :func:`packeteer.parse.parse_pcap_packet`, and it
cannot be used: ``_try_parse_dns`` / ``_try_parse_dhcp`` / ``_try_parse_http``
run unconditionally after the transport header and return ``b""`` on success,
so ``ParsedPacket.payload`` is empty for every packet on ports 80/8080,
53/5353 and 67/68.  Those are exactly the payloads a payload format exists to
carry, and there is no flag to decline the behaviour.

So the walk below drives packeteer's *per-layer* parsers directly — they all
share the signature ``packet_parser(data) -> (header_size, next_layer, header)``
— and slices by the header sizes they report.  The parsing is still
packeteer's; only the dispatch is local.

This whole module collapses to a single ``parse_packet(..., decode_app=False)``
call once packeteer#61 lands.  Two smaller pieces of hand-work here have their
own upstream issues: reading the IP length from raw bytes (packeteer#66) and
the absence of decoded TCP options (packeteer#63).

- https://github.com/adamkjonsson/packeteer/issues/61
- https://github.com/adamkjonsson/packeteer/issues/66
- https://github.com/adamkjonsson/packeteer/issues/63
"""

from __future__ import annotations

import os
import socket
import struct
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO

from packeteer.generate.ethernet import ETHERTYPE_IPV4, ETHERTYPE_IPV6
from packeteer.generate.ip import IPHeader
from packeteer.parse.ethernet import packet_parser as _ethernet_parser
from packeteer.parse.ip import packet_parser as _ip_parser
from packeteer.parse.tcp import packet_parser as _tcp_parser
from packeteer.parse.udp import packet_parser as _udp_parser
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, PcapFileHeader, read_pcap

__all__ = [
    "TICK_HZ_NS",
    "TICK_HZ_US",
    "CaptureReader",
    "PacketView",
    "SkipReason",
    "tick_hz_for",
]

TICK_HZ_US: int = 1_000_000
"""Ticks per second for a microsecond-resolution capture."""

TICK_HZ_NS: int = 1_000_000_000
"""Ticks per second for a nanosecond-resolution capture."""

_IPV4_MORE_FRAGMENTS = 0b001
_IPV6_FRAGMENT_HEADER = 44


class SkipReason:
    """Why a packet produced no :class:`PacketView`.

    These are the keys of :attr:`CaptureReader.skipped`.  They are plain
    strings rather than an enum so that a caller can print a tally without
    translating anything.
    """

    UNSUPPORTED_LINKTYPE = "unsupported-linktype"
    MALFORMED_LINK = "malformed-link-header"
    NON_IP = "non-ip"
    MALFORMED_IP = "malformed-ip-header"
    FRAGMENT = "ip-fragment"
    NOT_TCP_UDP = "not-tcp-or-udp"
    MALFORMED_TRANSPORT = "malformed-transport-header"


@dataclass(frozen=True)
class PacketView:
    """One TCP segment or UDP datagram, reduced to what reassembly needs.

    Attributes:
        packet_num: 1-based index of the packet within the capture.
        ts_ticks: Capture timestamp in ``tick_hz`` ticks since the Unix epoch.
        protocol: ``"tcp"`` or ``"udp"``.
        src: Source IP address, as text.
        dst: Destination IP address, as text.
        src_port: Source port.
        dst_port: Destination port.
        payload: Transport payload, trimmed to the IP length so that any
            link-layer padding is excluded.
        seq: TCP sequence number; ``0`` for UDP.
        ack: TCP acknowledgement number; ``0`` for UDP.
        tcp_flags: Raw 8-bit TCP flags bitmask; ``0`` for UDP.

    """

    packet_num: int
    ts_ticks: int
    protocol: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    payload: bytes
    seq: int = 0
    ack: int = 0
    tcp_flags: int = 0

    @property
    def src_endpoint(self) -> str:
        """The source as a zipline endpoint string, e.g. ``10.0.0.1:443``."""
        return format_endpoint(self.src, self.src_port)

    @property
    def dst_endpoint(self) -> str:
        """The destination as a zipline endpoint string."""
        return format_endpoint(self.dst, self.dst_port)


def format_endpoint(ip: str, port: int) -> str:
    """Spell an address and port the way the specification recommends.

    IPv6 addresses are bracketed so that the port separator is unambiguous.

    Args:
        ip: IP address in text form.
        port: Port number.

    Returns:
        ``"10.0.0.1:80"`` or ``"[2001:db8::1]:443"``.

    """
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def tick_hz_for(header: PcapFileHeader) -> int:
    """Return the tick rate matching a capture's timestamp resolution.

    packeteer reduces pcapng's ``if_tsresol`` option to a single boolean, so
    only microsecond and nanosecond resolutions survive the read; anything
    else is reported as microseconds and would be misread here in exactly the
    same way (packeteer#64).  Callers who know better can override the value.

    Args:
        header: The capture's file header.

    Returns:
        Ticks per second — :data:`TICK_HZ_NS` or :data:`TICK_HZ_US`.

    """
    return TICK_HZ_NS if header.nanoseconds else TICK_HZ_US


class CaptureReader:
    """Iterates a capture file as :class:`PacketView` objects.

    Packets that carry no TCP or UDP payload stream — anything that is not
    IP, is fragmented, or uses another transport — are not yielded; they are
    tallied in :attr:`skipped` so a caller can report them rather than lose
    them silently.

    The whole capture is read into memory on construction, because
    :func:`packeteer.pcap.read_pcap` has no streaming counterpart
    (packeteer#62).

    Attributes:
        header: The capture's file header.
        tick_hz: Ticks per second for every :attr:`PacketView.ts_ticks`.
        packet_count: Number of packets in the capture, including skipped ones.
        skipped: Tally of skip reasons; keys come from :class:`SkipReason`.

    Example:
        >>> reader = CaptureReader(path="capture.pcap")
        >>> for pkt in reader:
        ...     print(pkt.protocol, pkt.src_endpoint)

    """

    def __init__(
        self,
        *,
        path: str | os.PathLike[str] | None = None,
        file_object: IO[bytes] | None = None,
        link_type: int | None = None,
        tick_hz: int | None = None,
    ) -> None:
        """Read a capture.

        Args:
            path: Path to a pcap or pcapng file.  Mutually exclusive with
                *file_object*.
            file_object: An open binary stream positioned at the file header.
            link_type: Override the link type for headerless input.
            tick_hz: Override the tick rate derived from the file header.

        Raises:
            ValueError: If neither or both of *path* and *file_object* are given.

        """
        if (path is None) == (file_object is None):
            raise ValueError("exactly one of 'path' or 'file_object' is required")

        capture = read_pcap(path=path, file_object=file_object, link_type=link_type)
        self.header: PcapFileHeader = capture.header
        self.tick_hz: int = tick_hz if tick_hz is not None else tick_hz_for(capture.header)
        self.packet_count: int = len(capture.packets)
        self.skipped: Counter[str] = Counter()
        self._records = capture.packets
        self._frac_scale = self.tick_hz // (
            TICK_HZ_NS if capture.header.nanoseconds else TICK_HZ_US
        )

    @property
    def link_type(self) -> int:
        """The capture's link-layer type."""
        return self.header.link_type

    def __iter__(self) -> Iterator[PacketView]:
        """Yield a :class:`PacketView` for every TCP segment and UDP datagram."""
        self.skipped.clear()
        for index, (data, ts_sec, ts_frac) in enumerate(self._records, start=1):
            result = _walk(data, self.header.link_type)
            if isinstance(result, str):
                self.skipped[result] += 1
                continue
            yield _view(result, index, self._ticks(ts_sec, ts_frac))

    def _ticks(self, ts_sec: int, ts_frac: int) -> int:
        return ts_sec * self.tick_hz + ts_frac * self._frac_scale


@dataclass(frozen=True)
class _Transport:
    """The result of a successful layer walk, before timestamping."""

    protocol: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    payload: bytes
    seq: int
    ack: int
    tcp_flags: int


def _view(t: _Transport, packet_num: int, ts_ticks: int) -> PacketView:
    return PacketView(
        packet_num=packet_num,
        ts_ticks=ts_ticks,
        protocol=t.protocol,
        src=t.src,
        dst=t.dst,
        src_port=t.src_port,
        dst_port=t.dst_port,
        payload=t.payload,
        seq=t.seq,
        ack=t.ack,
        tcp_flags=t.tcp_flags,
    )


def _walk(data: bytes, link_type: int) -> _Transport | str:
    """Walk one frame down to its transport payload.

    Returns:
        A :class:`_Transport` on success, or a :class:`SkipReason` string.

    """
    remaining = _strip_link_layer(data, link_type)
    if isinstance(remaining, str):
        return remaining

    ip_size, ip_proto, ip_hdr = _ip_parser(remaining)
    if ip_size == 0 or ip_hdr is None:
        return SkipReason.MALFORMED_IP

    if _is_fragment(ip_hdr, ip_proto):
        return SkipReason.FRAGMENT

    ip_payload = _ip_payload(remaining, ip_size)
    if ip_payload is None:
        return SkipReason.MALFORMED_IP

    if ip_proto == socket.IPPROTO_TCP:
        return _tcp(ip_hdr.src, ip_hdr.dst, ip_payload)
    if ip_proto == socket.IPPROTO_UDP:
        return _udp(ip_hdr.src, ip_hdr.dst, ip_payload)
    return SkipReason.NOT_TCP_UDP


def _strip_link_layer(data: bytes, link_type: int) -> bytes | str:
    """Remove the link-layer header, leaving the IP header first.

    ``packeteer.parse.ethernet`` consumes 802.1Q and QinQ tags itself and
    reports the innermost EtherType, so VLANs need no handling here.
    """
    if link_type == LINKTYPE_RAW:
        return data
    if link_type != LINKTYPE_ETHERNET:
        return SkipReason.UNSUPPORTED_LINKTYPE

    size, ethertype, _ = _ethernet_parser(data)
    if size == 0:
        return SkipReason.MALFORMED_LINK
    if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        return SkipReason.NON_IP
    return data[size:]


def _is_fragment(ip_hdr: object, ip_proto: int | None) -> bool:
    """Report whether this packet is a fragment of a larger datagram.

    Fragments are skipped rather than reassembled; defragmentation belongs
    upstream in packeteer (packeteer#65).
    """
    if isinstance(ip_hdr, IPHeader):
        return bool(ip_hdr.flags & _IPV4_MORE_FRAGMENTS) or ip_hdr.fragment_offset != 0
    return ip_proto == _IPV6_FRAGMENT_HEADER


def _ip_payload(data: bytes, ip_size: int) -> bytes | None:
    """Slice the IP payload, trimming any link-layer padding.

    A frame shorter than the Ethernet minimum is padded, and that padding sits
    after the IP datagram.  The parsed header does not carry the IP length
    (packeteer#66), so it is read from the raw bytes here — without this, every
    small packet's payload would gain trailing zeroes.
    """
    version = data[0] >> 4
    if version == 4:
        total_length = struct.unpack("!H", data[2:4])[0]
        # A zero total length means segmentation offload wrote the frame
        # before the NIC filled the field in; the capture holds the whole
        # datagram, so fall back to everything present.
        end = len(data) if total_length == 0 else total_length
    else:
        payload_length = struct.unpack("!H", data[4:6])[0]
        # IPv6 counts extension headers in payload_length, and ip_size already
        # includes any Hop-by-Hop header the parser consumed.
        end = 40 + payload_length

    if end < ip_size:
        return None
    return data[ip_size:min(end, len(data))]


def _tcp(src: str, dst: str, ip_payload: bytes) -> _Transport | str:
    size, _, hdr = _tcp_parser(ip_payload)
    if size == 0 or hdr is None:
        return SkipReason.MALFORMED_TRANSPORT
    return _Transport(
        protocol="tcp",
        src=src,
        dst=dst,
        src_port=hdr.src_port,
        dst_port=hdr.dst_port,
        payload=ip_payload[size:],
        seq=hdr.seq,
        ack=hdr.ack,
        tcp_flags=hdr.flags,
    )


def _udp(src: str, dst: str, ip_payload: bytes) -> _Transport | str:
    size, _, hdr = _udp_parser(ip_payload)
    if size == 0 or hdr is None:
        return SkipReason.MALFORMED_TRANSPORT
    # The UDP length field covers header plus data and may be shorter than
    # what the IP length allows; trust the narrower of the two.
    udp_length = struct.unpack("!H", ip_payload[4:6])[0]
    end = len(ip_payload) if udp_length < size else min(udp_length, len(ip_payload))
    return _Transport(
        protocol="udp",
        src=src,
        dst=dst,
        src_port=hdr.src_port,
        dst_port=hdr.dst_port,
        payload=ip_payload[size:end],
        seq=0,
        ack=0,
        tcp_flags=0,
    )
