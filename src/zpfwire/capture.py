"""Reading a capture file into a stream of transport-layer packet views.

This is the seam against packeteer.  Everything that knows about link layers,
IP headers, or pcap framing lives here; the rest of :mod:`zpfwire` sees only
:class:`PacketView` objects.

The module used to walk the layers itself, driving packeteer's per-layer
parsers and slicing by the header sizes they reported, because
``parse_pcap_packet`` destroyed the payload on exactly the ports a payload
format exists to serve.  packeteer 0.8.0 closed that gap and the four others
the walk was compensating for, so the walk is gone:

- ``decode_app=False`` keeps the payload (packeteer#61);
- the parser trims Ethernet padding itself (packeteer#66);
- fragments are reassembled before parsing, so no packet arrives with a
  transport header over a truncated payload (packeteer#65);
- ``payload_offset`` says where the payload sits in the frame, which
  ``len(frame) - len(payload)`` cannot answer once padding is trimmed
  (packeteer#71);
- and :func:`~packeteer.parse.iter_packets` carries the capture header and the
  datagrams reassembly gave up on alongside the packets (packeteer#76).

packeteer 0.9.0 adds one more (packeteer#68): a parsed transport header keeps
its ``checksum`` only where a rebuild could not derive it, so a value that
survives the parse is one the bytes beside it do not produce.  That is how
:attr:`PacketView.checksum_bad` is known, and it cannot be worked out here —
verifying a checksum needs the pseudo-header the parser has already consumed.

packeteer 0.12.0 moves that line back for one case: a **truncated** packet
keeps its checksum again, because rebuilding it as truncated needs the captured
value (packeteer#126).  Reading the field as corruption therefore takes
``datagram_truncated`` beside it, which is what :func:`_checksum_bad` does.
The same release reads BSD loopback captures (packeteer#124); they arrive here
as ordinary IP packets and ask nothing of this module but that a frame whose
address family announced IP be told apart from one that did not.

packeteer 0.14.0 answers a question this module used to guess at
(packeteer#138): whether a capture's link type is one it can decode.
:func:`~packeteer.parse.supports_link_type` is asked once, at open, and the
answer is :attr:`CaptureReader.link_type_supported`.  Before that the skip
ladder inferred "unsupported link type" from every link-layer object being
``None`` — which is also what a raw-IP packet with a bad IP header looks
like, since ``LINKTYPE_RAW`` has no link-layer header to parse.  That packet
is now filed where it belongs, as a malformed IP header.

What remains here is the mapping from packeteer's model to ours: deciding what
counts as a convertible packet, tallying what does not, and putting timestamps
on one clock.
"""

from __future__ import annotations

import os
import socket
import warnings
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO

from packeteer.generate import ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPv6Header
from packeteer.generate.loopback import AF_INET, LoopbackHeader
from packeteer.generate.tcp import TCPHeader, TCPOptions
from packeteer.generate.udp import UDPHeader
from packeteer.parse import (
    PacketReader,
    ParsedPacket,
    UnsupportedLinkTypeWarning,
    iter_packets,
    supports_link_type,
)
from packeteer.pcap import LINKTYPE_RAW, SNAPLEN_UNLIMITED, PcapFileHeader

__all__ = [
    "TICK_HZ_NS",
    "TICK_HZ_US",
    "CaptureReader",
    "PacketView",
    "SkipReason",
    "format_endpoint",
]

TICK_HZ_US: int = 1_000_000
"""Ticks per second for a microsecond-resolution capture."""

TICK_HZ_NS: int = 1_000_000_000
"""Ticks per second for a nanosecond-resolution capture."""

_IP_ETHERTYPES = (ETHERTYPE_IPV4, ETHERTYPE_IPV6)
_STREAM_PROTOCOLS = (socket.IPPROTO_TCP, socket.IPPROTO_UDP)


class SkipReason:
    """Why a packet produced no :class:`PacketView`.

    These are the keys of :attr:`CaptureReader.skipped`.  They are plain
    strings rather than an enum so that a caller can print a tally without
    translating anything.

    Attributes:
        UNSUPPORTED_LINKTYPE: The capture's link type is one packeteer cannot
            decode, so nothing in any packet could be reached.  A property of
            the file, not the packet — see
            :attr:`CaptureReader.link_type_supported` — and so every packet
            of such a capture lands here.
        NON_IP: The link layer carried something other than IP — ARP, for
            instance.
        MALFORMED_IP: The link layer announced IP, but no IP header parsed.
        NOT_TCP_UDP: An IP datagram carrying neither TCP nor UDP.
        MALFORMED_TRANSPORT: The IP header announced TCP or UDP, but no
            transport header parsed.
        INCOMPLETE_DATAGRAM: A fragmented datagram whose fragments never all
            arrived, counted once per datagram rather than per fragment.

    """

    UNSUPPORTED_LINKTYPE = "unsupported-linktype"
    NON_IP = "non-ip"
    MALFORMED_IP = "malformed-ip-header"
    NOT_TCP_UDP = "not-tcp-or-udp"
    MALFORMED_TRANSPORT = "malformed-transport-header"
    INCOMPLETE_DATAGRAM = "incomplete-datagram"


@dataclass(frozen=True)
class PacketView:
    """One TCP segment or UDP datagram, reduced to what reassembly needs.

    Attributes:
        packet_num: 1-based index of the packet within the capture, counting
            packets that were skipped.  A datagram reassembled from several
            fragments counts once.
        ts_ticks: Capture timestamp in :attr:`CaptureReader.tick_hz` ticks
            since the Unix epoch.
        protocol: ``"tcp"`` or ``"udp"``.
        src: Source IP address, as text.
        dst: Destination IP address, as text.
        src_port: Source port.
        dst_port: Destination port.
        payload: Transport payload, exactly as captured.
        seq: TCP sequence number; ``0`` for UDP.
        ack: TCP acknowledgement number; ``0`` for UDP.
        tcp_flags: Raw 8-bit TCP flags bitmask; ``0`` for UDP.
        tcp_options: Parsed TCP options, or ``None`` when the segment carried
            none.  SACK blocks and timestamps live here.
        payload_offset: Where :attr:`payload` came from, as a number the
            reassembler adds a payload-relative ``skip`` to when it names
            discarded bytes.  From a capture, the byte offset of the payload's
            first byte within the capture file, or ``None`` when there is no
            payload or the packet was reassembled — a reassembled payload
            occupies several discontiguous ranges, which one offset cannot
            express.  From a ``.zpf`` of packets, a number naming the input
            packet, which every ``payload_offset + skip`` still falls inside;
            see :class:`~zpfwire.packets.PacketSink`.
        fragment_count: How many input records the packet came from; ``1``
            unless it was reassembled.
        checksum_bad: Whether the transport checksum disagrees with the bytes
            it covers.  A receiver drops such a packet, so a conversion may
            too — see :attr:`~zpfwire.options.ReassemblyOptions.checksum`.
        truncated: Whether the capture holds less of this packet than the IP
            header says was sent, as after a capture taken with a snaplen.
            :attr:`payload` is then short of what crossed the wire, and no
            later stage can tell that from a short payload the sender chose.

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
    tcp_options: TCPOptions | None = None
    payload_offset: int | None = None
    fragment_count: int = 1
    checksum_bad: bool = False
    truncated: bool = False

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


class CaptureReader:
    """Iterates a capture file as :class:`PacketView` objects.

    Packets that carry no TCP or UDP payload stream are not yielded; they are
    tallied in :attr:`skipped` so a caller can report them rather than lose
    them silently.  Fragmented datagrams are reassembled before parsing, so a
    fragment is never mistaken for a whole packet; a datagram whose fragments
    never all arrived is counted in :attr:`skipped` too.

    The capture is read one packet at a time, so a file larger than memory is
    fine.  Iterating twice re-reads the file and resets the tallies.

    Attributes:
        header: The capture's file header.
        link_type_supported: Whether packeteer can decode the capture's link
            type — asked of :func:`~packeteer.parse.supports_link_type` once,
            at open, for the effective link type (a *link_type* override
            included).  When ``False`` nothing above the link layer can be
            reached, so every packet is skipped as
            :attr:`SkipReason.UNSUPPORTED_LINKTYPE` and the reader yields
            nothing; the tally still counts them.
        tick_hz: Ticks per second for every :attr:`PacketView.ts_ticks`.  Taken
            from the header unless overridden; per-packet timestamps are
            rescaled into it, so a pcapng whose interfaces disagree still lands
            on one clock.
        packet_count: Packets seen during the most recent iteration, including
            skipped ones.  Zero before the first.
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
        """Open a capture and read its header.

        Args:
            path: Path to a pcap or pcapng file.  Mutually exclusive with
                *file_object*.
            file_object: An open binary stream positioned at the file header.
            link_type: Override the link type for headerless input.
            tick_hz: Override the tick rate derived from the file header.

        Raises:
            ValueError: If neither or both of *path* and *file_object* are
                given, or if the capture cannot be read at all.

        """
        if (path is None) == (file_object is None):
            raise ValueError("exactly one of 'path' or 'file_object' is required")

        self._path = path
        self._file_object = file_object
        self._link_type = link_type
        with self._open() as reader:
            self.header: PcapFileHeader = reader.header
        # One link type per capture, and an override lands in the header, so
        # this is asked once here rather than inferred per packet from which
        # header objects came back None — an inference that cannot tell an
        # unknown link layer from a headerless one whose IP header failed.
        self.link_type_supported: bool = supports_link_type(self.header.link_type)
        self.tick_hz: int = tick_hz if tick_hz is not None else self.header.tick_hz
        self.packet_count: int = 0
        self.skipped: Counter[str] = Counter()

    @property
    def link_type(self) -> int:
        """The capture's link-layer type."""
        return self.header.link_type

    @property
    def snaplen(self) -> int | None:
        """Bytes kept per packet, or ``None`` when nothing was cut.

        A capture written with no limit records
        :data:`~packeteer.pcap.SNAPLEN_UNLIMITED`, and one written by a tool
        that did not fill the field records ``0``; neither says a packet was
        cut short, so both read as ``None`` here.
        """
        if self.header.snaplen in (0, SNAPLEN_UNLIMITED):
            return None
        return self.header.snaplen

    def __iter__(self) -> Iterator[PacketView]:
        """Yield a :class:`PacketView` for every TCP segment and UDP datagram."""
        self.skipped.clear()
        self.packet_count = 0
        if not self.link_type_supported:
            # Nothing in the file can be reached, and that was decided at
            # open.  packeteer says the same thing as a warning when it
            # parses the first record; it is silenced here, and only here,
            # because the reader has already said it in its own terms.
            with self._open() as reader, warnings.catch_warnings():
                warnings.simplefilter("ignore", UnsupportedLinkTypeWarning)
                for index, _packet in enumerate(reader, start=1):
                    self.packet_count = index
                    self.skipped[SkipReason.UNSUPPORTED_LINKTYPE] += 1
            return
        with self._open() as reader:
            for index, packet in enumerate(reader, start=1):
                self.packet_count = index
                view = self._view(packet, index)
                if view is None:
                    continue
                yield view
            # Datagrams that never completed are dropped by the reassembler.
            # Counting them here is what keeps that from being silent.  They
            # are counted per datagram, not per fragment, and they never
            # became packets, so they are not in `packet_count`.
            if reader.incomplete:
                self.skipped[SkipReason.INCOMPLETE_DATAGRAM] += len(reader.incomplete)

    def _open(self) -> PacketReader:
        if self._file_object is not None:
            self._file_object.seek(0)
        return iter_packets(
            path=self._path,
            file_object=self._file_object,
            link_type=self._link_type,
            decode_app=False,
        )

    def _view(self, packet: ParsedPacket, index: int) -> PacketView | None:
        reason = skip_reason(packet, headerless=self.link_type == LINKTYPE_RAW)
        if reason is not None:
            self.skipped[reason] += 1
            return None
        return packet_view(
            packet,
            packet_num=index,
            ts_ticks=self._ticks(packet),
            payload_offset=_payload_offset(packet),
            fragment_count=len(packet.source_records) or 1,
        )

    def _ticks(self, packet: ParsedPacket) -> int:
        """Put one packet's timestamp on this reader's clock.

        A pcapng states its resolution per interface, so two packets in one
        file can be counted in different units.  A `.zpf` file header carries
        exactly one tick rate, so each packet is rescaled into ours rather
        than assumed to share it.
        """
        source_hz = packet.tick_hz or self.tick_hz
        if source_hz == self.tick_hz:
            return packet.ts_sec * self.tick_hz + packet.ts_frac
        return packet.ts_sec * self.tick_hz + (packet.ts_frac * self.tick_hz) // source_hz


def packet_view(
    packet: ParsedPacket,
    *,
    packet_num: int,
    ts_ticks: int,
    payload_offset: int | None,
    fragment_count: int,
) -> PacketView:
    """Reduce a parsed TCP segment or UDP datagram to what reassembly needs.

    Shared by both readers, so that a capture and a ``.zpf`` of packets
    yield the same view of the same packet.  Call it only for a packet
    :func:`skip_reason` accepts.

    Args:
        packet: The parsed packet.
        packet_num: Its 1-based index in the input.
        ts_ticks: Its timestamp, already on the reader's clock.
        payload_offset: Where the reader says its payload is; see
            :attr:`PacketView.payload_offset`.
        fragment_count: How many input records it was reassembled from.

    Returns:
        The packet's view.

    """
    transport = packet.transport
    assert isinstance(transport, (TCPHeader, UDPHeader)) and packet.ip is not None
    tcp = transport if isinstance(transport, TCPHeader) else None
    return PacketView(
        packet_num=packet_num,
        ts_ticks=ts_ticks,
        protocol="tcp" if tcp is not None else "udp",
        src=packet.ip.src,
        dst=packet.ip.dst,
        src_port=transport.src_port,
        dst_port=transport.dst_port,
        payload=packet.payload,
        seq=tcp.seq if tcp is not None else 0,
        ack=tcp.ack if tcp is not None else 0,
        tcp_flags=tcp.flags if tcp is not None else 0,
        tcp_options=tcp.options if tcp is not None else None,
        payload_offset=payload_offset,
        fragment_count=fragment_count,
        checksum_bad=_checksum_bad(packet),
        truncated=packet.datagram_truncated,
    )


def skip_reason(packet: ParsedPacket, *, headerless: bool) -> str | None:
    """Return why a packet carries no stream, or ``None`` when it does.

    Only called for a link type packeteer decodes; an unsupported one is
    settled per file, not per packet.  Shared by both readers.

    Args:
        packet: The parsed packet.
        headerless: Whether the capture's link type carries no link-layer
            header at all — raw IP.  The packet cannot say so itself: a
            raw-IP packet whose IP header failed has no header object of any
            kind, exactly as an unknown link layer would, so the fact has to
            come from the file.

    """
    if packet.ip is None:
        if headerless:
            # The link type itself announced IP, so this is the same failure
            # as an Ethernet frame with an IP EtherType and no IP header.
            return SkipReason.MALFORMED_IP
        if packet.loopback is not None:
            return _loopback_skip_reason(packet.loopback)
        ethertype = packet.ethernet.ethertype if packet.ethernet is not None else None
        if ethertype in _IP_ETHERTYPES:
            return SkipReason.MALFORMED_IP
        return SkipReason.NON_IP

    if isinstance(packet.transport, (TCPHeader, UDPHeader)):
        return None
    # The IP header names the transport, so a missing header for a protocol we
    # would have converted is a parse failure rather than a protocol we skip.
    if _ip_protocol(packet) in _STREAM_PROTOCOLS:
        return SkipReason.MALFORMED_TRANSPORT
    return SkipReason.NOT_TCP_UDP


def _loopback_skip_reason(header: LoopbackHeader) -> str:
    """Tell a malformed IP packet from a non-IP one on a loopback capture.

    A loopback frame states an address family rather than an EtherType, and the
    value is the capturing platform's — ``AF_INET6`` is 30 on macOS and 10 on
    Linux — so the comparison uses packeteer's own constants rather than a
    table repeated here.
    """
    if header.family == AF_INET or header.is_ipv6:
        return SkipReason.MALFORMED_IP
    return SkipReason.NON_IP


def _ip_protocol(packet: ParsedPacket) -> int | None:
    """Return the transport protocol number the IP header declares, if any."""
    if isinstance(packet.ip, IPv6Header):
        return packet.ip.next_header
    return packet.ip.protocol if packet.ip is not None else None


def _checksum_bad(packet: ParsedPacket) -> bool:
    """Report whether the transport checksum disagrees with the bytes it covers.

    packeteer keeps ``checksum`` on a parsed header only where a rebuild could
    not derive it (packeteer#68), so a value that is not ``None`` here is one
    the payload beside it does not produce.

    Two cases survive that test without being a failure.

    A **truncated** packet is the first.  packeteer 0.9.1 cleared the field
    there (packeteer#92); 0.12.0 records it again, because rebuilding the
    packet as truncated needs the captured value (packeteer#126), and upstream
    now asks a consumer reading a checksum as corruption to test
    :attr:`~packeteer.parse.ParsedPacket.datagram_truncated` beside it.  The
    bytes the sender checksummed are not in the file, so the value cannot be
    checked at all — which is a different statement from its being wrong.
    Corruption stays unreportable in a truncated capture, as it was before.

    The second is **IPv4 UDP carrying ``0``**, which means *no checksum was
    computed* (RFC 768) rather than a wrong one.  Over IPv6 a zero checksum is
    illegal (RFC 8200 section 8.1), so there it stands as a failure.
    """
    transport = packet.transport
    if not isinstance(transport, (TCPHeader, UDPHeader)) or transport.checksum is None:
        return False
    if packet.datagram_truncated:
        return False
    if isinstance(transport, UDPHeader) and transport.checksum == 0:
        return isinstance(packet.ip, IPv6Header)
    return True


def _payload_offset(packet: ParsedPacket) -> int | None:
    """Where the payload's first byte sits in the capture file.

    ``payload_offset`` is relative to the frame handed to the parser, so it
    composes with the record's own offset — but only while the frame *is* a
    capture record.  A reassembled datagram's payload spans several
    discontiguous ranges, and one offset cannot express that (packeteer#72
    gives the contributing records, should a caller want to walk them).
    """
    if packet.payload_offset is None or len(packet.source_records) != 1:
        return None
    return packet.source_records[0].data_offset + packet.payload_offset
