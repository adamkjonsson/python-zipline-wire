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

What remains here is the mapping from packeteer's model to ours: deciding what
counts as a convertible packet, tallying what does not, and putting timestamps
on one clock.
"""

from __future__ import annotations

import os
import socket
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO

from packeteer.generate import ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPv6Header
from packeteer.generate.tcp import TCPHeader, TCPOptions
from packeteer.generate.udp import UDPHeader
from packeteer.parse import PacketReader, ParsedPacket, iter_packets
from packeteer.pcap import PcapFileHeader

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
        UNSUPPORTED_LINKTYPE: No link-layer header was recognised, so nothing
            below it could be reached.
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
        payload_offset: Byte offset of :attr:`payload`'s first byte within the
            capture file, or ``None`` when there is no payload or the packet
            was reassembled — a reassembled payload occupies several
            discontiguous ranges, which one offset cannot express.
        fragment_count: How many capture records the packet came from; ``1``
            unless it was reassembled.
        checksum_bad: Whether the transport checksum disagrees with the bytes
            it covers.  A receiver drops such a packet, so a conversion may
            too — see :attr:`~zpfwire.options.ReassemblyOptions.checksum`.

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
        self.tick_hz: int = tick_hz if tick_hz is not None else self.header.tick_hz
        self.packet_count: int = 0
        self.skipped: Counter[str] = Counter()

    @property
    def link_type(self) -> int:
        """The capture's link-layer type."""
        return self.header.link_type

    def __iter__(self) -> Iterator[PacketView]:
        """Yield a :class:`PacketView` for every TCP segment and UDP datagram."""
        self.skipped.clear()
        self.packet_count = 0
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
        reason = _unconvertible(packet)
        if reason is not None:
            self.skipped[reason] += 1
            return None

        transport = packet.transport
        tcp = transport if isinstance(transport, TCPHeader) else None
        return PacketView(
            packet_num=index,
            ts_ticks=self._ticks(packet),
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
            payload_offset=_payload_offset(packet),
            fragment_count=len(packet.source_records) or 1,
            checksum_bad=_checksum_bad(packet),
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


def _unconvertible(packet: ParsedPacket) -> str | None:
    """Return why a packet carries no stream, or ``None`` when it does."""
    if packet.ip is None:
        if packet.ethernet is None and packet.sll is None:
            return SkipReason.UNSUPPORTED_LINKTYPE
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


def _ip_protocol(packet: ParsedPacket) -> int | None:
    """Return the transport protocol number the IP header declares, if any."""
    if isinstance(packet.ip, IPv6Header):
        return packet.ip.next_header
    return packet.ip.protocol if packet.ip is not None else None


def _checksum_bad(packet: ParsedPacket) -> bool:
    """Report whether the transport checksum disagrees with the bytes it covers.

    packeteer keeps ``checksum`` on a parsed header only where a rebuild could
    not derive it (packeteer#68), so a value that is not ``None`` here is one
    the payload beside it does not produce.  Two cases that survive that test
    are nonetheless not failures:

    * **IPv4 UDP carrying ``0``**, which means *no checksum was computed*
      (RFC 768) rather than a wrong one.  Over IPv6 a zero checksum is illegal
      (RFC 8200 section 8.1), so there it stands as a failure.
    * **A truncated capture**, where a snaplen cut off bytes the checksum
      covers.  The sender's value cannot be recomputed from what was kept, so
      the verdict is unknown rather than bad.  packeteer means to make this
      case a ``None`` upstream (packeteer#92); until it does, the check below
      is ours, and it goes when the fix lands.
    """
    transport = packet.transport
    if not isinstance(transport, (TCPHeader, UDPHeader)) or transport.checksum is None:
        return False
    if _truncated(packet):
        return False
    if isinstance(transport, UDPHeader) and transport.checksum == 0:
        return isinstance(packet.ip, IPv6Header)
    return True


def _truncated(packet: ParsedPacket) -> bool:
    """Report whether a snaplen cut bytes off any record behind this packet."""
    return any(len(record.data) < record.orig_len for record in packet.source_records)


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
