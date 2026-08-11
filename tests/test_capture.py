from __future__ import annotations

import io

import pytest
from helpers import (
    CAPTURES,
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    SERVER_PORT,
    TCP_PSH,
    capture_of,
    tcp_packet,
    udp_packet,
)
from packeteer.generate import PacketBuilder
from packeteer.pcap import read_pcap

from zpfwire.capture import (
    TICK_HZ_US,
    CaptureReader,
    PacketView,
    SkipReason,
    format_endpoint,
)


def views(buf: io.BytesIO) -> tuple[CaptureReader, list[PacketView]]:
    reader = CaptureReader(file_object=buf)
    return reader, list(reader)


# ── the layer walk ──────────────────────────────────────────────────────


def test_a_tcp_segment_becomes_a_packet_view():
    buf = capture_of([tcp_packet(seq=1001, ack=5001, flags=TCP_PSH, payload=b"hello")])
    reader, pkts = views(buf)

    assert len(pkts) == 1
    pkt = pkts[0]
    assert pkt.protocol == "tcp"
    assert pkt.payload == b"hello"
    assert pkt.seq == 1001
    assert pkt.ack == 5001
    assert pkt.tcp_flags & TCP_PSH
    assert pkt.src == CLIENT_IP
    assert pkt.dst == SERVER_IP
    assert pkt.src_port == CLIENT_PORT
    assert pkt.dst_port == SERVER_PORT
    assert pkt.packet_num == 1
    assert reader.skipped == {}


def test_a_udp_datagram_becomes_a_packet_view():
    buf = capture_of([udp_packet(payload=b"query")])
    _, pkts = views(buf)

    assert len(pkts) == 1
    assert pkts[0].protocol == "udp"
    assert pkts[0].payload == b"query"
    assert pkts[0].seq == 0
    assert pkts[0].tcp_flags == 0


def test_packet_numbers_are_one_based_and_count_skipped_packets():
    buf = capture_of([
        tcp_packet(seq=1, payload=b"a"),
        udp_packet(payload=b"b"),
        tcp_packet(seq=2, payload=b"c"),
    ])
    _, pkts = views(buf)

    assert [p.packet_num for p in pkts] == [1, 2, 3]


def test_timestamps_are_scaled_to_ticks():
    buf = capture_of(
        [tcp_packet(payload=b"x"), tcp_packet(payload=b"y")],
        start_us=1_700_000_000_000_000,
        step_us=250,
    )
    reader, pkts = views(buf)

    assert reader.tick_hz == TICK_HZ_US
    assert pkts[0].ts_ticks == 1_700_000_000_000_000
    assert pkts[1].ts_ticks == 1_700_000_000_000_250


def test_an_explicit_tick_hz_overrides_the_header():
    buf = capture_of([tcp_packet(payload=b"x")], start_us=2_000_000)
    reader = CaptureReader(file_object=buf, tick_hz=1_000_000_000)

    # The frac field still holds microseconds, so it scales by 1000.
    assert list(reader)[0].ts_ticks == 2_000_000_000


# ── the details the hand-rolled walk exists for ─────────────────────────


def test_ethernet_padding_is_not_treated_as_payload():
    """A frame below the 60-byte Ethernet minimum is padded after the datagram.

    Slicing "everything after the TCP header" would append those zero bytes to
    the payload, injecting bytes that were never sent. See packeteer#66.
    """
    frame = tcp_packet(seq=1, payload=b"hi")
    # The builder already pads to the 60-byte minimum, so the frame carries
    # 4 bytes of trailing padding beyond the 56-byte IP datagram.
    assert len(frame) == 60
    assert frame.endswith(b"hi" + b"\x00" * 4)

    _, pkts = views(capture_of([frame]))

    assert pkts[0].payload == b"hi"


def test_http_payloads_survive_the_walk():
    """The regression that motivated bypassing parse_packet (packeteer#61).

    parse_pcap_packet consumes the payload into ParsedPacket.http on port 80,
    leaving payload empty. A payload format cannot be built on that.
    """
    reader = CaptureReader(path=CAPTURES / "http_example.pcapng")
    ours = sum(len(p.payload) for p in reader)

    capture = read_pcap(path=str(CAPTURES / "http_example.pcapng"))
    from packeteer.parse import parse_pcap_packet

    theirs = sum(len(parse_pcap_packet(r, capture.header).payload) for r in capture.packets)

    assert ours > theirs
    assert theirs == 1308
    assert ours == 3138


def test_an_empty_payload_is_kept_as_an_empty_view():
    buf = capture_of([tcp_packet(seq=1, ack=99)])
    _, pkts = views(buf)

    assert len(pkts) == 1
    assert pkts[0].payload == b""
    assert pkts[0].ack == 99


# ── what gets skipped ───────────────────────────────────────────────────


def test_non_ip_frames_are_skipped_and_counted():
    arp_ish = (
        b"\xff\xff\xff\xff\xff\xff" + b"\x00\x00\x00\x00\x00\x01" + b"\x08\x06" + b"\x00" * 28
    )
    reader, pkts = views(capture_of([arp_ish]))

    assert pkts == []
    assert reader.skipped == {SkipReason.NON_IP: 1}


def test_non_tcp_udp_transports_are_skipped_and_counted():
    reader = CaptureReader(path=CAPTURES / "sctp.pcap")
    pkts = list(reader)

    assert pkts == []
    assert reader.skipped[SkipReason.NOT_TCP_UDP] == reader.packet_count


def test_ip_fragments_are_skipped_and_counted():
    """Defragmentation belongs upstream (packeteer#65); until then, count them."""
    reader = CaptureReader(path=CAPTURES / "fragmentation.pcap")
    pkts = list(reader)

    assert reader.skipped[SkipReason.FRAGMENT] > 0
    assert len(pkts) + reader.skipped[SkipReason.FRAGMENT] == reader.packet_count


def test_an_unsupported_link_type_skips_every_packet():
    buf = capture_of([tcp_packet(payload=b"x")], link_type=113)
    reader, pkts = views(buf)

    assert pkts == []
    assert reader.skipped == {SkipReason.UNSUPPORTED_LINKTYPE: 1}


def test_a_truncated_ip_header_is_skipped():
    stub = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00" + b"\x45\x00"
    reader, pkts = views(capture_of([stub]))

    assert pkts == []
    assert reader.skipped == {SkipReason.MALFORMED_IP: 1}


# ── IPv6 ────────────────────────────────────────────────────────────────


def test_ipv6_tcp_is_walked_and_endpoints_are_bracketed():
    frame = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src="2001:db8::1", dst="2001:db8::2")
        .tcp(src_port=4000, dst_port=443, seq=7, flags=TCP_PSH)
        .payload(data=b"v6")
        .build()
    )
    _, pkts = views(capture_of([frame]))

    assert len(pkts) == 1
    assert pkts[0].payload == b"v6"
    assert pkts[0].src == "2001:db8::1"
    assert pkts[0].src_endpoint == "[2001:db8::1]:4000"
    assert pkts[0].dst_endpoint == "[2001:db8::2]:443"


# ── plumbing ────────────────────────────────────────────────────────────


def test_endpoints_are_spelled_as_the_spec_recommends():
    assert format_endpoint("10.0.0.1", 80) == "10.0.0.1:80"
    assert format_endpoint("2001:db8::1", 443) == "[2001:db8::1]:443"


def test_path_and_file_object_are_mutually_exclusive():
    with pytest.raises(ValueError, match="exactly one"):
        CaptureReader()
    with pytest.raises(ValueError, match="exactly one"):
        CaptureReader(path="x.pcap", file_object=capture_of([]))


def test_iterating_twice_does_not_double_count_skips():
    reader = CaptureReader(path=CAPTURES / "sctp.pcap")
    first = dict(reader.skipped) or None
    list(reader)
    after_one = dict(reader.skipped)
    list(reader)
    after_two = dict(reader.skipped)

    assert first is None
    assert after_one == after_two
