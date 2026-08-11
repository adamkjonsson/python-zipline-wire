from __future__ import annotations

import pathlib

import zpf
from helpers import (
    CAPTURES,
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    capture_of,
    to_zpf,
    udp_packet,
)

from zpfwire import ReassemblyOptions

CLIENT = f"{CLIENT_IP}:{CLIENT_PORT}"
SERVER = f"{SERVER_IP}:53"


def test_one_datagram_becomes_one_record(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([
        udp_packet(payload=b"first"),
        udp_packet(payload=b"second"),
    ]), tmp_path)
    session = out.only

    assert session.proto == "udp"
    assert [r.payload for r in session.by(0)] == [b"first", b"second"]


def test_datagram_records_carry_the_message_flag(tmp_path: pathlib.Path):
    """The spec asks a message-oriented transport to mark its boundaries."""
    out = to_zpf(capture_of([udp_packet(payload=b"one")]), tmp_path)

    for record in out.only.records:
        assert record.flags & zpf.RecordFlags.MESSAGE


def test_udp_records_carry_no_sequence_hints(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([udp_packet(payload=b"one")]), tmp_path)

    record = out.only.records[0]
    assert record.seq_start is None
    assert record.ack is None


def test_udp_participants_carry_no_isn(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([udp_packet(payload=b"one")]), tmp_path)

    for participant in out.only.participants:
        assert participant.isn is None


def test_both_endpoints_are_declared(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([udp_packet(payload=b"one")]), tmp_path)

    assert {p.endpoint for p in out.only.participants} == {CLIENT, SERVER}


def test_both_directions_share_one_session(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([
        udp_packet(payload=b"question"),
        udp_packet(src=SERVER_IP, dst=CLIENT_IP, src_port=53, dst_port=CLIENT_PORT,
                   payload=b"answer"),
    ]), tmp_path)
    session = out.only

    assert len(session.participants) == 2
    assert session.stream(0) == b"question"
    assert session.stream(1) == b"answer"


def test_an_empty_datagram_is_still_a_record(tmp_path: pathlib.Path):
    """A zero-length datagram is a message that was sent, not an absence."""
    out = to_zpf(capture_of([udp_packet(payload=b"")]), tmp_path)

    assert len(out.only.records) == 1
    assert out.only.records[0].payload == b""


def test_a_udp_flow_ends_at_capture_end(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([udp_packet(payload=b"one")]), tmp_path)

    assert out.only.end_reason == "capture-end"


def test_a_silent_udp_flow_times_out(tmp_path: pathlib.Path):
    out = to_zpf(
        capture_of([udp_packet(payload=b"early"), udp_packet(payload=b"late")],
                   step_us=60_000_000),
        tmp_path,
        options=ReassemblyOptions(session_timeout=10.0),
    )

    assert len(out.sessions) == 2
    assert out.sessions[0].end_reason == "timeout"


def test_dns_over_udp_keeps_its_payload(tmp_path: pathlib.Path):
    """Packeteer's parse path would have consumed these into ParsedPacket.dns."""
    out = to_zpf(CAPTURES / "dns_example.pcapng", tmp_path)

    assert out.diagnostics == []
    assert out.stats.payload_bytes == 676


def test_separate_port_pairs_are_separate_sessions(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([
        udp_packet(src_port=1111, payload=b"a"),
        udp_packet(src_port=2222, payload=b"b"),
    ]), tmp_path)

    assert len(out.sessions) == 2
