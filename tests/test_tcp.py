from __future__ import annotations

import pathlib

import pytest
import zpf
from helpers import (
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    SERVER_PORT,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    Seg,
    capture_of,
    tcp_packet,
    tcp_segments,
    to_zpf,
)

from zpfwire import ReassemblyOptions

CLIENT = f"{CLIENT_IP}:{CLIENT_PORT}"
SERVER = f"{SERVER_IP}:{SERVER_PORT}"

ISN = 1000


def handshake() -> list[bytes]:
    """Build the three-way handshake, so participants get an isn and a role."""
    return [
        tcp_packet(seq=ISN, flags=TCP_SYN),
        tcp_packet(src=SERVER_IP, dst=CLIENT_IP, src_port=SERVER_PORT, dst_port=CLIENT_PORT,
                   seq=5000, ack=ISN + 1, flags=TCP_SYN | TCP_ACK),
        tcp_packet(seq=ISN + 1, ack=5001, flags=TCP_ACK),
    ]


# ── the straightforward case ────────────────────────────────────────────


def test_a_simple_stream_round_trips(tmp_path: pathlib.Path):
    frames = [
        *handshake(),
        tcp_packet(seq=ISN + 1, ack=5001, flags=TCP_PSH | TCP_ACK, payload=b"GET / HTTP/1.1\r\n"),
        tcp_packet(seq=ISN + 17, ack=5001, flags=TCP_PSH | TCP_ACK, payload=b"\r\n"),
    ]
    out = to_zpf(capture_of(frames), tmp_path)

    assert out.diagnostics == []
    session = out.only
    assert session.proto == "tcp"
    assert session.key == f"{CLIENT} <-> {SERVER}"
    assert session.stream(0) == b"GET / HTTP/1.1\r\n\r\n"


def test_the_handshake_fixes_isn_and_roles(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([*handshake(),
                             tcp_packet(seq=ISN + 1, flags=TCP_PSH, payload=b"x")]), tmp_path)
    session = out.only

    client = session.participant(CLIENT)
    server = session.participant(SERVER)
    assert client.isn == ISN
    assert server.isn == 5000
    assert client.tcp_role == zpf.TcpRole.INITIATOR
    assert server.tcp_role == zpf.TcpRole.RESPONDER


def test_seq_start_is_the_absolute_wire_number(tmp_path: pathlib.Path):
    """The first application byte is isn + 1, and seq_start is absolute.

    The handshake now writes an empty SYN record at the isn itself, so the
    data record is the second one — and the pair demonstrates the point,
    since the two seq_starts differ by exactly the sequence number the SYN
    consumes.
    """
    out = to_zpf(capture_of([*handshake(),
                             tcp_packet(seq=ISN + 1, flags=TCP_PSH, payload=b"abc")]), tmp_path)

    syn, record = out.only.by(0)
    assert syn.flags & zpf.RecordFlags.SYN
    assert syn.seq_start == ISN
    assert syn.payload == b""
    assert record.seq_start == ISN + 1


def test_a_mid_stream_capture_carries_no_isn(tmp_path: pathlib.Path):
    """The spec requires isn exactly when the handshake was seen, and not otherwise."""
    out = to_zpf(tcp_segments([Seg(9000, b"already running", flags=TCP_PSH)]), tmp_path)
    session = out.only

    assert session.participant(CLIENT).isn is None
    assert session.participant(CLIENT).tcp_role in (None, zpf.TcpRole.UNKNOWN)
    assert session.stream(0) == b"already running"


def test_both_endpoints_are_declared_even_when_only_one_speaks(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([Seg(1, b"hello", flags=TCP_PSH)]), tmp_path)

    endpoints = {p.endpoint for p in out.only.participants}
    assert endpoints == {CLIENT, SERVER}


def test_both_directions_land_in_one_session(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"ping", flags=TCP_PSH),
        Seg(1, b"pong", flags=TCP_PSH, from_client=False),
    ]), tmp_path)
    session = out.only

    assert len(session.participants) == 2
    assert session.stream(0) == b"ping"
    assert session.stream(1) == b"pong"


# ── retransmits and overlap ─────────────────────────────────────────────


def test_an_exact_retransmit_is_discarded_and_counted(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"hello", flags=TCP_PSH),
        Seg(1, b"hello", flags=TCP_PSH),
        Seg(6, b"world", flags=TCP_PSH),
    ]), tmp_path)

    assert out.only.stream(0) == b"helloworld"
    assert out.stats.overlap_bytes == 5
    assert out.stats.late_bytes == 0


def test_a_partial_overlap_is_trimmed_to_the_new_bytes(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"abcde", flags=TCP_PSH),
        Seg(3, b"cdefg", flags=TCP_PSH),
    ]), tmp_path)

    assert out.only.stream(0) == b"abcdefg"
    assert out.stats.overlap_bytes == 3


def test_a_retransmit_marks_the_record(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"abcde"),
        Seg(3, b"cdefg", flags=TCP_PSH),
    ]), tmp_path)

    record = out.only.by(0)[0]
    assert record.flags & zpf.RecordFlags.RETRANSMIT


def test_every_observed_byte_is_written_or_counted(tmp_path: pathlib.Path):
    """The accounting invariant: nothing is lost without being tallied."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa"),
        Seg(1, b"aaaa"),
        Seg(5, b"bbbb"),
        Seg(3, b"aabbbbcc", flags=TCP_PSH),
    ]), tmp_path)

    observed = 4 + 4 + 4 + 8
    accounted = out.stats.payload_bytes + out.stats.overlap_bytes + out.stats.late_bytes
    assert accounted == observed
    assert out.only.stream(0) == b"aaaabbbbcc"


# ── reordering ──────────────────────────────────────────────────────────


def test_out_of_order_segments_are_put_back_in_order(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"one"),
        Seg(7, b"three", flags=TCP_PSH),
        Seg(4, b"two"),
    ]), tmp_path)

    assert out.only.stream(0) == b"onetwothree"
    assert out.stats.gaps == 0


def test_reordering_is_bounded_by_the_window(tmp_path: pathlib.Path):
    """Beyond the window the reassembler stops waiting and commits the gap."""
    out = to_zpf(
        tcp_segments([Seg(1, b"A" * 10), Seg(100, b"B" * 10, flags=TCP_PSH)]),
        tmp_path,
        options=ReassemblyOptions(reorder_window=4),
    )

    assert out.stats.gaps == 1
    assert out.only.stream(0) == b"A" * 10 + b"B" * 10


def test_a_committed_gap_shows_as_a_jump_in_seq_start(tmp_path: pathlib.Path):
    """A transport-layer hole needs no marker: absolute seq numbers reveal it."""
    out = to_zpf(
        tcp_segments([Seg(1, b"A" * 10), Seg(100, b"B" * 10, flags=TCP_PSH)]),
        tmp_path,
        options=ReassemblyOptions(reorder_window=4),
    )
    records = out.only.by(0)

    assert len(records) == 2
    first, second = records
    assert first.seq_start == 1
    assert first.seq_start + len(first.payload) == 11
    assert second.seq_start == 100


def test_bytes_arriving_after_their_gap_was_committed_are_dropped(tmp_path: pathlib.Path):
    """The spec forbids writing them, so they are counted as lost, not as overlap."""
    out = to_zpf(
        tcp_segments([
            Seg(1, b"A" * 10),
            Seg(100, b"B" * 10, flags=TCP_PSH),
            Seg(11, b"MISSING!!", flags=TCP_PSH),
        ]),
        tmp_path,
        options=ReassemblyOptions(reorder_window=4),
    )

    assert out.stats.gaps == 1
    assert out.stats.late_bytes == 9
    assert b"MISSING" not in out.only.stream(0)


def test_a_stale_gap_is_committed_on_the_flush_timeout(tmp_path: pathlib.Path):
    out = to_zpf(
        capture_of(
            [Seg(1, b"A" * 4).frame(), Seg(50, b"B" * 4, flags=TCP_PSH).frame()],
            step_us=10_000_000,
        ),
        tmp_path,
        options=ReassemblyOptions(reorder_window=1 << 20, flush_timeout=1.0),
    )

    assert out.stats.gaps == 1


def test_whatever_is_still_held_at_the_end_is_written_not_dropped(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([Seg(1, b"AAAA"), Seg(50, b"BBBB")]), tmp_path)

    assert out.only.stream(0) == b"AAAABBBB"
    assert out.stats.gaps == 1


# ── the ordering MUST ───────────────────────────────────────────────────


@pytest.mark.parametrize("window", [0, 4, 1 << 20])
def test_records_are_stored_in_ascending_seq_start(tmp_path: pathlib.Path, window: int):
    """Enforced by zpf's conformance checker, so a violation would raise.

    Asserting it here as well makes the failure legible when it happens.
    """
    out = to_zpf(
        tcp_segments([
            Seg(1, b"one"), Seg(20, b"far"), Seg(4, b"two"),
            Seg(7, b"three", flags=TCP_PSH), Seg(30, b"later", flags=TCP_PSH),
        ]),
        tmp_path,
        options=ReassemblyOptions(reorder_window=window),
    )

    seqs = [r.seq_start for r in out.only.by(0)]
    assert seqs == sorted(seqs)


# ── record shaping ──────────────────────────────────────────────────────


def test_contiguous_segments_coalesce_into_one_record(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"aa"), Seg(3, b"bb"), Seg(5, b"cc", flags=TCP_PSH),
    ]), tmp_path)

    records = out.only.by(0)
    assert len(records) == 1
    assert records[0].payload == b"aabbcc"


def test_push_ends_a_run(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"aa", flags=TCP_PSH), Seg(3, b"bb", flags=TCP_PSH),
    ]), tmp_path)

    assert [r.payload for r in out.only.by(0)] == [b"aa", b"bb"]


def test_coalescing_can_be_turned_off(tmp_path: pathlib.Path):
    out = to_zpf(
        tcp_segments([Seg(1, b"aa"), Seg(3, b"bb"), Seg(5, b"cc")]),
        tmp_path,
        options=ReassemblyOptions(coalesce=False),
    )

    assert [r.payload for r in out.only.by(0)] == [b"aa", b"bb", b"cc"]


def test_a_records_timestamp_is_its_last_contributing_packet(tmp_path: pathlib.Path):
    """The spec's rule: the moment the unit became complete, not when it started."""
    out = to_zpf(
        capture_of([Seg(1, b"aa").frame(), Seg(3, b"bb", flags=TCP_PSH).frame()],
                   start_us=1_000_000, step_us=1_000),
        tmp_path,
    )

    record = out.only.by(0)[0]
    assert record.payload == b"aabb"
    assert record.timestamp == 1_001_000


def test_pure_acks_produce_no_records(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"data", flags=TCP_PSH),
        Seg(5, b"", from_client=False),
    ]), tmp_path)

    assert len(out.only.records) == 1


def test_the_ack_hint_comes_from_the_wire(tmp_path: pathlib.Path):
    frames = [tcp_packet(seq=1, ack=7777, flags=TCP_PSH, payload=b"hi")]
    out = to_zpf(capture_of(frames), tmp_path)

    assert out.only.by(0)[0].ack == 7777


def test_transport_records_carry_no_content_type_and_no_spans(tmp_path: pathlib.Path):
    """Both are forbidden here: content_type by the layer, spans by the provenance."""
    out = to_zpf(tcp_segments([Seg(1, b"payload", flags=TCP_PSH)]), tmp_path)

    for record in out.only.records:
        assert record.content_type is None
        assert record.spans == ()


# ── how sessions end ────────────────────────────────────────────────────


def test_a_clean_close_ends_the_session_with_fin(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"bye", flags=TCP_PSH),
        Seg(4, b"", flags=TCP_FIN | TCP_ACK),
        Seg(1, b"", flags=TCP_FIN | TCP_ACK, from_client=False),
    ]), tmp_path)

    assert out.only.end_reason == "fin"


def test_a_reset_ends_the_session_with_rst(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"hi", flags=TCP_PSH),
        Seg(3, b"", flags=TCP_RST, from_client=False),
    ]), tmp_path)

    assert out.only.end_reason == "rst"


def test_an_unfinished_flow_ends_at_capture_end(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([Seg(1, b"hi", flags=TCP_PSH)]), tmp_path)

    assert out.only.end_reason == "capture-end"


def test_a_silent_flow_times_out_into_a_new_session(tmp_path: pathlib.Path):
    out = to_zpf(
        capture_of(
            [Seg(1, b"early", flags=TCP_PSH).frame(), Seg(6, b"late", flags=TCP_PSH).frame()],
            step_us=60_000_000,
        ),
        tmp_path,
        options=ReassemblyOptions(session_timeout=10.0),
    )

    assert len(out.sessions) == 2
    assert out.sessions[0].end_reason == "timeout"
    assert out.sessions[0].stream(0) == b"early"
    assert out.sessions[1].stream(0) == b"late"


def test_a_fin_carried_with_data_flags_the_record(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([Seg(1, b"last", flags=TCP_FIN | TCP_PSH)]), tmp_path)

    assert out.only.by(0)[0].flags & zpf.RecordFlags.FIN
