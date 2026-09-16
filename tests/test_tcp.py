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

    The handshake writes an empty SYN record at the origin, so the data
    record is the second one — and both sit at the same seq_start, which is
    what the origin being isn + 1 means: the SYN consumed the isn without
    delivering a byte there.
    """
    out = to_zpf(capture_of([*handshake(),
                             tcp_packet(seq=ISN + 1, flags=TCP_PSH, payload=b"abc")]), tmp_path)

    syn, record = out.only.by(0)
    assert syn.flags & zpf.RecordFlags.SYN
    assert syn.seq_start == ISN + 1
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
    accounted = (
        out.stats.payload_bytes
        + out.stats.overlap_bytes
        + out.stats.duplicate_bytes
        + out.stats.late_bytes
        + out.stats.paws_bytes
    )
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


# ── the Timestamps option: copy or resend ───────────────────────────────
#
# A repeat is a *duplicate* — the same transmission seen twice by the capture
# point — only when both copies carry the option, their TSvals are equal, and
# nothing from the peer arrived in between.  Anything else is a
# retransmission, which is what the specification asks a producer that cannot
# tell to say.  One test per clause failing, one per site where a repeat is
# judged, and the two fallbacks counted by name.


def _flagged(out: object) -> list[bool]:
    """Whether each record of the only session carries ``retransmit``."""
    return [bool(r.flags & zpf.RecordFlags.RETRANSMIT) for r in out.only.records]  # type: ignore[attr-defined]


def _reasons(out: object) -> list[str]:
    return [u.reason for u in out.undecoded]  # type: ignore[attr-defined]


def test_a_copy_with_the_same_tsval_and_nothing_between_is_a_duplicate(
    tmp_path: pathlib.Path,
):
    """The mirror-port shape: the sender resent nothing, so no flag."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(101, 0)),
    ]), tmp_path)

    assert out.only.stream(0) == b"aaaabbbb"
    assert out.stats.duplicates == 1
    assert out.stats.duplicate_bytes == 4
    assert out.stats.overlap_bytes == 0
    assert _reasons(out) == ["duplicate-discarded"]
    assert _flagged(out) == [False]
    assert out.stats.ts_fallback == {}


def test_a_peer_packet_between_the_copies_makes_it_a_retransmission(
    tmp_path: pathlib.Path,
):
    """Same TSval, but the peer's ACK sits between: a fast retransmit inside one tick."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(1, b"", from_client=False, timestamps=(500, 100)),
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(101, 0)),
    ]), tmp_path)

    assert out.stats.duplicates == 0
    assert out.stats.overlap_bytes == 4
    assert _reasons(out) == ["overlap-discarded"]
    assert _flagged(out) == [True]
    assert out.stats.ts_fallback == {}


def test_a_later_tsval_is_a_retransmission_however_close_it_follows(
    tmp_path: pathlib.Path,
):
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(1, b"aaaa", timestamps=(140, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(141, 0)),
    ]), tmp_path)

    assert out.stats.duplicates == 0
    assert out.stats.overlap_bytes == 4
    assert _flagged(out) == [True]
    assert out.stats.ts_fallback == {}


def test_a_repeat_without_the_option_falls_back_and_says_so(tmp_path: pathlib.Path):
    """Neither side carries it: the conservative reading, counted as ``absent``."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa"),
        Seg(1, b"aaaa"),
        Seg(5, b"bbbb", flags=TCP_PSH),
    ]), tmp_path)

    assert out.stats.overlap_bytes == 4
    assert _flagged(out) == [True]
    assert out.stats.ts_fallback == {"absent": 1}


def test_a_repeat_with_the_option_on_one_side_only_is_absent_too(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa"),
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(101, 0)),
    ]), tmp_path)

    assert out.stats.overlap_bytes == 4
    assert out.stats.ts_fallback == {"absent": 1}


def test_a_repeat_of_something_forgotten_falls_back_as_stale(tmp_path: pathlib.Path):
    """The memory of accepted transmissions is bounded by ``reorder_window``.

    With a four-byte window the first segment is forgotten once the second is
    accepted, so a copy of it — same TSval, nothing between — cannot be
    judged and is treated as a retransmission, counted as ``stale``.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(5, b"bbbb", timestamps=(101, 0)),
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(102, 0)),
    ]), tmp_path, options=ReassemblyOptions(reorder_window=4))

    assert out.only.stream(0) == b"aaaabbbbcccc"
    assert out.stats.duplicates == 0
    assert out.stats.overlap_bytes == 4
    assert out.stats.ts_fallback == {"stale": 1}


def test_the_newest_transmission_is_never_forgotten(tmp_path: pathlib.Path):
    """Even at ``reorder_window=0`` the copy that follows its original is judged."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(101, 0)),
    ]), tmp_path, options=ReassemblyOptions(reorder_window=0))

    assert out.stats.duplicates == 1
    assert out.stats.ts_fallback == {}


def test_a_leading_trim_is_judged_too(tmp_path: pathlib.Path):
    """Site two: a segment that re-covers accepted bytes and adds new ones."""
    resend = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(3, b"aabb", flags=TCP_PSH, timestamps=(140, 0)),
    ]), tmp_path / "resend")
    copy = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(3, b"aabb", flags=TCP_PSH, timestamps=(100, 0)),
    ]), tmp_path / "copy")

    assert resend.only.stream(0) == copy.only.stream(0) == b"aaaabb"
    assert resend.stats.overlap_bytes == 2 and _flagged(resend) == [True]
    assert copy.stats.duplicate_bytes == 2 and _flagged(copy) == [False]


def test_a_repeat_of_a_held_segment_is_judged_against_it(tmp_path: pathlib.Path):
    """Site three: the copy arrives while its original waits behind a hole."""
    copy = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"cccc", timestamps=(102, 0)),
        Seg(9, b"cccc", timestamps=(102, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(103, 0)),
    ]), tmp_path / "copy")
    resend = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"cccc", timestamps=(102, 0)),
        Seg(1, b"", from_client=False, timestamps=(500, 100)),
        Seg(9, b"cccc", timestamps=(102, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(103, 0)),
    ]), tmp_path / "resend")

    assert copy.only.stream(0) == resend.only.stream(0) == b"aaaabbbbcccc"
    assert copy.stats.duplicates == 1 and _flagged(copy) == [False]
    assert resend.stats.overlap_bytes == 4 and _flagged(resend) == [True]


def test_a_trim_while_draining_is_judged_against_the_fill(tmp_path: pathlib.Path):
    """Site four: the fill re-covers the head of a held segment."""
    resend = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(7, b"bbcc", timestamps=(101, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(140, 0)),
    ]), tmp_path / "resend")
    copy = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(7, b"bbcc", timestamps=(101, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(101, 0)),
    ]), tmp_path / "copy")

    assert resend.only.stream(0) == copy.only.stream(0) == b"aaaabbbbcc"
    assert resend.stats.overlap_bytes == 2 and _flagged(resend) == [True]
    assert copy.stats.duplicate_bytes == 2 and _flagged(copy) == [False]


# ── the Timestamps option: why a byte was late ──────────────────────────
#
# A byte that arrives inside a committed gap is compared against the clock of
# the first segment that overtook it.  Older: the original, delayed by the
# network — a wider window would have kept it.  Newer: a resend of bytes that
# were lost — nothing of ours could have.  Same tick, or no option: late, and
# no more is said.


def _late(seq_tsval: int | None, passer_tsval: int | None, tmp_path: pathlib.Path) -> object:
    """Commit a gap with ``reorder_window=0`` and land a byte in it afterwards."""
    return to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)),
        Seg(9, b"cccc", flags=TCP_PSH,
            timestamps=None if passer_tsval is None else (passer_tsval, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH,
            timestamps=None if seq_tsval is None else (seq_tsval, 0)),
    ]), tmp_path, options=ReassemblyOptions(reorder_window=0))


def test_a_late_byte_older_than_what_passed_it_was_reordered(tmp_path: pathlib.Path):
    out = _late(seq_tsval=101, passer_tsval=105, tmp_path=tmp_path)

    assert out.stats.late_bytes == 4
    assert out.stats.late_reordered_bytes == 4
    assert out.stats.late_retransmitted_bytes == 0
    assert _reasons(out) == ["late-reordered"]


def test_a_late_byte_newer_than_what_passed_it_was_resent(tmp_path: pathlib.Path):
    out = _late(seq_tsval=150, passer_tsval=105, tmp_path=tmp_path)

    assert out.stats.late_bytes == 4
    assert out.stats.late_reordered_bytes == 0
    assert out.stats.late_retransmitted_bytes == 4
    assert _reasons(out) == ["late-retransmitted"]


def test_a_late_byte_in_the_same_tick_as_what_passed_it_is_just_late(
    tmp_path: pathlib.Path,
):
    out = _late(seq_tsval=105, passer_tsval=105, tmp_path=tmp_path)

    assert out.stats.late_bytes == 4
    assert out.stats.late_reordered_bytes == 0
    assert out.stats.late_retransmitted_bytes == 0
    assert _reasons(out) == ["late-arrival"]


@pytest.mark.parametrize(("seq_tsval", "passer_tsval"), [(None, None), (101, None), (None, 105)])
def test_a_late_byte_without_the_option_is_just_late(
    tmp_path: pathlib.Path, seq_tsval: int | None, passer_tsval: int | None,
):
    out = _late(seq_tsval=seq_tsval, passer_tsval=passer_tsval, tmp_path=tmp_path)

    assert out.stats.late_bytes == 4
    assert out.stats.late_reordered_bytes == out.stats.late_retransmitted_bytes == 0
    assert _reasons(out) == ["late-arrival"]


def test_the_reference_is_the_first_passer_not_the_latest_commit(tmp_path: pathlib.Path):
    """A resend can be slow to arrive too; it is still a resend.

    By the time the resend lands, the sender has committed segments newer than
    it — so compared against *everything* committed it would look older, and
    read as reordered.  Compared against the segment that overtook the gap,
    it was sent afterwards, which is what makes it a resend.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)),
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(105, 0)),    # overtakes 5..8
        Seg(13, b"dddd", flags=TCP_PSH, timestamps=(200, 0)),   # newer still
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(140, 0)),    # sent after 105
    ]), tmp_path, options=ReassemblyOptions(reorder_window=0))

    assert out.stats.late_retransmitted_bytes == 4
    assert _reasons(out) == ["late-retransmitted"]


# ── the Timestamps option: PAWS and the wrap ────────────────────────────


def test_a_segment_older_than_the_clock_is_rejected_whole(tmp_path: pathlib.Path):
    """PAWS: new bytes with a TSval below ``TS.Recent`` are an old segment come round."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(90, 0)),
        Seg(5, b"BBBB", flags=TCP_PSH, timestamps=(101, 0)),
    ]), tmp_path)

    assert out.only.stream(0) == b"aaaaBBBB"
    assert out.stats.paws_bytes == 4
    assert out.stats.overlap_bytes == 0
    assert _reasons(out) == ["paws-rejected"]
    assert _flagged(out) == [False, False]


def test_a_delayed_original_behind_a_hole_passes_paws(tmp_path: pathlib.Path):
    """The held segment's newer clock does not reject the original that fills the hole.

    ``TS.Recent`` moves only on in-order arrival — which is what a real
    receiver does, and what ``tcp_reorder_ts``'s D-SACKs prove.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"cccc", timestamps=(105, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(103, 0)),
    ]), tmp_path)

    assert out.only.stream(0) == b"aaaabbbbcccc"
    assert out.stats.paws_bytes == 0


def test_paws_does_not_apply_to_a_repeat(tmp_path: pathlib.Path):
    """A repeat of accepted bytes is judged as a repeat, whatever its clock."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(5, b"bbbb", timestamps=(101, 0)),
        Seg(1, b"aaaa", timestamps=(90, 0)),
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(102, 0)),
    ]), tmp_path)

    assert out.stats.paws_bytes == 0
    assert out.stats.overlap_bytes == 4
    assert _reasons(out) == ["overlap-discarded"]


PAST_THE_WRAP = 1 + 4 + (1 << 31) + 100
"""A segment this far on is more than any window behind, by serial arithmetic."""


def test_a_segment_from_past_the_wrap_opens_a_new_session(tmp_path: pathlib.Path):
    """A hole wider than 2**31: the clock says the segment is from ahead.

    One session cannot hold both sides — records are stored in serial order,
    and a record that far past its predecessor *precedes* it — so the first
    ends for ``capture-gap`` and the second carries on.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)),
        Seg(PAST_THE_WRAP, b"zzzz", flags=TCP_PSH, timestamps=(900, 0)),
        Seg(PAST_THE_WRAP + 4, b"yyyy", flags=TCP_PSH, timestamps=(901, 0)),
    ]), tmp_path)

    assert [s.end_reason for s in out.sessions] == ["capture-gap", "capture-end"]
    assert out.sessions[0].stream(0) == b"aaaa"
    assert out.sessions[1].stream(0) == b"zzzzyyyy"
    assert out.stats.wrap_resolved == 1
    assert out.stats.sessions == 2
    assert out.stats.overlap_bytes == 0


@pytest.mark.parametrize("timestamps", [None, (90, 0)], ids=["no-option", "older-clock"])
def test_without_a_newer_clock_the_far_side_of_a_hole_is_old_data(
    tmp_path: pathlib.Path, timestamps: tuple[int, int] | None,
):
    """As before this release: serial arithmetic calls it behind, and it is dropped."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH, timestamps=None if timestamps is None else (100, 0)),
        Seg(PAST_THE_WRAP, b"zzzz", flags=TCP_PSH, timestamps=timestamps),
    ]), tmp_path)

    assert len(out.sessions) == 1
    assert out.only.stream(0) == b"aaaa"
    assert out.stats.wrap_resolved == 0
    assert out.stats.overlap_bytes == 4


def test_a_resend_a_window_behind_is_not_mistaken_for_the_far_side(tmp_path: pathlib.Path):
    """Behind by less than the largest window TCP allows is a repeat, clock or no clock."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)),
        Seg(1, b"aaaa", flags=TCP_PSH, timestamps=(140, 0)),
    ]), tmp_path)

    assert len(out.sessions) == 1
    assert out.stats.wrap_resolved == 0
    assert out.stats.overlap_bytes == 4


# ── SHIM (zipline#146): a direction longer than 2 GiB ──────────────────
#
# The format places a transport record by its seq_start against the stream
# origin with serial arithmetic, which reaches 2**31 and no further: the
# writer refuses a record past that, and a reader zero-widths one.  Until the
# format unwraps offsets along stored order, a direction is continued in a
# new session every 2 GiB.  Delete this section with the shim.

GIB = 1 << 30


def _long_stream(samples: int) -> list[bytes]:
    """Build the handshake, then one 4-byte segment per GiB of one direction."""
    return handshake() + [
        Seg((ISN + 1 + k * GIB) % (1 << 32), b"kkkk", flags=TCP_PSH,
            timestamps=(100 + k, 0)).frame(ack=5001)
        for k in range(samples)
    ]


def test_a_direction_past_2_gib_continues_in_a_new_session(tmp_path: pathlib.Path):
    out = to_zpf(capture_of(_long_stream(4)), tmp_path,
                 options=ReassemblyOptions(reorder_window=0))

    assert [s.end_reason for s in out.sessions] == ["offset-limit", "capture-end"]
    assert [r.seq_start for r in out.sessions[0].records if r.payload] == [
        ISN + 1, ISN + 1 + GIB,
    ]
    assert [r.seq_start for r in out.sessions[1].records if r.payload] == [
        ISN + 1 + 2 * GIB, ISN + 1 + 3 * GIB,
    ]
    assert out.stats.offset_splits == 1
    assert out.diagnostics == [] and out.unplaceable == []


def test_every_record_of_a_split_stream_is_placed(tmp_path: pathlib.Path):
    """The point of the shim: no data record has a zero-width range, in any session."""
    out = to_zpf(capture_of(_long_stream(5)), tmp_path,
                 options=ReassemblyOptions(reorder_window=0))

    with zpf.open(out.path) as reader:
        for session in reader.sessions():
            for participant in session.participants:
                pid = participant.participant_id
                for record, (start, end) in zip(session.stream(pid), session.ranges(pid),
                                                strict=True):
                    assert end - start == len(record.payload)
    assert out.stats.offset_splits == 2
    assert out.stats.sessions == 3


def test_a_record_straddling_the_limit_stays_where_it_starts(tmp_path: pathlib.Path):
    """Only the start is placed; a record beginning just under 2**31 is fine."""
    out = to_zpf(capture_of(handshake() + [
        Seg(ISN + 1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)).frame(ack=5001),
        Seg(ISN + 1 + (1 << 31) - 2, b"bbbb", flags=TCP_PSH, timestamps=(101, 0)).frame(ack=5001),
    ]), tmp_path, options=ReassemblyOptions(reorder_window=0))

    assert len(out.sessions) == 1
    assert out.stats.offset_splits == 0
    assert out.diagnostics == [] and out.unplaceable == []


def test_a_split_stream_sequences_cleanly(tmp_path: pathlib.Path):
    out = to_zpf(capture_of(_long_stream(4)), tmp_path,
                 options=ReassemblyOptions(reorder_window=0), sequenced=True)

    assert out.diagnostics == [] and out.unplaceable == []
    for session in out.sessions:
        zpf.verify_sequenced(session.records, participant_count=len(session.participants))
