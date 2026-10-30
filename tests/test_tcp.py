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
    Converted,
    Seg,
    capture_of,
    is_pure_ack,
    tcp_packet,
    tcp_segments,
    to_zpf,
)

from zpfwire import TS_ABSENT, ReassemblyOptions

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

    The handshake writes an empty SYN record at the origin, then the
    handshake's own pure ACK, then the data — and all three sit at the same
    seq_start, which is what the origin being isn + 1 means: the SYN
    consumed the isn without delivering a byte there, and the ACK carries
    the next number, the first byte's.
    """
    out = to_zpf(capture_of([*handshake(),
                             tcp_packet(seq=ISN + 1, flags=TCP_PSH, payload=b"abc")]), tmp_path)

    syn, ack, record = out.only.by(0)
    assert syn.flags & zpf.RecordFlags.SYN
    assert syn.seq_start == ISN + 1
    assert syn.payload == b""
    assert is_pure_ack(ack)
    assert ack.seq_start == ISN + 1
    assert ack.ack == 5001
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


def test_a_gap_a_full_wrap_back_does_not_claim_a_resend_with_its_numbers(
    tmp_path: pathlib.Path,
):
    """A committed gap is behind for good, even once its sequence numbers come round again (#45).

    A gap is kept as wire sequence numbers, and those repeat every 2**32
    bytes.  A direction that moves 4 GiB on from a loss is carrying the
    gap's own numbers again, so a resend there must not be read as a late
    arrival into the old gap: it is a resend of bytes this direction
    accepted.  The 4 GiB are crossed by committing a gap at each jump, so
    the capture holds a few kilobytes.
    """
    chunk = b"R" * 1_000
    segments = [Seg(0, chunk), Seg(2_000, chunk)]  # [1000, 2000) is lost and committed
    segments += [Seg(gigabytes * 10**9, chunk) for gigabytes in (1, 2, 3, 4)]
    segments.append(Seg(1_000, chunk))  # 2**32 + 1000: the lost range's numbers, accepted
    segments.append(Seg(1_000, chunk, flags=TCP_PSH))  # and its resend
    out = to_zpf(tcp_segments(segments), tmp_path, options=ReassemblyOptions(reorder_window=500))

    assert out.stats.gaps == 6
    assert out.stats.late_bytes == 0
    assert out.stats.overlap_bytes == 1_000


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


def test_a_pure_ack_is_a_zero_length_record_carrying_its_ack(tmp_path: pathlib.Path):
    """Spec 0.23 advises storing them, and since 0.6.0 that is the default (#37)."""
    out = to_zpf(tcp_segments([
        Seg(1, b"data", flags=TCP_PSH),
        Seg(700, b"", from_client=False, ack=5),
    ]), tmp_path)

    (ack,) = out.only.by(1)
    assert ack.payload == b""
    assert ack.flags == zpf.RecordFlags(0)
    assert ack.seq_start == 700
    assert ack.ack == 5
    assert out.stats.pure_acks == 1


def test_pure_acks_produce_no_records_when_opted_out(tmp_path: pathlib.Path):
    """Every release before 0.6.0, and ``pure_acks=False`` since."""
    out = to_zpf(tcp_segments([
        Seg(1, b"data", flags=TCP_PSH),
        Seg(5, b"", from_client=False),
    ]), tmp_path, options=ReassemblyOptions(pure_acks=False))

    assert len(out.only.records) == 1
    assert out.stats.pure_acks == 0


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
    """Whether each record of the only session carries ``retransmit``, pure ACKs aside.

    A pure ACK's record carries no bytes, so no resend can flag it; the
    question these tests ask is about the records that do.
    """
    return [
        bool(r.flags & zpf.RecordFlags.RETRANSMIT)
        for r in out.only.records  # type: ignore[attr-defined]
        if not is_pure_ack(r)
    ]


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
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(102, 0)),
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(102, 0)),
        Seg(5, b"bbbb", timestamps=(103, 0)),
    ]), tmp_path / "copy")
    resend = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(102, 0)),
        Seg(1, b"", from_client=False, timestamps=(500, 100)),
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(102, 0)),
        Seg(5, b"bbbb", timestamps=(103, 0)),
    ]), tmp_path / "resend")

    assert copy.only.stream(0) == resend.only.stream(0) == b"aaaabbbbcccc"
    assert copy.stats.duplicates == 1 and _flagged(copy) == [False]
    assert resend.stats.overlap_bytes == 4 and _flagged(resend) == [True]


def test_a_trim_while_draining_is_judged_against_the_fill(tmp_path: pathlib.Path):
    """Site four: the fill re-covers the head of a held segment."""
    resend = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(7, b"bbcc", flags=TCP_PSH, timestamps=(101, 0)),
        Seg(5, b"bbbb", timestamps=(140, 0)),
    ]), tmp_path / "resend")
    copy = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(7, b"bbcc", flags=TCP_PSH, timestamps=(101, 0)),
        Seg(5, b"bbbb", timestamps=(101, 0)),
    ]), tmp_path / "copy")

    assert resend.only.stream(0) == copy.only.stream(0) == b"aaaabbbbcc"
    assert resend.stats.overlap_bytes == 2 and _flagged(resend) == [True]
    assert copy.stats.duplicate_bytes == 2 and _flagged(copy) == [False]


def test_a_held_segment_wholly_superseded_by_the_fill_is_judged_and_flagged(
    tmp_path: pathlib.Path,
):
    """Site five (#31): the fill covers the whole of a segment held behind the hole.

    The sender resent the missing bytes and the held segment's with them, so
    it sent the held segment's bytes twice, and the record covering them is
    flagged as at the other four sites.  A copy with the same clock and
    nothing from the peer between is a duplicate instead, and flags nothing.
    """
    resend = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"cccc", timestamps=(101, 0)),
        Seg(5, b"bbbbcccc", flags=TCP_PSH, timestamps=(140, 0)),
    ]), tmp_path / "resend")
    no_option = to_zpf(tcp_segments([
        Seg(1, b"aaaa"),
        Seg(9, b"cccc"),
        Seg(5, b"bbbbcccc", flags=TCP_PSH),
    ]), tmp_path / "no-option")
    copy = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"cccc", timestamps=(101, 0)),
        Seg(5, b"bbbbcccc", flags=TCP_PSH, timestamps=(101, 0)),
    ]), tmp_path / "copy")

    for out in (resend, no_option, copy):
        assert out.only.stream(0) == b"aaaabbbbcccc"
        assert out.diagnostics == [] and out.unplaceable == []
    assert resend.stats.overlap_bytes == 4 and _flagged(resend) == [True]
    assert _reasons(resend) == ["overlap-discarded"]
    assert no_option.stats.overlap_bytes == 4 and _flagged(no_option) == [True]
    assert no_option.stats.ts_fallback == {TS_ABSENT: 1}
    assert copy.stats.duplicate_bytes == 4 and _flagged(copy) == [False]
    assert _reasons(copy) == ["duplicate-discarded"]


def test_a_held_segment_superseded_by_another_held_one_is_flagged(tmp_path: pathlib.Path):
    """Site five, reached inside one drain: the "fill" is a held segment drained first.

    Two segments wait behind the hole and the second lies wholly inside the
    first.  The hole's fill drains the first, which then covers the second
    before the loop reaches it.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"ccccdddd", flags=TCP_PSH, timestamps=(140, 0)),
        Seg(13, b"dddd", flags=TCP_PSH, timestamps=(101, 0)),
        Seg(5, b"bbbb", timestamps=(141, 0)),
    ]), tmp_path)

    assert out.only.stream(0) == b"aaaabbbbccccdddd"
    assert out.stats.overlap_bytes == 4 and _flagged(out) == [True]
    assert _reasons(out) == ["overlap-discarded"]
    assert out.diagnostics == [] and out.unplaceable == []


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


def test_the_session_after_a_capture_gap_is_on_the_same_key_with_no_isn(
    tmp_path: pathlib.Path,
):
    """The specification's exit for the unmeasurable hole, in full (spec 0.21).

    "Ends the session at the hole and opens another on the same key, with no
    ``isn``, so the stream resumes at its first captured byte."  The reason
    is asserted above; this is the rest of the sentence.  A handshake makes
    it bite: the first session's client carries the ``isn`` it saw, and the
    follow-on must *not* carry it forward — an ``isn`` there would put the
    resumed stream's first record 2**31 bytes below its origin.  The checked
    writer refuses that on its own (tried: it does), so what this test adds
    is the sentence's positive half, that the follow-on is the same
    conversation with its origin at the first captured byte.
    """
    out = to_zpf(capture_of(handshake() + [
        Seg(ISN + 1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)).frame(ack=5001),
        Seg(ISN + 1 + PAST_THE_WRAP, b"zzzz", flags=TCP_PSH,
            timestamps=(900, 0)).frame(ack=5001),
    ]), tmp_path)

    before, after = out.sessions
    assert (before.end_reason, after.end_reason) == ("capture-gap", "capture-end")
    assert before.key == after.key
    assert {p.endpoint for p in before.participants} == {p.endpoint for p in after.participants}
    assert before.participant(CLIENT).isn == ISN
    assert after.participant(CLIENT).isn is None
    assert after.participant(SERVER).isn is None
    assert out.diagnostics == [] and out.unplaceable == []
    with zpf.open(out.path) as reader:
        _, resumed = reader.sessions()
        client = next(p for p in resumed.participants if p.endpoint == CLIENT)
        assert resumed.ranges(client.participant_id) == ((0, 4),)


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


# ── A direction longer than 2 GiB (spec 0.21, zipline#146) ─────────────
#
# Since spec 0.21 a transport record's offset is its predecessor's plus the
# signed serial delta of their seq_starts, so a stream is placed at any
# length and through 2**32.  Through 0.20 every record was measured against
# the origin, which stopped at 2**31, and 0.3.0 split a direction into a new
# session every 2 GiB to get past it; these tests pinned that shim, and now
# pin the rule it waited for.  The only shape one session cannot hold is a
# hole of 2**31 or more between consecutive records — that is capture-gap,
# tested above.

GIB = 1 << 30


def _long_stream(samples: int) -> list[bytes]:
    """Build the handshake, then one 4-byte segment per GiB of one direction."""
    return handshake() + [
        Seg((ISN + 1 + k * GIB) % (1 << 32), b"kkkk", flags=TCP_PSH,
            timestamps=(100 + k, 0)).frame(ack=5001)
        for k in range(samples)
    ]


def _client_extent(out: Converted) -> int:
    """Return the client's stream extent as ``zpf`` computes it from the file."""
    with zpf.open(out.path) as reader:
        (session,) = reader.sessions()
        client = next(p for p in session.participants if p.endpoint.endswith(":51000"))
        pid = client.participant_id
        return zpf.stream_extent(client, list(session.stream_blocks(pid)), session.layer(pid))


@pytest.mark.parametrize("samples", [4, 5], ids=["to-3GiB", "past-2^32"])
def test_a_direction_past_2_gib_is_one_session(tmp_path: pathlib.Path, samples: int):
    """Four records a GiB apart are one stream; five put the last past 2**32."""
    out = to_zpf(capture_of(_long_stream(samples)), tmp_path,
                 options=ReassemblyOptions(reorder_window=0))

    assert [s.end_reason for s in out.sessions] == ["capture-end"]
    assert [r.seq_start for r in out.only.records if r.payload] == [
        (ISN + 1 + k * GIB) % (1 << 32) for k in range(samples)
    ]
    assert out.diagnostics == [] and out.unplaceable == []


def test_every_record_of_a_long_stream_is_placed(tmp_path: pathlib.Path):
    """No data record has a zero-width range, and the extent is the last byte."""
    out = to_zpf(capture_of(_long_stream(5)), tmp_path,
                 options=ReassemblyOptions(reorder_window=0))

    with zpf.open(out.path) as reader:
        for session in reader.sessions():
            for participant in session.participants:
                pid = participant.participant_id
                for record, (start, end) in zip(session.stream(pid), session.ranges(pid),
                                                strict=True):
                    assert end - start == len(record.payload)
    assert _client_extent(out) == 4 * GIB + 4
    assert out.stats.sessions == 1


def test_a_record_far_from_the_origin_but_near_its_predecessor_is_placed(
    tmp_path: pathlib.Path,
):
    """The case 0.20 got wrong: 2**31 - 2 past the origin, under 2**31 past the last."""
    out = to_zpf(capture_of(handshake() + [
        Seg(ISN + 1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)).frame(ack=5001),
        Seg(ISN + 1 + (1 << 31) - 2, b"bbbb", flags=TCP_PSH, timestamps=(101, 0)).frame(ack=5001),
    ]), tmp_path, options=ReassemblyOptions(reorder_window=0))

    assert len(out.sessions) == 1
    assert _client_extent(out) == (1 << 31) + 2
    assert out.diagnostics == [] and out.unplaceable == []


def _upload(samples: int, *, peer: str) -> list[bytes]:
    """Build a client upload sampled per GiB, with the server answering as *peer* says.

    ``"pure-ack"`` is the ordinary upload: the server acknowledges each
    segment and sends nothing, so after its SYN-ACK it writes no record.
    ``"data"`` has it send four bytes back per sample, each record carrying
    a current ``ack``.
    """
    frames = handshake()
    for k in range(samples):
        seq = (ISN + 1 + k * GIB) % (1 << 32)
        frames.append(Seg(seq, b"kkkk", flags=TCP_PSH, timestamps=(100 + k, 0)).frame(ack=5001))
        ack = (seq + 4) % (1 << 32)
        if peer == "pure-ack":
            frames.append(tcp_packet(
                src=SERVER_IP, dst=CLIENT_IP, src_port=SERVER_PORT, dst_port=CLIENT_PORT,
                seq=5001, ack=ack, flags=TCP_ACK, timestamps=(100 + k, 100 + k),
            ))
        else:
            frames.append(Seg(5001 + 4 * k, b"okok", flags=TCP_PSH, from_client=False,
                              timestamps=(100 + k, 100 + k)).frame(ack=ack))
    return frames


def test_a_long_stream_sequences_cleanly(tmp_path: pathlib.Path):
    """With a peer whose records carry current acks, the causal order holds past 2 GiB."""
    out = to_zpf(capture_of(_upload(4, peer="data")), tmp_path,
                 options=ReassemblyOptions(reorder_window=0), sequenced=True)

    assert len(out.sessions) == 1
    assert out.diagnostics == [] and out.unplaceable == []
    for session in out.sessions:
        zpf.verify_sequenced(session.records, participant_count=len(session.participants))


def test_a_sequenced_upload_past_2_gib_with_a_pure_ack_peer(tmp_path: pathlib.Path):
    """The ordinary upload: the server only acks, so its ack is never *recorded* again.

    Its last record is the SYN-ACK, whose ``ack`` stays ``isn + 1`` for the
    whole session.  Through spec ``0.21`` the causal edge rule compared that
    ack with client record ends by serial arithmetic, so every record 2 GiB
    past it read as *below* it, and ``0.4.0`` refused the conversion with a
    ``SemanticError`` (zipline#151).  Since ``0.22`` an ack is a position,
    unwrapped along the acker's records, and the order the shape always had
    is written — and verified on the read-back, with each participant's
    ``isn`` anchoring its offsets.
    """
    out = to_zpf(capture_of(_upload(4, peer="pure-ack")), tmp_path,
                 options=ReassemblyOptions(reorder_window=0), sequenced=True)

    assert len(out.sessions) == 1
    assert out.only.sequenced
    assert out.diagnostics == [] and out.unplaceable == []
    with zpf.open(out.path) as reader:
        for session in reader.sessions():
            session.verify()


# ── overlap="favor-acked": the copy the receiver kept ───────────────────
#
# Two copies of a range disagree — a segment corrupted in flight, then resent
# clean.  favor-old keeps the first seen.  favor-acked keeps the one whose
# TSval the peer's first covering ack echoed as TSecr: the receiver's own
# word on which copy advanced its window.  The evidence arrives after both
# copies, so a run is held after it closes until the peer acks it.

ACKED = ReassemblyOptions(overlap="favor-acked")


def _ack(ack: int, tsecr: int | None, tsval: int = 500) -> Seg:
    """Build a bare acknowledgement from the server, echoing *tsecr*."""
    return Seg(1, b"", from_client=False, ack=ack,
               timestamps=None if tsecr is None else (tsval, tsecr))


def _corrupt_then_resent(*, echo: int | None, ack: bool = True) -> list[Seg]:
    """Build a corrupted original, its clean resend, more data, and the server's ack."""
    segs = [
        Seg(1, b"XXXX", timestamps=(100, 0)),                  # corrupted in flight
        Seg(1, b"aaaa", timestamps=(140, 0)),                  # resent clean
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(141, 0)),   # closes the run
    ]
    if ack:
        segs.append(_ack(9, echo))
    return segs


def test_favor_acked_keeps_the_copy_the_receiver_echoed(tmp_path: pathlib.Path):
    old = to_zpf(tcp_segments(_corrupt_then_resent(echo=140)), tmp_path / "old")
    acked = to_zpf(tcp_segments(_corrupt_then_resent(echo=140)), tmp_path / "acked",
                   options=ACKED)

    assert old.only.stream(0) == b"XXXXbbbb"
    assert acked.only.stream(0) == b"aaaabbbb"
    assert acked.stats.acked_swaps == 1
    assert acked.stats.acked_fallback_bytes == 0
    assert acked.stats.overlap_bytes == 4          # the loser, whichever it was
    assert _reasons(acked) == ["overlap-discarded"]
    assert _flagged(acked) == [True, False]        # the resend is its own record (#55)
    assert acked.diagnostics == [] and acked.unplaceable == []


def test_favor_acked_keeps_the_first_copy_when_the_receiver_echoed_it(
    tmp_path: pathlib.Path,
):
    acked = to_zpf(tcp_segments(_corrupt_then_resent(echo=100)), tmp_path, options=ACKED)

    assert acked.only.stream(0) == b"XXXXbbbb"
    assert acked.stats.acked_swaps == 0
    assert acked.stats.acked_fallback_bytes == 0


def test_the_loser_is_cited_wherever_it_lies(tmp_path: pathlib.Path):
    """The Undecoded block names the copy that lost, not the one that arrived second."""
    buf = tcp_segments(_corrupt_then_resent(echo=140))
    capture = buf.getvalue()
    acked = to_zpf(buf, tmp_path, options=ACKED)

    (loser,) = acked.undecoded
    assert capture[loser.off_start:loser.off_end] == b"XXXX"


def test_a_swapped_copy_is_a_record_stamped_with_the_resend(tmp_path: pathlib.Path):
    """A record's time is its last contributing packet, and a swapped-in copy is its own (#55).

    The resend went out after the original's neighbours.  In one record with
    them its time would date them all; apart, each record's stamps are its
    own: the resend's, and then ``bbbb``'s.
    """
    old = to_zpf(tcp_segments(_corrupt_then_resent(echo=140)), tmp_path / "old")
    acked = to_zpf(tcp_segments(_corrupt_then_resent(echo=140)), tmp_path / "acked",
                   options=ACKED)

    (record,) = [r for r in old.only.by(0) if r.payload]
    assert (record.payload, record.timestamp, record.ts_first) == (b"XXXXbbbb", 1_002_000,
                                                                     1_000_000)
    swapped, after = [r for r in acked.only.by(0) if r.payload]
    assert (swapped.payload, swapped.timestamp, swapped.ts_first) == (b"aaaa", 1_001_000, None)
    assert (after.payload, after.timestamp, after.ts_first) == (b"bbbb", 1_002_000, None)
    assert after.flags & zpf.RecordFlags.PSH and not swapped.flags & zpf.RecordFlags.PSH


@pytest.mark.parametrize("echo", [None], ids=["ack-without-option"])
def test_an_ack_without_the_option_is_no_evidence(tmp_path: pathlib.Path, echo: int | None):
    acked = to_zpf(tcp_segments(_corrupt_then_resent(echo=echo)), tmp_path, options=ACKED)

    assert acked.only.stream(0) == b"XXXXbbbb"
    assert acked.stats.acked_fallback_bytes == 4


def test_a_one_way_capture_falls_back_at_the_end(tmp_path: pathlib.Path):
    acked = to_zpf(tcp_segments(_corrupt_then_resent(echo=140, ack=False)), tmp_path,
                   options=ACKED)

    assert acked.only.stream(0) == b"XXXXbbbb"
    assert acked.stats.acked_fallback_bytes == 4
    assert acked.stats.records == 1


def test_a_run_held_past_flush_timeout_falls_back(tmp_path: pathlib.Path):
    """The evidence came, but too late: something else arrived first, past the bound."""
    segs = _corrupt_then_resent(echo=140, ack=False) + [
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(150, 0)),   # 2 s later; the bound expires
        _ack(13, 140),                                         # covers everything, now
    ]
    acked = to_zpf(tcp_segments(segs, step_us=2_000_000), tmp_path,
                   options=ReassemblyOptions(overlap="favor-acked", flush_timeout=1.0))

    assert acked.only.stream(0) == b"XXXXbbbbcccc"
    assert acked.stats.acked_fallback_bytes == 4
    assert acked.stats.acked_swaps == 0


def test_the_hold_is_bounded_by_reorder_window(tmp_path: pathlib.Path):
    """Closed runs held beyond the window are written oldest first, on the fallback."""
    segs = _corrupt_then_resent(echo=140, ack=False) + [
        Seg(9, b"cccc", flags=TCP_PSH, timestamps=(142, 0)),   # a second closed run: 12 > 8
        _ack(13, 140),
    ]
    acked = to_zpf(tcp_segments(segs), tmp_path,
                   options=ReassemblyOptions(overlap="favor-acked", reorder_window=8))

    assert acked.only.stream(0) == b"XXXXbbbbcccc"
    assert acked.stats.acked_fallback_bytes == 4


def test_the_evidence_is_the_first_ack_covering_the_range_not_the_run(
    tmp_path: pathlib.Path,
):
    """The receiver echoes what last advanced its window, so a later ack names later data."""
    segs = [
        Seg(1, b"XXXX", timestamps=(100, 0)),
        Seg(1, b"aaaa", timestamps=(140, 0)),
        _ack(5, 140),                                          # covers the range: echoes the resend
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(160, 0)),
        _ack(9, 160),                                          # covers the run: echoes bbbb
    ]
    acked = to_zpf(tcp_segments(segs), tmp_path, options=ACKED)

    assert acked.only.stream(0) == b"aaaabbbb"
    assert acked.stats.acked_swaps == 1


def test_a_disagreeing_copy_of_a_held_segment_is_contested_too(tmp_path: pathlib.Path):
    """Site three: both copies wait behind the hole, and the run takes the echoed one."""
    segs = [
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"XXXX", timestamps=(102, 0)),                  # held, corrupted
        Seg(9, b"cccc", timestamps=(140, 0)),                  # its clean resend, held too
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(141, 0)),   # fills; the run closes
        _ack(13, 140),
    ]
    acked = to_zpf(tcp_segments(segs), tmp_path, options=ACKED)

    assert acked.only.stream(0) == b"aaaabbbbcccc"
    assert acked.stats.acked_swaps == 1


def test_a_held_segments_trimmed_head_is_contested_against_the_fill(tmp_path: pathlib.Path):
    """Site four: the fill re-covers the head of a held segment with different bytes."""
    def convert(echo: int) -> bytes:
        segs = [
            Seg(1, b"aaaa", timestamps=(100, 0)),
            Seg(7, b"XXcc", timestamps=(101, 0)),              # held; its head disagrees with..
            Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(140, 0)),  # ..the fill's tail
            _ack(11, echo),
        ]
        return to_zpf(tcp_segments(segs), tmp_path / str(echo), options=ACKED).only.stream(0)

    assert convert(140) == b"aaaabbbbcc"   # the receiver kept the fill
    assert convert(101) == b"aaaabbXXcc"   # the receiver kept the held segment


def test_agreeing_copies_are_not_held_against_the_run(tmp_path: pathlib.Path):
    """Where the copies agree the choice is moot; it is discarded at once, as favor-old does."""
    segs = [
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(1, b"aaaa", timestamps=(140, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH, timestamps=(141, 0)),
        _ack(9, 140),
    ]
    acked = to_zpf(tcp_segments(segs), tmp_path, options=ACKED)

    assert acked.stats.overlap_bytes == 4
    assert acked.stats.acked_swaps == 0
    assert acked.stats.acked_fallback_bytes == 0


def test_favor_acked_sequences_cleanly(tmp_path: pathlib.Path):
    acked = to_zpf(tcp_segments(_corrupt_then_resent(echo=140)), tmp_path,
                   options=ACKED, sequenced=True)

    assert acked.only.stream(0) == b"aaaabbbb"
    assert acked.diagnostics == [] and acked.unplaceable == []
    zpf.verify_sequenced(acked.only.records, participant_count=len(acked.only.participants))


def test_favor_acked_is_recorded_in_the_policy_digest():
    assert ACKED.params_digest() != ReassemblyOptions().params_digest()


# ── 0.7.0: where runs end, what flags say, and the favor-acked hold ─────
#
# Each found by the fidelity tool (#52) and pinned here on the smallest
# shape that shows it.


def _payloads(out: Converted, pid: int = 0) -> list[bytes]:
    return [r.payload for r in out.only.by(pid) if r.payload]


def test_without_coalescing_a_drained_backlog_is_a_record_per_segment(tmp_path: pathlib.Path):
    """``coalesce=False`` holds after a hole fills, not only for in-order arrivals (#53)."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa"),
        Seg(9, b"cccc"),       # held
        Seg(13, b"dddd"),      # held
        Seg(5, b"bbbb"),       # fills
    ]), tmp_path, options=ReassemblyOptions(coalesce=False))

    assert _payloads(out) == [b"aaaa", b"bbbb", b"cccc", b"dddd"]


def test_a_held_push_ends_its_own_run_not_the_one_open_when_it_arrived(
    tmp_path: pathlib.Path,
):
    """PSH ends a run where the pushed segment's bytes join it, in sequence order (#53).

    ``cc`` arrives first, held, and its PSH used to end ``aa``'s run then:
    a boundary the sender never put there.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aa"),
        Seg(5, b"cc", flags=TCP_PSH | TCP_ACK),   # held
        Seg(3, b"bb"),                            # fills
        Seg(7, b"dd", flags=TCP_PSH | TCP_ACK),
    ]), tmp_path)

    assert _payloads(out) == [b"aabbcc", b"dd"]


def test_a_fin_beyond_a_hole_ends_the_record_that_ends_where_it_sits(tmp_path: pathlib.Path):
    """It used to mark whichever run was open when it arrived."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa"),
        Seg(9, b"cccc"),                             # held
        Seg(13, b"", flags=TCP_FIN | TCP_ACK),       # bytes 5-8 still missing
        Seg(5, b"bbbb"),                             # fills
    ]), tmp_path)

    data = [r for r in out.only.by(0) if r.payload]
    assert [r.payload for r in data] == [b"aaaa", b"bbbbcccc"]
    assert [bool(r.flags & zpf.RecordFlags.FIN) for r in data] == [False, True]


def test_peer_data_answering_an_open_run_closes_it(tmp_path: pathlib.Path):
    """Two unpushed requests and the reply between them are three records (#55).

    Joined, the requests' record would hold bytes sent before the reply and
    bytes sent after it, and no position for it would be valid.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"req1", ack=100),
        Seg(100, b"reply", from_client=False, ack=5),    # acknowledges req1
        Seg(5, b"req2", ack=105),
    ]), tmp_path)

    assert _payloads(out, 0) == [b"req1", b"req2"]
    assert [(r.payload, r.ack) for r in out.only.by(0) if r.payload] == [
        (b"req1", 100), (b"req2", 105),
    ]


def test_a_pure_ack_answering_an_open_run_does_not_close_it(tmp_path: pathlib.Path):
    """A one-way transfer still coalesces: a pure ACK orders against no byte."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", ack=100),
        Seg(100, b"", from_client=False, ack=5),
        Seg(5, b"bbbb", ack=100),
    ]), tmp_path)

    assert _payloads(out, 0) == [b"aaaabbbb"]


def test_a_resend_of_written_bytes_flags_no_later_record(tmp_path: pathlib.Path):
    """It used to flag whichever run was open, here one holding bytes nobody resent (#59)."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK, timestamps=(100, 0)),
        Seg(5, b"bb", timestamps=(101, 0)),
        Seg(1, b"aaaa", timestamps=(140, 0)),                 # resend of a written record
        Seg(7, b"cc", flags=TCP_PSH | TCP_ACK, timestamps=(141, 0)),
    ]), tmp_path)

    assert _payloads(out) == [b"aaaa", b"bbcc"]
    assert _flagged(out) == [False, False]
    assert _reasons(out) == ["overlap-discarded"]


def test_a_resend_of_a_held_segment_flags_the_record_it_lands_in(tmp_path: pathlib.Path):
    """Its record does not exist yet, so the held segment carries the flag to it (#59)."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK, timestamps=(100, 0)),
        Seg(9, b"cccc", flags=TCP_PSH | TCP_ACK, timestamps=(101, 0)),   # held
        Seg(1, b"", from_client=False),
        Seg(9, b"cccc", flags=TCP_PSH | TCP_ACK, timestamps=(140, 0)),   # resent while held
        Seg(5, b"bbbb", timestamps=(141, 0)),                            # fills
    ]), tmp_path)

    assert _payloads(out) == [b"aaaa", b"bbbbcccc"]
    assert _flagged(out) == [False, True]


def test_a_copy_of_a_discarded_resend_is_a_duplicate(tmp_path: pathlib.Path):
    """``DUP[RETRANS]``: judged against the resend, not the original it repeats (#56)."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK, timestamps=(100, 0)),
        Seg(1, b"", from_client=False),
        Seg(1, b"aaaa", timestamps=(140, 0)),        # the resend, discarded
        Seg(1, b"aaaa", timestamps=(140, 0)),        # the capture point's copy of it
    ]), tmp_path)

    assert _reasons(out) == ["overlap-discarded", "duplicate-discarded"]
    assert out.stats.duplicates == 1
    assert out.stats.overlap_bytes == 4


def _released_before_its_resend() -> list[Seg]:
    """Build a corrupted copy whose run a 2 ms bound releases, then its resend and the ack."""
    return [
        Seg(1, b"XXXX", timestamps=(100, 0)),                    # corrupted in flight
        Seg(5, b"bbbb", flags=TCP_PSH | TCP_ACK, timestamps=(101, 0)),
        Seg(1, b"", from_client=False, ack=1),                   # the hole: nothing acked
        Seg(1, b"", from_client=False, ack=1),
        Seg(1, b"", from_client=False, ack=1),
        Seg(1, b"aaaa", timestamps=(140, 0)),                    # resent clean, late
        _ack(9, 140),
    ]


def test_favor_acked_counts_a_run_released_before_its_resend(tmp_path: pathlib.Path):
    """The resend arrives after a bound wrote the run: favor-old's bytes, now counted (#54)."""
    out = to_zpf(tcp_segments(_released_before_its_resend()), tmp_path,
                 options=ReassemblyOptions(overlap="favor-acked", flush_timeout=0.002))

    assert out.only.stream(0) == b"XXXXbbbb"
    assert out.stats.acked_swaps == 0
    assert out.stats.acked_fallback_bytes == 4


def test_acked_hold_waits_past_flush_timeout_for_the_resend(tmp_path: pathlib.Path):
    """#32: the same capture, with a hold that outlives ``flush_timeout``."""
    out = to_zpf(tcp_segments(_released_before_its_resend()), tmp_path,
                 options=ReassemblyOptions(overlap="favor-acked", flush_timeout=0.002,
                                           acked_hold=1.0))

    assert out.only.stream(0) == b"aaaabbbb"
    assert out.stats.acked_swaps == 1
    assert out.stats.acked_fallback_bytes == 0
    assert out.diagnostics == [] and out.unplaceable == []


def test_evidence_naming_neither_copy_is_counted_as_a_fallback(tmp_path: pathlib.Path):
    """One cumulative ack over two resends echoes only the last filler's clock (#54)."""
    out = to_zpf(tcp_segments([
        Seg(1, b"XXXX", timestamps=(100, 0)),
        Seg(5, b"YYYY", flags=TCP_PSH | TCP_ACK, timestamps=(101, 0)),
        Seg(1, b"aaaa", timestamps=(140, 0)),
        Seg(5, b"bbbb", flags=TCP_PSH | TCP_ACK, timestamps=(141, 0)),
        _ack(9, 141),
    ]), tmp_path, options=ACKED)

    assert out.only.stream(0) == b"XXXXbbbb"
    assert out.stats.acked_swaps == 1
    assert out.stats.acked_fallback_bytes == 4


def _handshake(*, timestamps: bool) -> list[Seg]:
    options = {"timestamps": (10, 0)} if timestamps else {}
    reply = {"timestamps": (50, 10)} if timestamps else {}
    return [
        Seg(0, flags=TCP_SYN, **options),
        Seg(99, flags=TCP_SYN | TCP_ACK, from_client=False, ack=1, **reply),
    ]


def _stray_without_the_option(*, timestamps: bool) -> list[Seg]:
    stamp = {"timestamps": (11, 50)} if timestamps else {}
    later = {"timestamps": (12, 50)} if timestamps else {}
    return [
        Seg(1, b"aaaa", ack=100, **stamp),
        Seg(5, b"XXXX", ack=100),                      # forged: no option
        Seg(5, b"bbbb", ack=100, **later),
    ]


REQUIRE_TS = ReassemblyOptions(require_timestamps=True)


def test_require_timestamps_drops_a_segment_without_the_option(tmp_path: pathlib.Path):
    """RFC 7323 §3.2, on a connection whose SYNs both carried it (#57)."""
    segs = [*_handshake(timestamps=True), *_stray_without_the_option(timestamps=True)]
    kept = to_zpf(tcp_segments(segs), tmp_path / "kept")
    dropped = to_zpf(tcp_segments(segs), tmp_path / "dropped", options=REQUIRE_TS)

    assert kept.only.stream(0) == b"aaaaXXXX"
    assert dropped.only.stream(0) == b"aaaabbbb"
    assert dropped.stats.ts_missing == 1 and dropped.stats.ts_missing_bytes == 4
    assert _reasons(dropped) == ["timestamp-missing"]
    assert dropped.diagnostics == [] and dropped.unplaceable == []


@pytest.mark.parametrize("handshake", ["none", "without-option"])
def test_require_timestamps_needs_the_option_negotiated(tmp_path: pathlib.Path, handshake: str):
    """A capture that missed the handshake, or one that never negotiated, drops nothing."""
    segs = _stray_without_the_option(timestamps=True)
    if handshake == "without-option":
        segs = [*_handshake(timestamps=False), *segs]
    out = to_zpf(tcp_segments(segs), tmp_path, options=REQUIRE_TS)

    assert out.only.stream(0) == b"aaaaXXXX"
    assert out.stats.ts_missing == 0


def test_the_new_options_are_left_out_of_the_digest_until_set():
    """A policy that sets neither declares what it declared before they existed (#32, #57)."""
    default = ReassemblyOptions().params_digest()

    assert ReassemblyOptions(acked_hold=None, require_timestamps=False).params_digest() == default
    assert ReassemblyOptions(acked_hold=5.0).params_digest() != default
    assert ReassemblyOptions(require_timestamps=True).params_digest() != default
    with pytest.raises(ValueError, match="acked_hold"):
        ReassemblyOptions(acked_hold=-1.0)


@pytest.mark.parametrize("options", [None, ACKED], ids=["favor-old", "favor-acked"])
def test_a_bare_fin_after_a_pushed_segment_is_a_record_of_its_own(
    tmp_path: pathlib.Path, options: ReassemblyOptions | None,
):
    """The usual close: the PSH flushed the run, and the FIN found nothing to mark (#60).

    It is written as a zero-length record at its sequence number, as a pure
    ACK is — under favor-acked straight after the run still held, so that
    both policies write the same records.
    """
    kwargs = {} if options is None else {"options": options}
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK),
        Seg(5, b"", flags=TCP_FIN | TCP_ACK),
        Seg(6, b"", ack=100),                       # the final ACK, one past the FIN
    ]), tmp_path, **kwargs)

    records = out.only.by(0)
    assert [(r.seq_start, r.payload, r.flags) for r in records[:2]] == [
        (1, b"aaaa", zpf.RecordFlags.PSH), (5, b"", zpf.RecordFlags.FIN),
    ]
    assert is_pure_ack(records[2]) and records[2].seq_start == 6
    assert out.diagnostics == [] and out.unplaceable == []


def test_a_fin_is_placed_once(tmp_path: pathlib.Path):
    """A resent FIN does not close the stream twice."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK),
        Seg(5, b"", flags=TCP_FIN | TCP_ACK),
        Seg(5, b"", flags=TCP_FIN | TCP_ACK),
    ]), tmp_path)

    assert sum(1 for r in out.only.by(0) if r.flags & zpf.RecordFlags.FIN) == 1


def test_a_capture_of_only_the_teardown_starts_the_stream_at_the_fin(tmp_path: pathlib.Path):
    """No SYN, no data: the FIN is where this direction's view begins."""
    out = to_zpf(tcp_segments([
        Seg(100, b"", flags=TCP_FIN | TCP_ACK, ack=50),
        Seg(50, b"", flags=TCP_FIN | TCP_ACK, from_client=False, ack=101),
        Seg(101, b"", ack=51),
    ]), tmp_path)

    first, final = out.only.by(0)
    assert (first.seq_start, first.flags) == (100, zpf.RecordFlags.FIN)
    assert is_pure_ack(final) and final.seq_start == 101
    assert out.diagnostics == [] and out.unplaceable == []


def test_a_pure_ack_inside_a_split_run_follows_the_piece_it_falls_in(tmp_path: pathlib.Path):
    """A swap splits the run; what trailed it is interleaved, not appended (#55).

    The client's pure ACK sits at 5, inside the run.  Written after the
    last piece, which starts at 9, it would break serial order, and the
    writer refuses that.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(5, b"", ack=0, timestamps=(100, 0)),                       # the client's pure ACK
        Seg(5, b"XXXX", timestamps=(101, 0)),                          # corrupted in flight
        Seg(9, b"cccc", flags=TCP_PSH | TCP_ACK, timestamps=(102, 0)),
        Seg(5, b"bbbb", timestamps=(140, 0)),                          # resent clean
        _ack(13, 140),
    ]), tmp_path, options=ACKED)

    assert out.only.stream(0) == b"aaaabbbbcccc"
    assert [(r.seq_start, r.payload) for r in out.only.by(0)] == [
        (1, b"aaaa"), (5, b"bbbb"), (5, b""), (9, b"cccc"),
    ]
    assert out.diagnostics == [] and out.unplaceable == []


def test_a_fin_the_stream_has_run_past_writes_no_record_below_it(tmp_path: pathlib.Path):
    """A forged segment reached beyond the real FIN: nothing can end where it sits.

    Written as a record of its own at its number, the FIN would precede the
    forged one already out, and the writer refuses that (#60).
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK),
        Seg(5, b"XXXXXXXX"),                          # forged, past the real end
        Seg(5, b"bbbb", flags=TCP_PSH | TCP_ACK),      # the real bytes, a repeat now
        Seg(9, b"", flags=TCP_FIN | TCP_ACK),          # the real FIN, behind the stream
    ]), tmp_path)

    starts = [r.seq_start for r in out.only.by(0)]
    assert starts == sorted(starts)
    assert out.diagnostics == [] and out.unplaceable == []


# ── #61: a copy is the same bytes ───────────────────────────────────────


def test_a_same_clock_repeat_with_other_bytes_is_not_a_copy(tmp_path: pathlib.Path):
    """A mirror's copy is byte-identical; one that differs is a forgery or a resend (#61).

    Judged on the clock alone it was discarded as ``duplicate-discarded``,
    which says the capture point saw one transmission twice.
    """
    forged = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(1, b"XXXX", timestamps=(100, 0)),       # the same tick, other bytes
        Seg(5, b"bbbb", flags=TCP_PSH | TCP_ACK, timestamps=(101, 0)),
    ]), tmp_path / "forged")
    copied = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(1, b"aaaa", timestamps=(100, 0)),       # a true copy
        Seg(5, b"bbbb", flags=TCP_PSH | TCP_ACK, timestamps=(101, 0)),
    ]), tmp_path / "copied")

    assert forged.only.stream(0) == copied.only.stream(0) == b"aaaabbbb"
    assert _reasons(forged) == ["overlap-discarded"] and forged.stats.duplicates == 0
    assert _reasons(copied) == ["duplicate-discarded"] and copied.stats.duplicates == 1


def test_a_same_clock_repeat_of_a_held_segment_with_other_bytes_is_not_a_copy(
    tmp_path: pathlib.Path,
):
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(9, b"cccc", timestamps=(102, 0)),       # held
        Seg(9, b"XXXX", timestamps=(102, 0)),       # the same tick, other bytes
        Seg(5, b"bbbb", flags=TCP_PSH | TCP_ACK, timestamps=(101, 0)),
    ]), tmp_path)

    assert _reasons(out) == ["overlap-discarded"]
    assert out.stats.duplicates == 0


def test_a_same_clock_copy_of_a_resend_with_other_bytes_is_not_a_copy(tmp_path: pathlib.Path):
    """#56's memory of a discarded resend keeps its bytes, so #61 holds there too."""
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK, timestamps=(100, 0)),
        Seg(1, b"", from_client=False),
        Seg(1, b"aaaa", timestamps=(140, 0)),        # the resend, discarded
        Seg(1, b"XXXX", timestamps=(140, 0)),        # the resend's tick, other bytes
    ]), tmp_path)

    assert _reasons(out) == ["overlap-discarded", "overlap-discarded"]
    assert out.stats.duplicates == 0


@pytest.mark.parametrize("coalesce", [True, False], ids=["coalesce", "no-coalesce"])
def test_once_its_bytes_are_written_a_copy_is_the_same_packet(
    tmp_path: pathlib.Path, coalesce: bool,
):
    """No run holds them to compare, so a copy must match one transmission's range and CRC.

    Without coalescing every segment is written at once, and on the clock
    alone every same-tick forgery passed as a copy (#61).
    """
    options = ReassemblyOptions(coalesce=coalesce)
    forged = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK, timestamps=(100, 0)),   # written at once
        Seg(1, b"XXXX", timestamps=(100, 0)),                            # same range, other bytes
        Seg(1, b"aa", timestamps=(100, 0)),                              # same bytes, other range
    ]), tmp_path / "forged", options=options)
    copied = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK, timestamps=(100, 0)),
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK, timestamps=(100, 0)),   # the same packet
    ]), tmp_path / "copied", options=options)

    assert _reasons(forged) == ["overlap-discarded", "overlap-discarded"]
    assert _reasons(copied) == ["duplicate-discarded"]


def test_an_echo_naming_both_copies_is_counted_as_a_fallback(tmp_path: pathlib.Path):
    """A forgery first, on the real segment's clock: the receiver's echo cannot choose (#61).

    It names the clock both copies carry.  The first copy is kept, as
    favor-old keeps it, and every contested byte is counted: before, the
    forgery was a "duplicate", never contested at all.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"XXXX", timestamps=(100, 0)),                    # forged, first
        Seg(1, b"aaaa", timestamps=(100, 0)),                    # real, the same tick
        Seg(5, b"bbbb", flags=TCP_PSH | TCP_ACK, timestamps=(101, 0)),
        _ack(9, 100),
    ]), tmp_path, options=ACKED)

    assert out.only.stream(0) == b"XXXXbbbb"
    assert out.stats.duplicates == 0
    assert out.stats.acked_swaps == 0
    assert out.stats.acked_fallback_bytes == 4


# ── #62: favor-acked does not contest what the receiver already took ───


def _forged_after_the_ack() -> list[Seg]:
    """Build a held run, its first bytes acknowledged, then a forgery of them a tick later."""
    return [
        Seg(1, b"aaaa", timestamps=(100, 0)),
        Seg(5, b"bbbb", timestamps=(101, 0)),
        _ack(5, 100),                                                    # aaaa accepted
        Seg(1, b"XXXX", timestamps=(102, 0)),                            # forged, later
        Seg(9, b"cccc", flags=TCP_PSH | TCP_ACK, timestamps=(102, 0)),  # real, the same tick
        _ack(13, 102),                                                   # echoes that tick
    ]


def test_favor_acked_does_not_contest_a_copy_of_acknowledged_bytes(tmp_path: pathlib.Path):
    """The receiver chose with only the first copy to hand, and drops a later one (#62).

    Contested, the copy was decided by the next covering ack, whose echo
    names ``cccc``'s tick — which the forgery shares — so it was swapped in.
    """
    out = to_zpf(tcp_segments(_forged_after_the_ack()), tmp_path, options=ACKED)

    assert out.only.stream(0) == b"aaaabbbbcccc"
    assert out.stats.acked_swaps == 0
    assert out.stats.acked_fallback_bytes == 0
    assert _reasons(out) == ["overlap-discarded"]
    assert _flagged(out) == [True]          # the held run holds the repeated range (#59)


def test_a_copy_before_the_ack_is_still_contested(tmp_path: pathlib.Path):
    """The guard is the ack, not the order: a corrupted copy resent before it is still judged."""
    out = to_zpf(tcp_segments(_corrupt_then_resent(echo=140)), tmp_path, options=ACKED)

    assert out.only.stream(0) == b"aaaabbbb"
    assert out.stats.acked_swaps == 1


def test_an_ack_of_bytes_never_sent_does_not_stop_a_contest(tmp_path: pathlib.Path):
    """A forged segment's ack covers what the sender has not sent yet (#62).

    A receiver ignores such an ack, and so does the rule that stops
    favor-acked contesting what was already acknowledged: taken as proof,
    it would leave the forgery in place and the real copy uncontested.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"XXXX", timestamps=(100, 0)),                    # forged, first
        Seg(500, b"", from_client=False, ack=999,                 # a forged ack of byte 998,
            timestamps=(600, 100)),                               # and only 5 were ever sent
        Seg(1, b"aaaa", timestamps=(140, 0)),                     # the real segment
        Seg(5, b"bbbb", flags=TCP_PSH | TCP_ACK, timestamps=(141, 0)),
        _ack(9, 140),                                             # the receiver kept aaaa
    ]), tmp_path, options=ACKED)

    assert out.only.stream(0) == b"aaaabbbb"
    assert out.stats.acked_swaps == 1


# ── #68: a contest's written prefix is cited ────────────────────────────


def test_the_written_part_of_a_contested_repeat_is_cited(tmp_path: pathlib.Path):
    """A repeat straddling written and held bytes contests the held part only (#68).

    The written part had no run left to contest it against, and was
    neither written nor cited: two bytes lost quietly.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK, timestamps=(100, 0)),
        _ack(5, 100),                                                    # aaaa written
        Seg(5, b"bbbb", timestamps=(101, 0)),                            # open
        Seg(3, b"XXYYYY", timestamps=(102, 0)),                          # over both
        Seg(9, b"cccc", flags=TCP_PSH | TCP_ACK, timestamps=(103, 0)),
        _ack(13, 103),
    ]), tmp_path, options=ACKED)

    assert out.only.stream(0) == b"aaaabbbbcccc"
    assert _reasons(out) == ["overlap-discarded", "overlap-discarded"]
    assert sorted(u.off_end - u.off_start for u in out.undecoded) == [2, 4]
    assert out.stats.overlap_bytes == 6


# ── #76: a hole under the records written last is a committed gap ───────


def _file_gaps(out: object) -> int:
    """Count the ``Gap`` chunks a reader of the file sees, both directions."""
    with zpf.open(out.path) as reader:  # type: ignore[attr-defined]
        return sum(
            isinstance(chunk, zpf.Gap)
            for session in reader.sessions()
            for view in session.reassemble()
            # The silent peer stores nothing, so it has no stream to read.
            if any(r.seq_start is not None
                   for r in session.stream(view.participant.participant_id))
            for chunk in view.chunks()
        )


@pytest.mark.parametrize(("segments", "gaps"), [
    pytest.param([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK),
        # bbbb at 5 is lost, and nothing resends it
        Seg(9),                                             # a pure ACK past it
    ], 1, id="lost-tail"),
    pytest.param([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK),
        # the FIN at 5 is lost
        Seg(6),                                             # the final ACK, past it
    ], 1, id="lost-fin"),
    pytest.param([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK),
        # bbbb at 5 is lost
        Seg(9, flags=TCP_FIN | TCP_ACK),                    # the FIN, past it
        Seg(10),
    ], 1, id="fin-past-a-hole"),
    pytest.param([
        Seg(1, b"aaaa", flags=TCP_PSH | TCP_ACK),
        Seg(5, flags=TCP_FIN | TCP_ACK),
        Seg(6),                                             # the final ACK, one past the FIN
    ], 0, id="closed-cleanly"),
])
def test_a_hole_under_the_records_written_last_is_counted(
    tmp_path: pathlib.Path, segments: list[Seg], gaps: int,
):
    """``stats.gaps`` counts what the file shows since spec 0.24 (#76, zipline#168).

    A record written past bytes that never arrived leaves a gap.  At the
    end of a session the last such records are a FIN whose data never all
    came and pure ACKs held ahead of the frontier, and the hole below them
    went uncounted, so a lossy conversion reported itself lossless.  A FIN occupies
    its one number, so a final ACK just past a captured FIN leaves none.
    """
    out = to_zpf(tcp_segments(segments), tmp_path)

    assert out.stats.gaps == _file_gaps(out) == gaps
    assert out.stats.lossless is (gaps == 0)
    assert out.diagnostics == [] and out.unplaceable == []
