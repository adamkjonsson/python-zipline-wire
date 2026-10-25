"""Capture-scoped provenance: what a conversion says about what it dropped.

A `.zpf` derived from a capture can express two things a transport stream
cannot express on its own — when a coalesced record *started*, and which bytes
of the capture reached no record at all.  Both matter because the alternative
is losing them quietly.

Gaps are deliberately absent from these tests: against a capture source the
specification bars a hole-class Undecoded block, because a transport stream's
offsets already carry the extent of what is missing.  What it permits, and what
nothing else can say, is the other class — bytes that *are* in the capture and
were discarded.
"""

from __future__ import annotations

import pathlib

import zpf
from helpers import (
    CAPTURES,
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    SERVER_PORT,
    TCP_ACK,
    TCP_PSH,
    TCP_SYN,
    Seg,
    capture_of,
    tcp_packet,
    tcp_segments,
    to_zpf,
)
from packeteer.generate import PacketBuilder

from zpfwire import ReassemblyOptions
from zpfwire.flow import REASON_LATE, REASON_OVERLAP

ISN = 1000


def cited(out: object, capture: bytes) -> list[bytes]:
    """Slice the capture at every range the file declared undecoded."""
    return [capture[b.off_start:b.off_end] for b in out.undecoded]


# ── undecoded regions ───────────────────────────────────────────────────


def test_a_discarded_retransmit_names_its_bytes_in_the_capture(
    tmp_path: pathlib.Path,
):
    """The case the spec singles out for a capture-sourced Undecoded block.

    The retransmitted bytes are in the capture and reach no record, and
    nothing else in the format can say so.
    """
    buf = capture_of([
        Seg(1, b"hello", flags=TCP_PSH).frame(),
        Seg(1, b"hello", flags=TCP_PSH).frame(),   # a pure duplicate
        Seg(6, b" world", flags=TCP_PSH).frame(),
    ])
    capture = buf.getvalue()
    out = to_zpf(buf, tmp_path)

    assert out.diagnostics == []
    assert out.only.stream(0) == b"hello world"
    assert len(out.undecoded) == 1

    block = out.undecoded[0]
    assert block.reason == REASON_OVERLAP
    assert block.reason_class == "bytes"
    assert capture[block.off_start:block.off_end] == b"hello"


def test_an_undecoded_block_addresses_the_capture_not_a_zpf_stream(
    tmp_path: pathlib.Path,
):
    """Against a capture source there is no id namespace, so both ids are 0."""
    out = to_zpf(
        capture_of([
            Seg(1, b"abc", flags=TCP_PSH).frame(),
            Seg(1, b"abc", flags=TCP_PSH).frame(),
        ]),
        tmp_path,
    )

    block = out.undecoded[0]
    assert block.session_id == 0
    assert block.participant_id == 0
    assert block.source_id == 0


def test_only_the_overlapping_part_of_a_segment_is_cited(tmp_path: pathlib.Path):
    """A partial retransmit is trimmed, so only the trimmed bytes are undecoded."""
    buf = capture_of([
        Seg(1, b"abcdef", flags=TCP_PSH).frame(),
        Seg(4, b"defghi", flags=TCP_PSH).frame(),   # "def" repeats, "ghi" is new
    ])
    capture = buf.getvalue()
    out = to_zpf(buf, tmp_path)

    assert out.only.stream(0) == b"abcdefghi"
    assert cited(out, capture) == [b"def"]


def test_every_discarded_byte_is_either_cited_or_counted_as_unlocatable(
    tmp_path: pathlib.Path,
):
    """The accounting rule: no byte is dropped without an entry somewhere."""
    out = to_zpf(CAPTURES / "retransmission.pcap", tmp_path)
    stats = out.stats

    assert stats.overlap_bytes > 0
    cited_bytes = sum(b.off_end - b.off_start for b in out.undecoded)
    assert cited_bytes + stats.unlocatable_bytes == (
        stats.overlap_bytes + stats.duplicate_bytes + stats.late_bytes + stats.paws_bytes
    )


def test_cited_retransmit_bytes_are_the_ones_already_in_the_stream(
    tmp_path: pathlib.Path,
):
    """An overlap discard is by definition a second copy of accepted bytes."""
    capture = (CAPTURES / "retransmission.pcap").read_bytes()
    out = to_zpf(CAPTURES / "retransmission.pcap", tmp_path)

    stream = out.only.stream(0) + out.only.stream(1)
    assert out.undecoded
    for region in cited(out, capture):
        assert region in stream


def test_bytes_arriving_after_their_gap_was_committed_are_cited_as_late(
    tmp_path: pathlib.Path,
):
    """Committing a gap is irreversible, so these bytes may never be written.

    They still exist in the capture, which is exactly what separates them
    from the hole itself — the hole needs no block and may not have one.
    """
    buf = capture_of(
        [
            Seg(1, b"aaaa", flags=TCP_PSH).frame(),
            Seg(9, b"cccc", flags=TCP_PSH).frame(),   # jumps the missing 5..8
            # Arriving past the flush timeout is what makes the reassembler
            # stop waiting and commit the gap, which the late bytes then hit.
            Seg(13, b"dddd", flags=TCP_PSH).frame(),
            Seg(5, b"bbbb", flags=TCP_PSH).frame(),   # too late; the gap is closed
        ],
        step_us=5_000_000,
    )
    capture = buf.getvalue()
    out = to_zpf(buf, tmp_path, options=ReassemblyOptions(flush_timeout=1.0))

    assert out.stats.gaps == 1
    assert out.stats.late_bytes == 4
    assert b"bbbb" not in out.only.stream(0)
    late = [b for b in out.undecoded if b.reason == REASON_LATE]
    assert [capture[b.off_start:b.off_end] for b in late] == [b"bbbb"]


def test_a_gap_itself_gets_no_block(tmp_path: pathlib.Path):
    """A hole-class region MUST NOT be declared against a capture source.

    The stream's own offsets already carry its extent, and two accounts of
    the same missing bytes would leave a consumer no rule for which to believe.
    """
    out = to_zpf(
        capture_of(
            [Seg(1, b"aaaa", flags=TCP_PSH).frame(), Seg(9, b"cccc", flags=TCP_PSH).frame()],
            step_us=5_000_000,
        ),
        tmp_path,
        options=ReassemblyOptions(flush_timeout=1.0),
    )

    assert out.stats.gaps == 1
    assert out.undecoded == []
    # And nowhere else either: no conversion may produce a hole-class block.
    for name in ("packet_loss.pcap", "retransmission.pcap"):
        other = to_zpf(CAPTURES / name, tmp_path)
        assert all(b.reason_class == "bytes" for b in other.undecoded), name


def test_a_discard_from_a_reassembled_datagram_is_counted_not_guessed(
    tmp_path: pathlib.Path,
):
    """One offset cannot name bytes that live in several capture records.

    Citing the first fragment's offset would name bytes that are partly IP
    headers, so the conversion declines to cite and reports how many bytes it
    could not place — the counter exists for exactly this case.
    """
    payload = b"fragmented-tcp-payload" * 60
    fragments = (
        PacketBuilder()
        .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
        .ip(src=CLIENT_IP, dst=SERVER_IP)
        .tcp(src_port=CLIENT_PORT, dst_port=SERVER_PORT, seq=1, flags=TCP_PSH | TCP_ACK)
        .payload(data=payload)
        .fragment(600)
    )
    assert len(fragments) > 1
    # The same datagram twice: the second is a pure retransmit, so every byte
    # of it is discarded — and none of them can be given a capture range.
    out = to_zpf(capture_of([*fragments, *fragments]), tmp_path)

    assert out.diagnostics == []
    assert out.only.stream(0) == payload
    assert out.stats.overlap_bytes == len(payload)
    assert out.stats.unlocatable_bytes == len(payload)
    assert out.undecoded == []


# ── ts_first ────────────────────────────────────────────────────────────


def test_a_coalesced_record_says_when_it_started(tmp_path: pathlib.Path):
    """`ts` is the last contributing packet; without ts_first the start is lost.

    A capture converter cannot use `spans` for this — they must reference a
    zpf-input source and ours is a capture — so ts_first is the only place
    the run's beginning fits.
    """
    out = to_zpf(
        capture_of(
            [Seg(1, b"aa").frame(), Seg(3, b"bb").frame(),
             Seg(5, b"cc", flags=TCP_PSH).frame()],
            start_us=1_000_000,
            step_us=1_000,
        ),
        tmp_path,
    )

    record = out.only.by(0)[0]
    assert record.payload == b"aabbcc"
    assert record.timestamp == 1_002_000
    assert record.ts_first == 1_000_000


def test_a_single_segment_record_does_not_repeat_its_timestamp(
    tmp_path: pathlib.Path,
):
    """ts_first would carry no information there, so it is left out."""
    out = to_zpf(tcp_segments([Seg(1, b"only", flags=TCP_PSH)]), tmp_path)

    record = out.only.by(0)[0]
    assert record.ts_first is None


def test_ts_first_never_follows_ts(tmp_path: pathlib.Path):
    """A record cannot have started after it finished."""
    out = to_zpf(CAPTURES / "no_errors.pcap", tmp_path)

    for session in out.sessions:
        for record in session.records:
            if record.ts_first is not None:
                assert record.ts_first <= record.timestamp


def test_a_held_segment_does_not_drag_the_stamps_backwards(
    tmp_path: pathlib.Path,
):
    """Both stamps are per unit: the last and the first contributor in capture order.

    A segment held out of order arrives *before* the one that fills the hole
    below it and is appended *after* it.  Stamping the run from whichever
    packet was appended last dates the unit complete before its final packet
    arrived, and leaves ts_first after ts — a record that started after it
    finished.
    """
    out = to_zpf(
        capture_of(
            [tcp_packet(seq=ISN, flags=TCP_SYN),                            # 1_000_000
             tcp_packet(seq=ISN + 3, payload=b"bb"),                        # 1_001_000, held
             tcp_packet(seq=ISN + 1, flags=TCP_PSH | TCP_ACK,
                        payload=b"aa")],                                    # 1_002_000, fills
            start_us=1_000_000,
            step_us=1_000,
        ),
        tmp_path,
    )

    record = out.only.by(0)[1]                 # [0] is the handshake record
    assert record.payload == b"aabb"
    assert record.timestamp == 1_002_000
    assert record.ts_first == 1_001_000


def test_the_ack_is_the_highest_a_contributor_carried_not_the_last_appended(
    tmp_path: pathlib.Path,
):
    """The third hint on a run, on the same rule as the two stamps beside it.

    The held segment is appended *after* the one that fills the hole below it,
    so taking the last append's ack keeps the earlier packet's — a record
    reporting a timestamp and an acknowledgement from two different packets.
    Acks are cumulative, so the maximum over the contributors is the strongest
    statement the run can make that is certainly true.
    """
    out = to_zpf(
        capture_of(
            [tcp_packet(seq=ISN, flags=TCP_SYN),
             tcp_packet(seq=ISN + 3, ack=6000, payload=b"bb"),            # held
             tcp_packet(seq=ISN + 1, ack=7000, flags=TCP_PSH | TCP_ACK,
                        payload=b"aa")],                                  # fills
            start_us=1_000_000,
            step_us=1_000,
        ),
        tmp_path,
    )

    record = out.only.by(0)[1]
    assert record.payload == b"aabb"
    assert record.timestamp == 1_002_000       # the last contributor's
    assert record.ack == 7000                  # and its ack, this time


def test_a_higher_ack_on_the_held_segment_is_kept_by_rule_not_by_luck(
    tmp_path: pathlib.Path,
):
    """The mirror case, which the old behaviour got right for the wrong reason.

    Peer acks reordered on the wire, or a delayed ack on the filling segment,
    put the higher ack on the packet appended first.  Keeping it is sound —
    a cumulative ack observed from this sender stays true later — and under
    the maximum it is sound by rule rather than by which append happened last.
    """
    out = to_zpf(
        capture_of(
            [tcp_packet(seq=ISN, flags=TCP_SYN),
             tcp_packet(seq=ISN + 3, ack=9000, payload=b"bb"),            # held
             tcp_packet(seq=ISN + 1, ack=5000, flags=TCP_PSH | TCP_ACK,
                        payload=b"aa")],                                  # fills
            start_us=1_000_000,
            step_us=1_000,
        ),
        tmp_path,
    )

    record = out.only.by(0)[1]
    assert record.payload == b"aabb"
    assert record.ack == 9000


def test_the_ack_maximum_is_serial_so_it_survives_a_wrap(
    tmp_path: pathlib.Path,
):
    """Sequence space wraps, so the comparison cannot be a plain `>`.

    An ack just past 2**32 is *ahead* of one just below it, and a numeric
    maximum would take the larger integer and hand the record an ack four
    billion bytes in the past.
    """
    before_wrap = 0xFFFF_FF00
    after_wrap = 0x0000_0100
    out = to_zpf(
        capture_of(
            [tcp_packet(seq=ISN, flags=TCP_SYN),
             tcp_packet(seq=ISN + 3, ack=before_wrap, payload=b"bb"),
             tcp_packet(seq=ISN + 1, ack=after_wrap, flags=TCP_PSH | TCP_ACK,
                        payload=b"aa")],
            start_us=1_000_000,
            step_us=1_000,
        ),
        tmp_path,
    )

    record = out.only.by(0)[1]
    assert record.payload == b"aabb"
    assert record.ack == after_wrap


# ── the handshake ───────────────────────────────────────────────────────


def handshake() -> list[bytes]:
    return [
        tcp_packet(seq=ISN, flags=TCP_SYN),
        tcp_packet(src=SERVER_IP, dst=CLIENT_IP, src_port=SERVER_PORT,
                   dst_port=CLIENT_PORT, seq=5000, ack=ISN + 1, flags=TCP_SYN | TCP_ACK),
        tcp_packet(seq=ISN + 1, ack=5001, flags=TCP_ACK),
    ]


def test_the_handshake_is_written_as_a_record_in_each_direction(
    tmp_path: pathlib.Path,
):
    """Otherwise the moment the connection opened is nowhere in the file.

    `isn` says where a stream begins in sequence space but not when, and the
    first data record carries its own arrival time.
    """
    out = to_zpf(capture_of(handshake()), tmp_path)

    assert out.diagnostics == []
    syn = out.only.by(0)[0]
    syn_ack = out.only.by(1)[0]

    assert syn.flags & zpf.RecordFlags.SYN
    assert syn.seq_start == ISN + 1
    assert syn.payload == b""
    assert syn.ack is None            # a bare SYN acknowledges nothing

    assert syn_ack.flags & zpf.RecordFlags.SYN
    assert syn_ack.seq_start == 5001
    assert syn_ack.ack == ISN + 1


def test_the_syn_record_sits_at_the_origin_and_never_below_it(
    tmp_path: pathlib.Path,
):
    """A record below isn + 1 has no offset, and the arithmetic hides it.

    The origin is a floor.  At the isn the offset is negative, the modular
    subtraction returns just under 2**32 instead, and the stream measures
    that many bytes however far its data actually runs.
    """
    for name in sorted(p.name for p in CAPTURES.glob("*.pcap*")):
        out = to_zpf(CAPTURES / name, tmp_path)
        for session in out.sessions:
            for participant in session.participants:
                if participant.isn is None:
                    continue
                origin = (participant.isn + 1) % (1 << 32)
                for record in session.by(participant.participant_id):
                    if record.seq_start is None:
                        continue
                    # Serial arithmetic: the offset is in the half-space
                    # above the origin, never wrapped around from below it.
                    assert (record.seq_start - origin) % (1 << 32) < (1 << 31), name


def test_a_retransmitted_syn_does_not_get_a_second_record(tmp_path: pathlib.Path):
    """A retransmitted SYN re-opens nothing, so it reports nothing new."""
    out = to_zpf(
        capture_of([tcp_packet(seq=ISN, flags=TCP_SYN), tcp_packet(seq=ISN, flags=TCP_SYN)]),
        tmp_path,
    )

    assert out.diagnostics == []
    assert len(out.only.by(0)) == 1


def test_a_mid_stream_capture_writes_no_syn_record(tmp_path: pathlib.Path):
    """No handshake was seen, so there is no opening to report."""
    out = to_zpf(tcp_segments([Seg(9000, b"already running", flags=TCP_PSH)]), tmp_path)

    assert all(not (r.flags & zpf.RecordFlags.SYN) for r in out.only.records)


def test_a_udp_flow_has_no_handshake_to_report(tmp_path: pathlib.Path):
    """The SYN record is a TCP notion; nothing here should invent one."""
    from helpers import udp_packet

    out = to_zpf(capture_of([udp_packet(payload=b"q")]), tmp_path)

    assert all(not (r.flags & zpf.RecordFlags.SYN) for r in out.only.records)


# ── the whole thing still reads back ────────────────────────────────────


def test_provenance_does_not_break_the_fixtures(tmp_path: pathlib.Path):
    """Every capture still converts to a file the reader accepts."""
    for name in sorted(p.name for p in CAPTURES.glob("*.pcap*")):
        out = to_zpf(CAPTURES / name, tmp_path)
        assert out.diagnostics == [], name


def test_records_stay_in_ascending_seq_start_per_participant(
    tmp_path: pathlib.Path,
):
    """The MUST that the SYN record is most likely to have broken.

    *Order* is serial-number order, so it is checked pairwise the way the
    specification states it: each ``seq_start`` no further back than the one
    before it.  ``tcp_wrap_ts.pcap`` has a participant whose records cross
    2**32, which plain sorting would call out of order.
    """
    for name in sorted(p.name for p in CAPTURES.glob("*.pcap*")):
        out = to_zpf(CAPTURES / name, tmp_path)
        for session in out.sessions:
            for pid in {r.sender_pid for r in session.records}:
                starts = [r.seq_start for r in session.by(pid) if r.seq_start is not None]
                steps = [(b - a) % 2**32 for a, b in zip(starts, starts[1:], strict=False)]
                assert all(step < 2**31 for step in steps), f"{name} pid {pid}"
