from __future__ import annotations

import pathlib

import pytest
import zpf
from helpers import (
    CAPTURES,
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    capture_of,
    fragmented_frames,
    packets_zpf,
    to_zpf,
    udp_packet,
)

import zpfwire
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


# ── #77: a capture point's copy is marked copy ─────────────────────────


def _copies(out: object) -> list[bool]:
    """Whether each record of the only session carries ``copy``, in stored order."""
    return [bool(r.flags & zpf.RecordFlags.COPY) for r in out.only.records]  # type: ignore[attr-defined]


def _answer(payload: bytes = b"answer", identification: int = 0x77) -> bytes:
    return udp_packet(src=SERVER_IP, dst=CLIENT_IP, src_port=53, dst_port=CLIENT_PORT,
                      payload=payload, identification=identification)


def test_a_mirror_copy_is_marked_copy(tmp_path: pathlib.Path):
    """Spec 0.24's ``copy`` (zipline#169): the same frames seen twice, the sender sent once.

    It is still written, since a datagram may not be withheld from a stream
    without sequence numbers, and a reader that wants the stream as the
    sender sent it skips it.
    """
    query = udp_packet(payload=b"query", identification=0x1234)
    out = to_zpf(capture_of([query, query]), tmp_path)

    assert _copies(out) == [False, True]
    assert out.stats.copies == 1
    assert out.diagnostics == [] and out.unplaceable == []
    with zpf.open(out.path) as reader:
        (session,) = reader.sessions()
        view = next(v for v in session.reassemble() if v.participant.endpoint == CLIENT)
        assert [d.data for d in view.datagrams()] == [b"query", b"query"]
        assert [d.data for d in view.datagrams(copies=False)] == [b"query"]


@pytest.mark.parametrize(("first", "second"), [
    pytest.param(udp_packet(payload=b"query", identification=0x1234),
                 udp_packet(payload=b"query", identification=0x1235),
                 id="a-resend-gets-a-new-id"),
    pytest.param(udp_packet(payload=b"query"), udp_packet(payload=b"query"),
                 id="id-0-cannot-tell"),
])
def test_a_repeat_zpfwire_cannot_tell_from_a_resend_is_not_marked(
    tmp_path: pathlib.Path, first: bytes, second: bytes,
):
    """A DNS client retrying its query sends the same bytes: only the ID tells them apart."""
    out = to_zpf(capture_of([first, second]), tmp_path)

    assert _copies(out) == [False, False]
    assert out.stats.copies == 0


def test_a_copy_must_follow_its_original(tmp_path: pathlib.Path):
    """``copy`` says the record repeats its participant's *preceding* record."""
    query = udp_packet(payload=b"query", identification=0x1234)
    other = udp_packet(payload=b"other", identification=0x1240)
    out = to_zpf(capture_of([query, other, query]), tmp_path)

    assert _copies(out) == [False, False, False]


def test_the_peer_s_datagram_between_does_not_matter(tmp_path: pathlib.Path):
    """The rule is per participant: the server's answer is not the client's record."""
    query = udp_packet(payload=b"query", identification=0x1234)
    out = to_zpf(capture_of([query, _answer(), query]), tmp_path)

    client = [bool(r.flags & zpf.RecordFlags.COPY) for r in out.only.records
              if r.sender_pid == out.only.records[0].sender_pid]
    assert client == [False, True]


def test_a_fragmented_datagram_seen_twice_is_marked(tmp_path: pathlib.Path):
    """A mirror repeats every fragment, under the same identification."""
    frames = fragmented_frames(identification=0x4444)
    out = to_zpf(capture_of([*frames, *frames]), tmp_path)

    assert _copies(out) == [False, True]


def test_the_packets_path_marks_the_same_copy(tmp_path: pathlib.Path):
    """A ``.zpf`` of the same packets reaches the same verdict (#77)."""
    query = udp_packet(payload=b"query", identification=0x1234)
    capture = capture_of([query, query, _answer()])
    packets = packets_zpf(capture, tmp_path / "packets.zpf", fields=False)
    inner = tmp_path / "inner.zpf"
    stats = zpfwire.packets_to_zpf(packets, inner, produced_at=1_700_000_000)

    assert stats.copies == 1
    with zpf.open(inner) as reader:
        flagged = [bool(r.flags & zpf.RecordFlags.COPY)
                   for s in reader.sessions() for r in s.records()]
        assert reader.diagnostics == [] and reader.unplaceable == []
    assert sorted(flagged) == [False, False, True]


def test_the_writer_refuses_a_copy_whose_bytes_differ(tmp_path: pathlib.Path):
    """The second guard: a ``copy`` that does not repeat its predecessor is refused (spec 0.24)."""
    with zpf.create(tmp_path / "out.zpf", tick_hz=1_000_000) as writer:
        writer.add_source("capture")
        session = writer.begin_session(proto="udp")
        sender = session.participant(CLIENT)
        session.record(sender, ts=1, payload=b"query", flags=zpf.RecordFlags.MESSAGE)
        with pytest.raises(zpf.ZpfError, match="copy"):
            session.record(sender, ts=2, payload=b"other",
                           flags=zpf.RecordFlags.MESSAGE | zpf.RecordFlags.COPY)

