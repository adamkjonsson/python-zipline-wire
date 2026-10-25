"""Sequenced sessions: storing a conversation in a causal order.

Capture order is not causal order.  Two packets recorded a microsecond apart
may have crossed on the wire, and a `.zpf` that stores them in capture order is
telling a reader something the capture never established.  ``SEQUENCED`` says
the stored order *is* a valid causal linearization, and a reader may act on it.

The reassembler produces each direction in its own order — the only order it
has — and `zpf`'s ``linearize`` computes the interleaving when the session
ends.  So the work here is the choice of when to claim it, not the merge.
"""

from __future__ import annotations

import pathlib

import pytest
import zpf
from helpers import (
    CAPTURES,
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    SERVER_PORT,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_SYN,
    Seg,
    capture_of,
    tcp_packet,
    tcp_segments,
    to_zpf,
    udp_packet,
)

from zpfwire import ReassemblyOptions

ISN = 1000
SERVER_ISN = 5000

ALL_CAPTURES = sorted(p.name for p in CAPTURES.glob("*.pcap*"))


def conversation() -> list[bytes]:
    """Build a handshake and two exchanges, in the order a tap would see them."""
    return [
        tcp_packet(seq=ISN, flags=TCP_SYN),
        tcp_packet(src=SERVER_IP, dst=CLIENT_IP, src_port=SERVER_PORT,
                   dst_port=CLIENT_PORT, seq=SERVER_ISN, ack=ISN + 1,
                   flags=TCP_SYN | TCP_ACK),
        tcp_packet(seq=ISN + 1, ack=SERVER_ISN + 1, flags=TCP_PSH | TCP_ACK,
                   payload=b"GET /"),
        tcp_packet(src=SERVER_IP, dst=CLIENT_IP, src_port=SERVER_PORT,
                   dst_port=CLIENT_PORT, seq=SERVER_ISN + 1, ack=ISN + 6,
                   flags=TCP_PSH | TCP_ACK, payload=b"200 OK"),
        tcp_packet(seq=ISN + 6, ack=SERVER_ISN + 7, flags=TCP_PSH | TCP_ACK,
                   payload=b"bye"),
    ]


# ── the claim ───────────────────────────────────────────────────────────


def test_sequenced_is_off_unless_asked_for(tmp_path: pathlib.Path):
    """Buffering a whole session is not something to do behind a caller's back."""
    out = to_zpf(capture_of(conversation()), tmp_path)

    assert out.only.sequenced is False


def test_a_tcp_session_is_marked_and_stored_in_causal_order(
    tmp_path: pathlib.Path,
):
    out = to_zpf(capture_of(conversation()), tmp_path, sequenced=True)

    assert out.diagnostics == []
    assert out.only.sequenced is True
    # The reader-side check of exactly what the flag asserts.
    zpf.verify_sequenced(out.only.records, participant_count=2)


def test_the_stored_order_is_the_conversation(tmp_path: pathlib.Path):
    """Request, response, request — each after what it answers."""
    out = to_zpf(capture_of(conversation()), tmp_path, sequenced=True)

    spoken = [(r.sender_pid, r.payload) for r in out.only.records if r.payload]
    assert spoken == [(0, b"GET /"), (1, b"200 OK"), (0, b"bye")]


def test_a_reordered_capture_still_stores_causally(tmp_path: pathlib.Path):
    """The point of the flag: stored order does not follow arrival order.

    Here the server's reply is recorded before the request it answers, which
    a tap can do. The stored order has to put the request first regardless.
    """
    frames = conversation()
    frames[2], frames[3] = frames[3], frames[2]
    out = to_zpf(capture_of(frames), tmp_path, sequenced=True)

    assert out.diagnostics == []
    zpf.verify_sequenced(out.only.records, participant_count=2)
    spoken = [(r.sender_pid, r.payload) for r in out.only.records if r.payload]
    assert spoken.index((0, b"GET /")) < spoken.index((1, b"200 OK"))


def test_the_payload_is_unchanged_by_sequencing(tmp_path: pathlib.Path):
    """Reordering storage must not alter either direction's byte stream."""
    plain = to_zpf(capture_of(conversation()), tmp_path / "plain")
    seq = to_zpf(capture_of(conversation()), tmp_path / "seq", sequenced=True)

    for pid in (0, 1):
        assert plain.only.stream(pid) == seq.only.stream(pid)


# ── what may and may not be claimed ─────────────────────────────────────


def test_a_udp_session_is_not_marked(tmp_path: pathlib.Path):
    """A UDP session is hint-less: its order would rest on something else.

    Datagrams carry no seq or ack, so nothing in the session establishes what
    happened before what. Claiming it here would be a separate judgement from
    the one this flag was added to make.
    """
    out = to_zpf(capture_of([udp_packet(payload=b"one"), udp_packet(payload=b"two")]),
                 tmp_path, sequenced=True)

    assert out.only.proto == "udp"
    assert out.only.sequenced is False


def test_a_session_with_no_records_still_validates(tmp_path: pathlib.Path):
    """The case that used to need an answer at write time.

    A TCP conversation of pure acks produces no records when they are not
    stored (``pure_acks=False``; the default before ``0.6.0``), and a session
    with no records carries no seq or ack — so it is hint-less however TCP it
    is.
    Under spec ``0.16`` that meant it had to say what its order rested on,
    and the flag is written on the Session Descriptor before any record
    exists, so a producer could not know which kind of session it had.  Since
    ``0.19`` there is nothing to say: the producer is trusted for the basis
    exactly as it already was for the order, neither being checkable.  Three
    of the four sessions in ``http_example.pcapng`` are this shape, so the
    guard stays whichever way the format goes.
    """
    out = to_zpf(
        capture_of([tcp_packet(seq=ISN + 1, ack=SERVER_ISN + 1, flags=TCP_ACK)]),
        tmp_path,
        sequenced=True,
        options=ReassemblyOptions(pure_acks=False),
    )

    assert out.diagnostics == []
    assert out.only.records == []
    assert out.only.sequenced is True


def test_a_session_of_one_pure_ack_validates_sequenced(tmp_path: pathlib.Path):
    """The same capture under the default: one zero-length record with no end (#37).

    A record with no end is the source of no edge, so a session holding only
    one is trivially in causal order.  What this checks is that the
    linearizing writer and the reader both accept the shape.
    """
    out = to_zpf(
        capture_of([tcp_packet(seq=ISN + 1, ack=SERVER_ISN + 1, flags=TCP_ACK)]),
        tmp_path,
        sequenced=True,
    )

    assert out.diagnostics == []
    (ack,) = out.only.records
    assert ack.payload == b""
    assert (ack.seq_start, ack.ack) == (ISN + 1, SERVER_ISN + 1)
    assert out.only.sequenced is True


def test_a_coalesced_records_ack_carries_the_edge_the_merge_needs(
    tmp_path: pathlib.Path,
):
    """Where the ack stops being decoration.

    The merge releases a stream's next record once every peer record it
    acknowledges has been emitted, so the ack a coalesced record carries is
    what places it.  Here the client's two segments coalesce into one record
    and carry *different* acks — the second is stale, the peer's acks having
    been reordered on the wire — so taking either the first or the last
    arrival's would understate what the sender had seen and lose the edge to
    the banner.  The maximum over the contributors keeps it.
    """
    server = {"src": SERVER_IP, "dst": CLIENT_IP,
              "src_port": SERVER_PORT, "dst_port": CLIENT_PORT}
    out = to_zpf(
        capture_of([
            tcp_packet(seq=ISN, flags=TCP_SYN),
            tcp_packet(**server, seq=SERVER_ISN, ack=ISN + 1,
                       flags=TCP_SYN | TCP_ACK),
            tcp_packet(**server, seq=SERVER_ISN + 1, ack=ISN + 1,
                       flags=TCP_PSH | TCP_ACK, payload=b"banner"),
            # Acks the banner; no PSH, so the run stays open.
            tcp_packet(seq=ISN + 1, ack=SERVER_ISN + 7, flags=TCP_ACK,
                       payload=b"GET"),
            # A stale ack on the segment that completes the run.
            tcp_packet(seq=ISN + 4, ack=SERVER_ISN + 1,
                       flags=TCP_PSH | TCP_ACK, payload=b" /"),
        ]),
        tmp_path,
        sequenced=True,
    )

    session = out.only
    zpf.verify_sequenced(session.records,
                         participant_count=len(session.participants))

    request = session.by(0)[-1]
    assert request.payload == b"GET /"
    assert request.ack == SERVER_ISN + 7

    # And the edge is honoured: the record acknowledging the banner is stored
    # after it.
    payloads = [r.payload for r in session.records]
    assert payloads.index(b"banner") < payloads.index(b"GET /")


@pytest.mark.parametrize("name", ALL_CAPTURES)
def test_every_capture_sequences_without_diagnostics(
    tmp_path: pathlib.Path, name: str,
):
    """The assertion that matters, with the flag on."""
    out = to_zpf(CAPTURES / name, tmp_path, sequenced=True)

    assert out.diagnostics == []
    assert out.unplaceable == []
    for session in out.sessions:
        if session.sequenced:
            zpf.verify_sequenced(session.records,
                                 participant_count=len(session.participants))


@pytest.mark.parametrize("name", ALL_CAPTURES)
def test_sequencing_changes_order_but_never_content(
    tmp_path: pathlib.Path, name: str,
):
    """A stored order is a presentation choice; the streams are the data."""
    plain = to_zpf(CAPTURES / name, tmp_path / "plain")
    seq = to_zpf(CAPTURES / name, tmp_path / "seq", sequenced=True)

    assert len(plain.sessions) == len(seq.sessions)
    for before, after in zip(plain.sessions, seq.sessions, strict=True):
        for pid in {r.sender_pid for r in before.records}:
            assert before.stream(pid) == after.stream(pid)


# ── the trade-off it carries ────────────────────────────────────────────


def test_a_session_that_never_ends_is_still_written(tmp_path: pathlib.Path):
    """Linearizing holds the session until it ends; capture-end is an ending."""
    out = to_zpf(tcp_segments([Seg(1, b"unfinished", flags=TCP_PSH)]),
                 tmp_path, sequenced=True)

    assert out.only.end_reason == "capture-end"
    assert out.only.stream(0) == b"unfinished"


def test_a_timed_out_flow_sequences_each_of_its_sessions(tmp_path: pathlib.Path):
    """A flow split by the idle timeout becomes two sessions, both buffered."""
    out = to_zpf(
        capture_of(
            [Seg(1, b"early", flags=TCP_PSH).frame(), Seg(6, b"late", flags=TCP_PSH).frame()],
            step_us=60_000_000,
        ),
        tmp_path,
        options=ReassemblyOptions(session_timeout=10.0),
        sequenced=True,
    )

    assert out.diagnostics == []
    assert [s.sequenced for s in out.sessions] == [True, True]
    assert out.sessions[0].stream(0) == b"early"
    assert out.sessions[1].stream(0) == b"late"


def test_a_reset_session_sequences_too(tmp_path: pathlib.Path):
    out = to_zpf(
        capture_of([
            *conversation(),
            tcp_packet(seq=ISN + 9, ack=SERVER_ISN + 7, flags=TCP_ACK | TCP_FIN),
        ]),
        tmp_path,
        sequenced=True,
    )

    assert out.diagnostics == []
    zpf.verify_sequenced(out.only.records, participant_count=2)
