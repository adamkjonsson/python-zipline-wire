"""A `.zpf` of packets as input (#35): the same sessions a capture gives, citing their packets.

The load-bearing claim is a differential one.  Every fixture capture is
repackaged as a ``.zpf`` of packet records — the shape a tunnel decryptor
writes — and converted again: the sessions, participants, records, hints,
flags and timestamps must be the ones the capture gave, and the file must
meet the coverage guarantee against its input.  What may differ is stated,
and asserted rather than excluded: the Source, the spans, how discards are
addressed, the ``skipped`` regions the stage fills in, and the order of two
directions' records sharing a timestamp, which a ``.zpf`` does not carry.
"""

from __future__ import annotations

import io
import json
import pathlib
import socket
import struct

import pytest
import zpf
from helpers import (
    CAPTURES,
    TCP_ACK,
    TCP_PSH,
    VECTORS,
    Seg,
    capture_of,
    packets_zpf,
    tcp_packet,
    tcp_segments,
    udp_packet,
)
from packeteer.generate.ethernet import EthernetHeader
from packeteer.generate.fragmentation import fragment_ipv4
from packeteer.generate.ip import IPHeader
from test_tcp import ISN, PAST_THE_WRAP, handshake

from zpfwire import (
    OVERLAP_POLICIES,
    REASON_UNDECODABLE,
    SKIP_FRAGMENTED_UDP,
    ReassemblyOptions,
    capture_to_zpf,
    input_kind,
    packets_to_zpf,
)

FIXTURES = sorted(p.name for p in CAPTURES.glob("*.pcap*"))
SHAPES = [zpf.Adjacency.UNITS, zpf.Adjacency.CONTIGUOUS]
PINNED = 1_700_000_000
"""``produced_at`` for every derived file here: the stage requires one."""

LOSS = (
    "sessions", "records", "payload_bytes", "gaps", "late_bytes", "late_reordered_bytes",
    "late_retransmitted_bytes", "overlap_bytes", "duplicates", "duplicate_bytes", "paws_bytes",
    "acked_swaps", "acked_fallback_bytes", "bad_checksum", "checksum_dropped_bytes", "truncated",
)
"""Every figure that says what reassembly decided, which must not depend on the input's kind."""


def shape(path: pathlib.Path) -> list[tuple[object, ...]]:
    """Everything a conversion decided, per session, with each sender's records in order.

    Records are grouped by sender rather than taken in stored order: two
    directions' records that share a timestamp have no order in a ``.zpf``
    of packets, so the interleaving across participants is the one thing a
    conversion of one may choose differently from a capture's.
    """
    sessions = []
    with zpf.open(path) as reader:
        for session in reader.sessions():
            endpoint = {p.participant_id: p.endpoint for p in session.participants}
            senders: dict[str, list[tuple[object, ...]]] = {}
            for r in session.records():
                senders.setdefault(endpoint[r.sender_pid], []).append(
                    (r.payload, int(r.flags), r.seq_start, r.ack, r.timestamp, r.ts_first),
                )
            sessions.append((
                session.proto,
                session.key,
                session.end.reason if session.end else None,
                bool(session.sequenced),
                sorted((p.endpoint, p.isn, p.tcp_role) for p in session.participants),
                sorted(senders.items()),
            ))
        assert reader.diagnostics == [] and reader.unplaceable == []
    return sessions


def convert_both(
    capture: pathlib.Path | io.BytesIO,
    tmp_path: pathlib.Path,
    **kwargs: object,
) -> tuple[object, pathlib.Path, object, pathlib.Path, pathlib.Path]:
    """Convert *capture* directly, and again as a `.zpf` of packets."""
    shape_kwargs = {k: kwargs.pop(k) for k in ("adjacency", "label", "fields", "interleave")
                    if k in kwargs}
    tmp_path.mkdir(parents=True, exist_ok=True)
    direct, packets = tmp_path / "direct.zpf", tmp_path / "packets.zpf"
    inner = tmp_path / "inner.zpf"
    if isinstance(capture, io.BytesIO):
        capture.seek(0)
    direct_stats = capture_to_zpf(capture, direct, produced_at=None, **kwargs)  # type: ignore[arg-type]
    packets_zpf(capture, packets, **shape_kwargs)  # type: ignore[arg-type]
    inner_stats = packets_to_zpf(packets, inner, produced_at=PINNED, **kwargs)  # type: ignore[arg-type]
    return direct_stats, direct, inner_stats, inner, packets


# ── the differential ────────────────────────────────────────────────────


@pytest.mark.parametrize("policy", OVERLAP_POLICIES)
@pytest.mark.parametrize("adjacency", SHAPES, ids=lambda a: a.name.lower())
@pytest.mark.parametrize("name", FIXTURES)
def test_a_packets_file_converts_to_the_sessions_of_its_capture(
    tmp_path: pathlib.Path, name: str, adjacency: zpf.Adjacency, policy: str,
):
    """Every fixture, as kober's ``units`` shape and the vector's ``contiguous`` one."""
    direct_stats, direct, inner_stats, inner, packets = convert_both(
        CAPTURES / name, tmp_path, adjacency=adjacency,
        options=ReassemblyOptions(overlap=policy),
    )

    assert shape(inner) == shape(direct)
    for figure in LOSS:
        assert getattr(inner_stats, figure) == getattr(direct_stats, figure), figure
    # A frame with no IP header is not a packet record, so the only packets
    # the capture has and the .zpf does not are the ones it skipped as non-IP.
    assert inner_stats.packets == direct_stats.packets - direct_stats.skipped["non-ip"]
    assert zpf.check_coverage(inner, packets) == []
    assert zpf.check_extents(inner) == []
    assert_cites_whole_packets(inner, packets)
    # Every seam a break (units), or one declared Discontinuity (contiguous):
    # either way crossed under seq_start, which spec 0.22 permits.
    assert zpf.check_splice(inner, packets) == []


def assert_cites_whole_packets(inner: pathlib.Path, packets: pathlib.Path) -> None:
    """Every record cites runs of whole packets, in the input's own namespace."""
    with zpf.open(packets) as reader:
        (session,) = reader.sessions()
        packet_ranges = {
            (session.session_id, pid, start, end)
            for pid in (0, 1)
            for record, (start, end) in zip(
                (r for r in session.records() if r.sender_pid == pid),
                session.ranges(pid), strict=True,
            )
            if record.content_type in (zpf.NET_IP, zpf.NET_ETHERNET)
        }
    with zpf.open(inner) as reader:
        for out in reader.sessions():
            for record in out.records():
                assert record.spans, "every record cites its input"
                for span in record.spans:
                    covered = [
                        (s, p, a, b) for (s, p, a, b) in packet_ranges
                        if (s, p) == (span.session_id, span.participant_id)
                        and span.off_start <= a and b <= span.off_end
                    ]
                    assert covered, "a span is a run of whole packets"
                    assert sum(b - a for _, _, a, b in covered) <= span.off_end - span.off_start


def test_a_splice_check_accepts_a_transport_record_crossing_a_declared_break(
    tmp_path: pathlib.Path,
):
    """The vector's shape: one declared Discontinuity, which a TCP record may cross.

    Spec ``0.22`` lets a transport record carrying ``seq_start`` cite across
    an input break (zipline#152); python-zipline's checker reported it until
    python-zipline#90.  ``packet_loss.pcap`` has a record that does.
    """
    _, _, _, inner, packets = convert_both(CAPTURES / "packet_loss.pcap", tmp_path,
                                           adjacency=zpf.Adjacency.CONTIGUOUS)

    assert zpf.check_splice(inner, packets) == []


def test_the_order_records_are_stored_in_across_participants_does_not_matter(
    tmp_path: pathlib.Path,
):
    """One direction stored before the other, as kober does: the reader merges by time."""
    _, _, _, apart, _ = convert_both(CAPTURES / "http_stream_1.pcap", tmp_path / "apart")
    _, _, _, mixed, _ = convert_both(CAPTURES / "http_stream_1.pcap", tmp_path / "mixed",
                                     interleave=True)

    assert shape(apart) == shape(mixed)


# ── the specification's tunnel ──────────────────────────────────────────


def test_the_tunnel_vectors_packets_rebuild_its_inner_file(tmp_path: pathlib.Path):
    """``vectors/tunnel``: ``packets.zpf`` converts to ``inner.zpf``'s two flows.

    The stated differences are three.  The session key is spelled ``a <-> b``
    here, ``a -> b`` there.  This tree declares each flow's silent peer.  And
    no participant carries an ``isn``: the vector's ``inner.zpf`` declares
    one, but ``packets.zpf`` holds no SYN to read it from.
    """
    tunnel = VECTORS / "tunnel"
    out = tmp_path / "inner.zpf"
    stats = packets_to_zpf(tunnel / "packets.zpf", out, produced_at=PINNED)

    def records(path: pathlib.Path) -> list[tuple[object, ...]]:
        found = []
        with zpf.open(path) as reader:
            for session in reader.sessions():
                for r in session.records():
                    found.append((
                        r.payload, r.seq_start, r.ack, int(r.flags),
                        tuple((s.session_id, s.participant_id, s.off_start, s.off_end)
                              for s in r.spans),
                    ))
            assert reader.diagnostics == [] and reader.unplaceable == []
        return sorted(found, key=lambda r: r[1])

    assert records(out) == records(tunnel / "inner.zpf")
    assert stats.sessions == 2 and stats.gaps == 1
    expected_extents = [
        json.loads(line)["input_extents"]
        for line in (tunnel / "inner.jsonl").read_text().splitlines()
        if json.loads(line)["type"] == "session_end"
    ]
    with zpf.open(out) as reader:
        for session in reader.sessions():
            assert {p.isn for p in session.participants} == {None}
            assert [(e.session_id, e.participant_id, e.extent) for e in session.end.input_extents] \
                == [(e["session_id"], e["pid"], e["extent"]) for e in expected_extents[0]]
    assert zpf.check_coverage(out, tunnel / "packets.zpf") == []
    assert zpf.check_extents(out) == []


# ── what the stage owes, and what it cannot yet do ──────────────────────


def _fragmented_udp() -> io.BytesIO:
    """One UDP datagram, fragmented in three, over IPv4 with no checksum."""
    payload = bytes(range(256)) * 4
    datagram = struct.pack("!HHHH", 12345, 53, 8 + len(payload), 0) + payload
    header = IPHeader("10.0.0.1", "10.0.0.2", socket.IPPROTO_UDP, identification=4242)
    eth = EthernetHeader("00:00:00:00:00:02", "00:00:00:00:00:01")
    return capture_of(fragment_ipv4(header, datagram, mtu=400, eth_header=eth))


def test_a_fragmented_udp_datagram_is_marked_undecodable(tmp_path: pathlib.Path):
    """No record without ``seq_start`` may cite several input units (zipline#166).

    A capture conversion writes the reassembled datagram.  Over a ``.zpf``
    each fragment is its own input record, so the datagram would cite three
    of them, and a UDP record has no sequence numbers to say they join; the
    fragments are declared ``undecodable`` instead, and counted.
    """
    direct_stats, _, inner_stats, inner, packets = convert_both(_fragmented_udp(), tmp_path)

    assert direct_stats.records == 1
    assert inner_stats.records == 0
    assert inner_stats.skipped[SKIP_FRAGMENTED_UDP] == 1
    with zpf.open(inner) as reader:
        marked = [u for u in reader.undecoded if u.reason == REASON_UNDECODABLE]
        assert len(marked) == 3
        assert all("zipline#166" in (u.comment or "") for u in marked)
    assert zpf.check_coverage(inner, packets) == []


def test_fragmented_tcp_is_one_record(tmp_path: pathlib.Path):
    """``fragmentation.pcap`` fragments TCP, whose record carries ``seq_start``."""
    _, direct, _, inner, _ = convert_both(CAPTURES / "fragmentation.pcap", tmp_path)

    assert shape(inner) == shape(direct)


def test_a_flow_that_resumes_after_a_timeout_gets_a_new_session(tmp_path: pathlib.Path):
    """Two sessions on one key, as a capture conversion writes them.

    The stage gives a key a new session once its last one has ended
    (python-zipline#88); before that, the second session could not be opened.
    """
    silent = capture_of(
        [Seg(1, b"early", flags=TCP_PSH).frame(), Seg(6, b"late", flags=TCP_PSH).frame()],
        step_us=60_000_000,
    )
    direct_stats, direct, _, inner, packets = convert_both(
        silent, tmp_path, options=ReassemblyOptions(session_timeout=10.0),
    )

    assert direct_stats.sessions == 2
    assert shape(inner) == shape(direct)
    assert [s[2] for s in shape(inner)] == ["timeout", "capture-end"]
    assert zpf.check_coverage(inner, packets) == []
    assert zpf.check_extents(inner) == []


def test_the_session_after_a_capture_gap_is_on_the_same_key(tmp_path: pathlib.Path):
    """The specification's exit for the unmeasurable hole: end the session, open another.

    "On the same key, with no ``isn``" — which ``shape`` compares, together
    with the two Session End reasons.
    """
    gapped = capture_of(handshake() + [
        Seg(ISN + 1, b"aaaa", flags=TCP_PSH, timestamps=(100, 0)).frame(ack=5001),
        Seg(ISN + 1 + PAST_THE_WRAP, b"zzzz", flags=TCP_PSH, timestamps=(900, 0)).frame(ack=5001),
    ])
    direct_stats, direct, _, inner, packets = convert_both(gapped, tmp_path)

    assert direct_stats.sessions == 2
    assert shape(inner) == shape(direct)
    assert [s[2] for s in shape(inner)] == ["capture-gap", "capture-end"]
    assert zpf.check_coverage(inner, packets) == []
    assert zpf.check_extents(inner) == []


def test_drop_discards_a_corrupt_segment_and_keeps_a_corrupt_datagram(tmp_path: pathlib.Path):
    """``checksum="drop"`` over a `.zpf`, as over a capture: TCP only.

    The corrupt segment's packet is marked ``bad-checksum`` whole, and its
    resend supplies the bytes.  The corrupt datagram is written, since a UDP
    stream cannot show one missing.
    """
    capture = capture_of([
        tcp_packet(seq=1, payload=b"BAD!", flags=TCP_ACK | TCP_PSH, checksum=0x1234),
        tcp_packet(seq=1, payload=b"good", flags=TCP_ACK | TCP_PSH),
        udp_packet(payload=b"junk", checksum=0x1234),
    ])
    direct_stats, direct, inner_stats, inner, packets = convert_both(
        capture, tmp_path, options=ReassemblyOptions(checksum="drop"),
    )

    assert shape(inner) == shape(direct)
    assert inner_stats.bad_checksum == direct_stats.bad_checksum == 2
    assert inner_stats.checksum_dropped_bytes == direct_stats.checksum_dropped_bytes == 4
    with zpf.open(inner) as reader:
        payloads = sorted(r.payload for s in reader.sessions() for r in s.records() if r.payload)
        assert payloads == [b"good", b"junk"]
        assert [u.reason for u in reader.undecoded if u.reason != "skipped"] == ["bad-checksum"]
    assert zpf.check_coverage(inner, packets) == []


# ── selection ───────────────────────────────────────────────────────────


def test_a_decoder_private_label_is_selected_by_name(tmp_path: pathlib.Path):
    """zipline-kober labels its packets ``dec:ip-packet``; the default selects ``net:`` only."""
    capture = tcp_segments([Seg(1, b"hello", flags=TCP_PSH)])
    packets = packets_zpf(capture, tmp_path / "packets.zpf", label="dec:ip-packet")

    unselected = packets_to_zpf(packets, tmp_path / "none.zpf", produced_at=PINNED)
    selected = packets_to_zpf(packets, tmp_path / "some.zpf", produced_at=PINNED,
                              content_type="dec:ip-packet")

    assert (unselected.records_selected, unselected.records) == (0, 0)
    assert selected.records_selected == 1 and selected.records == 1
    assert zpf.check_coverage(tmp_path / "none.zpf", packets) == []


def test_ethernet_frames_are_parsed_as_ethernet(tmp_path: pathlib.Path):
    """``net:ethernet`` means ``LINKTYPE_ETHERNET``, frame check sequence excluded."""
    _, direct, _, inner, _ = convert_both(CAPTURES / "http.pcap", tmp_path,
                                          label=zpf.NET_ETHERNET)

    assert shape(inner) == shape(direct)


@pytest.mark.parametrize(("kwargs", "message"), [
    ({"link_type": 101}, "needs a content_type"),
    ({"content_type": "net:ppp"}, "not a net: label"),
    ({"content_type": "net:ip", "link_type": 1}, "means link type 101"),
    ({"produced_at": None}, "must say when it was built"),
    ({"tcp": False, "udp": False}, "at least one"),
])
def test_an_inconsistent_request_is_refused(
    tmp_path: pathlib.Path, kwargs: dict[str, object], message: str,
):
    kwargs.setdefault("produced_at", PINNED)
    with pytest.raises(ValueError, match=message):
        packets_to_zpf(VECTORS / "tunnel" / "packets.zpf", tmp_path / "out.zpf", **kwargs)


def test_an_input_is_told_apart_by_its_first_bytes():
    assert input_kind(CAPTURES / "http.pcap") == "capture"
    assert input_kind(CAPTURES / "dns_example.pcapng") == "capture"
    assert input_kind(VECTORS / "tunnel" / "packets.zpf") == "zpf"
    assert input_kind(VECTORS / "tunnel" / "packets.jsonl") == "zpf"


def test_the_jsonl_face_is_written_and_names_its_creator(tmp_path: pathlib.Path):
    """The JSON-Lines projection, as for a capture, with the File Header's ``creator``."""
    binary, jsonl = tmp_path / "inner.zpf", tmp_path / "inner.jsonl"
    packets_to_zpf(VECTORS / "tunnel" / "packets.zpf", binary, produced_at=PINNED)
    packets_to_zpf(VECTORS / "tunnel" / "packets.zpf", jsonl, produced_at=PINNED, face="jsonl")

    header = json.loads(jsonl.read_text().splitlines()[0])
    assert header["creator"] == header["produced_by"]
    assert header["creator"].startswith("zpfwire ")
    assert shape(jsonl) == shape(binary)
    assert zpf.check_coverage(jsonl, VECTORS / "tunnel" / "packets.zpf") == []
