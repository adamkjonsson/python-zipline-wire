from __future__ import annotations

import hashlib
import pathlib
import time

import pytest
import zpf
from helpers import (
    CAPTURES,
    TCP_PSH,
    Seg,
    capture_of,
    tcp_segments,
    to_zpf,
    udp_packet,
)

from zpfwire import (
    DECODER_NAME,
    CaptureReader,
    ReassemblyOptions,
    SkipReason,
    capture_to_zpf,
)

ALL_CAPTURES = sorted(p.name for p in CAPTURES.glob("*.pcap*"))


def read(path: pathlib.Path) -> zpf.FileReader:
    return zpf.open(path)


# ── the file this tool produces ─────────────────────────────────────────


def test_the_stream_is_capture_sourced_and_transport_layer(tmp_path: pathlib.Path):
    """The whole design follows from landing in this cell of the spec's table."""
    out = to_zpf(tcp_segments([Seg(1, b"x", flags=TCP_PSH)]), tmp_path)

    with read(out.path) as f:
        session = next(iter(f.sessions()))
        kind, layer = f.stream_kind(session.descriptor.session_id, 0)

    assert kind == zpf.SourceKind.CAPTURE
    assert layer == zpf.OutputLayer.TRANSPORT


def test_the_header_names_the_tool_and_says_when_it_ran(tmp_path: pathlib.Path):
    """Build provenance: who wrote this, and when.

    Since spec ``0.19`` this is the whole of a file's account of itself — a
    ``SEQUENCED`` session no longer records what its order rests on, so what
    a consumer has to go on is the producer and its build time.
    """
    before = int(time.time())
    out = to_zpf(tcp_segments([Seg(1, b"x", flags=TCP_PSH)]), tmp_path)

    with read(out.path) as f:
        header = f.header

    assert header.creator.startswith("zpfwire ")
    assert header.produced_by.startswith("zpfwire ")
    assert before <= header.produced_at <= int(time.time())
    assert (header.version_major, header.version_minor) == zpf.SPEC_VERSION


def test_the_build_stamp_can_be_pinned_for_a_reproducible_conversion(
    tmp_path: pathlib.Path,
):
    """The stamp is the only part of the output that is not a function of input.

    So it is the only thing standing between two conversions of one capture
    and byte-identical results, and pinning it is how a caller gets them.
    """
    capture = CAPTURES / "no_errors.pcap"
    first = tmp_path / "first.zpf"
    second = tmp_path / "second.zpf"

    for sink in (first, second):
        capture_to_zpf(capture, sink, produced_at=1_600_000_000)

    assert first.read_bytes() == second.read_bytes()

    with read(first) as f:
        assert f.header.produced_at == 1_600_000_000


def test_the_build_stamp_can_be_left_off(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([Seg(1, b"x", flags=TCP_PSH)]), tmp_path,
                 produced_at=None)

    with read(out.path) as f:
        assert f.header.produced_at is None


def test_the_capture_is_declared_as_the_source_with_its_digest(tmp_path: pathlib.Path):
    path = CAPTURES / "no_errors.pcap"
    out = to_zpf(path, tmp_path)

    with read(out.path) as f:
        source = next(iter(f.sources.values()))

    expected = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    assert source.kind == zpf.SourceKind.CAPTURE
    assert source.digest == expected
    assert source.uri == str(path)
    assert source.link_type == 1


def test_the_reassembler_declares_itself_and_its_policy(tmp_path: pathlib.Path):
    """Check the Decoder Descriptor and the records that reference it.

    A head-of-pipeline reassembler SHOULD declare itself, and its params
    digest is the only place the gap policy is recorded.
    """
    options = ReassemblyOptions(reorder_window=99)
    out = to_zpf(tcp_segments([Seg(1, b"x", flags=TCP_PSH)]), tmp_path, options=options)

    with read(out.path) as f:
        decoder = next(iter(f.decoders.values()))
        record = next(iter(next(iter(f.sessions())).records()))

    assert decoder.name == DECODER_NAME
    assert decoder.output_layer == zpf.OutputLayer.TRANSPORT
    assert decoder.params_digest == options.params_digest()
    assert record.decoder_id == decoder.decoder_id


def test_a_different_policy_gives_a_different_params_digest():
    assert (
        ReassemblyOptions(reorder_window=1).params_digest()
        != ReassemblyOptions(reorder_window=2).params_digest()
    )
    assert ReassemblyOptions().params_digest() == ReassemblyOptions().params_digest()


def test_sessions_are_not_claimed_to_be_sequenced(tmp_path: pathlib.Path):
    """Records go out in capture order; no total order has been committed."""
    out = to_zpf(tcp_segments([
        Seg(1, b"a", flags=TCP_PSH),
        Seg(1, b"b", flags=TCP_PSH, from_client=False),
    ]), tmp_path)

    with read(out.path) as f:
        for session in f.sessions():
            assert not session.sequenced


def test_the_tick_rate_follows_the_capture(tmp_path: pathlib.Path):
    out = to_zpf(tcp_segments([Seg(1, b"x", flags=TCP_PSH)]), tmp_path)
    with read(out.path) as f:
        assert f.header.tick_hz == 1_000_000

    out = to_zpf(tcp_segments([Seg(1, b"x", flags=TCP_PSH)]), tmp_path, tick_hz=1_000_000_000)
    with read(out.path) as f:
        assert f.header.tick_hz == 1_000_000_000


# ── the JSON-Lines face ─────────────────────────────────────────────────


def test_the_jsonl_face_is_written_and_reads_back(tmp_path: pathlib.Path):
    out = tmp_path / "out.jsonl"
    capture_to_zpf(CAPTURES / "http_example.pcapng", out, face="jsonl")

    text = out.read_text()
    assert '"type":"file"' in text.replace(", ", ",")

    with zpf.open(out) as f:
        sessions = list(f.sessions())
        for session in sessions:
            list(session.records())
        assert f.diagnostics == []
    assert sessions


# ── selecting what to convert ───────────────────────────────────────────


def test_udp_can_be_excluded(tmp_path: pathlib.Path):
    frames = [
        Seg(1, b"tcp", flags=TCP_PSH).frame(),
        udp_packet(payload=b"udp"),
    ]
    out = to_zpf(capture_of(frames), tmp_path, udp=False)

    assert [s.proto for s in out.sessions] == ["tcp"]
    assert out.stats.skipped["udp-not-requested"] == 1


def test_tcp_can_be_excluded(tmp_path: pathlib.Path):
    frames = [
        Seg(1, b"tcp", flags=TCP_PSH).frame(),
        udp_packet(payload=b"udp"),
    ]
    out = to_zpf(capture_of(frames), tmp_path, tcp=False)

    assert [s.proto for s in out.sessions] == ["udp"]


def test_excluding_everything_is_refused(tmp_path: pathlib.Path):
    with pytest.raises(ValueError, match="at least one"):
        capture_to_zpf(CAPTURES / "udp.pcap", tmp_path / "x.zpf", tcp=False, udp=False)


def test_a_packet_filter_excludes_and_counts(tmp_path: pathlib.Path):
    frames = [
        Seg(1, b"keep", flags=TCP_PSH).frame(),
        udp_packet(payload=b"drop"),
        udp_packet(payload=b"drop too"),
    ]
    out = to_zpf(capture_of(frames), tmp_path, packet_filter=lambda p: p.protocol == "tcp")

    assert out.stats.filtered == 2
    assert [s.proto for s in out.sessions] == ["tcp"]


# ── every fixture, end to end ───────────────────────────────────────────


@pytest.mark.parametrize("name", ALL_CAPTURES)
def test_every_capture_produces_a_file_that_reads_back_clean(
    tmp_path: pathlib.Path, name: str,
):
    """The load-bearing assertion: zpf accepts what we wrote, with no findings.

    Two lists since spec ``0.19``.  A record the offset space cannot place
    breaks no rule, so the file reads clean and ``unplaceable`` is the only
    thing that says otherwise — and a producer writing one has put its bytes
    in no offset, which is a bug every time.  This project shipped exactly
    that for months, as the handshake record one below the origin.
    """
    out = to_zpf(CAPTURES / name, tmp_path)

    assert out.diagnostics == []
    assert out.unplaceable == []


@pytest.mark.parametrize("name", ALL_CAPTURES)
def test_every_participant_is_contiguous(tmp_path: pathlib.Path, name: str):
    """Every participant this tree writes is ``adjacency = contiguous`` (spec 0.21).

    The Participant Descriptor's ``adjacency`` field is inert on a
    transport-layer participant — its offsets come from sequence numbers, so
    stored neighbours join by construction — and the specification forbids a
    writer to set ``units`` there.  A capture-sourced, transport-layer file is
    the only kind this project writes, so ``contiguous`` is the only
    conformant value and the writer's default supplies it; this pins the
    policy, so that a later change passing ``adjacency=`` through
    ``FlowTracker.participant`` is caught.  ``is_unit_sequence`` is asked of
    the reader's view, which is layer-aware, so it also pins that every
    participant resolved to the transport layer.
    """
    out = to_zpf(CAPTURES / name, tmp_path)

    with zpf.open(out.path) as reader:
        for session in reader.sessions():
            for participant in session.participants:
                assert participant.adjacency is zpf.Adjacency.CONTIGUOUS
            for view in session.reassemble():
                assert view.is_unit_sequence is False


@pytest.mark.parametrize("name", ALL_CAPTURES)
def test_no_capture_loses_bytes_without_counting_them(tmp_path: pathlib.Path, name: str):
    reader = CaptureReader(path=CAPTURES / name)
    observed = sum(len(p.payload) for p in reader)

    out = to_zpf(CAPTURES / name, tmp_path)
    accounted = (
        out.stats.payload_bytes
        + out.stats.overlap_bytes
        + out.stats.duplicate_bytes
        + out.stats.late_bytes
        + out.stats.paws_bytes
    )

    assert accounted == observed


@pytest.mark.parametrize("name", ALL_CAPTURES)
def test_every_packet_is_converted_skipped_or_filtered(tmp_path: pathlib.Path, name: str):
    out = to_zpf(CAPTURES / name, tmp_path)
    stats = out.stats

    # The reader streams, so a packet count exists only once it has read the
    # file; and an incomplete datagram is counted without ever being a packet,
    # so it is the one skip that is not also a packet.
    reader = CaptureReader(path=CAPTURES / name)
    list(reader)
    total = reader.packet_count + reader.skipped[SkipReason.INCOMPLETE_DATAGRAM]

    assert stats.converted + sum(stats.skipped.values()) + stats.filtered == total


def test_http_payloads_reach_the_output(tmp_path: pathlib.Path):
    """The end-to-end form of the packeteer#61 regression."""
    out = to_zpf(CAPTURES / "http_example.pcapng", tmp_path)

    payloads = b"".join(r.payload for s in out.sessions for r in s.records)
    assert b"HTTP/1." in payloads
    assert out.stats.payload_bytes == 3138


def test_a_lossless_capture_reports_itself_lossless(tmp_path: pathlib.Path):
    out = to_zpf(CAPTURES / "no_errors.pcap", tmp_path)

    assert out.stats.lossless
    assert out.stats.gaps == 0


def test_a_lossy_capture_reports_its_gaps(tmp_path: pathlib.Path):
    out = to_zpf(CAPTURES / "packet_loss.pcap", tmp_path)

    assert out.stats.gaps > 0
    assert not out.stats.lossless


# ── reporting ───────────────────────────────────────────────────────────


def test_the_summary_mentions_what_was_lost(tmp_path: pathlib.Path):
    out = to_zpf(CAPTURES / "packet_loss.pcap", tmp_path)
    summary = out.stats.summary()

    assert "sessions" in summary
    assert "gaps" in summary


def test_skipped_packets_are_reported_by_reason(tmp_path: pathlib.Path):
    out = to_zpf(CAPTURES / "sctp.pcap", tmp_path)

    assert out.stats.skipped["not-tcp-or-udp"] > 0
    assert "not-tcp-or-udp" in out.stats.summary()


def test_the_packet_count_includes_the_packets_that_were_skipped(
    tmp_path: pathlib.Path,
):
    """A capture converting nothing still has to say how much it looked at.

    Counting inside the conversion loop only ever saw the survivors, so a
    capture of entirely unconvertible traffic reported zero packets.
    """
    out = to_zpf(CAPTURES / "sctp.pcap", tmp_path)

    assert out.stats.converted == 0
    assert out.stats.packets == out.stats.skipped["not-tcp-or-udp"] > 0


# ── options validation ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"overlap": "favour-old"}, "overlap must be one of"),
        # Offered until 0.2.0 and never applied; refused rather than ignored,
        # so a digest never again names a policy no code ran.
        ({"overlap": "favor-new"}, "overlap must be one of"),
        ({"reorder_window": -1}, "reorder_window"),
        ({"flush_timeout": -1}, "flush_timeout"),
        ({"session_timeout": -1}, "session_timeout"),
    ],
)
def test_bad_options_are_rejected(kwargs: dict[str, object], match: str):
    with pytest.raises(ValueError, match=match):
        ReassemblyOptions(**kwargs)  # type: ignore[arg-type]
