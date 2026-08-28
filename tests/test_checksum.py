"""What happens to a packet whose transport checksum does not verify.

A receiver drops such a packet and takes the retransmission that follows.
Doing the same is a policy rather than the default, because checksum offload
makes a capture taken on a sending host report wrong checksums for traffic
that was correct on the wire.
"""

from __future__ import annotations

import io
import pathlib
import struct

import pytest
import zpf
from helpers import (
    CAPTURES,
    TCP_ACK,
    TCP_PSH,
    TCP_SYN,
    capture_of,
    tcp_packet,
    to_zpf,
    udp_packet,
)

from zpfwire import CaptureReader, ReassemblyOptions
from zpfwire.__main__ import main

ALL_CAPTURES = sorted(p.name for p in CAPTURES.glob("*.pcap*"))

DROP = ReassemblyOptions(checksum="drop")

_WRONG = 0x1234
"""A checksum no payload here produces, so the packet reads as corrupt."""


def corrupted_then_retransmitted() -> io.BytesIO:
    """One segment that arrived damaged, then the clean copy that replaced it.

    This is the shape `payload_corruption.pcap` has and the one the policy
    exists for: the damaged copy comes first, so keeping the older bytes keeps
    the wrong ones.
    """
    return capture_of([
        tcp_packet(seq=1, payload=b"BAD!", flags=TCP_ACK | TCP_PSH, checksum=_WRONG),
        tcp_packet(seq=1, payload=b"good", flags=TCP_ACK | TCP_PSH),
    ])


# ── the policy ──────────────────────────────────────────────────────────


def test_a_corrupt_segment_is_kept_by_default(tmp_path: pathlib.Path):
    """Checksum offload means dropping cannot be the default; see the docs."""
    out = to_zpf(corrupted_then_retransmitted(), tmp_path)

    assert out.only.stream(0) == b"BAD!"
    assert out.diagnostics == []


def test_dropping_takes_the_clean_retransmission_instead(tmp_path: pathlib.Path):
    out = to_zpf(corrupted_then_retransmitted(), tmp_path, options=DROP)

    assert out.only.stream(0) == b"good"
    assert out.diagnostics == []


def test_a_bad_checksum_is_counted_even_when_the_packet_is_kept(tmp_path: pathlib.Path):
    """A conversion that keeps corrupt bytes still has to say it did."""
    out = to_zpf(corrupted_then_retransmitted(), tmp_path)

    assert out.stats.bad_checksum == 1
    assert out.stats.checksum_dropped_bytes == 0


def test_dropping_counts_the_packet_and_its_bytes(tmp_path: pathlib.Path):
    out = to_zpf(corrupted_then_retransmitted(), tmp_path, options=DROP)

    assert out.stats.bad_checksum == 1
    assert out.stats.checksum_dropped_bytes == 4
    assert out.stats.skipped["bad-checksum"] == 1
    assert out.stats.overlap_bytes == 0


def test_dropped_bytes_are_cited_as_undecoded(tmp_path: pathlib.Path):
    """They exist in the capture and reach no record, which is the whole class."""
    out = to_zpf(corrupted_then_retransmitted(), tmp_path, options=DROP)

    reasons = [block.reason for block in out.undecoded]
    assert reasons == ["bad-checksum"]
    assert out.undecoded[0].off_end - out.undecoded[0].off_start == 4


def test_a_corrupt_packet_opens_no_session(tmp_path: pathlib.Path):
    """The whole packet goes, so its SYN establishes nothing."""
    capture = capture_of([tcp_packet(seq=1, flags=TCP_SYN, checksum=_WRONG)])

    out = to_zpf(capture, tmp_path, options=DROP)

    assert out.sessions == []
    assert out.stats.sessions == 0


def test_a_corrupt_datagram_is_dropped_on_udp_too(tmp_path: pathlib.Path):
    """UDP carries a checksum as well, and a receiver treats it the same way."""
    capture = capture_of([udp_packet(payload=b"junk", checksum=_WRONG)])

    out = to_zpf(capture, tmp_path, options=DROP)

    assert out.stats.bad_checksum == 1
    assert out.stats.checksum_dropped_bytes == 4
    assert out.sessions == []


# ── what a failure is not ───────────────────────────────────────────────


def test_an_ipv4_udp_datagram_without_a_checksum_is_not_corrupt(tmp_path: pathlib.Path):
    """Zero means *not computed* over IPv4 (RFC 768), not *computed wrong*."""
    capture = capture_of([udp_packet(payload=b"fine", checksum=0)])

    out = to_zpf(capture, tmp_path, options=DROP)

    assert out.stats.bad_checksum == 0
    assert out.only.stream(0) == b"fine"


def test_a_truncated_capture_is_not_read_as_corrupt(tmp_path: pathlib.Path):
    """A snaplen cuts off bytes the checksum covers, so it cannot be checked.

    The parser clears the field it cannot compare (packeteer#92), so this
    guards an upstream promise rather than anything decided here.
    """
    capture = _truncate(capture_of([
        tcp_packet(seq=1, payload=b"x" * 200, flags=TCP_ACK | TCP_PSH),
    ]), keep=120)

    reader = CaptureReader(file_object=capture)
    views = list(reader)

    assert [view.checksum_bad for view in views] == [False]

    out = to_zpf(capture, tmp_path, options=DROP)
    assert out.stats.bad_checksum == 0


def test_a_sound_capture_reports_no_bad_checksums(tmp_path: pathlib.Path):
    out = to_zpf(CAPTURES / "no_errors.pcap", tmp_path, options=DROP)

    assert out.stats.bad_checksum == 0
    assert out.stats.checksum_dropped_bytes == 0


# ── the fixture the policy was written for ──────────────────────────────


def test_the_corruption_fixture_keeps_bytes_no_receiver_accepted(tmp_path: pathlib.Path):
    """Eleven segments were damaged and cleanly retransmitted; the wrong copy wins."""
    kept = to_zpf(CAPTURES / "payload_corruption.pcap", tmp_path)
    dropped = to_zpf(CAPTURES / "payload_corruption.pcap", tmp_path / "drop", options=DROP)

    assert kept.stats.bad_checksum == dropped.stats.bad_checksum == 11
    # The same bytes are written either way — one per damaged segment differs.
    assert kept.stats.payload_bytes == dropped.stats.payload_bytes
    kept_stream = kept.only.stream(0)
    dropped_stream = dropped.only.stream(0)
    pairs = zip(kept_stream, dropped_stream, strict=True)
    differing = [i for i, (a, b) in enumerate(pairs) if a != b]
    assert len(differing) == 11

    # Under the drop policy the clean copies are no longer overlap to discard.
    assert kept.stats.overlap_bytes == 9150
    assert dropped.stats.overlap_bytes == 0
    assert dropped.stats.checksum_dropped_bytes == 9150


@pytest.mark.parametrize("name", ALL_CAPTURES)
def test_every_capture_still_reads_back_clean_when_dropping(
    tmp_path: pathlib.Path, name: str,
):
    out = to_zpf(CAPTURES / name, tmp_path, options=DROP)

    assert out.diagnostics == []


@pytest.mark.parametrize("name", ALL_CAPTURES)
def test_dropped_bytes_are_accounted_for(tmp_path: pathlib.Path, name: str):
    """The rule stands under either policy: every byte is written or counted."""
    reader = CaptureReader(path=CAPTURES / name)
    observed = sum(len(p.payload) for p in reader)

    out = to_zpf(CAPTURES / name, tmp_path, options=DROP)
    accounted = (
        out.stats.payload_bytes
        + out.stats.overlap_bytes
        + out.stats.late_bytes
        + out.stats.checksum_dropped_bytes
    )

    assert accounted == observed


# ── the option itself ───────────────────────────────────────────────────


def test_the_policy_is_part_of_the_reproducibility_digest():
    """It decides which bytes reach the output, so it has to be hashed in."""
    assert DROP.params_digest() != ReassemblyOptions().params_digest()


def test_an_unknown_policy_is_refused():
    with pytest.raises(ValueError, match="checksum must be one of"):
        ReassemblyOptions(checksum="verify")


def test_the_cli_exposes_the_policy(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
                                    capsys: pytest.CaptureFixture[str]):
    out = tmp_path / "out.zpf"
    monkeypatch.setattr("sys.argv", [
        "zpfwire", "convert", str(CAPTURES / "payload_corruption.pcap"),
        "-o", str(out), "--checksum", "drop",
    ])
    main()

    assert "bad cksum    11 packet(s)" in capsys.readouterr().out
    with zpf.open(out) as reader:
        for session in reader.sessions():
            list(session.records())
        assert list(reader.diagnostics) == []


def _truncate(capture: io.BytesIO, *, keep: int) -> io.BytesIO:
    """Re-write a one-record pcap as if a snaplen had cut the frame short.

    The record keeps its original length, which is what tells a reader the
    bytes are missing rather than absent.
    """
    raw = bytearray(capture.getvalue())
    header, record = 24, 24 + 16
    incl, _ = struct.unpack_from("<II", raw, header + 8)
    assert keep < incl, "the frame must actually be cut"
    struct.pack_into("<I", raw, header + 8, keep)
    del raw[record + keep:record + incl]
    return io.BytesIO(bytes(raw))
