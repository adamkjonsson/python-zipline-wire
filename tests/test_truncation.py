"""What a conversion says when the capture itself was cut short.

A capture taken with ``tcpdump -s`` holds less of each packet than crossed the
wire, so every payload past the limit reaches a record short.  Nothing in the
payload says so — a datagram cut to 78 bytes looks exactly like a datagram the
sender chose to make 78 bytes long — which is why the count and the capture's
snaplen are written out rather than inferred later.
"""

from __future__ import annotations

import pathlib

import zpf
from helpers import (
    TCP_ACK,
    TCP_PSH,
    capture_of,
    tcp_packet,
    to_zpf,
    udp_packet,
)

from zpfwire import CaptureReader

SNAPLEN = 120
"""Short enough to cut the payload and long enough to keep every header."""


# ── the reader ──────────────────────────────────────────────────────────


def test_the_reader_reports_the_limit_the_capture_was_taken_with():
    reader = CaptureReader(file_object=capture_of(
        [tcp_packet(seq=1, payload=b"x" * 200, flags=TCP_ACK | TCP_PSH)],
        snaplen=SNAPLEN,
    ))

    assert reader.snaplen == SNAPLEN
    assert [pkt.truncated for pkt in reader] == [True]


def test_a_capture_with_no_limit_states_none():
    """65535 is the file header's spelling of *nothing was cut*, not a limit."""
    reader = CaptureReader(file_object=capture_of([tcp_packet(payload=b"x" * 20)]))

    assert reader.snaplen is None
    assert [pkt.truncated for pkt in reader] == [False]


def test_a_packet_shorter_than_the_limit_is_not_truncated():
    """The limit applies to every record; only the ones it reached were cut."""
    reader = CaptureReader(file_object=capture_of(
        [
            tcp_packet(seq=1, payload=b"s", flags=TCP_ACK | TCP_PSH),
            tcp_packet(seq=2, payload=b"l" * 200, flags=TCP_ACK | TCP_PSH),
        ],
        snaplen=SNAPLEN,
    ))

    assert [pkt.truncated for pkt in reader] == [False, True]


# ── what the conversion reports ─────────────────────────────────────────


def test_a_truncated_tcp_segment_is_counted(tmp_path: pathlib.Path):
    """TCP shows the loss twice: as this count, and as the gap it leaves.

    The next segment's sequence number skips the bytes the snaplen cut, so the
    reassembler commits a gap over them — which is the honest outcome, since
    those bytes are not in the file to write.
    """
    capture = capture_of(
        [
            tcp_packet(seq=1, payload=b"x" * 200, flags=TCP_ACK | TCP_PSH),
            tcp_packet(seq=201, payload=b"y" * 200, flags=TCP_ACK | TCP_PSH),
        ],
        snaplen=SNAPLEN,
    )

    out = to_zpf(capture, tmp_path)

    assert out.stats.truncated == 2
    assert out.stats.gaps == 1
    assert out.stats.payload_bytes < 400


def test_a_truncated_udp_datagram_is_counted_because_nothing_else_shows_it(
    tmp_path: pathlib.Path,
):
    """A datagram has no sequence numbers, so a short one leaves no other trace."""
    capture = capture_of([udp_packet(payload=b"z" * 200)], snaplen=SNAPLEN)

    out = to_zpf(capture, tmp_path)

    assert out.stats.truncated == 1
    assert out.stats.gaps == 0
    assert len(out.only.stream(0)) < 200


def test_a_whole_capture_counts_none(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([tcp_packet(seq=1, payload=b"x" * 20, flags=TCP_PSH)]), tmp_path)

    assert out.stats.truncated == 0
    assert "truncated" not in out.stats.summary()


def test_the_count_is_reported(tmp_path: pathlib.Path):
    capture = capture_of([udp_packet(payload=b"z" * 200)], snaplen=SNAPLEN)

    out = to_zpf(capture, tmp_path)

    assert "truncated    1 packet(s) (payload cut by snaplen)" in out.stats.summary()


# ── what the file says ──────────────────────────────────────────────────


def test_the_snaplen_is_recorded_on_the_capture_source(tmp_path: pathlib.Path):
    """It explains the short payloads, so it belongs with the capture's provenance.

    The Source Descriptor has no field of its own for it, so it goes in the
    block's comment.
    """
    capture = capture_of([udp_packet(payload=b"z" * 200)], snaplen=SNAPLEN)

    out = to_zpf(capture, tmp_path)

    with zpf.open(out.path) as reader:
        comments = [source.comment for source in reader.sources.values()]
    assert comments == [f"snaplen={SNAPLEN}"]


def test_an_uncut_capture_says_nothing_about_a_snaplen(tmp_path: pathlib.Path):
    out = to_zpf(capture_of([udp_packet(payload=b"z" * 20)]), tmp_path)

    with zpf.open(out.path) as reader:
        comments = [source.comment for source in reader.sources.values()]
    assert comments == [None]
