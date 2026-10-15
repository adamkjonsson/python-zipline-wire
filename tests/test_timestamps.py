"""What the six real Timestamps captures say, phase by phase.

The fixtures are packeteer's ``testcases/real/tcp_*_ts.pcap`` — real Linux
stacks, real loss, duplication, corruption, reordering and a sequence wrap,
every segment carrying the TCP Timestamps option.  Each ``0.3.0`` phase adds
the assertions its rule makes against them; Phase 0 adds only the ones the
tree already satisfies, so that a later phase which breaks one is caught
against a baseline rather than a hope.
"""

from __future__ import annotations

import io
import pathlib

import pytest
import zpf
from helpers import CAPTURES, decode_digest, to_zpf
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.pcap import write_pcap

from zpfwire import CaptureReader, ReassemblyOptions, capture_to_zpf

NO_HOLD = ReassemblyOptions(reorder_window=0)
"""Give up on every hole at once — the policy that makes a receiver-side
capture show its gaps, since the default window absorbs all of them."""

REAL = [
    "tcp_corrupt_ts.pcap",
    "tcp_dup_ts.pcap",
    "tcp_gap_ts.pcap",
    "tcp_lossy_ts.pcap",
    "tcp_reorder_ts.pcap",
    "tcp_wrap_ts.pcap",
]


def flagged(out: object) -> int:
    """How many records across the file carry ``retransmit``."""
    return sum(
        1 for s in out.sessions for r in s.records  # type: ignore[attr-defined]
        if r.flags & zpf.RecordFlags.RETRANSMIT
    )


def generated(tmp_path: pathlib.Path, **impairments: float) -> object:
    """Convert a seeded 40-segment stream under the given impairments.

    Every connection packeteer generates negotiates the option, a resend is
    rebuilt with the clock at resend time, and a duplicate is the packet
    again with only its capture time moved — so the generator produces both
    shapes on demand, reproducibly.
    """
    stream = generate_tcp_stream(
        client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=40,
        config=TCPStreamConfig(seed=7, **impairments),
    )
    buf = io.BytesIO()
    write_pcap(stream.to_pcap_tuples(), file_object=buf)
    buf.seek(0)
    return to_zpf(buf, tmp_path)


@pytest.mark.parametrize("options", [None, NO_HOLD], ids=["default", "no-hold"])
def test_a_stream_that_wraps_is_placeable(
    tmp_path: pathlib.Path, options: ReassemblyOptions | None,
):
    """``tcp_wrap_ts`` crosses 2**32 mid-stream, and every record still lands.

    The server's ISN sits 36 226 bytes below the wrap, so most of its bytes
    have a sequence number numerically *below* the ``isn`` — under the default
    policy inside one coalesced record that starts just under 2**32 and spans
    it, under ``no-hold`` in records of their own.  The offset space is
    modular and this has always worked; the point of pinning it before Phase
    3 is that the wrap-aware rules are then measured against a file that was
    already right.
    """
    kwargs = {} if options is None else {"options": options}
    out = to_zpf(CAPTURES / "tcp_wrap_ts.pcap", tmp_path, **kwargs)

    assert out.diagnostics == []
    assert out.unplaceable == []
    (session,) = out.sessions
    server = next(p for p in session.participants if p.endpoint.endswith(":8443"))
    assert server.isn == 4294931070
    past_wrap = [
        r for r in session.records
        if r.sender_pid == server.participant_id
        and (r.seq_start < server.isn or r.seq_start + len(r.payload) > 2**32)
    ]
    assert past_wrap, "no record's bytes lie past the wrap"
    # The transfer is 64 KiB.  With no hold, the four delayed pre-wrap
    # originals arrive after their gap was committed and are lost with their
    # resends: 8 × 524 late bytes, of which 4 × 524 were the only copy.
    transferred = 65536 if options is None else 65536 - 4 * 524
    assert len(session.stream(server.participant_id)) == transferred
    assert out.stats.late_bytes == (0 if options is None else 8 * 524)
    # The extent is the whole transfer under either policy — the offset space
    # is hole-inclusive, so the bytes no-hold loses are still *in* it — and
    # since spec 0.21 it is computed by unwrapping along stored order rather
    # than against the origin, which is what makes it right past the wrap.
    with zpf.open(out.path) as reader:
        (read_back,) = reader.sessions()
        pid = server.participant_id
        blocks = list(read_back.stream_blocks(pid))
        assert zpf.stream_extent(read_back.participant(pid), blocks, read_back.layer(pid)) == 65536


# ── duplicate or retransmission ─────────────────────────────────────────


def test_a_mirrored_capture_sets_no_retransmit_flag(tmp_path: pathlib.Path):
    """``tcp_dup_ts``: 10 segments seen twice, identical TSval, nothing between.

    Before the option was read every one set ``retransmit`` on its record —
    3 of 7 records — for a session in which the sender resent nothing.
    """
    out = to_zpf(CAPTURES / "tcp_dup_ts.pcap", tmp_path)

    assert flagged(out) == 0
    assert out.stats.duplicates == 10
    assert out.stats.duplicate_bytes == 5092
    assert out.stats.overlap_bytes == 0
    assert [u.reason for u in out.undecoded] == ["duplicate-discarded"] * 10
    assert out.stats.ts_fallback == {}


@pytest.mark.parametrize(("name", "flags", "overlap"), [
    ("tcp_lossy_ts.pcap", 7, 8384),
    ("tcp_reorder_ts.pcap", 4, 5240),
    ("tcp_corrupt_ts.pcap", 2, 2620),
    ("tcp_wrap_ts.pcap", 1, 2096),
])
def test_a_real_resend_keeps_its_flag(
    tmp_path: pathlib.Path, name: str, flags: int, overlap: int,
):
    """Every resend in the corpus carries a later TSval, and none is a duplicate.

    ``tcp_reorder_ts`` is the guard against over-correcting: its resends are
    *spurious* — the originals arrived, late — but the sender did resend, and
    that is what the flag says.
    """
    out = to_zpf(CAPTURES / name, tmp_path)

    assert flagged(out) == flags
    assert out.stats.duplicates == 0
    assert out.stats.overlap_bytes == overlap
    assert out.stats.ts_fallback == {}


@pytest.mark.parametrize("name", REAL)
def test_every_repeat_in_the_real_corpus_is_judged_by_evidence(
    tmp_path: pathlib.Path, name: str,
):
    """Both sides captured, every segment carrying the option: no fallback."""
    out = to_zpf(CAPTURES / name, tmp_path)

    assert out.stats.ts_fallback == {}


@pytest.mark.parametrize("name", REAL)
def test_the_accounting_identity_holds_with_duplicates(tmp_path: pathlib.Path, name: str):
    observed = sum(len(p.payload) for p in CaptureReader(path=CAPTURES / name))
    out = to_zpf(CAPTURES / name, tmp_path)
    stats = out.stats

    assert (
        stats.payload_bytes + stats.overlap_bytes + stats.duplicate_bytes
        + stats.late_bytes + stats.paws_bytes
        == observed
    )


def test_generated_duplicates_are_all_duplicates(tmp_path: pathlib.Path):
    out = generated(tmp_path, duplicate_probability=0.3)

    assert out.stats.duplicates == 18
    assert out.stats.overlap_bytes == 0
    assert flagged(out) == 0
    assert out.stats.ts_fallback == {}


def test_generated_retransmissions_are_all_retransmissions(tmp_path: pathlib.Path):
    out = generated(tmp_path, retransmission_probability=0.3)

    assert out.stats.duplicates == 0
    assert out.stats.overlap_bytes == 12028
    assert out.stats.ts_fallback == {}


def test_a_duplicated_retransmission_is_both(tmp_path: pathlib.Path):
    """``DUP[RETRANS[n]]``: the resend is a resend, its copy is a copy."""
    out = generated(tmp_path, retransmission_probability=0.3, duplicate_probability=0.3)

    assert out.stats.duplicates == 16
    assert out.stats.overlap_bytes == 13369
    assert out.stats.ts_fallback == {}


# ── why a byte was late ─────────────────────────────────────────────────


def late_reasons(out: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    for u in out.undecoded:  # type: ignore[attr-defined]
        if u.reason.startswith("late"):
            counts[u.reason] = counts.get(u.reason, 0) + 1
    return counts


def test_a_receiver_side_capture_of_loss_shows_only_resends(tmp_path: pathlib.Path):
    """``tcp_gap_ts`` with no hold: every hole is given up on, every fill is late.

    Each fill carries a TSval newer than the segment that overtook its hole —
    the sender resent after the loss — so all 13 are ``late-retransmitted``,
    and the reordered bucket, the one that says the policy was too impatient,
    is empty: no policy could have kept bytes that never arrived in time.
    """
    out = to_zpf(CAPTURES / "tcp_gap_ts.pcap", tmp_path, options=NO_HOLD)

    assert out.stats.gaps == 11
    assert out.stats.late_bytes == 6812
    assert out.stats.late_reordered_bytes == 0
    assert out.stats.late_retransmitted_bytes == 6812
    assert late_reasons(out) == {"late-retransmitted": 13}


def test_a_receiver_side_capture_of_reordering_shows_both(tmp_path: pathlib.Path):
    """``tcp_reorder_ts``: delayed originals, then the sender's spurious resends.

    Of the 8 delayed originals, 2 carry a TSval strictly older than the
    segment that overtook them and 6 share its tick — a burst-mate — which
    the option cannot separate from a resend inside the same tick, so those
    stay ``late-arrival``.  The 10 resends were sent after the overtaking
    segment, and say so.  The manifest counts the same 2-and-6.
    """
    out = to_zpf(CAPTURES / "tcp_reorder_ts.pcap", tmp_path, options=NO_HOLD)

    assert out.stats.gaps == 8
    assert out.stats.late_bytes == 9432
    assert out.stats.late_reordered_bytes == 2 * 524
    assert out.stats.late_retransmitted_bytes == 10 * 524
    assert late_reasons(out) == {
        "late-reordered": 2, "late-arrival": 6, "late-retransmitted": 10,
    }


def test_the_split_holds_across_the_wrap(tmp_path: pathlib.Path):
    """``tcp_wrap_ts``: four originals delayed past the wrap, four resends after."""
    out = to_zpf(CAPTURES / "tcp_wrap_ts.pcap", tmp_path, options=NO_HOLD)

    assert out.stats.late_reordered_bytes == 4 * 524
    assert out.stats.late_retransmitted_bytes == 4 * 524
    assert late_reasons(out) == {"late-reordered": 4, "late-retransmitted": 4}


# ── PAWS and the wrap ───────────────────────────────────────────────────


@pytest.mark.parametrize("name", REAL)
@pytest.mark.parametrize("options", [None, NO_HOLD], ids=["default", "no-hold"])
def test_neither_wrap_rule_fires_on_real_traffic(
    tmp_path: pathlib.Path, name: str, options: ReassemblyOptions | None,
):
    """A rule that emulates the receiver must agree with what the receiver did.

    Every delayed original in the corpus — including the four in
    ``tcp_wrap_ts`` that arrive after post-wrap data with an older clock —
    was kept by the real receiver, whose D-SACKs of their resends say so.
    PAWS keeps them too, because ``TS.Recent`` moves only on in-order
    arrival; and no real capture has a hole wider than a window.
    """
    kwargs = {} if options is None else {"options": options}
    out = to_zpf(CAPTURES / name, tmp_path, **kwargs)

    assert out.stats.paws_bytes == 0
    assert out.stats.wrap_resolved == 0
    assert all(s.end_reason != "capture-gap" for s in out.sessions)


def test_the_stream_that_wraps_is_untouched_by_the_wrap_rules(tmp_path: pathlib.Path):
    """``tcp_wrap_ts`` under defaults decodes exactly as it did before any rule read the option."""
    out = tmp_path / "wrap.zpf"
    capture_to_zpf(CAPTURES / "tcp_wrap_ts.pcap", out)

    assert decode_digest(out) == (
        "sha256:1b7cb603bfa511d1495a579d38540b9ee319b63f395ed90d3719a5b9a1f7eb1e"
    )


# ── favor-acked ─────────────────────────────────────────────────────────

ACKED = ReassemblyOptions(overlap="favor-acked")


def streams(out: object) -> dict[int, bytes]:
    (session,) = out.sessions  # type: ignore[attr-defined]
    return {p.participant_id: session.stream(p.participant_id) for p in session.participants}


def test_favor_acked_takes_the_bytes_the_receiver_kept(tmp_path: pathlib.Path):
    """``tcp_corrupt_ts``: five segments corrupted in flight, each resent clean.

    ``favor-old`` writes the corrupt copies.  ``favor-acked`` writes what the
    receiver's echo says it kept — which is what ``checksum="drop"`` writes
    too, arrived at from the other side: the checksum says which copy was
    damaged, the echo says which copy the receiver accepted, and on real
    traffic they agree at every one of the five offsets.
    """
    old = streams(to_zpf(CAPTURES / "tcp_corrupt_ts.pcap", tmp_path / "old"))
    acked_out = to_zpf(CAPTURES / "tcp_corrupt_ts.pcap", tmp_path / "acked", options=ACKED)
    acked = streams(acked_out)
    dropped = streams(to_zpf(CAPTURES / "tcp_corrupt_ts.pcap", tmp_path / "drop",
                             options=ReassemblyOptions(checksum="drop")))

    server = next(pid for pid, data in old.items() if len(data) == 65536)
    differing = [i for i in range(65536) if old[server][i] != acked[server][i]]
    assert differing == [13393, 21537, 28435, 31668, 58959]
    assert acked == dropped
    assert acked_out.stats.acked_swaps == 5
    assert acked_out.stats.acked_fallback_bytes == 0
    assert acked_out.stats.overlap_bytes == 5 * 524          # the five losers
    assert acked_out.diagnostics == [] and acked_out.unplaceable == []


def test_favor_acked_without_the_reverse_direction_falls_back(tmp_path: pathlib.Path):
    """The same capture with the receiver's packets filtered out: no evidence, counted."""
    def only_server(p: object) -> bool:
        return p.src_port == 8443  # type: ignore[attr-defined]

    old = streams(to_zpf(CAPTURES / "tcp_corrupt_ts.pcap", tmp_path / "old",
                         packet_filter=only_server))
    acked_out = to_zpf(CAPTURES / "tcp_corrupt_ts.pcap", tmp_path / "acked",
                       options=ACKED, packet_filter=only_server)

    assert streams(acked_out) == old
    assert acked_out.stats.acked_swaps == 0
    assert acked_out.stats.acked_fallback_bytes == 5 * 524


@pytest.mark.parametrize("seed", [1, 2, 3, 7])
def test_favor_acked_swaps_once_per_generated_corruption(tmp_path: pathlib.Path, seed: int):
    """The claim ``tcp_corrupt_ts`` makes, on a seeded stream that can vary it (#30).

    packeteer's generator corrupts a data segment's last byte in flight,
    labels it ``CORRUPT[i]``, and resends it clean; since packeteer ``0.16.0``
    its receiver no longer acknowledges past the corrupted copy before the
    resend arrives (packeteer#163), so the first covering ack echoes the
    resend's TSval, as a real receiver's would.  ``favor-acked`` must then
    swap exactly once per corruption, with no fallback, and land on the bytes
    ``checksum="drop"`` reaches from the other side.
    """
    stream = generate_tcp_stream(
        client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=40,
        config=TCPStreamConfig(seed=seed, payload_corruption_probability=0.15),
    )
    corrupted = sum(1 for p in stream.packets if p.label.startswith("CORRUPT["))
    buf = io.BytesIO()
    write_pcap(stream.to_pcap_tuples(), file_object=buf)

    def convert(name: str, options: ReassemblyOptions | None = None) -> object:
        kwargs = {} if options is None else {"options": options}
        return to_zpf(io.BytesIO(buf.getvalue()), tmp_path / name, **kwargs)

    old = convert("old")
    acked_out = convert("acked", ACKED)
    dropped = convert("drop", ReassemblyOptions(checksum="drop"))

    assert corrupted > 0, "the seed reaches a corruption"
    assert acked_out.stats.acked_swaps == corrupted
    assert acked_out.stats.acked_fallback_bytes == 0
    assert streams(acked_out) == streams(dropped)
    assert streams(acked_out) != streams(old), "favor-old keeps the corrupted copies"
    for out in (old, acked_out, dropped):
        assert out.diagnostics == [] and out.unplaceable == []  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", [n for n in REAL if n != "tcp_corrupt_ts.pcap"])
def test_favor_acked_costs_nothing_where_copies_agree(tmp_path: pathlib.Path, name: str):
    """Every other resend in the corpus is byte-identical to its original."""
    old_out = to_zpf(CAPTURES / name, tmp_path / "old")
    acked_out = to_zpf(CAPTURES / name, tmp_path / "acked", options=ACKED)

    assert streams(acked_out) == streams(old_out)
    assert acked_out.stats.acked_swaps == 0
    assert acked_out.stats.acked_fallback_bytes == 0
    assert acked_out.stats.records == old_out.stats.records
    assert acked_out.diagnostics == [] and acked_out.unplaceable == []
