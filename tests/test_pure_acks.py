"""Pure ACKs, stored as zero-length records by default since ``0.6.0`` (#37).

The specification advises it since ``0.23``: a pure ACK has no end, so no
edge runs from it, but its ``ack`` orders it after the peer bytes it covers.
The load-bearing claim here is that storing them **adds records and moves
nothing else**: every fixture, under every policy, converts to what
``pure_acks=False`` writes plus one zero-length record per stored pure ACK.
The rest pins where a pure ACK is placed, which is the one design question
the option raised: it sits at its wire sequence number, so it waits for its
sender's bytes below that number to be placed first.
"""

from __future__ import annotations

import dataclasses
import pathlib
from collections import Counter

import pytest
import zpf
from helpers import (
    CAPTURES,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    Converted,
    Seg,
    is_pure_ack,
    packets_zpf,
    tcp_segments,
    to_zpf,
)

from zpfwire import ReassemblyOptions, packets_to_zpf
from zpfwire.capture import PacketView
from zpfwire.flow import FlowKey, RecordSink
from zpfwire.stats import ConversionStats
from zpfwire.tcp import TcpFlow

FIXTURES = sorted(p.name for p in CAPTURES.glob("*.pcap*"))
POLICIES = {
    "favor-old": {},
    "favor-acked": {"overlap": "favor-acked"},
    "tight": {"reorder_window": 2048, "flush_timeout": 0.01},
    "no-coalesce": {"coalesce": False},
}
OFF = ReassemblyOptions(pure_acks=False)


class _Discard(RecordSink):
    """A sink for driving a tracker directly, where only its state is asked about."""

    def participant(self, endpoint: str, **declaration: object) -> str:  # type: ignore[override]
        return endpoint

    def record(self, sender: object, **kwargs: object) -> None:  # type: ignore[override]
        pass

    def undecoded(self, off_start: int | None, length: int, *, reason: str) -> None:
        pass

    def end(self, reason: str) -> None:
        pass


def _view(seq: int, payload: bytes, *, flags: int = TCP_ACK) -> PacketView:
    return PacketView(packet_num=seq, ts_ticks=seq, protocol="tcp", src="10.0.0.1",
                      dst="10.0.0.2", src_port=51000, dst_port=80, payload=payload,
                      seq=seq, ack=700, tcp_flags=flags)


def _by_endpoint(out: Converted) -> dict[tuple[str, tuple[str, ...]], list[tuple[object, ...]]]:
    """Every sender's records, as what they say, keyed by session and endpoint.

    Keyed by endpoint rather than participant id: a sender that only ever
    acknowledges is declared at its first pure ACK when they are stored,
    and at the session's end when they are not, so its id can differ.
    """
    records: dict[tuple[str, tuple[str, ...]], list[tuple[object, ...]]] = {}
    for session in out.sessions:
        endpoints = {p.participant_id: tuple(p.endpoints) for p in session.participants}
        for r in session.records:
            records.setdefault((session.key, endpoints[r.sender_pid]), []).append(
                (r.payload, int(r.flags), r.seq_start, r.ack, r.timestamp, r.ts_first),
            )
    return records


# ── storing them adds records, and moves nothing else ───────────────────


@pytest.mark.parametrize("sequenced", [False, True], ids=["stored-order", "sequenced"])
@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("name", FIXTURES)
def test_the_default_is_the_opt_out_plus_the_pure_acks(
    tmp_path: pathlib.Path, name: str, policy: str, sequenced: bool,
):
    on = to_zpf(CAPTURES / name, tmp_path / "on", sequenced=sequenced,
                options=ReassemblyOptions(**POLICIES[policy]))
    off = to_zpf(CAPTURES / name, tmp_path / "off", sequenced=sequenced,
                 options=ReassemblyOptions(**POLICIES[policy], pure_acks=False))

    with_acks = _by_endpoint(on)
    without = _by_endpoint(off)
    stripped = {
        key: [r for r in records if not (r[0] == b"" and r[1] == 0 and r[3] is not None)]
        for key, records in with_acks.items()
    }
    assert {k: v for k, v in stripped.items() if v} == without
    assert [(u.off_start, u.off_end, u.reason) for u in on.undecoded] == [
        (u.off_start, u.off_end, u.reason) for u in off.undecoded
    ]

    stored = sum(1 for s in on.sessions for r in s.records if is_pure_ack(r))
    assert stored == on.stats.pure_acks
    assert on.stats.records == off.stats.records + stored
    moved = {"records", "pure_acks", "pure_acks_unstored"}
    on_stats, off_stats = dataclasses.asdict(on.stats), dataclasses.asdict(off.stats)
    assert {k: v for k, v in on_stats.items() if k not in moved} == {
        k: v for k, v in off_stats.items() if k not in moved
    }


def test_the_fixtures_store_nearly_every_pure_ack(tmp_path: pathlib.Path):
    """A pure ACK goes unstored only behind its sender's placed bytes, which is rare."""
    stored = unstored = 0
    for name in FIXTURES:
        out = to_zpf(CAPTURES / name, tmp_path / name)
        stored += out.stats.pure_acks
        unstored += out.stats.pure_acks_unstored

    assert stored > 3_000
    assert unstored <= stored // 1_000


def test_opting_out_declares_the_digest_0_5_0_declared():
    """Same policy, same digest: a file written with the option off is 0.5.0's to the byte."""
    assert OFF.params_digest() == (
        "sha256:ed166a2352d207caa487231dc518ad3642f3210926184570833470e66fa86c54"
    )
    assert ReassemblyOptions(overlap="favor-acked", pure_acks=False).params_digest() == (
        "sha256:925c167f77bbb46196ae11bee9edc859e1b981bd988b2f6133ea6a469d52a8dc"
    )
    assert ReassemblyOptions().params_digest() != OFF.params_digest()


# ── where a pure ACK is placed ──────────────────────────────────────────


def test_a_pure_ack_inside_a_run_follows_it_and_leaves_its_boundaries_alone(
    tmp_path: pathlib.Path,
):
    """The ACK's number lies inside the run that continues past it, so it is stored after the run.

    A zero-length record covers no byte, so following a record that ends
    beyond it overlaps nothing, and the run coalesces exactly as it would
    have without the ACK.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"abcd"),
        Seg(5, b"", ack=700),
        Seg(5, b"efgh", flags=TCP_PSH),
    ]), tmp_path)

    run, ack = out.only.by(0)
    assert (run.seq_start, run.payload) == (1, b"abcdefgh")
    assert is_pure_ack(ack)
    assert (ack.seq_start, ack.ack) == (5, 700)


def test_a_pure_ack_ahead_of_held_bytes_waits_for_them(tmp_path: pathlib.Path):
    """Stored at its own number, it may only follow every record of its sender that starts below."""
    out = to_zpf(tcp_segments([
        Seg(1, b"ab"),
        Seg(7, b"gh"),             # held: bytes 3-6 have not arrived
        Seg(9, b"", ack=700),      # the sender's next number is 9
        Seg(3, b"cdef", flags=TCP_PSH),
    ]), tmp_path)

    run, ack = out.only.by(0)
    assert (run.seq_start, run.payload) == (1, b"abcdefgh")
    assert (ack.seq_start, ack.ack) == (9, 700)


def test_a_pure_ack_after_the_fin_sits_one_past_it(tmp_path: pathlib.Path):
    """The FIN occupies a sequence number, and the final ACK carries the next one.

    It stays at that wire number: the causal merge reads a peer's progress
    from where its records sit, and two final ACKs each acknowledge the
    other side's FIN.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"abcd", flags=TCP_PSH | TCP_FIN),
        Seg(6, b"", ack=700),
    ]), tmp_path)

    run, ack = out.only.by(0)
    assert run.flags & zpf.RecordFlags.FIN
    assert (ack.seq_start, ack.ack) == (6, 700)
    assert out.stats.pure_acks_unstored == 0


def test_a_pure_ack_after_the_fin_is_placed_at_once_not_held_to_the_end():
    """The FIN is in the frontier, so the final ACK is not kept for the rest of the session.

    Held, it would still be written last and the file would not differ, so
    only the reassembler's state can show it: streaming is the point.
    """
    flow = TcpFlow(FlowKey.of(_view(1, b"abcd")), _Discard(), options=ReassemblyOptions(),
                   stats=ConversionStats(), tick_hz=1_000_000)
    flow.packet(_view(1, b"abcd", flags=TCP_ACK | TCP_PSH | TCP_FIN))
    flow.packet(_view(6, b""))

    (stream,) = flow._streams.values()
    assert stream.held_acks == []
    assert flow._stats.pure_acks == 1


def test_a_pure_ack_passed_by_a_gap_commit_is_stored_before_the_run_past_it(
    tmp_path: pathlib.Path,
):
    """A commit jumps the frontier past a held ACK; the ACK must land before what follows.

    The run that opens at the commit's target starts beyond the ACK's
    number, so the ACK is placed when the frontier jumps, ahead of it.
    """
    out = to_zpf(tcp_segments([
        Seg(1, b"ab"),
        Seg(5, b"", ack=700),            # bytes 3-4 were sent, and never arrive
        Seg(10, b"jk", flags=TCP_PSH),   # held past the hole, then committed
    ]), tmp_path, options=ReassemblyOptions(reorder_window=1))

    assert [(r.seq_start, r.payload) for r in out.only.by(0)] == [
        (1, b"ab"), (5, b""), (10, b"jk"),
    ]
    assert out.stats.gaps == 1


def test_a_pure_ack_behind_placed_bytes_is_counted_not_stored(tmp_path: pathlib.Path):
    """Stored at its number, it would precede records already placed, which the order forbids."""
    out = to_zpf(tcp_segments([
        Seg(1, b"abcdefgh", flags=TCP_PSH),
        Seg(5, b"", ack=700),      # sent before bytes 5-8, captured after them
    ]), tmp_path)

    (run,) = out.only.by(0)
    assert run.payload == b"abcdefgh"
    assert out.stats.pure_acks == 0
    assert out.stats.pure_acks_unstored == 1
    assert "pure ACKs    1 not stored" in out.stats.summary()


def test_a_sender_that_only_acknowledges_gets_a_stream_of_them(tmp_path: pathlib.Path):
    """Its stream begins at its first pure ACK, as it would at a first data segment."""
    out = to_zpf(tcp_segments([
        Seg(1, b"abcd", flags=TCP_PSH),
        Seg(700, b"", from_client=False, ack=5),
        Seg(5, b"efgh", flags=TCP_PSH),
        Seg(700, b"", from_client=False, ack=9),
    ]), tmp_path)

    acks = out.only.by(1)
    assert [(r.seq_start, r.ack) for r in acks] == [(700, 5), (700, 9)]
    assert all(is_pure_ack(r) for r in acks)


# ── what storing them is for ────────────────────────────────────────────


def test_a_pure_ack_is_merged_after_the_bytes_it_covers_whatever_the_clock(
    tmp_path: pathlib.Path,
):
    """The edge #37 is for: the ACK is captured, and stamped, before the data it acknowledges.

    Two capture points with skewed clocks give exactly this.  The ACK's
    ``ack`` places it after the client's bytes anyway; without it stored,
    the server has no record for the merge to place at all.
    """
    frames = tcp_segments([
        Seg(700, b"", from_client=False, ack=9),
        Seg(1, b"abcdefgh", flags=TCP_PSH),
    ])
    out = to_zpf(frames, tmp_path / "on")
    with zpf.open(out.path) as reader:
        (session,) = reader.sessions()
        merged = [(r.sender_pid, r.payload) for r in session.timeline()]
    client = next(
        p.participant_id for p in out.only.participants if p.endpoints[0].endswith(":51000")
    )

    assert merged == [(client, b"abcdefgh"), (1 - client, b"")]
    assert out.only.records[0].timestamp < out.only.records[1].timestamp

    frames.seek(0)
    off = to_zpf(frames, tmp_path / "off", options=OFF)
    assert [r.payload for r in off.only.records] == [b"abcdefgh"]


def test_a_zpf_input_cites_its_pure_acks_instead_of_skipping_them(tmp_path: pathlib.Path):
    """Over a ``.zpf`` of packets, each stored pure ACK cites the packet it came from.

    So the stage's ``skipped`` auto-fill, which marks what nothing cited or
    marked, covers fewer input bytes: the pure ACKs' packets are no longer
    left to it.
    """
    packets = packets_zpf(CAPTURES / "http.pcap", tmp_path / "packets.zpf")
    skipped: dict[str, int] = {}
    for label, options in (("on", ReassemblyOptions()), ("off", OFF)):
        out = tmp_path / f"{label}.zpf"
        stats = packets_to_zpf(packets, out, options=options, produced_at=1_700_000_000)
        with zpf.open(out) as reader:
            for session in reader.sessions():
                for _ in session.records():
                    pass
            assert reader.diagnostics == []
            assert reader.unplaceable == []
            skipped[label] = sum(u.off_end - u.off_start for u in reader.undecoded
                                 if u.reason == "skipped")
        if label == "on":
            assert stats.pure_acks > 0

    assert skipped["on"] < skipped["off"]


def test_the_summary_counts_the_pure_acks(tmp_path: pathlib.Path):
    out = to_zpf(CAPTURES / "http.pcap", tmp_path)
    counted = Counter(is_pure_ack(r) for s in out.sessions for r in s.records)

    assert f"({counted[True]} pure ACKs)" in out.stats.summary()
    assert counted[True] == out.stats.pure_acks

