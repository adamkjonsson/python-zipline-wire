"""The reorder buffer and the repeat history decide exactly what they did before (#43, #44).

Both were rewritten for speed in ``0.6.0``: the next held segment is the
first entry of a sorted list instead of a ``min`` over the buffer, and
``_judge`` bisects ``recent`` instead of scanning it.  Neither may change a
decision, and the fixtures barely reach either path, so this file checks
the new code against the old, **call for call**, on randomized streams that
do: deep reordering, small segments, copies and resends with and without
the Timestamps option, losses committed as gaps, and sequence wrap.

The old implementations are copied here as the reference.  They are the
specification of the behaviour, not code to keep in step with ``tcp.py``.
"""

from __future__ import annotations

import random
from collections import Counter
from collections.abc import Iterable

import pytest
from helpers import TCP_ACK, TCP_PSH, TCP_SYN
from packeteer.generate.tcp import TCPOptions

from zpfwire import TS_ABSENT, TS_STALE, ReassemblyOptions
from zpfwire.capture import PacketView
from zpfwire.flow import FlowKey, RecordSink
from zpfwire.stats import ConversionStats
from zpfwire.tcp import _MAX_WINDOW, _SEQ_MOD, TcpFlow, _delta, _Sent, _Stream

A, B = ("10.0.0.1", 40000), ("10.0.0.2", 80)


# ── the reference: the 0.5.0 implementations ────────────────────────────


def reference_next_pending(stream: _Stream) -> int:
    """``TcpFlow._next_pending`` as of ``0.5.0``."""
    return min(stream.pending, key=lambda s: _delta(s, stream.next_seq))


def reference_judge(
    recent: Iterable[_Sent], seq: int, end: int, tsval: int | None, peer_count: int,
) -> str:
    """``TcpFlow._judge`` as of ``0.5.0``, over the live part of ``recent``."""
    if tsval is None:
        return TS_ABSENT
    covered = 0
    length = _delta(end, seq)
    for sent in recent:
        lo = max(_delta(sent.seq, seq), 0)
        hi = min(_delta(sent.end, seq), length)
        if hi <= lo:
            continue
        if sent.tsval is None:
            return TS_ABSENT
        if sent.tsval != tsval or sent.peer_count != peer_count:
            return "retransmit"
        covered += hi - lo
    return "duplicate" if covered >= length else TS_STALE


# ── a tracker that checks itself ────────────────────────────────────────


class _NullSink(RecordSink):
    def __init__(self) -> None:
        self.seq_starts: list[int | None] = []

    def participant(self, endpoint: str, **declaration: object) -> str:  # type: ignore[override]
        return endpoint

    def record(self, sender: object, **kwargs: object) -> None:  # type: ignore[override]
        hints = kwargs.get("hints")
        self.seq_starts.append(None if hints is None else hints.seq_start)

    def undecoded(self, off_start: int | None, length: int, *, reason: str) -> None:
        pass

    def end(self, reason: str) -> None:
        pass


class CheckedFlow(TcpFlow):
    """A ``TcpFlow`` whose every ordering decision is checked against the reference."""

    def __init__(self, options: ReassemblyOptions) -> None:
        self.sink_ = _NullSink()
        key = FlowKey.of(_segment(0, A, B, seq=0))
        super().__init__(key, self.sink_, options=options, stats=ConversionStats(),
                         tick_hz=1_000_000)
        self.calls: Counter[str] = Counter()

    def _next_pending(self, stream: _Stream) -> int:
        got = super()._next_pending(stream)
        assert got == reference_next_pending(stream)
        self.calls["next_pending"] += 1
        return got

    def _judge(
        self, stream: _Stream, seq: int, end: int, tsval: int | None, peer_count: int,
    ) -> str:
        got = super()._judge(stream, seq, end, tsval, peer_count)
        live = stream.recent[stream.recent_head:]
        assert got == reference_judge(live, seq, end, tsval, peer_count)
        self.calls[f"judge:{got}"] += 1
        return got

    def packet(self, pkt: PacketView) -> None:
        super().packet(pkt)
        for stream in self._streams.values():
            check_invariants(stream)


def check_invariants(stream: _Stream) -> None:
    """Assert what the two structures promise between packets."""
    order = stream.pending_order
    assert order == sorted(order)
    assert len(set(order)) == len(order) == len(stream.pending)
    assert {(stream.pending_anchor + offset) % _SEQ_MOD for offset in order} == set(stream.pending)

    live = stream.recent[stream.recent_head:]
    assert all(a.pos < b.pos for a, b in zip(live, live[1:], strict=False))
    assert stream.recent_bytes == sum(_delta(s.end, s.seq) for s in live)
    if stream.recent:
        assert live, "recent is never emptied"


# ── streams ─────────────────────────────────────────────────────────────


def _segment(
    ts: int,
    src: tuple[str, int],
    dst: tuple[str, int],
    *,
    seq: int,
    data: bytes = b"",
    ack: int = 0,
    flags: int = TCP_ACK,
    timestamps: tuple[int, int] | None = None,
    offset: int | None = None,
) -> PacketView:
    return PacketView(
        packet_num=ts, ts_ticks=ts, protocol="tcp", src=src[0], dst=dst[0],
        src_port=src[1], dst_port=dst[1], payload=data, seq=seq % _SEQ_MOD,
        ack=ack % _SEQ_MOD, tcp_flags=flags,
        tcp_options=None if timestamps is None else TCPOptions(timestamps=timestamps),
        payload_offset=offset,
    )


def random_stream(seed: int) -> list[PacketView]:
    """Return one direction's data, perturbed, with the peer's acks among it.

    The sender's sequence space starts just short of the wrap.  Each segment
    may be lost, copied (same TSval, nothing from the peer between), resent
    later (a new TSval), or delayed among its successors.  About a third of
    the streams carry no Timestamps option at all, and in another third it
    is dropped from some packets, so every fallback is reached.
    """
    rng = random.Random(seed)
    isn = _SEQ_MOD - rng.randrange(1, 40_000)
    small = rng.random() < 0.5
    timestamps = rng.choice(["all", "none", "some"])
    segments = []
    seq = isn
    for _ in range(rng.randrange(150, 400)):
        size = rng.randrange(1, 40) if small else rng.randrange(1, 1460)
        segments.append((seq, bytes(rng.randrange(256) for _ in range(size))))
        seq += size

    events: list[tuple[float, int, bytes, bool]] = []  # (order key, seq, data, fresh tsval?)
    for index, (start, data) in enumerate(segments):
        key = index + (rng.expovariate(1 / 6) if rng.random() < 0.3 else 0)
        if rng.random() > 0.05:
            events.append((key, start, data, True))
        if rng.random() < 0.06:
            events.append((key + 0.001, start, data, False))  # a copy
        if rng.random() < 0.08:
            # A resend, sometimes of a little more than the one segment.
            more = segments[index + 1][1] if index + 1 < len(segments) else b""
            events.append((key + rng.randrange(2, 30), start, data + more[:rng.randrange(0, 4)],
                           True))
        if rng.random() < 0.02:
            # A run of pure ACKs from the peer, which ends any chance of a copy.
            events.append((key + 0.5, -1, b"", True))
    events.sort(key=lambda event: event[0])

    packets: list[PacketView] = []
    clock = 1_000_000
    tsval = 1_000
    for _key, start, data, fresh in events:
        clock += rng.choice([10, 50, 200, 1_000, 30_000]) if rng.random() < 0.97 else 6_000_000
        if fresh:
            tsval += rng.choice([0, 1, 1, 5])
        has_ts = timestamps == "all" or (timestamps == "some" and rng.random() < 0.8)
        if start == -1:
            packets.append(_segment(clock, B, A, seq=7_000, ack=rng.choice(segments)[0],
                                    timestamps=(5_000, tsval) if has_ts else None))
            continue
        flags = TCP_ACK | (TCP_PSH if rng.random() < 0.2 else 0)
        packets.append(_segment(clock, A, B, seq=start, data=data, ack=7_000, flags=flags,
                                timestamps=(tsval, 4_000) if has_ts else None,
                                offset=len(packets) * 2_000))
        if rng.random() < 0.15:
            clock += 5
            packets.append(_segment(clock, B, A, seq=7_000, ack=start + len(data),
                                    timestamps=(5_000, tsval) if has_ts else None))
    return packets


POLICIES = {
    "favor-old": ReassemblyOptions(),
    "favor-acked": ReassemblyOptions(overlap="favor-acked"),
    "tight": ReassemblyOptions(reorder_window=2048, flush_timeout=0.01),
    "no-coalesce": ReassemblyOptions(coalesce=False, reorder_window=8192),
}


@pytest.mark.parametrize("policy", POLICIES)
def test_every_decision_matches_the_reference_on_random_streams(policy: str):
    calls: Counter[str] = Counter()
    for seed in range(40):
        flow = CheckedFlow(POLICIES[policy])
        for pkt in random_stream(seed):
            flow.packet(pkt)
        flow.finish()
        calls.update(flow.calls)

    # The streams must reach what they are here to check, or a pass means nothing.
    assert calls["next_pending"] > 1_000
    for verdict in ("duplicate", "retransmit", TS_ABSENT, TS_STALE):
        assert calls[f"judge:{verdict}"] > 0, f"no {verdict} verdict in {dict(calls)}"


# ── the two paths random streams cannot reach ───────────────────────────


def test_the_anchor_moves_up_when_a_held_segment_outlives_a_gigabyte():
    """A segment held far ahead while gaps are committed past others.

    Each commit jumps ``next_seq`` to the first held segment, so ``next_seq``
    runs more than ``_MAX_WINDOW`` past the anchor while the far segment is
    still held.  The anchor has to move, and the order must not.
    """
    flow = CheckedFlow(ReassemblyOptions(reorder_window=2_500))
    start = _SEQ_MOD - 500  # across the wrap, too
    gb = 1 << 30
    far, first, second, third = (start + 1_000 + offset
                                 for offset in (int(1.9 * gb), int(0.6 * gb), int(1.2 * gb),
                                                int(1.25 * gb)))
    chunk = b"x" * 1_000
    sends = [start, far, first, second, third]
    for ts, seq in enumerate(sends, start=1):
        flow.packet(_segment(ts, A, B, seq=seq, data=chunk, offset=ts * 2_000))
    anchor = flow._streams[f"{A[0]}:{A[1]}"].pending_anchor
    flow.finish()

    assert anchor != start + 1_000, "the anchor never moved; the test missed its path"
    expected = [s % _SEQ_MOD for s in (start, first, second, third, far)]
    assert flow.sink_.seq_starts == expected
    assert flow.calls["next_pending"] >= 4


def test_judge_scans_everything_when_recent_spans_more_than_the_window():
    """Two accepted transmissions a gigabyte apart, then copies of both.

    A committed gap between them leaves ``recent`` spanning more than
    ``_MAX_WINDOW``, where ``_delta`` from a repeat need not be monotone
    along it, so bisection is not used.  The verdicts must still be the
    reference's.
    """
    flow = CheckedFlow(ReassemblyOptions(reorder_window=2_500))
    start = 10_000
    gb = 1 << 30
    chunk = b"y" * 1_000
    near, jump = start, start + 1_000 + int(1.2 * gb)
    sends = [(near, 1), (jump, 2), (jump + 5_000, 3), (jump + 9_000, 4)]
    for ts, (seq, tsval) in enumerate(sends, start=1):
        flow.packet(_segment(ts, A, B, seq=seq, data=chunk, timestamps=(tsval, 0)))
    stream = flow._streams[f"{A[0]}:{A[1]}"]
    live = stream.recent[stream.recent_head:]
    assert live[-1].pos + 1_000 - live[0].pos > _MAX_WINDOW

    flow.packet(_segment(10, A, B, seq=near, data=chunk, timestamps=(1, 0)))
    flow.packet(_segment(11, A, B, seq=jump, data=chunk, timestamps=(9, 0)))

    assert flow.calls["judge:duplicate"] == 1
    assert flow.calls["judge:retransmit"] == 1


def test_a_repeat_before_any_data_is_judged_stale():
    """After a handshake and before any data, nothing is remembered to judge against."""
    flow = CheckedFlow(ReassemblyOptions())
    flow.packet(_segment(1, A, B, seq=999, flags=TCP_SYN, timestamps=(1, 0)))
    flow.packet(_segment(2, A, B, seq=990, data=b"z" * 5, timestamps=(2, 0)))

    assert flow.calls[f"judge:{TS_STALE}"] == 1
