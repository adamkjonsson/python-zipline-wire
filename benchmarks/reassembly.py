"""Time the reassembler on the shapes the ``0.6.0`` performance issues were found on.

Not a test, and not collected by pytest: timings depend on the machine, and a
threshold generous enough not to flake would prove little.  Correctness of a
speed change is pinned by the suite and by ``tools/byte_identity.py``; this
says how much faster it is, and each phase of the plan records its numbers.

Two kinds of measurement:

- **Shapes**: synthetic TCP traffic fed straight into
  :class:`~zpfwire.tcp.TcpFlow` through a sink that discards everything, so
  only the reassembler is timed.  Each is one of the shapes in #43, #44 and
  #45, plus an in-order control that none of them should move.
- **Capture**: ``tests/captures/http_stream_1.pcap`` through packeteer alone,
  through :class:`~zpfwire.capture.CaptureReader`, and through the whole
  conversion.

Every figure is the median of ``--runs`` runs, after one warm-up.

Usage::

    .venv/bin/python benchmarks/reassembly.py
    .venv/bin/python benchmarks/reassembly.py --runs 9 --json out.json
"""

from __future__ import annotations

import argparse
import importlib.metadata
import io
import json
import pathlib
import platform
import statistics
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from packeteer.generate.tcp import TCP_ACK, TCP_PSH, TCPOptions
from packeteer.parse import iter_packets

import zpfwire
from zpfwire.capture import CaptureReader, PacketView
from zpfwire.convert import capture_to_zpf
from zpfwire.flow import FlowKey, RecordSink
from zpfwire.options import ReassemblyOptions
from zpfwire.stats import ConversionStats
from zpfwire.tcp import TcpFlow

ROOT = pathlib.Path(__file__).resolve().parent.parent
CAPTURE = ROOT / "tests" / "captures" / "http_stream_1.pcap"
SEQ_MOD = 1 << 32


class _NullSink(RecordSink):
    """Accepts every record and citation and keeps nothing."""

    def participant(self, endpoint: str, **declaration: object) -> str:  # type: ignore[override]
        """Return the endpoint as its own handle."""
        return endpoint

    def record(self, sender: object, **kwargs: object) -> None:  # type: ignore[override]
        """Discard a record."""

    def undecoded(self, off_start: int | None, length: int, *, reason: str) -> None:
        """Discard a citation."""

    def end(self, reason: str) -> None:
        """Discard the session end."""


@dataclass
class Shape:
    """One synthetic stream, and the issue it stands for."""

    issue: str
    name: str
    packets: list[PacketView]
    options: dict[str, object] = field(default_factory=dict)


def _segment(
    index: int, seq: int, size: int, flags: int = TCP_ACK, tsval: int | None = None,
) -> PacketView:
    return PacketView(
        packet_num=index, ts_ticks=index, protocol="tcp",
        src="10.0.0.1", dst="10.0.0.2", src_port=1, dst_port=2,
        payload=b"x" * size, seq=seq % SEQ_MOD, ack=0, tcp_flags=flags,
        tcp_options=None if tsval is None else TCPOptions(timestamps=(tsval, 0)),
        payload_offset=index * 100,
    )


def in_order(count: int, size: int) -> list[PacketView]:
    """Return *count* segments in order, each pushed: the control."""
    return [_segment(k, k * size, size, TCP_ACK | TCP_PSH) for k in range(count)]


def reversed_blocks(count: int, size: int, block: int) -> list[PacketView]:
    """Return segments arriving back to front in blocks, so each block waits on its first."""
    out: list[PacketView] = []
    for start in range(0, count, block):
        for k in reversed(range(start, min(start + block, count))):
            out.append(_segment(len(out), k * size, size))
    return out


def repeats_with_timestamps(count: int, size: int, every: int) -> list[PacketView]:
    """Return segments carrying TSvals, every *every* th followed by a resend from 8 back."""
    out: list[PacketView] = []
    for k in range(count):
        out.append(_segment(len(out), k * size, size, tsval=k))
        if k % every == 0 and k > 8:
            out.append(_segment(len(out), (k - 8) * size, size, tsval=k))
    return out


def lossy(count: int, size: int, every: int) -> list[PacketView]:
    """Return segments with every *every* th lost, and a late copy from 400 back after each loss."""
    out: list[PacketView] = []
    for k in range(count):
        if k % every:
            out.append(_segment(len(out), k * size, size))
        if k % every == 0 and k > 400:
            out.append(_segment(len(out), (k - 400) * size, size))
    return out


def shapes() -> list[Shape]:
    """Return every shape, in the order the plan's table lists them."""
    return [
        Shape("#43", "repeats with TSvals, 10 B", repeats_with_timestamps(20_000, 10, 10)),
        Shape("#43", "repeats with TSvals, 100 B", repeats_with_timestamps(20_000, 100, 10)),
        Shape("#44", "reordered blocks of 2,000 x 100 B", reversed_blocks(20_000, 100, 2_000)),
        Shape("#44", "reordered blocks of 170 x 1,460 B", reversed_blocks(20_000, 1_460, 170)),
        Shape("#45", "1 in 50 lost, 80k packets, window 4096", lossy(80_000, 1_460, 50),
              {"reorder_window": 4096}),
        Shape("control", "in order, 1,460 B", in_order(20_000, 1_460)),
    ]


def _median(runs: int, work: Callable[[], object]) -> float:
    """Return the median wall time of *work*, in seconds, after one warm-up."""
    work()
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        work()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def _feed(packets: Sequence[PacketView], options: dict[str, object]) -> None:
    flow = TcpFlow(FlowKey.of(packets[0]), _NullSink(), options=ReassemblyOptions(**options),
                   stats=ConversionStats(), tick_hz=1_000_000)
    for pkt in packets:
        flow.packet(pkt)
    flow.finish()


def _iterate() -> None:
    with iter_packets(path=CAPTURE, decode_app=False) as packets:
        for _ in packets:
            pass


def _read() -> None:
    for _ in CaptureReader(path=CAPTURE):
        pass


def _convert() -> None:
    capture_to_zpf(CAPTURE, io.BytesIO(), produced_at=None)


def main() -> None:
    """Run every measurement and print the table."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--runs", type=int, default=5, help="timed runs per figure (default 5)")
    parser.add_argument("--json", type=pathlib.Path, help="also write the figures here")
    args = parser.parse_args()

    ran = {
        "zpfwire": f"{zpfwire.__version__} from {zpfwire.__file__}",
        "zpf": importlib.metadata.version("zpf"),
        "packeteer": importlib.metadata.version("packeteer"),
        "python": f"{platform.python_implementation()} {platform.python_version()}",
        "machine": f"{platform.system()} {platform.machine()}",
    }
    for name, value in ran.items():
        print(f"{name:10s} {value}")
    print(f"median of {args.runs}\n")

    figures: dict[str, float] = {}
    for shape in shapes():
        seconds = _median(args.runs, lambda s=shape: _feed(s.packets, s.options))
        per_packet = seconds / len(shape.packets) * 1e6
        figures[f"{shape.issue} {shape.name}"] = per_packet
        print(f"{shape.issue:8s} {shape.name:40s} {per_packet:8.2f} µs/packet")

    count = sum(1 for _ in CaptureReader(path=CAPTURE))
    print()
    for name, work in (("iter_packets", _iterate), ("CaptureReader", _read),
                       ("capture_to_zpf", _convert)):
        milliseconds = _median(args.runs, work) * 1e3
        figures[f"{CAPTURE.name} {name}"] = milliseconds
        print(f"{CAPTURE.name} {name:16s} {milliseconds:8.1f} ms  "
              f"({count / milliseconds * 1e3:,.0f} packets/s)")

    if args.json:
        args.json.write_text(json.dumps({"ran": ran, "runs": args.runs, "figures": figures},
                                        indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
