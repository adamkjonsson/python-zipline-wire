"""Measure how well a conversion represents the traffic that was actually sent.

The fidelity tool, ``0.7.0``'s instrument.  packeteer generates a
conversation under impairments of our choosing and knows exactly what was
sent; zpfwire converts the impaired capture; each transport's scorer judges
the ``.zpf`` against what was sent — TCP's in the public
:mod:`zpfwire.fidelity` with :mod:`fidelity_tcp` for order and timing, UDP's
in :mod:`fidelity_udp` — and this one runs the project's matrix: scenario
families × impairments × seeds × reassembly policies, reported as one JSON
line per conversion and a Markdown summary per cell.

``plans/V0.7.0-RELEASE-PLAN.md`` and ``plans/V0.8.0-RELEASE-PLAN.md`` are
the design; run it as ``.venv/bin/python tools/fidelity.py --out DIR``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import pathlib
import statistics
import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from typing import Any

import fidelity_udp as udp
import zpf
from fidelity_tcp import measure

from zpfwire import ReassemblyOptions
from zpfwire.fidelity import (
    DIRECTIONS,
    PROTOTYPE,
    Direction,
    Impairments,
    Ledger,
    Scenario,
    Unclean,
    run,
)

# ── The sweep ───────────────────────────────────────────────────────────

MIB = 1 << 20

EXERCISED = 10
"""Runs a cell needs to have actually exercised its impairment to be scored."""


@dataclass(frozen=True)
class Shape:
    """A scenario family in the matrix: what is said, and how the path behaves.

    Attributes:
        name: The report's name for it.
        shape: The messages, as :attr:`Scenario.shape`.
        seeds: Seeds per cell.
        psh_probability: As :attr:`Scenario.psh_probability`.
        retransmission_timeout: Every resend's delay, in seconds; part of
            the path, so it overrides the impairment's.
        note: What the family is for.

    """

    name: str
    shape: tuple[tuple[Direction, int], ...]
    seeds: int
    psh_probability: float = 0.5
    retransmission_timeout: float = 0.2
    note: str = ""


def _small(pairs: int) -> tuple[tuple[Direction, int], ...]:
    exchange: tuple[tuple[Direction, int], ...] = (("c2s", 64), ("s2c", 256))
    return exchange * pairs


SHAPES: tuple[Shape, ...] = (
    Shape("prototype", PROTOTYPE, 40,
          note="the prototype's four messages, at packeteer's PSH rate"),
    Shape("prototype-pushed", PROTOTYPE, 40, psh_probability=1.0,
          note="the same, PSH on every message, as a real stack sends"),
    Shape("bulk-c2s", (("c2s", MIB),), 12, retransmission_timeout=1.0,
          note="1 MiB one way; a 1 s RTO holds ~720 KB behind a hole, past the window"),
    Shape("bulk-s2c", (("s2c", MIB),), 12, retransmission_timeout=1.0,
          note="the same, server to client"),
    Shape("small", _small(100), 40,
          note="100 exchanges of 64 and 256 bytes, at packeteer's PSH rate"),
    Shape("small-pushed", _small(100), 40, psh_probability=1.0,
          note="the same, PSH on every message"),
    Shape("delayed-ack", (("c2s", 3000), ("c2s", 9000)), 40, retransmission_timeout=6.0,
          note="#32: a covering ack 6 s after the run, past the 5 s flush_timeout"),
)


@dataclass(frozen=True)
class Harm:
    """One impairment cell: what is configured, and how to tell it happened.

    Attributes:
        name: The report's name for it.
        impairments: The configuration; its ``retransmission_timeout`` is
            replaced by the shape's.
        realised: The ledger kind whose presence shows the run exercised
            it, or a special: ``""`` for always, ``"lost"`` for data lost on
            the wire, ``"reset"`` for a captured RST.

    """

    name: str
    impairments: Impairments
    realised: str


HARMS: tuple[Harm, ...] = (
    Harm("none", Impairments(), ""),
    Harm("loss 0.02", Impairments(packet_loss_probability=0.02), "lost"),
    Harm("loss 0.1", Impairments(packet_loss_probability=0.1), "lost"),
    Harm("loss 0.02, recovered",
         Impairments(packet_loss_probability=0.02, retransmit_lost=True), "lost"),
    Harm("loss 0.1, recovered",
         Impairments(packet_loss_probability=0.1, retransmit_lost=True), "lost"),
    Harm("retransmission 0.1", Impairments(retransmission_probability=0.1), "RETRANS"),
    Harm("retransmission 0.3", Impairments(retransmission_probability=0.3), "RETRANS"),
    Harm("duplication 0.1", Impairments(duplicate_probability=0.1), "DUP"),
    Harm("duplication 0.3", Impairments(duplicate_probability=0.3), "DUP"),
    # The prototype's row: only together do they make a copy of a resend.
    Harm("duplication + retransmission 0.2",
         Impairments(duplicate_probability=0.2, retransmission_probability=0.2), "DUP"),
    Harm("corruption 0.05", Impairments(payload_corruption_probability=0.05), "CORRUPT"),
    Harm("corruption 0.2", Impairments(payload_corruption_probability=0.2), "CORRUPT"),
    Harm("stray 1", Impairments(stray_packet_count=1), "STRAY"),
    Harm("stray 3", Impairments(stray_packet_count=3), "STRAY"),
    Harm("stray 3, stamped", Impairments(stray_packet_count=3, stray_timestamps=True), "STRAY"),
    Harm("rst", Impairments(server_rst_probability=1.0), "reset"),
)


@dataclass(frozen=True)
class Policy:
    """One conversion policy in the matrix.

    Attributes:
        name: The report's name for it.
        options: The reassembly options.
        sequenced: Whether the session is written in causal order.

    """

    name: str
    options: ReassemblyOptions
    sequenced: bool = False


POLICIES: tuple[Policy, ...] = (
    Policy("favor-old", ReassemblyOptions()),
    Policy("favor-acked", ReassemblyOptions(overlap="favor-acked")),
    Policy("checksum=drop", ReassemblyOptions(checksum="drop")),
    Policy("tight", ReassemblyOptions(reorder_window=2048, flush_timeout=0.01)),
    Policy("no-coalesce", ReassemblyOptions(coalesce=False)),
    Policy("no-pure-acks", ReassemblyOptions(pure_acks=False)),
    Policy("sequenced", ReassemblyOptions(), sequenced=True),
    # Since 0.7.0: a hold past flush_timeout (#32), and RFC 7323 §3.2 (#57).
    Policy("favor-acked, hold 10 s", ReassemblyOptions(overlap="favor-acked", acked_hold=10.0)),
    Policy("require-timestamps", ReassemblyOptions(require_timestamps=True)),
)


def realised(ledger: Ledger, harm: Harm) -> bool:
    """Return whether a run exercised its cell's impairment (Decision 5).

    Args:
        ledger: The run's ledger.
        harm: The cell.

    Returns:
        Whether the ledger shows the impairment happened.

    """
    if harm.realised == "":
        return True
    if harm.realised == "reset":
        return ledger.reset
    if harm.realised == "lost":
        return any(ledger.lost.values()) or any(s.sent_usec is None for s in ledger.segments)
    return any(harm.realised in e.kinds for e in ledger.entries)


def sweep_one(job: tuple[str, str, int]) -> list[dict[str, Any]]:
    """Generate one run and measure it under every policy.

    Module-level so that a process pool can run it.

    Args:
        job: ``(shape name, harm name, seed)``.

    Returns:
        One result per policy, as JSON-ready dicts.

    """
    shape_name, harm_name, seed = job
    shape = next(s for s in SHAPES if s.name == shape_name)
    harm = next(h for h in HARMS if h.name == harm_name)
    scenario = Scenario(
        shape=shape.shape, seed=seed, psh_probability=shape.psh_probability,
        impairments=dataclasses.replace(
            harm.impairments, retransmission_timeout=shape.retransmission_timeout,
        ),
    )
    r = run(scenario)
    base = {
        "shape": shape.name, "harm": harm.name, "seed": seed,
        "void": list(r.void), "realised": realised(r.ledger, harm),
    }
    results = []
    for policy in POLICIES:
        try:
            m = measure(r, policy.options, sequenced=policy.sequenced)
        except (Unclean, zpf.ZpfError) as error:
            # A file that reads back unclean, or one the writer refused to
            # write: either way a bug, reported as such, and not scored.
            results.append({**base, "policy": policy.name,
                            "unclean": f"{type(error).__name__}: {error}"})
            continue
        stats = m.conversion.stats
        a = m.accounting
        results.append({
            **base,
            "policy": policy.name,
            "unclean": None,
            "bytes": {d: dataclasses.asdict(m.bytes[d]) for d in DIRECTIONS},
            "fidelity": m.total.fidelity,
            "recovery": m.total.recovery,
            "failures": a.failures(late_bytes=stats.late_bytes),
            "judged": {f"{kind}/{reason}": n for (kind, reason), n in sorted(a.judged.items())},
            "copies_as_resends": a.copies_as_resends,
            "resends_as_copies": a.resends_as_copies,
            "order": {
                "positions": list(m.order.positions), "inversions": m.order.inversions,
                "reordered": m.order.reordered, "forged": m.order.forged,
            },
            "timing": [dataclasses.asdict(t) for t in m.order.timing],
            "stats": {
                "gaps": stats.gaps, "late_bytes": stats.late_bytes,
                "acked_swaps": stats.acked_swaps,
                "acked_fallback_bytes": stats.acked_fallback_bytes,
            },
        })
    return results


def sweep(
    shapes: tuple[Shape, ...] = SHAPES,
    harms: tuple[Harm, ...] = HARMS,
    *,
    seeds: int | None = None,
    jobs: int | None = None,
) -> list[dict[str, Any]]:
    """Run the matrix.

    Args:
        shapes: The scenario families.
        harms: The impairment cells.
        seeds: Seeds per cell, overriding each shape's own; for a quick look.
        jobs: Worker processes; one per CPU when ``None``, none when 1.

    Returns:
        One result per (shape, harm, seed, policy), in that order whatever
        the worker count, so the same matrix gives the same results.

    """
    work = [
        (shape.name, harm.name, seed)
        for shape in shapes
        for harm in harms
        for seed in range(seeds if seeds is not None else shape.seeds)
    ]
    return _pooled(sweep_one, work, jobs)


def _pooled(
    worker: Callable[[tuple[str, str, int]], list[dict[str, Any]]],
    work: list[tuple[str, str, int]],
    jobs: int | None,
) -> list[dict[str, Any]]:
    """Run *worker* over *work*, in order whatever the worker count."""
    if jobs == 1:
        batches = map(worker, work)
        return [result for batch in batches for result in batch]
    # Imported here: only the sweep needs a pool, and only a pool needs it.
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(max_workers=jobs) as pool:
        batches = pool.map(worker, work, chunksize=4)
        return [result for batch in batches for result in batch]


# ── The UDP sweep ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class UdpShape:
    """A UDP scenario family: what is sent, and the path's MTU.

    Attributes:
        name: The report's name for it.
        shape: The datagrams, as :attr:`fidelity_udp.Scenario.shape`.
        seeds: Seeds per cell.
        mtu: As :attr:`fidelity_udp.Scenario.mtu`.
        note: What the family is for.

    """

    name: str
    shape: tuple[tuple[Direction, int], ...]
    seeds: int
    mtu: int | None = None
    note: str = ""


def _alternating(sizes: list[int]) -> tuple[tuple[Direction, int], ...]:
    return tuple(("c2s" if i % 2 == 0 else "s2c", size) for i, size in enumerate(sizes))


UDP_SHAPES: tuple[UdpShape, ...] = (
    UdpShape("udp-prototype", udp.PROTOTYPE, 40,
             note="the 0.8.0 prototype's 40 datagrams of 100–1,399 bytes, alternating ways"),
    UdpShape("udp-bulk", (("c2s", 1400),) * 2000, 12,
             note="2,000 datagrams of 1,400 bytes one way, just under the MTU"),
    UdpShape("udp-small", _alternating([16 + (i * 7) % 49 for i in range(200)]), 40,
             note="200 datagrams of 16–64 bytes, alternating ways"),
    UdpShape("udp-fragmented", _alternating([1000 + (i * 337) % 3001 for i in range(40)]), 40,
             mtu=576, note="40 datagrams of 1,000–4,000 bytes through a 576-byte MTU"),
    UdpShape("udp-tiny", _alternating([(i // 2) % 2 for i in range(100)]), 40,
             note="100 datagrams of 0 and 1 bytes, which only their order tells apart"),
)


@dataclass(frozen=True)
class UdpHarm:
    """One UDP impairment cell: what is configured, and how to tell it happened.

    Attributes:
        name: The report's name for it.
        impairments: The configuration.
        realised: The copy kind whose presence shows the run exercised it,
            ``"lost"`` for a datagram lost on the wire, or ``""`` for always.

    """

    name: str
    impairments: udp.Impairments
    realised: str


UDP_HARMS: tuple[UdpHarm, ...] = (
    UdpHarm("none", udp.Impairments(), ""),
    UdpHarm("loss 0.02", udp.Impairments(packet_loss_probability=0.02), "lost"),
    UdpHarm("loss 0.1", udp.Impairments(packet_loss_probability=0.1), "lost"),
    UdpHarm("duplication 0.05", udp.Impairments(duplicate_probability=0.05), "DUP"),
    UdpHarm("duplication 0.2", udp.Impairments(duplicate_probability=0.2), "DUP"),
    UdpHarm("reorder 0.05", udp.Impairments(reorder_probability=0.05), "REORDER"),
    UdpHarm("reorder 0.2", udp.Impairments(reorder_probability=0.2), "REORDER"),
    UdpHarm("reorder 0.2, depth 10",
            udp.Impairments(reorder_probability=0.2, reorder_depth=10), "REORDER"),
    UdpHarm("corruption 0.2", udp.Impairments(payload_corruption_probability=0.2), "CORRUPT"),
    UdpHarm("all at once", udp.Impairments(
        packet_loss_probability=0.1, payload_corruption_probability=0.2,
        reorder_probability=0.2, duplicate_probability=0.2,
    ), ""),
)

UDP_POLICIES: tuple[Policy, ...] = (
    Policy("default", ReassemblyOptions()),
    # TCP-only in zpfwire: a UDP datagram is kept and counted (0.5.0).
    Policy("checksum=drop", ReassemblyOptions(checksum="drop")),
    # TCP-only too: a UDP session's order would rest on the clock alone.
    Policy("sequenced", ReassemblyOptions(), sequenced=True),
)
"""Each is run along both paths, as ``"<policy>, <path>"``.  Every other
option is TCP's, and would only repeat the default."""


def realised_udp(ledger: udp.Ledger, harm: UdpHarm) -> bool:
    """Return whether a UDP run exercised its cell's impairment (Decision 5).

    Args:
        ledger: The run's ledger.
        harm: The cell.

    Returns:
        Whether the ledger shows the impairment happened.

    """
    if harm.realised == "":
        return True
    if harm.realised == "lost":
        return bool(ledger.lost)
    return any(harm.realised in c.kinds for c in ledger.copies)


def sweep_udp_one(job: tuple[str, str, int]) -> list[dict[str, Any]]:
    """Generate one UDP run and measure it under every policy, along both paths.

    Module-level so that a process pool can run it.

    Args:
        job: ``(shape name, harm name, seed)``.

    Returns:
        One result per policy and path, as JSON-ready dicts.

    """
    shape_name, harm_name, seed = job
    shape = next(s for s in UDP_SHAPES if s.name == shape_name)
    harm = next(h for h in UDP_HARMS if h.name == harm_name)
    r = udp.run(udp.Scenario(shape=shape.shape, seed=seed, impairments=harm.impairments,
                             mtu=shape.mtu))
    base = {
        "transport": "udp", "shape": shape.name, "harm": harm.name, "seed": seed,
        "void": list(r.void), "realised": realised_udp(r.ledger, harm),
    }
    results = []
    for policy in UDP_POLICIES:
        for path in udp.PATHS:
            name = f"{policy.name}, {path}"
            try:
                m = udp.measure(r, policy.options, path=path, sequenced=policy.sequenced)
            except (Unclean, zpf.ZpfError) as error:
                results.append({**base, "policy": name,
                                "unclean": f"{type(error).__name__}: {error}"})
                continue
            held = sorted(t.error_usec for t in m.order.timing if t.held)
            kept = max((t.error_usec for t in m.order.timing if not t.held), default=0)
            results.append({
                **base,
                "policy": name,
                "unclean": None,
                "delivery": dataclasses.asdict(m.delivery),
                "delivered": m.delivery.delivery,
                "conservation": m.delivery.conservation,
                "failures": m.accounting.failures(),
                "order": {"inversions": m.order.inversions,
                          "unexplained": m.order.unexplained},
                "timing": {"held": held, "kept_worst": kept},
            })
    return results


def sweep_udp(
    shapes: tuple[UdpShape, ...] = UDP_SHAPES,
    harms: tuple[UdpHarm, ...] = UDP_HARMS,
    *,
    seeds: int | None = None,
    jobs: int | None = None,
) -> list[dict[str, Any]]:
    """Run the UDP matrix.

    Args:
        shapes: The scenario families.
        harms: The impairment cells.
        seeds: Seeds per cell, overriding each shape's own; for a quick look.
        jobs: Worker processes; one per CPU when ``None``, none when 1.

    Returns:
        One result per (shape, harm, seed, policy, path), in that order
        whatever the worker count.

    """
    work = [
        (shape.name, harm.name, seed)
        for shape in shapes
        for harm in harms
        for seed in range(seeds if seeds is not None else shape.seeds)
    ]
    return _pooled(sweep_udp_one, work, jobs)


# ── The report ──────────────────────────────────────────────────────────


def _rate(value: float) -> str:
    """Format a score without ever rounding an imperfect one up to 1."""
    if value == 1.0:
        return "1"
    return f"{math.floor(value * 10_000) / 10_000:.4f}"


def _ms(values: list[int]) -> str:
    if not values:
        return "–"
    return f"{statistics.median(values) / 1000:.1f} / {max(values) / 1000:.1f}"


def summarise(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold per-run results into one row per (shape, harm, policy) cell.

    A run is scored when it is not void, read back clean, and exercised the
    cell's impairment.  A cell with fewer than :data:`EXERCISED` scored runs
    is *not exercised* and gets no score.

    Args:
        results: What :func:`sweep` returned.

    Returns:
        One dict per cell, in the matrix's order.

    """
    cells: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for result in results:
        key = (str(result["shape"]), str(result["harm"]), str(result["policy"]))
        cells.setdefault(key, []).append(result)

    rows = []
    for (shape, harm, policy), runs in cells.items():
        void = [r for r in runs if r["void"]]
        unclean = [r for r in runs if not r["void"] and r["unclean"]]
        scored = [r for r in runs if not r["void"] and not r["unclean"] and r["realised"]]
        row: dict[str, Any] = {
            "shape": shape, "harm": harm, "policy": policy,
            "runs": len(runs), "void": len(void), "unclean": len(unclean),
            "scored": len(scored), "exercised": len(scored) >= EXERCISED,
        }
        if scored:
            fidelity = [float(r["fidelity"]) for r in scored]
            recovery = [float(r["recovery"]) for r in scored]
            causes: dict[str, int] = {}
            extra = 0
            for r in scored:
                for direction in r["bytes"].values():
                    for cause, n in direction["causes"].items():
                        causes[cause] = causes.get(cause, 0) + n
                    extra += direction["extra"]
            timing = [t for r in scored for t in r["timing"]]
            sent = [t for t in timing if t["correct"] and not t["recovered"]]
            row.update({
                "fidelity": (statistics.median(fidelity), min(fidelity)),
                "recovery": (statistics.median(recovery), min(recovery)),
                "causes": dict(sorted(causes.items())),
                "extra": extra,
                "failing": sum(1 for r in scored if r["failures"]),
                "failures": sorted({f for r in scored for f in r["failures"]}),
                "misjudged": sum(int(r["copies_as_resends"]) + int(r["resends_as_copies"])
                                 for r in scored),
                "inverted": sum(1 for r in scored if r["order"]["inversions"]),
                "reordered": sum(1 for r in scored if r["order"]["reordered"]),
                "forged": sum(int(r["order"]["forged"]) for r in scored),
                "timestamp": _ms([t["timestamp_error"] for t in sent]),
                "ts_first": _ms([t["ts_first_error"] for t in sent
                                 if t["ts_first_error"] is not None]),
                "recovered": _ms([t["timestamp_error"] for t in timing
                                  if t["correct"] and t["recovered"]]),
                "acked_fallback_bytes": sum(int(r["stats"]["acked_fallback_bytes"])
                                            for r in scored),
            })
        rows.append(row)
    return rows


def summarise_udp(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold per-run UDP results into one row per (shape, harm, policy and path) cell.

    Scored as :func:`summarise` scores a TCP cell: not void, read back
    clean, and exercised.

    Args:
        results: What :func:`sweep_udp` returned.

    Returns:
        One dict per cell, in the matrix's order.

    """
    cells: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for result in results:
        key = (str(result["shape"]), str(result["harm"]), str(result["policy"]))
        cells.setdefault(key, []).append(result)

    rows = []
    for (shape, harm, policy), runs in cells.items():
        void = [r for r in runs if r["void"]]
        unclean = [r for r in runs if not r["void"] and r["unclean"]]
        scored = [r for r in runs if not r["void"] and not r["unclean"] and r["realised"]]
        row: dict[str, Any] = {
            "shape": shape, "harm": harm, "policy": policy,
            "runs": len(runs), "void": len(void), "unclean": len(unclean),
            "scored": len(scored), "exercised": len(scored) >= EXERCISED,
        }
        if scored:
            delivered = [float(r["delivered"]) for r in scored]
            conserved = [float(r["conservation"]) for r in scored]
            totals = {
                key: sum(int(r["delivery"][key]) for r in scored)
                for key in ("lost", "withheld", "cited", "repeated", "altered")
            }
            row.update({
                "delivered": (statistics.median(delivered), min(delivered)),
                "conservation": (statistics.median(conserved), min(conserved)),
                **totals,
                "failing": sum(1 for r in scored if r["failures"]),
                "failures": sorted({f for r in scored for f in r["failures"]}),
                "inversions": sum(int(r["order"]["inversions"]) for r in scored),
                "unexplained": sum(int(r["order"]["unexplained"]) for r in scored),
                "held": _ms([t for r in scored for t in r["timing"]["held"]]),
                "kept_worst": max(int(r["timing"]["kept_worst"]) for r in scored),
            })
        rows.append(row)
    return rows


def _report_udp(rows: list[dict[str, Any]]) -> list[str]:
    """Render the UDP cells, one table per scenario family."""
    lines = [
        "## UDP",
        "",
        "Each policy runs along both paths: a pcap, and a `.zpf` of its packets as a",
        "tunnel decryptor writes one.  *Delivered* is datagrams in exactly one record with",
        "their true bytes ÷ sent, *conserved* copies written ÷ copies captured; each is",
        "median / worst.  Then totals over the scored runs: datagrams *lost* on the wire,",
        "*withheld* (with how many of their copies are *cited*), *repeated* in more than one",
        "record, and *altered*.  *Inversions* are pairs of records stored against send",
        "order, with how many no reordered datagram explains.  *Held* is median / worst",
        "milliseconds a reordered datagram's record trails its send time; *kept* the worst",
        "microseconds any other does.",
        "",
    ]
    for shape in UDP_SHAPES:
        own = [row for row in rows if row["shape"] == shape.name]
        if not own:
            continue
        lines += [f"## {shape.name}", "", f"{shape.note}.", ""]
        lines += [
            "| impairment | policy | scored | void | delivered | conserved | lost "
            "| withheld (cited) | repeated | altered | failing | inversions (unexplained) "
            "| held | kept |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- "
            "| --- | --- |",
        ]
        for row in own:
            scored = f"{row['scored']}/{row['runs']}"
            if row["unclean"]:
                scored += f", **{row['unclean']} unclean**"
            if not row["exercised"]:
                lines.append(
                    f"| {row['harm']} | {row['policy']} | {scored} | {row['void']} "
                    "| *not exercised* | | | | | | | | | |"
                )
                continue
            delivered, worst_delivered = row["delivered"]
            conserved, worst_conserved = row["conservation"]
            withheld = f"{row['withheld']} ({row['cited']})" if row["withheld"] else "–"
            inversions = (f"{row['inversions']} ({row['unexplained']})"
                          if row["inversions"] else "–")
            lines.append(
                f"| {row['harm']} | {row['policy']} | {scored} | {row['void']} "
                f"| {_rate(delivered)} / {_rate(worst_delivered)} "
                f"| {_rate(conserved)} / {_rate(worst_conserved)} "
                f"| {row['lost'] or '–'} | {withheld} | {row['repeated'] or '–'} "
                f"| {row['altered'] or '–'} | {row['failing'] or '–'} | {inversions} "
                f"| {row['held']} | {row['kept_worst']} |"
            )
        lines.append("")
    return lines


def report(
    rows: list[dict[str, Any]], header: list[str],
    udp_rows: list[dict[str, Any]] | None = None,
) -> str:
    """Render the summary as Markdown, one table per scenario family.

    Args:
        rows: What :func:`summarise` returned.
        header: Lines naming what the sweep ran against.
        udp_rows: What :func:`summarise_udp` returned, rendered after the
            TCP families; a report without them is the TCP report alone.

    Returns:
        The report.  It holds nothing that varies between two runs of the
        same matrix, so it compares byte for byte.

    """
    lines = ["# Fidelity sweep", "", *(f"- {line}" for line in header), ""]
    lines += [
        "A cell is scored over runs that are not void (the generator's output not what",
        "the truth claims, as with packeteer#227 before 0.21.0), read back clean,",
        f"and exercised its impairment; fewer than {EXERCISED} and it is *not exercised*.",
        "Fidelity is correct ÷ sent, recovery correct ÷ available; each is median / worst.",
        "*Failing* counts runs with an accounting failure, *inverted* runs placing a",
        "message before one it depends on.  Timing is median / worst milliseconds by",
        "which a message's record `timestamp` (`ts_first`) trails its true send time,",
        "and *recovered* the same for a message whose original was lost.",
        "",
    ]
    for shape in SHAPES:
        own = [row for row in rows if row["shape"] == shape.name]
        if not own:
            continue
        lines += [f"## {shape.name}", "", f"{shape.note}.", ""]
        lines += [
            "| impairment | policy | scored | void | fidelity | recovery | wrong bytes "
            "| failing | misjudged | inverted | reordered | timestamp | ts_first "
            "| recovered |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- "
            "| --- | --- |",
        ]
        for row in own:
            scored = f"{row['scored']}/{row['runs']}"
            if row["unclean"]:
                scored += f", **{row['unclean']} unclean**"
            if not row["exercised"]:
                lines.append(
                    f"| {row['harm']} | {row['policy']} | {scored} | {row['void']} "
                    "| *not exercised* | | | | | | | | | |"
                )
                continue
            fidelity, worst_fidelity = row["fidelity"]
            recovery, worst_recovery = row["recovery"]
            causes = ", ".join(f"{k} {v}" for k, v in row["causes"].items())
            if row["extra"]:
                causes += f"{', ' if causes else ''}extra {row['extra']}"
            lines.append(
                f"| {row['harm']} | {row['policy']} | {scored} | {row['void']} "
                f"| {_rate(fidelity)} / {_rate(worst_fidelity)} "
                f"| {_rate(recovery)} / {_rate(worst_recovery)} "
                f"| {causes or '–'} | {row['failing'] or '–'} | {row['misjudged'] or '–'} "
                f"| {row['inverted'] or '–'} | {row['reordered'] or '–'} "
                f"| {row['timestamp']} | {row['ts_first']} | {row['recovered']} |"
            )
        lines.append("")
    udp_rows = udp_rows or []
    if udp_rows:
        lines += _report_udp(udp_rows)
    failures = sorted({f for row in [*rows, *udp_rows] for f in row.get("failures", [])})
    if failures:
        lines += ["## Accounting failures", "", *(f"- {f}" for f in failures), ""]
    return "\n".join(lines)


def ran_against() -> list[str]:
    """Name each build the sweep ran, with its version *and* the file it came from (#42).

    Returns:
        One line per package.

    """
    import packeteer

    import zpfwire

    return [
        f"packeteer {metadata.version('packeteer')} from {packeteer.__file__}",
        f"zpf {zpf.__version__} from {zpf.__file__}",
        f"zpfwire {metadata.version('zpfwire')} from {zpfwire.__file__}",
    ]


def main() -> int:
    """Run the sweep and write its report.

    Returns:
        The process exit status: 1 when any conversion read back unclean,
        which is a bug whatever the scores say.

    """
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--out", type=pathlib.Path,
                        help="directory for runs.jsonl and summary.md; stdout gets the summary")
    parser.add_argument("--seeds", type=int, help="seeds per cell, overriding each shape's own")
    parser.add_argument("--shape", action="append",
                        choices=[s.name for s in (*SHAPES, *UDP_SHAPES)],
                        help="only this scenario family; repeatable")
    parser.add_argument("--jobs", type=int, help="worker processes (default: one per CPU)")
    args = parser.parse_args()

    shapes = tuple(s for s in SHAPES if not args.shape or s.name in args.shape)
    udp_shapes = tuple(s for s in UDP_SHAPES if not args.shape or s.name in args.shape)
    results = sweep(shapes, seeds=args.seeds, jobs=args.jobs)
    udp_results = sweep_udp(udp_shapes, seeds=args.seeds, jobs=args.jobs)
    rows = summarise(results)
    udp_rows = summarise_udp(udp_results)
    summary = report(rows, ran_against(), udp_rows)
    results += udp_results
    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        with (args.out / "runs.jsonl").open("w", encoding="utf-8") as stream:
            for result in results:
                stream.write(json.dumps(result, sort_keys=True) + "\n")
        (args.out / "summary.md").write_text(summary + "\n", encoding="utf-8")
    sys.stdout.write(summary + "\n")
    return 1 if any(row["unclean"] for row in [*rows, *udp_rows]) else 0


if __name__ == "__main__":
    sys.exit(main())
