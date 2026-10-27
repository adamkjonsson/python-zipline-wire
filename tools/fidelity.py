"""Measure how well a conversion represents the traffic that was actually sent.

The fidelity tool, ``0.7.0``'s instrument.  packeteer generates a
conversation under impairments of our choosing and knows exactly what was
sent; zpfwire converts the impaired capture; each transport's module scores
the ``.zpf`` against what was sent — :mod:`fidelity_tcp` — and this one runs
the matrix: scenario families × impairments × seeds × reassembly policies,
reported as one JSON line per conversion and a Markdown summary per cell.

``plans/V0.7.0-RELEASE-PLAN.md`` is the design; run it as
``.venv/bin/python tools/fidelity.py --out DIR``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import pathlib
import statistics
import sys
from dataclasses import dataclass
from importlib import metadata
from typing import Any

import zpf
from fidelity_common import DIRECTIONS, Direction, Unclean
from fidelity_tcp import PROTOTYPE, Impairments, Ledger, Scenario, measure, run

from zpfwire import ReassemblyOptions

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
    if jobs == 1:
        batches = map(sweep_one, work)
        return [result for batch in batches for result in batch]
    # Imported here: only the sweep needs a pool, and only a pool needs it.
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(max_workers=jobs) as pool:
        batches = pool.map(sweep_one, work, chunksize=4)
        return [result for batch in batches for result in batch]


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


def report(rows: list[dict[str, Any]], header: list[str]) -> str:
    """Render the summary as Markdown, one table per scenario family.

    Args:
        rows: What :func:`summarise` returned.
        header: Lines naming what the sweep ran against.

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
    failures = sorted({f for row in rows for f in row.get("failures", [])})
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
    parser.add_argument("--shape", action="append", choices=[s.name for s in SHAPES],
                        help="only this scenario family; repeatable")
    parser.add_argument("--jobs", type=int, help="worker processes (default: one per CPU)")
    args = parser.parse_args()

    shapes = tuple(s for s in SHAPES if not args.shape or s.name in args.shape)
    results = sweep(shapes, seeds=args.seeds, jobs=args.jobs)
    rows = summarise(results)
    summary = report(rows, ran_against())
    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        with (args.out / "runs.jsonl").open("w", encoding="utf-8") as stream:
            for result in results:
                stream.write(json.dumps(result, sort_keys=True) + "\n")
        (args.out / "summary.md").write_text(summary + "\n", encoding="utf-8")
    sys.stdout.write(summary + "\n")
    return 1 if any(row["unclean"] for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
