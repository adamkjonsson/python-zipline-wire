"""Evaluate a reassembly policy against one scenario, over many seeds.

What ``zpfwire fidelity`` runs.  A seed changes what the network does — which
packets are lost, duplicated, forged — and not what was said, so a policy is
judged by how its scores spread over seeds, not by one run.
"""

from __future__ import annotations

import dataclasses
import json
import math
import statistics
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from importlib import metadata

import zpf

from zpfwire.fidelity._common import DIRECTIONS, Direction, Unclean
from zpfwire.fidelity._tcp import Impairments, Measurement, Scenario, measure, run
from zpfwire.options import ReassemblyOptions, tool_version

_ORDINARY = frozenset({"SYN", "SYN-ACK", "ACK", "DATA", "FIN", "FIN-ACK"})
"""Packet kinds every conversation has; the rest are what the network did."""


def parse_shape(text: str) -> tuple[tuple[Direction, int], ...]:
    """Parse a conversation's messages, as ``zpfwire fidelity --messages`` takes them.

    Args:
        text: Comma-separated ``direction:length`` pairs, in the order sent,
            e.g. ``"c2s:3000,s2c:9000"``.

    Returns:
        The shape, as :attr:`Scenario.shape` takes it.

    Raises:
        ValueError: If a pair is not ``c2s`` or ``s2c`` and a positive
            length, or there is none.

    """
    shape: list[tuple[Direction, int]] = []
    for item in text.split(","):
        direction, _, length = item.strip().partition(":")
        if direction not in DIRECTIONS or not length.isdigit() or int(length) <= 0:
            raise ValueError(
                f"each message is c2s:LENGTH or s2c:LENGTH with a positive length, "
                f"got {item.strip()!r}"
            )
        shape.append((direction, int(length)))  # type: ignore[arg-type]
    return tuple(shape)


@dataclass(frozen=True)
class Outcome:
    """One seed of an evaluation.

    Attributes:
        seed: The seed.
        void: Why the run may not be scored: packeteer's output was not what
            the truth claims.  Empty when it may.
        unclean: Why the converted file did not read back clean, or ``None``.
            Either way the run is not scored; an unclean file is a bug.
        measurement: The measurement, when the file read back clean.
        realised: What the network did in this run: the ledger's packets
            by impairment kind (``RETRANS``, ``DUP``, ``CORRUPT``, ``STRAY``,
            ``RST`` …), and ``lost`` for the bytes sent and never captured.
            A configured impairment is not a realised one: at a low rate,
            a seed may exercise nothing.

    """

    seed: int
    void: tuple[str, ...]
    unclean: str | None
    measurement: Measurement | None
    realised: dict[str, int]

    @property
    def scored(self) -> bool:
        """Whether the run counts toward the scores, being neither void nor unclean."""
        return not self.void and self.measurement is not None

    def failures(self) -> list[str]:
        """Return each way the converted file misstates the conversion.

        Returns:
            One line per failure; empty when the file accounts for itself, or
            when there is no measurement.

        """
        if self.measurement is None:
            return []
        stats = self.measurement.conversion.stats
        return self.measurement.accounting.failures(late_bytes=stats.late_bytes)


@dataclass(frozen=True)
class Evaluation:
    """One policy, run against one scenario over many seeds.

    Attributes:
        scenario: The scenario; its ``seed`` is replaced by each of the seeds.
        options: The reassembly policy.
        sequenced: Whether sessions were written in causal order.
        outcomes: One per seed, in order.

    """

    scenario: Scenario
    options: ReassemblyOptions
    sequenced: bool
    outcomes: tuple[Outcome, ...]

    @property
    def scored(self) -> list[Measurement]:
        """The measurements that count toward the scores."""
        return [o.measurement for o in self.outcomes if o.scored and o.measurement is not None]

    @property
    def unclean(self) -> int:
        """How many runs' files did not read back clean, each of them a bug."""
        return sum(1 for o in self.outcomes if o.unclean is not None)

    def jsonl(self) -> Iterator[str]:
        """Yield one JSON line per seed, without a trailing newline.

        Yields:
            The seed's scores, wrong bytes by direction and cause, and
            accounting failures, or why it was not scored.

        """
        for outcome in self.outcomes:
            line: dict[str, object] = {
                "seed": outcome.seed,
                "void": list(outcome.void),
                "unclean": outcome.unclean,
                "realised": outcome.realised,
            }
            m = outcome.measurement
            if m is not None:
                line.update({
                    "fidelity": m.total.fidelity,
                    "recovery": m.total.recovery,
                    "bytes": {d: dataclasses.asdict(m.bytes[d]) for d in DIRECTIONS},
                    "failures": outcome.failures(),
                })
            yield json.dumps(line, sort_keys=True)

    def report(self) -> str:
        """Render the evaluation as Markdown.

        Returns:
            The report.  It names the versions it ran against and holds
            nothing else that varies between two evaluations of the same
            scenario and policy, so it compares byte for byte.

        """
        lines = [
            "# Fidelity",
            "",
            f"zpfwire {tool_version()}, packeteer {_version('packeteer')}, "
            f"zpf {zpf.__version__} (spec {zpf.SPEC_VERSION[0]}.{zpf.SPEC_VERSION[1]}).",
            "",
            "## Scenario",
            "",
            *_scenario_lines(self.scenario, [o.seed for o in self.outcomes]),
            "",
            "## Policy",
            "",
            f"- {_policy(self.options, self.sequenced)}",
            "",
            *self._scores(),
            *self._runs(),
        ]
        return "\n".join(lines).rstrip("\n") + "\n"

    def _scores(self) -> list[str]:
        scored = self.scored
        void = sum(1 for o in self.outcomes if o.void)
        lines = [
            "## Scores",
            "",
            f"{len(scored)} of {len(self.outcomes)} runs scored"
            + (f"; {void} void, as packeteer's output was not what it claims" if void else "")
            + (f"; **{self.unclean} read back unclean, which is a bug**" if self.unclean else "")
            + ".",
            "",
        ]
        if not scored:
            return lines
        fidelity = [m.total.fidelity for m in scored]
        recovery = [m.total.recovery for m in scored]
        lines += [
            "| | median | worst |",
            "| --- | --- | --- |",
            f"| fidelity: correct ÷ sent | {_rate(statistics.median(fidelity))} "
            f"| {_rate(min(fidelity))} |",
            f"| recovery: correct ÷ captured | {_rate(statistics.median(recovery))} "
            f"| {_rate(min(recovery))} |",
            "",
        ]
        causes: dict[str, int] = {}
        extra = 0
        for m in scored:
            total = m.total
            extra += total.extra
            for cause, count in total.causes.items():
                causes[cause] = causes.get(cause, 0) + count
        if causes or extra:
            lines.append("Wrong bytes over all runs, by cause:")
            lines.append("")
            lines += [f"- {cause}: {count}" for cause, count in sorted(causes.items())]
            if extra:
                lines.append(f"- extra, past what was sent: {extra}")
            lines.append("")
        else:
            lines += ["Every byte sent is in the file, correct, in every run.", ""]
        failing = [o for o in self.outcomes if o.scored and o.failures()]
        if failing:
            seen = sorted({f for o in failing for f in o.failures()})
            lines += [
                f"**{len(failing)} runs' files misstate the conversion:**",
                "",
                *(f"- {f}" for f in seen),
                "",
            ]
        else:
            lines += ["Every scored file accounts for every byte it was given.", ""]
        return lines

    def _runs(self) -> list[str]:
        lines = [
            "## Runs",
            "",
            "| seed | realised | fidelity | recovery | wrong bytes | accounting |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for outcome in self.outcomes:
            realised = ", ".join(f"{k} {v}" for k, v in sorted(outcome.realised.items())) or "–"
            m = outcome.measurement
            if outcome.void:
                lines.append(f"| {outcome.seed} | {realised} | *void* | | | |")
            elif m is None:
                lines.append(f"| {outcome.seed} | {realised} | **unclean** | | | |")
            else:
                total = m.total
                wrong = ", ".join(f"{k} {v}" for k, v in sorted(total.causes.items()))
                if total.extra:
                    wrong += f"{', ' if wrong else ''}extra {total.extra}"
                failures = outcome.failures()
                lines.append(
                    f"| {outcome.seed} | {realised} | {_rate(total.fidelity)} "
                    f"| {_rate(total.recovery)} | {wrong or '–'} "
                    f"| {len(failures) if failures else 'ok'} |"
                )
        return lines


def evaluate(
    scenario: Scenario,
    options: ReassemblyOptions | None = None,
    *,
    seeds: Iterable[int] = range(10),
    sequenced: bool = False,
) -> Evaluation:
    """Run *scenario* over each seed, convert it under *options*, and score it.

    Args:
        scenario: What is said and what the network does; its ``seed`` is
            replaced by each of *seeds*.
        options: The reassembly policy; zpfwire's defaults when ``None``.
        seeds: The seeds to run.
        sequenced: Whether to write each session in causal order.

    Returns:
        The evaluation.  A file that does not read back clean is recorded,
        not raised: it is reported as the bug it is.

    """
    options = options or ReassemblyOptions()
    outcomes = []
    for seed in seeds:
        r = run(dataclasses.replace(scenario, seed=seed))
        lost = sum(end - start for ranges in r.ledger.lost.values() for start, end in ranges)
        realised = {kind: n for kind, n in r.ledger.kinds().items() if kind not in _ORDINARY}
        if lost:
            realised["lost"] = lost
        try:
            m: Measurement | None = measure(r, options, sequenced=sequenced)
            unclean = None
        except (Unclean, zpf.ZpfError) as error:
            m, unclean = None, f"{type(error).__name__}: {error}"
        outcomes.append(Outcome(seed, r.void, unclean, m, realised))
    return Evaluation(scenario, options, sequenced, tuple(outcomes))


def _scenario_lines(scenario: Scenario, seeds: list[int]) -> list[str]:
    sizes = {d: sum(n for direction, n in scenario.shape if direction == d) for d in DIRECTIONS}
    messages = ", ".join(f"{d} {n}" for d, n in scenario.shape)
    changed = {
        f.name: getattr(scenario.impairments, f.name)
        for f in dataclasses.fields(Impairments)
        if getattr(scenario.impairments, f.name) != f.default
    }
    impairments = ", ".join(f"{k} {v}" for k, v in changed.items()) or "none"
    span = (f"{seeds[0]}–{seeds[-1]}" if seeds == list(range(seeds[0], seeds[-1] + 1))
            else ", ".join(map(str, seeds))) if seeds else "none"
    return [
        f"- messages: {messages} ({sizes['c2s']} bytes c2s, {sizes['s2c']} s2c)",
        f"- psh_probability: {scenario.psh_probability}",
        f"- impairments: {impairments}",
        f"- seeds: {span} ({len(seeds)})",
    ]


def _policy(options: ReassemblyOptions, sequenced: bool) -> str:
    changed = [
        f"{f.name} {getattr(options, f.name)}"
        for f in dataclasses.fields(ReassemblyOptions)
        if getattr(options, f.name) != f.default
    ]
    if sequenced:
        changed.append("sequenced")
    return ", ".join(changed) or "zpfwire's defaults"


def _rate(value: float) -> str:
    """Format a score without ever rounding an imperfect one up to 1."""
    if value == 1.0:
        return "1"
    return f"{math.floor(value * 10_000) / 10_000:.4f}"


def _version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "unknown"
