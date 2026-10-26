"""Check that this tree converts every fixture to the bytes a release wrote.

The release check for any change meant to leave output alone, as every phase
of the ``0.6.0`` performance work is.  It is a script, not a test: the
Timestamps fixtures are deliberately left unpinned by ``tests/test_pins.py``,
so the comparison is made against a *release* at the moment a change claims
to move nothing, and its result is recorded in the plan.

Both trees run in this interpreter, against the same installed zpf and
packeteer, each in a subprocess with its own ``src`` first on the path.  The
baseline is checked out into a temporary git worktree.  Compared, per
fixture:

- ``capture_to_zpf`` under ``favor-old``, ``favor-acked`` and a tight window
  and timeout, each as binary and as JSONL, and under ``favor-old`` with
  ``sequenced=True``;
- ``packets_to_zpf`` of the fixture repackaged as a ``.zpf`` of packet
  records, the input built once and read by both trees from one path, since
  a ``zpf-input`` Source records its input's path;
- ``packets_to_pcap`` of the same input.

Each output is compared whole, file bytes and conversion stats.  The one
thing normalised is zpfwire's own version, which every file stamps in
``produced_by`` and on its Decoder: both trees have ``tool_version`` patched
to the same string.  Every binary output must also read back clean.

A change that moves output by default, behind an option that restores the
old output, is checked with that option: ``--option NAME=VALUE`` sets a
:class:`~zpfwire.options.ReassemblyOptions` field in every policy, in each
tree that has the field, and the report names it.  Since ``0.6.0`` stores
pure ACKs by default, a check against ``v0.5.0`` or older is run with
``--option pure_acks=false``.

The baseline is the most recent release tag reachable from ``HEAD`` unless
``--baseline`` names another ref, so the default does not go stale at each
release.

Usage::

    .venv/bin/python tools/byte_identity.py                  # against the last release
    .venv/bin/python tools/byte_identity.py --baseline v0.5.0 --option pure_acks=false
    .venv/bin/python tools/byte_identity.py --baseline 1b9f091 --keep

Exits ``0`` when every output matches, ``1`` otherwise.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.metadata
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests" / "captures"
PINNED_AT = 1_700_000_000
"""``produced_at`` of every ``.zpf``-input conversion: the stage requires one."""
VERSION = "byte-identity"
"""What ``tool_version`` returns in both trees."""


def main() -> int:
    """Run the comparison and report it.

    Returns:
        The process exit status.

    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--baseline",
                        help="git ref to compare against (default: the last release tag)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the work directory and print where it is")
    parser.add_argument("--option", action="append", default=[], metavar="NAME=VALUE",
                        help="set a ReassemblyOptions field, as JSON, in every tree that has it")
    args = parser.parse_args()
    if args.baseline is None:
        args.baseline = subprocess.run(
            ["git", "-C", str(ROOT), "describe", "--tags", "--abbrev=0", "--match", "v*"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    options = {}
    for setting in args.option:
        name, _, value = setting.partition("=")
        options[name] = json.loads(value)

    work = pathlib.Path(tempfile.mkdtemp(prefix="zpfwire-identity-"))
    baseline = work / "baseline"
    subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "--detach", "-q",
                    str(baseline), args.baseline], check=True)
    try:
        inputs = _packet_inputs(work / "inputs")
        results = {
            name: _collect(src, work / f"{name}.json", inputs, options)
            for name, src in (("baseline", baseline / "src"), ("current", ROOT / "src"))
        }
    finally:
        subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force",
                        str(baseline)], check=True)
        if not args.keep:
            shutil.rmtree(work)
    if args.keep:
        print(f"work directory: {work}")
    return _report(args.baseline, results["baseline"], results["current"])


def _packet_inputs(where: pathlib.Path) -> dict[str, str]:
    """Repackage every fixture as a ``.zpf`` of packets, once, for both trees to read."""
    sys.path.insert(0, str(ROOT / "tests"))
    from helpers import packets_zpf  # tests/ is on the path only from here

    where.mkdir(parents=True)
    return {
        capture.name: str(packets_zpf(capture, where / f"{capture.name}.packets.zpf"))
        for capture in sorted(CAPTURES.glob("*.pcap*"))
    }


def _collect(
    src: pathlib.Path, out: pathlib.Path, inputs: dict[str, str], options: dict[str, object],
) -> dict[str, object]:
    """Run :func:`collect` in a subprocess with *src* first on the path."""
    subprocess.run(
        [sys.executable, "-I", __file__, "--collect", str(src), str(out), json.dumps(inputs),
         json.dumps(options)],
        check=True,
    )
    return json.loads(out.read_text(encoding="utf-8"))


def collect(src: str, out: str, inputs: dict[str, str], options: dict[str, object]) -> None:
    """Convert every fixture with the zpfwire in *src*, and record what was written.

    Args:
        src: The ``src`` directory of the tree to run.
        out: Where to write the results, as JSON.
        inputs: Each fixture's ``.zpf``-of-packets repackaging, by fixture name.
        options: ``ReassemblyOptions`` fields to set, where this tree has them.

    """
    sys.path.insert(0, src)
    # Imported only once the tree under test is first on the path.
    import packeteer
    import zpf

    import zpfwire
    from zpfwire import convert, packets

    assert zpfwire.__file__.startswith(src), f"loaded {zpfwire.__file__}, not {src}"
    convert.tool_version = packets.tool_version = lambda: VERSION

    def clean(data: bytes) -> None:
        with zpf.open(io.BytesIO(data)) as reader:
            for session in reader.sessions():
                for _ in session.records():
                    pass
            assert reader.diagnostics == [], reader.diagnostics
            assert reader.unplaceable == [], reader.unplaceable

    def entry(data: bytes, stats: object) -> dict[str, object]:
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "stats": {k: repr(v) for k, v in dataclasses.asdict(stats).items()},
        }

    fields = {field.name for field in dataclasses.fields(zpfwire.ReassemblyOptions)}
    applied = {name: value for name, value in options.items() if name in fields}
    policies = {
        "favor-old": zpfwire.ReassemblyOptions(**applied),
        "favor-acked": zpfwire.ReassemblyOptions(overlap="favor-acked", **applied),
        "tight": zpfwire.ReassemblyOptions(reorder_window=2048, flush_timeout=0.01, **applied),
    }
    scratch = pathlib.Path(out).with_suffix(".d")
    scratch.mkdir()
    outputs: dict[str, object] = {}
    for capture in sorted(CAPTURES.glob("*.pcap*")):
        variants = [(name, policy, "binary", False) for name, policy in policies.items()]
        variants += [(name, policy, "jsonl", False) for name, policy in policies.items()]
        variants.append(("favor-old", policies["favor-old"], "binary", True))
        for name, policy, face, sequenced in variants:
            path = scratch / f"{capture.name}.{name}.{face}.{sequenced}"
            stats = zpfwire.capture_to_zpf(capture, path, options=policy, face=face,
                                           sequenced=sequenced, produced_at=None)
            data = path.read_bytes()
            if face == "binary":
                clean(data)
            label = f"capture/{capture.name}/{name}/{face}" + ("/sequenced" if sequenced else "")
            outputs[label] = entry(data, stats)

        sink = io.BytesIO()
        stats = zpfwire.packets_to_zpf(inputs[capture.name], sink, produced_at=PINNED_AT,
                                       options=policies["favor-old"])
        clean(sink.getvalue())
        outputs[f"packets/{capture.name}"] = entry(sink.getvalue(), stats)

        pcap = io.BytesIO()
        export = zpfwire.packets_to_pcap(inputs[capture.name], pcap)
        outputs[f"pcap-export/{capture.name}"] = entry(pcap.getvalue(), export)

    result = {
        "ran": {
            "zpfwire": zpfwire.__file__,
            "zpf": f"{zpf.__version__} from {zpf.__file__}",
            "packeteer": f"{importlib.metadata.version('packeteer')} from {packeteer.__file__}",
            "options": json.dumps(applied, sort_keys=True),
        },
        "outputs": outputs,
    }
    pathlib.Path(out).write_text(json.dumps(result, indent=1, sort_keys=True), encoding="utf-8")


def _report(ref: str, baseline: dict[str, object], current: dict[str, object]) -> int:
    """Print the comparison and return the exit status."""
    for name, result in (("baseline", baseline), ("current", current)):
        ran = result["ran"]
        print(f"{name:8s} zpfwire {ran['zpfwire']}")
        print(f"{'':8s} zpf {ran['zpf']}\n{'':8s} packeteer {ran['packeteer']}")
        print(f"{'':8s} options {ran['options']}")

    old, new = baseline["outputs"], current["outputs"]
    missing = sorted(set(old) ^ set(new))
    differ = []
    stats_only = []
    for label in sorted(set(old) & set(new)):
        if old[label]["sha256"] != new[label]["sha256"]:
            differ.append(label)
        elif _stats_differ(old[label]["stats"], new[label]["stats"]):
            stats_only.append(label)

    kinds: dict[str, int] = {}
    for label in old:
        kinds[label.split("/")[0]] = kinds.get(label.split("/")[0], 0) + 1
    print(f"\nagainst {ref}: " + ", ".join(f"{n} {kind}" for kind, n in sorted(kinds.items())))
    for title, labels in (("bytes differ", differ), ("stats differ", stats_only),
                          ("only in one tree", missing)):
        if labels:
            print(f"  {title}: {len(labels)}")
            for label in labels:
                print(f"    {label}")
    same = len(set(old) & set(new)) - len(differ) - len(stats_only)
    print(f"{same} of {len(set(old) | set(new))} identical")
    return 0 if same == len(set(old) | set(new)) else 1


def _stats_differ(old: dict[str, str], new: dict[str, str]) -> bool:
    """Compare stats on the fields both trees have; a field added since is not a difference."""
    return any(old[name] != new[name] for name in set(old) & set(new))


if __name__ == "__main__":
    if sys.argv[1:2] == ["--collect"]:
        collect(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]), json.loads(sys.argv[5]))
    else:
        sys.exit(main())
