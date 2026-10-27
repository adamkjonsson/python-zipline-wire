# Contributing

Working on zpfwire itself.  Development uses one virtualenv built from
`requirements.txt`, and optionally a second for working on the siblings at
the same time.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

Python ≥ 3.10 — the floor `zpf` sets.  `-e .` installs the two siblings from
the release tags `pyproject.toml` names, so `.venv` tests what the wheel
declares, and `pip list` says what is running.

To change packeteer or python-zipline alongside this tree, add a second venv
on the checkouts next to this one:

```bash
python3 -m venv .venv-dev
.venv-dev/bin/pip install -e . -r requirements.txt
.venv-dev/bin/pip install -r requirements-dev-siblings.txt
```

Every test run prints each sibling's version **and** the file it was imported
from.  In `.venv-dev` the path is a checkout, and the version beside it is
whatever was recorded when the install was made, which can be stale.  A
result to be quoted as "against release X" comes from `.venv`.  To reinstall
zpfwire there, use `pip install --no-deps -e .`, or pip puts the tags back over
the checkouts.

**Moving to a new sibling release** is one edit: the tag in `pyproject.toml`'s
`dependencies`, made once the suite has passed against that release.  The
tags are named there and nowhere else (#67); `test_package.py` fails if a
sibling is declared by name or a requirements file names one, and checks
that `.venv` runs the declared release.  Rebuild `.venv`, or run
`pip install -e .` in it, to take the new tag in.

Note the `-e .` — installing the requirements alone leaves zpfwire itself
uninstalled, and the tests will still pass because `pyproject.toml` puts `src`
on pytest's path, while `import zpfwire` from a plain interpreter and the
`zpfwire` console script will not work.

## The quality gate

Run all three before pushing.

```bash
.venv/bin/pytest                                    # tests — must be green
ruff check src/ tests/ docs/ tools/ benchmarks/     # lint — zero warnings
.venv/bin/sphinx-build -W docs docs/_build/html     # docs — warnings are errors
```

These are the same checks CI runs.  The docs build is not a formality: `-W`
turns a broken cross-reference or a stale autodoc target into a failure, so
renaming a public name without updating its API page fails here.

## A change that must not move output

A refactor or a speed fix claims that every conversion still writes the same
bytes. The suite alone cannot back that claim, because `tests/test_pins.py`
deliberately leaves the TCP Timestamps fixtures unpinned. Run the
byte-identity check against the last release instead:

```bash
.venv/bin/python tools/byte_identity.py                    # against the last release tag
.venv/bin/python tools/byte_identity.py --baseline 1b9f091  # against any ref
```

With no `--baseline` it compares against the most recent release tag
reachable from `HEAD`. A change that moves output by default, behind an
option that restores what came before, is checked with that option set:
`--option NAME=VALUE` sets a `ReassemblyOptions` field, as JSON, in each
tree that has it. Since `0.6.0` stores pure ACKs by default, a check
against `v0.5.0` or older takes `--option pure_acks=false`.

It checks the baseline out into a temporary worktree and runs both trees
against the same installed siblings. For each fixture it compares whole
output files and conversion stats across every overlap policy, binary and
JSONL, `--sequenced`, a `.zpf`-of-packets input, and the pcap export. The
only thing normalised is zpfwire's own version stamp. It exits non-zero on
any difference and names each one.

For the speed half of the claim, `benchmarks/reassembly.py` times the
reassembler on the synthetic shapes the performance issues were found on,
and a real capture end to end. It is not a test; record its figures where
the change is argued, before and after, from `.venv` (see *Setup*).

## A change meant to make output more right

Byte identity says a change moved nothing, and the benchmark says how fast
it is. Neither says whether the output is *right*. `tools/fidelity.py`
answers that. packeteer generates a TCP conversation or a UDP flow under
impairments, and knows exactly what each application sent and what
happened to every packet. zpfwire converts the impaired capture, and the
tool scores the `.zpf` against what was sent:

```bash
.venv/bin/python tools/fidelity.py --out fidelity/          # the full matrix, ~4.5 min
.venv/bin/python tools/fidelity.py --shape prototype --seeds 10
.venv/bin/python tools/fidelity.py --shape udp-prototype    # one UDP family
```

It runs scenario families × impairments × seeds × reassembly policies, and
writes `runs.jsonl` with one line per conversion, plus `summary.md`. For
each cell the summary gives:

- **fidelity** (correct bytes ÷ bytes sent) and **recovery** (correct ÷
  bytes some captured copy carried), as median and worst;
- the wrong bytes by cause: lost, dropped, a stray or corrupted copy kept;
- runs whose file misstates itself: an uncited byte, a wrong gap count, a
  wrong end reason;
- duplicates and resends judged the wrong way round;
- runs placing a message before one it depends on;
- timing errors.

A UDP flow has no sequence numbers, so nothing is placed by offset. What
can go wrong is which datagrams arrived, how many times, and in what
order. Each UDP policy runs along two paths: a pcap, and a `.zpf` of the
same packets, as a tunnel decryptor writes one. For each UDP cell the
summary gives:

- **delivered** (datagrams in exactly one record with their true bytes ÷
  datagrams sent) and **conserved** (copies written ÷ copies captured);
- the datagrams lost on the wire, withheld (and how many of their copies
  are cited), repeated in more than one record, or altered;
- runs whose file misstates itself: a copy in no record and not cited, a
  record matching no copy, capture order or capture time not kept, wrong
  provenance on the packets path, wrong stats;
- pairs of records stored against send order, each of which has to be
  explained by a datagram the network held back.

A captured duplicate is *repeated* by design. The specification forbids a
transport-layer stage to withhold content from a stream without sequence
numbers, so a copy the capture point saw twice is written twice.

Three rules keep it honest:

- **A run is void** when packeteer's own output is not what the truth
  claims, such as a corrupted segment whose checksum verifies
  (packeteer#227). A void run is reported and never scored.
- **A cell is scored on what happened, not on what was configured.** A cell
  that exercised its impairment fewer than ten times is *not exercised*.
- **A file that does not read back clean is never scored.** It is a bug,
  and the tool exits 1.

The same matrix gives the same report, byte for byte, whatever the worker
count, so a fix can quote its cells before and after. The header names each
sibling's version and the file it was imported from, as the pytest header
does, and zpfwire's own version too. So a comparison across a version bump
starts below the header, at line 6 (`tail -n +6 summary.md`). A baseline
claimed for a release runs in `.venv`.

The tool is four modules. `tools/fidelity.py` is the matrix, the sweep and
the report. `tools/fidelity_tcp.py` is TCP's truth, ledger and scorer, and
`tools/fidelity_udp.py` UDP's, where each datagram copy is reassembled from
its fragments and checksummed by the ledger itself.
`tools/fidelity_common.py` holds what every transport shares: the
position-unique payloads, packeteer's label grammar, and where a frame sits
in the capture a citation points into. Scores are reported,
not asserted. The cases that must be perfect are asserted:
`tests/test_fidelity.py` covers no impairment, duplication with
retransmission, and recovered loss. `tests/test_fidelity_udp.py` covers
every captured datagram written as captured, on both paths, under each
impairment.

## Code style

The rules in `CLAUDE.md` and `ruff.toml` are enforced, not aspirational:

- **Type hints everywhere** — every parameter, return, and class attribute
  annotated.  `from __future__ import annotations` at the top of every module.
- **Zero ruff warnings.**  After a change, the files you touched must produce
  none.  Do not relax `ruff.toml` to silence one — the config is copied
  verbatim from packeteer and changing a value there is not a fix.  A `# noqa`
  is a last resort that needs the maintainer's sign-off *first*.
- **Google-style docstrings**, ruff-formatted.  Sections (`Args`, `Returns`,
  `Raises`, `Attributes`, `Example`) need a blank line before the closing
  `"""`.
- **Keep `__main__.py` thin.**  Argparse and printing only.  Anything the CLI
  can do must be reachable from the Python API; a flag with no API equivalent
  is a bug in the API.
- **Aligned signatures.**  Code solving similar problems for different
  transports should look the same.  When you add a parameter to one path,
  check whether its sibling wants it too.

## The vocabulary trap

In `zpf`, a **decoder** is *a stage deriving one `.zpf` from another* —
`zpf.decode_stage`, `zpf.Decoder`, `output_layer`.  It is **not** a protocol
dissector.  Reassembly counts as a decoder in that sense, which is why this
project declares one.

So: never name anything here `Decoder`.  When protocol dissection arrives it
is `zpfwire.dissect` / `Dissector`.  This is also why the project is not
called `zipline-decode`.

## Upstream-first

If you find a defect or a missing capability in packeteer or python-zipline,
it gets fixed *there*.  Ask before filing, then file.  See
{doc}`upstream-first` for the rule and for what a good issue looks like.

## Git

- **Never commit or push without being asked.**  Do not run `git commit`,
  `git push`, or any destructive git command unless it was requested.
- Branch rather than committing to the default branch.
- Commit messages explain *why*, not what the diff already shows.  The
  interesting content of a commit here is usually the specification rule that
  forced a decision, or the case that broke the obvious implementation.

## The changelog

`CHANGELOG.md` follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
as both siblings do, and **a user-visible change lands with its entry** under
`## [Unreleased]` in the same commit — public API, CLI flags, reassembly
policy, defaults, the shape of what a conversion writes, bug fixes and docs.
Internal refactors and test-only changes do not get one.

Change types, in this order, omitting the empty ones: `Added`, `Changed`,
`Deprecated`, `Removed`, `Fixed`, `Security`, `Documentation`.  A break goes
under `Changed` or `Removed` with a leading **`Breaking:`** — and that
includes a change to what a conversion *writes*, since a `.zpf` whose bytes
move for the same input and the same options breaks anyone reproducing one.

Releasing renames `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`, adds a fresh empty
`Unreleased`, drops the `.devN` suffix from the version in `pyproject.toml`,
updates the link definitions at the foot of the file, tags `vX.Y.Z`, and
closes the release's issues and its milestone.  Issues close at **release**,
not at merge: work can sit merged on `main` under `Unreleased`, and closing
early would claim a fix is delivered when it is not yet in any release.

The `.devN` suffix goes on as soon as the tree diverges from the last tag,
not at the end: every file carries `produced_by = "zpfwire <version>"`, so a
tree that behaves differently from a release while stamping its output with
that release's number is a provenance error in the files themselves.

## Where the design lives

| Document | What it is |
|----------|------------|
| `plans/PLAN.md` | The design and phasing this project was originally built to, with the upstream issues each phase depended on. |
| `plans/V*-RELEASE-PLAN.md` | One per release: what it was measured against, the decisions taken, and where execution departed from the plan. |
| `CLAUDE.md` | The standing rules, in the short form. |
| `CHANGELOG.md` | What changed, per release, and which spec and sibling versions it was built against. |
| `docs/internals/` | How it works now. |

Everything under `plans/` records *why* — including decisions that were
reversed — and is **historical, not normative**: a plan describes the world as
it was when written, and nothing there is maintained after the work lands.
Where a plan disagrees with the code, the code is right; where it disagrees
with `CLAUDE.md` or `docs/`, those are.  See `plans/README.md`.

## Adding a transport

A new transport is a {class}`~zpfwire.flow.FlowTracker` subclass and one entry
in `convert._TRACKERS`.  {doc}`writer-mapping` has the checklist; `udp.py` is
some fifty lines and shows how much the base class already does.

## A note on what this project is for

zpfwire is glue.  It owns no file format and no packet parser, and when a
change here starts to look like implementing one of those, that is the signal
to check whether it belongs upstream instead.  The reassembler lives here for
a specific reason — its output shape is dictated by the payload format, and
moving it into packeteer would import format semantics into a format-agnostic
library — and that reasoning is worth re-applying to anything new.
