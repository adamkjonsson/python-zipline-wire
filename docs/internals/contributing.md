# Contributing

Working on zpfwire itself.  All development tasks use a single virtualenv
built from `requirements.txt`.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

Python ≥ 3.11 — the floor `zpf` sets.  The two siblings are installed editable
from `../packeteer` and `../python-zipline`, so a change in either is picked
up without reinstalling.

Note the `-e .` — installing the requirements alone leaves zpfwire itself
uninstalled, and the tests will still pass because `pyproject.toml` puts `src`
on pytest's path, while `import zpfwire` from a plain interpreter and the
`zpfwire` console script will not work.

## The quality gate

Run all three before pushing.

```bash
.venv/bin/pytest                                    # tests — must be green
ruff check src/ tests/ docs/                        # lint — zero warnings
.venv/bin/sphinx-build -W docs docs/_build/html     # docs — warnings are errors
```

These are the same checks CI runs.  The docs build is not a formality: `-W`
turns a broken cross-reference or a stale autodoc target into a failure, so
renaming a public name without updating its API page fails here.

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
