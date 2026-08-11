# zpfwire — Claude guidance

## The product

`zpfwire` turns network captures into **Zipline Payload Format** (`.zpf`) files.
It is glue: it owns no file format and no packet parser of its own.

- **packeteer** (`../packeteer`) parses captures and packets.
- **zpf** (`../python-zipline`, import name `zpf`) reads and writes `.zpf`
  against **spec v0.16** — `zpf.SPEC_VERSION` is the single source of truth.
- The specification itself lives in `../zipline/docs/zipline-payload-format.md`.

The output of a capture conversion is a **capture-sourced, transport-layer**
file — the top-left cell of the spec's two-axes table. That single fact settles
most encoding questions; see `PLAN.md`.

This code consists of a CLI defined in `src/zpfwire/__main__.py` and a Python
API which the CLI uses. It is important that all functionality implemented in
the CLI is easily available from the API as well. Keep `__main__.py` as lean as
possible.

The API should be easy to use and feel logical. Code solving different but
similar problems, for instance for different transports, should have aligned
signatures.

## Upstream-first

One purpose of this project is to **pressure-test packeteer and python-zipline**.
Gaps found here get fixed *there*, not papered over here.

- Every defect or missing capability found in either sibling gets a **GitHub
  issue filed in that repo** (`gh issue create`) — improvement ideas count, not
  just outright bugs. Ask before filing, then file.
- Any local shim is **temporary**. It carries a comment naming the upstream
  issue, and it is deleted when the fix lands.
- `PLAN.md` tracks the known gaps and which phase depends on them.

## Vocabulary trap

In `zpf`, a **decoder** is *a stage deriving one `.zpf` from another*
(`zpf.decode_stage`, `zpf.Decoder`, `output_layer`). It is **not** a protocol
dissector. Reassembly counts as a decoder in that sense, and declares
`output_layer = transport`.

So: never name anything here `Decoder`. When protocol dissection arrives, it is
`zpfwire.dissect` / `Dissector`. This is also why the project is not called
`zipline-decode`.

## Code style

- **Type hints everywhere.** All function parameters, return types, and class attributes must be annotated. Use `from __future__ import annotations` at the top of every module.
- **Zero ruff warnings.** After any change, the file you touched must produce no warnings from `ruff check`. The project config is in `ruff.toml`, copied verbatim from packeteer. Never make a warning
go away by changing values in the config file. Using a # noqa: comment to suppress
warnings can only be used as a last resort, and **always ask before making such a change**.

## Git

- **Never commit or push without explicit instruction.** Do not run `git commit`, `git push`, or any destructive git command (`reset --hard`, `checkout .`, etc.) unless I have asked for it in the current message.

## Project layout

- `src/zpfwire/` — the code
- `tests/` — test suite, native pytest style; run with `.venv/bin/pytest`
- `tests/captures/` — capture fixtures, copied from `../packeteer/testcases/`
- `PLAN.md` — the design and phasing this project is being built to

## Virtual environment

All development tasks use a single venv created from `requirements.txt`, which
installs the two siblings editable from the checkouts next to this one:

```bash
python -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

- **Run tests:** `.venv/bin/pytest`
- **Build wheel:** `.venv/bin/python -m build`

## Conventions

- Use `.venv/bin/pytest` to run tests and `ruff` (on PATH) to lint.
- Docstrings follow Google style with ruff-enforced formatting (see `ruff.toml`). Sections (Args, Returns, Raises, Attributes, Example) need a blank line before the closing `"""`.
- Every produced `.zpf` must read back clean: `zpf.open(path)`, walk the
  sessions, and assert `reader.diagnostics == []`. That is the load-bearing
  test assertion.
