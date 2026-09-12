# Installation

zpfwire requires **Python 3.11 or newer** — the floor its `zpf` dependency
sets — and depends on two sibling projects:

| Dependency | Import name | What it does here |
|------------|-------------|-------------------|
| packeteer | `packeteer` | Reads captures, parses packets, reassembles IP fragments |
| python-zipline | `zpf` | Writes and validates the `.zpf` container |

Neither is published to PyPI yet, so both are installed from checkouts placed
next to this one:

```
projects/
  packeteer/
  python-zipline/
  python-zipline-wire/     ← you are here
```

## Development install

```bash
python3 -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

`requirements.txt` installs both siblings editable from `../packeteer` and
`../python-zipline`, so a change in either is picked up without reinstalling.
It also brings in pytest, ruff, Sphinx, and the build tooling — everything the
project's checks need.

Verify the install:

```bash
.venv/bin/zpfwire --version
```

```
zpfwire 0.2.0 (zipline 0.19)
```

The second number is the **specification** version the `zpf` library
implements, read from `zpf.SPEC_VERSION` rather than hard-coded.  It is the
one to quote when asking whether a file zpfwire wrote will be readable by
something else.

## Building a wheel

```bash
.venv/bin/python -m build
```

The wheel floors `packeteer` and `zpf` at the releases the code was built
against — `CHANGELOG.md` names them per release — but with neither on PyPI a
floor documents more than it resolves.  An older checkout beside this one
fails at import rather than somewhere subtler, which is what the floor is
for.

## Running the checks

```bash
.venv/bin/pytest                                    # tests
ruff check src/ tests/ docs/                        # lint, must be silent
.venv/bin/sphinx-build -W docs docs/_build/html     # docs, warnings are errors
```

All three are release-blocking.  See {doc}`../internals/contributing` for what
each is guarding.
