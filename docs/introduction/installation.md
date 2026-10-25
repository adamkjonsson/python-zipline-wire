# Installation

zpfwire requires **Python 3.10 or newer** — the floor its `zpf` dependency
sets — and depends on two sibling projects:

| Dependency | Import name | What it does here |
|------------|-------------|-------------------|
| packeteer | `packeteer` | Reads captures, parses packets, reassembles IP fragments |
| python-zipline | `zpf` | Writes and validates the `.zpf` container |

Neither is published to PyPI yet, so both are installed from their GitHub
release tags.

## Development install

```bash
python3 -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

`requirements.txt` installs each sibling at the release tag this tree is
built against. It also brings in pytest, ruff, Sphinx, and the build tooling,
which is everything the project's checks need.

Verify the install:

```bash
.venv/bin/zpfwire --version
```

```
zpfwire 0.6.0 (zipline 0.23)
```

The test run's header names the build of each sibling it ran against:

```
zpf 0.7.0 from …/.venv/lib/python3.14/site-packages/zpf/__init__.py
packeteer 0.20.0 from …/.venv/lib/python3.14/site-packages/packeteer/__init__.py
```

## Working against the sibling checkouts

To change packeteer or python-zipline alongside zpfwire, check them out next
to this one and use a second venv, so the first keeps testing the releases:

```
projects/
  packeteer/
  python-zipline/
  python-zipline-wire/     ← you are here
```

```bash
python3 -m venv .venv-dev
.venv-dev/bin/pip install -e . -r requirements.txt
.venv-dev/bin/pip install -r requirements-dev-siblings.txt
```

The second install replaces the releases with editable installs of the
checkouts, so a change in either is picked up without reinstalling. An
editable install records its version once, when it is made. After that, `pip
list` and `zpf.__version__` can name a release while the code that runs is
whatever is checked out. The test header's path is what tells the two
apart. A result to be quoted as "against release X" comes from `.venv`.

The second number is the **specification** version the `zpf` library
implements, read from `zpf.SPEC_VERSION` rather than hard-coded.  It is the
one to quote when asking whether a file zpfwire wrote will be readable by
something else.

## Building a wheel

```bash
.venv/bin/python -m build
```

The wheel declares a range for each sibling, closed above:
`zpf>=0.7.0,<0.8` and `packeteer>=0.16.0,<0.21`. Both siblings are in `0.x`,
where every minor may break, so a range stops at the last minor this tree
was tested against. `CHANGELOG.md` names those releases. With neither sibling
on PyPI, installing the wheel needs them supplied, as `requirements.txt`
does; pip refuses a sibling outside the range rather than installing a
combination nobody ran.

## Running the checks

```bash
.venv/bin/pytest                                    # tests
ruff check src/ tests/ docs/ tools/ benchmarks/     # lint, must be silent
.venv/bin/sphinx-build -W docs docs/_build/html     # docs, warnings are errors
```

All three are release-blocking.  See {doc}`../internals/contributing` for what
each is guarding.
