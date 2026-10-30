# Installation

zpfwire requires **Python 3.10 or newer** — the floor its `zpf` dependency
sets — and depends on two sibling projects:

| Dependency | Import name | What it does here |
|------------|-------------|-------------------|
| packeteer | `packeteer` | Reads captures, parses packets, reassembles IP fragments |
| python-zipline | `zpf` | Writes and validates the `.zpf` container |

Neither is published to PyPI yet, and both names are taken there by
unrelated projects. So zpfwire declares each by its GitHub release tag, and
installing zpfwire installs them from there, never from an index.

## Development install

```bash
python3 -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

`-e .` installs each sibling at the release tag this tree is built against.
`requirements.txt` brings in pytest, ruff, Sphinx, and the build tooling,
which is everything the project's checks need.

Upgrading a venv made before zpfwire `0.9.0`: python-zipline was distributed
as `zpf` until its `0.8.0`, and is `python-zipline` since. Remove the old
distribution first, or its metadata stays behind beside the new one:

```bash
.venv/bin/pip uninstall zpf
.venv/bin/pip install -e . -r requirements.txt
```

Verify the install:

```bash
.venv/bin/zpfwire --version
```

```
zpfwire 0.8.0 (zipline 0.24)
```

The test run's header names the build of each sibling it ran against:

```
python-zipline 0.8.0 from …/.venv/lib/python3.14/site-packages/zpf/__init__.py
packeteer 0.21.0 from …/.venv/lib/python3.14/site-packages/packeteer/__init__.py
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

To reinstall zpfwire in this venv, pass `--no-deps`:

```bash
.venv-dev/bin/pip install --no-deps -e .
```

zpfwire names each sibling by its release tag, which no checkout satisfies,
so without the flag pip puts the releases back over the checkouts.

The second number is the **specification** version the `zpf` library
implements, read from `zpf.SPEC_VERSION` rather than hard-coded.  It is the
one to quote when asking whether a file zpfwire wrote will be readable by
something else.

## Building a wheel

```bash
.venv/bin/python -m build
```

The wheel declares each sibling as a direct reference to its release tag,
`packeteer @ git+https://github.com/adamkjonsson/packeteer.git@vX.Y.Z` and
`python-zipline @ git+https://github.com/adamkjonsson/python-zipline.git@vX.Y.Z`,
so installing it fetches them from GitHub. It never asks a package index for
either name. `packeteer` belongs to an unrelated project on PyPI, as `zpf`
does, the name python-zipline was distributed under before `0.8.0`, and
anything uploaded there under them would otherwise be installed in their
place. `CHANGELOG.md` names the releases. The wheel cannot be
uploaded to PyPI, which refuses packages that declare direct references.

## Running the checks

```bash
.venv/bin/pytest                                    # tests
ruff check src/ tests/ docs/ tools/ benchmarks/     # lint, must be silent
.venv/bin/sphinx-build -W docs docs/_build/html     # docs, warnings are errors
```

All three are release-blocking.  See {doc}`../internals/contributing` for what
each is guarding.
