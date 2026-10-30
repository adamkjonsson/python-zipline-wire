"""What the package declares about itself.

`zpfwire` writes files against one version of the Zipline Payload Format, and
that version is `zpf.SPEC_VERSION` — not a number this project chooses.  So
anything here that names it has to be derived from it rather than written out,
which is what these tests hold.
"""

from __future__ import annotations

import importlib.metadata
import json
import pathlib
import re
import sys

import pytest
import zpf
from packaging.requirements import Requirement

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

PYPROJECT = pathlib.Path(__file__).parent.parent / "pyproject.toml"


@pytest.fixture
def metadata() -> dict[str, object]:
    """Read the project's declared metadata out of ``pyproject.toml``."""
    if not PYPROJECT.is_file():
        pytest.skip("running against an installed package, without the source tree")
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_the_specification_link_names_the_version_we_write(
    metadata: dict[str, object],
):
    """The link went stale once already, in the sibling that owns the format.

    A URL naming a tag is the one piece of metadata that cannot be derived at
    runtime, so it is the one that drifts.  This is the same guard
    python-zipline added after the same thing happened to it.
    """
    urls = metadata["project"]["urls"]
    major, minor = zpf.SPEC_VERSION

    assert f"/v{major}.{minor}/" in urls["Specification"], (
        f"the Specification URL does not name spec v{major}.{minor}, "
        f"which is what this release writes: {urls['Specification']}"
    )


SIBLINGS = {
    "packeteer": "https://github.com/adamkjonsson/packeteer.git",
    "python-zipline": "https://github.com/adamkjonsson/python-zipline.git",
}
"""Each sibling's distribution name, and the repository its releases are tagged in.

python-zipline is distributed as ``python-zipline`` since ``0.8.0``, and
imported as ``zpf`` still (python-zipline#102).
"""

TAG = re.compile(r"v(\d+\.\d+\.\d+)")


def _declared(metadata: dict[str, object]) -> dict[str, Requirement]:
    """Return the project's dependencies, by name."""
    requirements = (Requirement(line) for line in metadata["project"]["dependencies"])
    return {requirement.name: requirement for requirement in requirements}


def _tags(metadata: dict[str, object]) -> dict[str, str]:
    """Return the release each sibling is declared at, as ``X.Y.Z``."""
    return {
        name: requirement.url.rsplit("@", 1)[1].removeprefix("v")
        for name, requirement in _declared(metadata).items()
        if requirement.url is not None
    }


def test_both_siblings_are_declared_by_their_release_tag(metadata: dict[str, object]):
    """Neither is on PyPI, and both names are taken there by other projects (#67).

    A declaration by name, however narrow its range, is resolved against
    PyPI, so whoever uploads a version inside it is installed by a plain
    ``pip install zpfwire``.  A direct reference to the sibling's own
    repository is never looked up on an index.  It names one release tag,
    which is also what #41's closed ranges were for: a release this tree
    was never run against is not installed beside it.
    """
    declared = _declared(metadata)

    assert set(declared) == set(SIBLINGS)
    for name, requirement in declared.items():
        assert requirement.url is not None, f"{name} is declared by name, which PyPI resolves"
        repository, _, ref = requirement.url.rpartition("@")
        assert repository == f"git+{SIBLINGS[name]}", f"{name} is declared from {repository}"
        assert TAG.fullmatch(ref), f"{name} is declared at {ref!r}, not a release tag"
        assert not requirement.specifier, f"{name} carries a range beside its tag"


def test_no_requirements_file_names_a_sibling():
    """``pyproject.toml`` names the tags, and only it.

    ``pip install -e .`` installs them from there, so a second copy in a
    requirements file adds nothing but a place for them to drift apart.
    The dev venv's editable checkouts are paths, not names, and are allowed.
    """
    for path in sorted(PYPROJECT.parent.glob("requirements*.txt")):
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            assert Requirement(line).name not in SIBLINGS, f"{path.name} names {line}"


@pytest.mark.parametrize("name", sorted(SIBLINGS))
def test_the_installed_sibling_is_the_declared_release(
    metadata: dict[str, object], name: str,
):
    """What the suite runs against is the release the wheel declares.

    An editable install of a checkout, as ``.venv-dev`` makes, records its
    version once and then runs whatever is checked out (#42), so it is
    skipped: the pytest header says what such a run ran against.
    """
    distribution = importlib.metadata.distribution(name)
    origin = distribution.read_text("direct_url.json")
    if origin and json.loads(origin).get("dir_info", {}).get("editable"):
        pytest.skip(f"{name} is an editable install of a checkout")

    assert distribution.version == _tags(metadata)[name]
