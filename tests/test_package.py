"""What the package declares about itself.

`zpfwire` writes files against one version of the Zipline Payload Format, and
that version is `zpf.SPEC_VERSION` — not a number this project chooses.  So
anything here that names it has to be derived from it rather than written out,
which is what these tests hold.
"""

from __future__ import annotations

import pathlib
import sys

import pytest
import zpf
from packaging.requirements import Requirement

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

PYPROJECT = pathlib.Path(__file__).parent.parent / "pyproject.toml"
REQUIREMENTS = PYPROJECT.parent / "requirements.txt"


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


def _declared(metadata: dict[str, object]) -> dict[str, Requirement]:
    """Return the project's dependencies, by name."""
    requirements = (Requirement(line) for line in metadata["project"]["dependencies"])
    return {requirement.name: requirement for requirement in requirements}


def test_both_siblings_carry_a_floor_and_a_ceiling(metadata: dict[str, object]):
    """Both siblings are in 0.x, where every minor may break (#41).

    The floor says which release the code needs: an older `zpf` refuses
    this tree's spec version at its gate rather than misreading it.  The
    ceiling says which releases it was run against.  An open range accepts a
    minor nobody tested, and `0.6.0` showed what that costs: it refused
    files written at spec `0.21` outright, so an unbounded pin across it
    installs a zpfwire that cannot read its predecessor's output.
    """
    declared = _declared(metadata)

    assert set(declared) == {"packeteer", "zpf"}
    for name, requirement in declared.items():
        operators = {spec.operator for spec in requirement.specifier}
        assert ">=" in operators, f"{name} is declared with no floor"
        assert "<" in operators, f"{name} is declared with no ceiling"


def test_the_pinned_releases_fall_inside_the_declared_ranges(
    metadata: dict[str, object],
):
    """``requirements.txt`` installs exact tags; ``pyproject.toml`` declares ranges.

    The two are edited in different files and would drift apart silently:
    the venv would pass the suite against a release the wheel then refuses,
    or the reverse.
    """
    declared = _declared(metadata)
    pinned = {}
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        requirement = Requirement(line)
        if requirement.name in declared:
            assert requirement.url is not None, f"{requirement.name} is not pinned to a tag"
            pinned[requirement.name] = requirement.url.rsplit("@v", 1)[1]

    assert set(pinned) == set(declared), "requirements.txt pins a different set of siblings"
    for name, version in pinned.items():
        assert declared[name].specifier.contains(version), (
            f"requirements.txt installs {name} {version}, "
            f"outside pyproject.toml's {declared[name].specifier}"
        )
