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


def test_both_siblings_carry_a_floor(metadata: dict[str, object]):
    """Neither is on PyPI, so the floor is documentation as much as resolution.

    It still has to be there: this release writes spec ``0.19``, which an
    older `zpf` refuses at its version gate rather than misreading, and an
    unconstrained dependency says nothing about which one to have.
    """
    declared = {
        name.split(">=")[0].strip(): name
        for name in metadata["project"]["dependencies"]
    }

    assert set(declared) == {"packeteer", "zpf"}
    for name, spec in declared.items():
        assert ">=" in spec, f"{name} is declared with no floor"
