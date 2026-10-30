"""Suite-wide pytest hooks."""

from __future__ import annotations

import importlib
import importlib.metadata

SIBLINGS = (("python-zipline", "zpf"), ("packeteer", "packeteer"))
"""``(distribution, import name)`` of each sibling this tree is glue between.

python-zipline is distributed as ``python-zipline`` since ``0.8.0``, and
imported as ``zpf`` (python-zipline#102).
"""


def pytest_report_header() -> list[str]:
    """Say which build of each sibling this run is testing against (#42).

    The installed version alone cannot say it: an editable install records
    its version when it is made, and goes on reporting it while the code it
    runs is whatever is checked out now.  The file the module was imported
    from can, so both are printed.  A path inside a sibling checkout means
    the version beside it may be stale.

    Returns:
        One header line per sibling.

    """
    lines = []
    for distribution, module_name in SIBLINGS:
        version = importlib.metadata.version(distribution)
        module = importlib.import_module(module_name)
        lines.append(f"{distribution} {version} from {module.__file__}")
    return lines
