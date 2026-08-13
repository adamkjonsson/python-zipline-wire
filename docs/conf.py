"""Sphinx configuration for zpfwire documentation."""
import os
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

# Make zpfwire importable without pip install
sys.path.insert(0, os.path.abspath("../src"))

# ── Project metadata ──────────────────────────────────────────────────────────

project = "zpfwire"
author = "Adam Jonsson"
try:
    release = _pkg_version("zpfwire")
except PackageNotFoundError:
    release = "unknown"
version = release
copyright = f"2026, {author}"

# ── Extensions ────────────────────────────────────────────────────────────────

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx_autodoc_typehints",
    "myst_parser",
]

# ── Source ────────────────────────────────────────────────────────────────────

source_suffix = {".md": "myst"}
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# ── MyST ──────────────────────────────────────────────────────────────────────

myst_enable_extensions = [
    "colon_fence",   # :::directive::: syntax for eval-rst blocks
    "deflist",       # definition lists in API pages
    "attrs_inline",  # inline {.class} attribute syntax
]

myst_heading_anchors = 3   # auto-generate anchors for h1–h3

# ── autodoc ───────────────────────────────────────────────────────────────────

autodoc_member_order = "bysource"       # preserve natural call-chain order
autodoc_typehints = "description"       # types in description, not signature
autodoc_typehints_format = "short"      # bytes not builtins.bytes

# ── intersphinx ───────────────────────────────────────────────────────────────

# The two siblings publish no object inventory, so their names are written as
# literals here rather than cross-referenced.
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# ── LaTeX / PDF ───────────────────────────────────────────────────────────────

latex_toplevel_sectioning = "part"

latex_elements = {
    "preamble": r"""
\setcounter{tocdepth}{2}
\setcounter{secnumdepth}{2}
\fancyhead[RE]{\nouppercase{\leftmark}}
\fancyhead[LO]{\nouppercase{\rightmark}}
% Raise the minimum column width in tabulary so short-label first columns
% (Field, Flag, Option, …) are not squeezed to a few characters.
\setlength{\tymin}{60pt}
""",
}

# ── Theme ─────────────────────────────────────────────────────────────────────

html_theme = "furo"
html_title = f"zpfwire {release}"

html_theme_options = {
    "source_repository": "https://github.com/adamkjonsson/python-zipline-wire",
    "source_branch": "main",
    "source_directory": "docs/",
}
