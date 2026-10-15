"""Filesystem locations shared by the PEA modules.

The package lives in ``src/`` but the schemas and catalog live in the
repository, not in the installed wheel. Both are located by walking up from
this file until a directory containing ``catalog/catalog.seed.json`` is
found, so the same code works from a source checkout and from an editable
install without any configuration.
"""
from __future__ import annotations

from pathlib import Path

_MARKER = Path("catalog") / "catalog.seed.json"
SCHEMA_SUFFIX = ".schema.json"


def find_repo_root() -> Path:
    """Walk up from this file to the directory holding ``catalog/catalog.seed.json``."""
    for candidate in Path(__file__).resolve().parents:
        if (candidate / _MARKER).is_file():
            return candidate
    raise RuntimeError("PEA repository root not found: no catalog/catalog.seed.json above src/pea")


def schema_dir() -> Path:
    """Directory holding the ``*.schema.json`` contract files."""
    return find_repo_root() / "schemas"
