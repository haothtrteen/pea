"""Shared pytest fixtures and import-path setup for the src layout."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def schemas_dir(repo_root: Path) -> Path:
    return repo_root / "schemas"


@pytest.fixture(scope="session")
def catalog_dir(repo_root: Path) -> Path:
    return repo_root / "catalog"


@pytest.fixture(scope="session")
def examples_dir(repo_root: Path) -> Path:
    return repo_root / "examples"
