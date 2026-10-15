"""Uniform protection-adapter interface (WP3).

PEA does not learn the internals of every protection tool. Each integration
implements one small protocol - ``inspect`` / ``preview`` / ``apply`` - and
carries a machine-readable manifest (license, version, supported targets,
transformations, limits) that the contract gates check. The tool无关
capabilities (verification, comparison, rollback) deliberately live *outside*
the adapter, in :mod:`pea.protect`: every adapter would otherwise re-implement
"run the tests", "diff the manifests" and "discard the workspace", and those
answers are the same for every tool.

An adapter is a registered, reviewed component - never free-form model
output. The planner selects an adapter; the adapter generates the structured
argument list; :mod:`pea.protect` runs the approved executable without a
shell, inside the managed workspace, under the contract's resource limits.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


class AdapterError(Exception):
    """A named adapter failure. ``reason`` is a stable code, never prose."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class AdapterInspect:
    """What ``inspect`` reports about one target: does this adapter apply?"""

    applies: bool
    tool_id: str
    tool_version: str
    reason: str
    #: Named unknowns when applicability cannot be decided (tool missing,
    #: version unreadable). "Not attempted" is a first-class answer.
    unknowns: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApplyPreview:
    """The exact, reviewable execution plan an approval covers."""

    argv: tuple[str, ...]
    affected_files: tuple[str, ...]
    output_destination: str
    expected_side_effects: tuple[str, ...]
    tool_id: str
    tool_version: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ApplyResult:
    """What an ``apply`` produced: artifacts plus honest process evidence."""

    outputs: tuple[str, ...]
    exit_code: int
    tool_id: str
    tool_version: str
    #: Bounded, redacted process log lines (bounded by the contract's limits).
    log_tail: tuple[str, ...] = ()


class ProtectionAdapter(Protocol):
    """The whole contract a protection tool integration must satisfy."""

    manifest: dict[str, Any]

    def inspect(self, target: Path) -> AdapterInspect: ...

    def preview(self, plan: dict[str, Any], workspace: Path) -> ApplyPreview: ...

    def apply(self, preview: ApplyPreview, workspace: Path) -> ApplyResult: ...


def load_manifests() -> dict[str, dict[str, Any]]:
    """The adapter manifests, keyed by tool id (the catalog ids they serve)."""
    from pea.adapters.jsobfuscator import MANIFEST as _js

    return {"javascript-obfuscator": _js}
