"""Adapter registry: the reviewed set of protection tool integrations.

Selection is mechanical: the planner's plan names catalog ids; the registry
resolves them to adapters; each adapter's ``inspect`` decides applicability
against the actual target. An id with no adapter is a named refusal, not a
fallback to "some tool that might work".
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pea.adapters.base import (
    AdapterError,
    AdapterInspect,
    ApplyPreview,
    ApplyResult,
    ProtectionAdapter,
    load_manifests,
)
from pea.adapters.jsobfuscator import ADAPTERS as _JS_ADAPTERS


def adapter_for(tool_id: str) -> ProtectionAdapter:
    """The adapter registered for ``tool_id``, or a named refusal."""
    factory = _JS_ADAPTERS.get(tool_id)
    if factory is None:
        raise AdapterError("adapter_not_registered", f"没有已登记的适配器：{tool_id}")
    return factory()


def inspect_adapters(target: Path, tool_ids: tuple[str, ...]) -> dict[str, AdapterInspect]:
    """Applicability of each requested adapter against the target."""
    reports: dict[str, AdapterInspect] = {}
    for tool_id in tool_ids:
        try:
            adapter = adapter_for(tool_id)
        except AdapterError as exc:
            reports[tool_id] = AdapterInspect(
                applies=False,
                tool_id=tool_id,
                tool_version="unknown",
                reason=f"{exc.reason}: {exc.detail}",
                unknowns=(exc.reason,),
            )
            continue
        reports[tool_id] = adapter.inspect(target)
    return reports


def manifests() -> dict[str, dict[str, Any]]:
    """All registered adapter manifests (for the contract gate)."""
    return load_manifests()


__all__ = [
    "AdapterError",
    "AdapterInspect",
    "ApplyPreview",
    "ApplyResult",
    "ProtectionAdapter",
    "adapter_for",
    "inspect_adapters",
    "manifests",
]
