"""The unified domain output shape (M3/D2, the REA parity plan's hard rule).

Every defense domain - project recon, artifact manifest, secret scan,
string-symbol scan - reports the same three things: ``findings``
(exposure-finding-shaped, so the ledger and report consume them without a
second representation), ``coverage`` (four-state, omissions included), and
``unknowns``. A domain whose provider cannot work declares ``unknown``
for its whole scope; it never degrades into a fake pass.

``DomainReport`` is the orchestration-level wrapper: it adds the human and
machine labels plus an optional detail table for the report, letting the
report render any domain without importing it. The per-domain result
dataclasses stay in their own modules - this module owns only the seam.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DomainReport:
    """One domain's outcome, in the shape the demo and the report consume."""

    #: Machine-readable domain key (also the ledger's ``domain`` field).
    key: str
    #: Human-readable label used in report prefixes and remediation actions.
    label: str
    coverage: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    unknowns: tuple[str, ...]
    #: Optional detail table (e.g. redacted hits or artifact digests).
    detail_title: str = ""
    detail_headers: tuple[str, ...] = ()
    detail_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Serialize. ``detail_rows`` stays a list of lists (JSON has no
        tuples); ``from_dict`` restores the tuple form."""
        return {
            "key": self.key,
            "label": self.label,
            "coverage": self.coverage,
            "findings": list(self.findings),
            "unknowns": list(self.unknowns),
            "detail_title": self.detail_title,
            "detail_headers": list(self.detail_headers),
            "detail_rows": [list(row) for row in self.detail_rows],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DomainReport:
        """Rebuild from ``to_dict`` output (the WP2 orchestrator's disk form).

        The orchestrator's recovery semantics require every step product to
        round-trip: a domain that ran before a crash must be reusable after
        it without re-observing the project.
        """
        return cls(
            key=str(data["key"]),
            label=str(data["label"]),
            coverage=dict(data.get("coverage") or {}),
            findings=tuple(data.get("findings") or ()),
            unknowns=tuple(data.get("unknowns") or ()),
            detail_title=str(data.get("detail_title", "")),
            detail_headers=tuple(data.get("detail_headers") or ()),
            detail_rows=tuple(tuple(row) for row in data.get("detail_rows") or ()),
        )
