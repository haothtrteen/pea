"""Candidate-review domain (M3/D2 + D6): the license and maintenance gate.

Where :mod:`pea.capintel` decides *what was said about a tool*, this domain
decides *what may be done with it*. A protection candidate that looks
technically perfect can still be unusable: an AGPL dependency in a closed
distribution, an archived upstream, a README claim that nobody has compiled.

The gate is mechanical and its outcomes are named:

* ``blocked`` - license needs review or upstream is archived. These do not
  become "use with caution" footnotes; they stop the candidate;
* ``research_only`` - the entry is documentation-level only. It may enter a
  research queue; it may never be labelled ``verified`` or auto-inserted
  into a plan (this is the Electron walkthrough's "VMP candidate with a
  pending license is not admitted" rule, mechanized);
* ``candidate_for_fixture`` - trust is low or unknown, so a fixture must run
  before any project review;
* ``eligible_for_project_review`` / ``production_eligible`` - the gates
  passed at the level the catalog can actually attest to.

Everything here is derived from the catalog entry's own declared status
fields. The domain never upgrades an entry: a catalog that says
``needs_review`` produces a block, not a guess.

The review can be exported as a document that validates against
``schemas/research-candidate-review.schema.json``, with every claim staying
at ``external_claim`` until a source audit or fixture says otherwise.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from pea.paths import find_repo_root
from pea.tiers import TIER_TOOL_EFFICIENCY

#: Catalog location, discovered the same way the schemas are.
DEFAULT_CATALOG_PATH = find_repo_root() / "catalog" / "catalog.seed.json"

#: Catalog license status -> gate outcome.
LICENSE_GATE: dict[str, str] = {
    "verified": "pass",
    "needs_review": "block",
    "not_applicable": "not_applicable",
}

#: Catalog maintenance state -> gate outcome.
MAINTENANCE_GATE: dict[str, str] = {
    "active": "pass",
    "archived": "block",
    "unknown": "needs_verification",
}

#: Schema-side license review status (research-candidate-review.schema.json).
LICENSE_REVIEW_STATUS: dict[str, str] = {
    "verified": "compatible_for_current_scope",
    "needs_review": "needs_legal_review",
    "not_applicable": "compatible_for_current_scope",
}

#: Catalog trust level -> whether a fixture is required first.
FIXTURE_REQUIRED_TRUST: frozenset[str] = frozenset({"low", "unknown"})


class CandidateReviewError(ValueError):
    """The catalog cannot be read, so no gate can be claimed."""


@dataclass(frozen=True)
class CandidateGate:
    """One gate's outcome for one candidate."""

    name: str  # license | maintenance | evidence | trust
    status: str  # pass | block | needs_verification | not_applicable
    detail: str


@dataclass(frozen=True)
class CandidateReview:
    """The gate outcome for one catalog entry."""

    candidate_id: str
    name: str
    source_url: str
    gates: tuple[CandidateGate, ...]
    decision: str  # blocked | research_only | candidate_for_fixture | eligible_for_project_review | production_eligible
    review_state: str = "documentation_reviewed"
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "name": self.name,
            "source_url": self.source_url,
            "gates": [{"name": g.name, "status": g.status, "detail": g.detail} for g in self.gates],
            "decision": self.decision,
            "review_state": self.review_state,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class CandidateReviewResult:
    """All gate outcomes, plus the catalog-side failure if the gate cannot run."""

    reviews: tuple[CandidateReview, ...]
    findings: tuple[dict[str, Any], ...] = ()
    coverage: dict[str, Any] = field(default_factory=dict)
    unknowns: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "reviews": [r.to_dict() for r in self.reviews],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_catalog(path: str | Path = DEFAULT_CATALOG_PATH) -> tuple[dict[str, Any], ...]:
    """Read the catalog seed. Raises on failure - an unreadable catalog is
    not an empty catalog."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateReviewError(f"catalog 无法读取：{path}（{exc.__class__.__name__}）") from exc
    if not isinstance(data, list):
        raise CandidateReviewError(f"catalog 结构非列表：{path}")
    return tuple(entry for entry in data if isinstance(entry, dict))


def _decide(gates: tuple[CandidateGate, ...], verification_status: str, trust_level: str) -> str:
    """Gate outcomes -> decision. Blocks outrank everything else."""
    if any(g.status == "block" for g in gates):
        return "blocked"
    if verification_status == "research_only":
        return "research_only"
    if verification_status == "verified" and all(
        g.status in ("pass", "not_applicable") for g in gates
    ):
        return "production_eligible"
    if trust_level in FIXTURE_REQUIRED_TRUST:
        return "candidate_for_fixture"
    return "eligible_for_project_review"


def review_entry(entry: Mapping[str, Any] | dict[str, Any]) -> CandidateReview:
    """Gate one catalog entry using only what the entry declares."""
    license_info = entry.get("license") or {}
    maintenance_info = entry.get("maintenance") or {}
    license_status = str(license_info.get("status", "unknown"))
    maintenance_state = str(maintenance_info.get("state", "unknown"))
    verification_status = str(entry.get("verification_status", "unknown"))
    trust_level = str(entry.get("trust_level", "unknown"))

    gates = (
        CandidateGate(
            name="license",
            status=LICENSE_GATE.get(license_status, "needs_verification"),
            detail=f"catalog license.status={license_status}；{license_info.get('notes', '')}".strip(),
        ),
        CandidateGate(
            name="maintenance",
            status=MAINTENANCE_GATE.get(maintenance_state, "needs_verification"),
            detail=f"catalog maintenance.state={maintenance_state}；{maintenance_info.get('notes', '')}".strip(),
        ),
        CandidateGate(
            name="evidence",
            status="pass" if verification_status == "verified" else "needs_verification",
            detail=f"catalog verification_status={verification_status}；未做源码审计与 fixture 实测",
        ),
        CandidateGate(
            name="trust",
            status="needs_verification" if trust_level in FIXTURE_REQUIRED_TRUST else "pass",
            detail=f"catalog trust_level={trust_level}",
        ),
    )

    decision = _decide(gates, verification_status, trust_level)
    limitations = list(entry.get("limits") or [])
    limitations.append("目录种子条目：结论来自 catalog 自身声明，未做源码审计或 fixture 实测")
    if verification_status == "research_only":
        limitations.append("研究级条目：不得作为 verified 结论，也不得自动进入计划")

    return CandidateReview(
        candidate_id=str(entry.get("id", "")),
        name=str(entry.get("name", "")),
        source_url=str(entry.get("repository_url", "")),
        gates=gates,
        decision=decision,
        limitations=tuple(limitations),
    )


def review_catalog(
    entries: tuple[Mapping[str, Any], ...] | None = None,
    *,
    catalog_path: str | Path = DEFAULT_CATALOG_PATH,
    now: str | None = None,
) -> CandidateReviewResult:
    """Gate every catalog entry (or the supplied entries)."""
    stamp = now or _utc_now()
    try:
        items = tuple(entries) if entries is not None else load_catalog(catalog_path)
    except CandidateReviewError as exc:
        return CandidateReviewResult(
            reviews=(),
            findings=(
                {
                    "id": "candidate-review-unavailable",
                    "category": "candidate_review",
                    "status": "unknown",
                    "severity": "unrated",
                    "title": "候选门控无法执行",
                    "summary": f"{exc}；候选许可与维护门控未评估（不可用降级：拒绝给出结论）",
                    "evidence": [
                        {
                            "evidence_id": "ev-candreview-unavailable",
                            "kind": "file_observation",
                            "source": "pea.candidatereview",
                            "observed_at": stamp,
                            "authority": "observation",
                            "limitations": ["catalog 不可读；门控结果未知而非通过"],
                            "redacted_summary": str(exc),
                        }
                    ],
                    "coverage": {"state": "unavailable", "scope": "catalog 不可读"},
                    "limitations": ["未读取 catalog；任何候选状态均不可声称"],
                    "recommended_actions": ["修复 catalog 路径或内容后重跑门控"],
                    "exposure_tier": TIER_TOOL_EFFICIENCY,
                },
            ),
            coverage={"state": "unavailable", "scope": "catalog 不可读", "omissions": [str(exc)]},
            unknowns=(str(exc), "门控未执行不等于候选可用"),
        )

    reviews = tuple(review_entry(entry) for entry in items)
    blocked = [r for r in reviews if r.decision == "blocked"]
    research = [r for r in reviews if r.decision == "research_only"]
    eligible = [r for r in reviews if r.decision in ("eligible_for_project_review", "production_eligible")]
    fixture = [r for r in reviews if r.decision == "candidate_for_fixture"]

    redacted = "; ".join(f"{r.candidate_id}: {r.decision}" for r in reviews)
    findings = (
        {
            "id": "candidate-review-gated",
            "category": "candidate_review",
            "status": "observed",
            "severity": "info",
            "title": "候选门控完成",
            "summary": (
                f"{len(reviews)} 个候选：blocked {len(blocked)} / research_only {len(research)} / "
                f"candidate_for_fixture {len(fixture)} / eligible {len(eligible)}；"
                "门控结论全部来自 catalog 自身声明"
            ),
            "evidence": [
                {
                    "evidence_id": "ev-candreview-gated",
                    "kind": "file_observation",
                    "source": "pea.candidatereview",
                    "observed_at": stamp,
                    "authority": "observation",
                    "limitations": ["结论依赖 catalog 声明的完备性与时效性"],
                    "redacted_summary": redacted,
                }
            ],
            "coverage": {"state": "complete_for_scope", "scope": f"catalog {len(reviews)} 个候选的门控"},
            "limitations": [
                "门控不等于验证：通过门控的候选仍需源码审计与 fixture 实测",
                "许可判断来自 catalog 声明，不构成法务意见",
            ],
            "recommended_actions": [
                "对 blocked 候选完成许可审查或改用替代方案后再评估",
                "对 research_only 候选固定 commit 做源码审计后再提升证据等级",
            ],
            "exposure_tier": TIER_TOOL_EFFICIENCY,
        },
    )

    return CandidateReviewResult(
        reviews=reviews,
        findings=findings,
        coverage={
            "state": "complete_for_scope",
            "scope": f"catalog {len(reviews)} 个候选的许可/维护/证据/信任门控",
            "omissions": [],
        },
        unknowns=(
            "维护状态与许可的时效性以 catalog 的 checked_at 为准；到期需重新核实",
            "未做源码审计：所有能力声明保留为 external_claim",
            "门控通过不等于保护有效：有效性需 fixture 与项目实测",
        ),
    )


def to_review_document(
    entry: Mapping[str, Any],
    review: CandidateReview,
    *,
    reviewed_at: str | None = None,
) -> dict[str, Any]:
    """Export one gated candidate as a research-candidate-review document.

    The document matches ``schemas/research-candidate-review.schema.json``
    with every claim at ``external_claim``: a gate that passed says nothing
    about the source, and this export does not pretend otherwise.
    """
    license_info = entry.get("license") or {}
    license_status = str(license_info.get("status", "unknown"))
    claims = [
        {
            "claim": f"候选声明具备能力：{capability}",
            "claim_status": "external_claim",
            "evidence_url": entry.get("documentation_url") or entry.get("repository_url"),
            "path_and_lines": None,
            "limitations": ["来自 catalog 声明；未做源码审计或 fixture 实测"],
        }
        for capability in (entry.get("capabilities") or [])
    ]
    if not claims:
        claims.append(
            {
                "claim": "候选未声明具体能力",
                "claim_status": "unknown",
                "evidence_url": entry.get("repository_url"),
                "path_and_lines": None,
                "limitations": ["catalog 未提供 capabilities"],
            }
        )

    return {
        "schema_version": "1.0",
        "candidate_id": review.candidate_id,
        "source_url": review.source_url,
        "reviewed_at": reviewed_at or date.today().isoformat(),
        "commit_sha": None,
        "release_or_tag": None,
        "review_state": review.review_state,
        "source_audit": {
            "status": "not_attempted",
            "notes": "门控来自 catalog 声明；未 clone、未固定 commit、未做源码审计。",
            "reviewed_paths": [],
            "source_digest": None,
        },
        "license_review": {
            "reported_license": license_info.get("spdx"),
            "status": LICENSE_REVIEW_STATUS.get(license_status, "unknown"),
            "notes": str(license_info.get("notes", "")),
            "third_party_dependencies_reviewed": False,
        },
        "fixture_test": {
            "status": "not_run",
            "test_scope": "none",
            "command_or_test_ref": None,
            "notes": "本域只做门控，未执行任何 fixture。",
        },
        "claims": claims,
        "limitations": list(review.limitations),
        "decision": review.decision,
    }
