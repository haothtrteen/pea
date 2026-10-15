"""研究记录（WP5）：把在线检索变成结构化、可审计的研究结论。

一份 :class:`ResearchRecord` 回答一个问题，并把它怎么得出的全部写在
明面上：检索来源（URL + 访问日期 + 版本锚点）、许可证/维护/平台三项
核对、适用性判断、限制声明、接受/拒绝及理由。三条硬边界：

* **权威级恒为 external_claim**——检索来的话是外部主张，未经源码审计与
  fixture 实测不得升级；这不是字段的默认值，是常量。
* **检索结果不是候选**——记录携带来源与判断，进入候选队列必须过
  candidate-review 门（license / maintenance / evidence / trust，block
  优先于一切）。本模块不做也不绕过那个门。
* **离线是第三态，不是零**——无 transport 时三项核对全 unknown、适用性
  unknown、结论 deferred；不空谈，也不假装"查过了没问题"。

机械门：``accepted`` 要求三项核对均非 unknown 且适用性为 applicable。
一个"核对全是 unknown 却接受"的记录是造假，构造时即拒绝。
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pea.capintel import CapabilityIntelResult

#: The schema file this module's output must satisfy (contract gate).
SCHEMA_PATH = "research-record.schema.json"

AUTHORITY = "external_claim"
SCHEMA_VERSION = "1.0"

LICENSE_STATES = ("verified", "needs_review", "incompatible", "unknown")
MAINTENANCE_STATES = ("active", "archived", "stale", "unknown")
PLATFORM_STATES = ("confirmed", "mismatch", "unknown")
APPLICABILITY_STATES = ("applicable", "not_applicable", "unknown")
DECISIONS = ("accepted", "rejected", "deferred")


class ResearchRecordError(Exception):
    """A refused research record. ``reason`` is a stable named code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ResearchSource:
    """One retrieval source: URL, access date, and an optional anchor."""

    url: str
    retrieved_at: str
    version_anchor: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "retrieved_at": self.retrieved_at,
            "version_anchor": self.version_anchor,
            "note": self.note,
        }


@dataclass(frozen=True)
class ResearchRecord:
    """The structured outcome of one research question."""

    question: str
    family: str
    sources: tuple[ResearchSource, ...]
    checks: dict[str, str]  # license / maintenance / platform
    applicability: str
    limitations: tuple[str, ...]
    decision: str
    decision_reason: str
    record_id: str = ""
    authority: str = AUTHORITY

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "record_id": self.record_id,
            "question": self.question,
            "family": self.family,
            "sources": [s.to_dict() for s in self.sources],
            "checks": dict(self.checks),
            "applicability": self.applicability,
            "limitations": list(self.limitations),
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "authority": self.authority,
        }


def make_record(
    *,
    question: str,
    family: str,
    sources: tuple[ResearchSource, ...] = (),
    checks: Mapping[str, str] | None = None,
    applicability: str = "unknown",
    limitations: tuple[str, ...] = (),
    decision: str = "deferred",
    decision_reason: str = "",
    now: str = "",
) -> ResearchRecord:
    """Build one record, enforcing the mechanical gates on the way in.

    ``accepted`` requires all three checks decided and applicability
    confirmed - a record that "accepted" with unknowns is a fabrication.
    Unknown values are honest states; the gate only refuses to rest an
    acceptance on them.
    """
    if not question.strip():
        raise ResearchRecordError("question_missing", "研究记录必须带一个明确的问题")
    if not family.strip():
        raise ResearchRecordError("family_missing", "研究记录必须带能力族")
    resolved = {
        "license": (checks or {}).get("license", "unknown"),
        "maintenance": (checks or {}).get("maintenance", "unknown"),
        "platform": (checks or {}).get("platform", "unknown"),
    }
    if resolved["license"] not in LICENSE_STATES:
        raise ResearchRecordError("check_state_invalid", f"license={resolved['license']!r}")
    if resolved["maintenance"] not in MAINTENANCE_STATES:
        raise ResearchRecordError("check_state_invalid", f"maintenance={resolved['maintenance']!r}")
    if resolved["platform"] not in PLATFORM_STATES:
        raise ResearchRecordError("check_state_invalid", f"platform={resolved['platform']!r}")
    if applicability not in APPLICABILITY_STATES:
        raise ResearchRecordError("applicability_invalid", applicability)
    if decision not in DECISIONS:
        raise ResearchRecordError("decision_invalid", decision)
    if not decision_reason.strip():
        raise ResearchRecordError("decision_reason_missing", "接受/拒绝/搁置都必须给明文理由")
    if decision == "accepted":
        undecided = [k for k, v in resolved.items() if v == "unknown"]
        if undecided or applicability != "applicable":
            raise ResearchRecordError(
                "acceptance_with_unknowns",
                f"accepted 需要三项核对均非 unknown 且适用性为 applicable（未决：{undecided or '无'}，applicability={applicability}）",
            )
    payload = json.dumps(
        {"question": question, "family": family, "decision": decision, "checks": resolved, "now": now},
        ensure_ascii=False,
        sort_keys=True,
    )
    record_id = "res-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return ResearchRecord(
        question=question,
        family=family,
        sources=tuple(sources),
        checks=resolved,
        applicability=applicability,
        limitations=tuple(limitations),
        decision=decision,
        decision_reason=decision_reason,
        record_id=record_id,
    )


def record_from_intel(
    result: CapabilityIntelResult,
    *,
    question: str,
    limitations: tuple[str, ...] = (),
    decision: str = "deferred",
    decision_reason: str = "",
    checks: Mapping[str, str] | None = None,
    applicability: str = "unknown",
    now: str = "",
) -> ResearchRecord:
    """Turn a retrieval result into a structured record.

    The retrieval's candidates become *sources*, never candidates: the
    record's authority stays ``external_claim`` and the candidate-review
    gate remains the only path into the catalog queue. When the retrieval
    failed (offline, blocked, empty), the record still exists - with no
    sources, all checks unknown, applicability unknown and a deferred
    decision that says why. "查不到" is a finding, not an empty record.
    """
    resolved_checks = dict(checks or {})
    if result.status != "ok":
        resolved_checks.setdefault("license", "unknown")
        resolved_checks.setdefault("maintenance", "unknown")
        resolved_checks.setdefault("platform", "unknown")
        if not decision_reason:
            decision_reason = f"检索未成功（{result.status}）：全部核对记 unknown，不假装查过"
    elif not decision_reason:
        decision_reason = f"检索成功（{len(result.candidates)} 条来源已归档）；判断待 candidate-review 门与人工复核"
    sources = tuple(
        ResearchSource(url=c.source_url, retrieved_at=c.retrieved_at, version_anchor=None, note=c.title)
        for c in result.candidates
    )
    return make_record(
        question=question,
        family=result.query.family,
        sources=sources,
        checks=resolved_checks,
        applicability=applicability,
        limitations=limitations,
        decision=decision,
        decision_reason=decision_reason,
        now=now,
    )
