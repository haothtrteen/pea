"""Evidence ledger: the runtime enforcement of PEA's evidence contract (D5/M5).

The schemas already say what evidence and unknowns *look like*; this module
makes them *bind*. It exists because "the plan says verified" is worthless if
nothing mechanically checks what the claim rests on.

Invariants enforced here (from the REA parity plan, D5):

1. **Resolving an unknown requires two-sided evidence.** ``update_unknown``
   refuses a resolution that cites only supporting evidence - a claim nobody
   tried to contradict is a belief, not a finding. Both ``supporting`` and
   ``contradicting`` evidence ids must be declared.
2. **Resolution only counts on observation-grade evidence.** Promoting an
   unknown to ``resolved`` requires at least one ``observation``-authority
   evidence record. Documentation, inference and human assertion can inform a
   resolution; they cannot be one.
3. **Static evidence never impersonates runtime observation.** Evidence
   authority is explicit on every record (``observation`` / ``inference`` /
   ``external_claim`` / ``human_assertion``); there is no default and no
   upgrade path that silently rewrites it.
4. **"No finding" is not "proof of safety."** ``audit_residual_unknowns``
   lists open blocking unknowns, and :func:`gate_for_verified` turns that list
   into hard blockers - a plan cannot reach ``verified`` while they remain.

Everything is a pure in-memory operation with explicit JSON serialization; no
IO happens inside this module.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pea.validation import validate_or_raise

EVIDENCE_SCHEMA = "evidence-record"

#: Authorities that may ground a resolution. Ordered strongest first.
OBSERVATION = "observation"
_RESOLUTION_AUTHORITIES = frozenset({OBSERVATION})

#: Unknown severities, mirroring the intake vocabulary.
SEVERITIES = ("blocking", "important", "informational")
#: Unknown lifecycle states.
UNKNOWN_STATUSES = ("open", "resolved", "wont_resolve")

_REQUIRED_EVIDENCE_FIELDS = ("evidence_id", "kind", "source", "observed_at", "authority")


class LedgerPolicyError(ValueError):
    """A ledger operation was attempted that the evidence contract forbids."""

    def __init__(self, code: str, remediation: str, detail: str = "") -> None:
        self.code = code
        self.remediation = remediation
        self.detail = detail
        super().__init__(f"[{code}] {detail or remediation}")


def _canonical_digest(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class UnknownRecord:
    """One open question the engineering loop must not silently answer."""

    unknown_id: str
    question: str
    severity: str
    domain: str
    required_authority: str
    recommended_probes: tuple[str, ...] = ()
    status: str = "open"
    resolution: str | None = None
    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
    created_at: str = ""
    resolved_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "unknown_id": self.unknown_id,
            "question": self.question,
            "severity": self.severity,
            "domain": self.domain,
            "required_authority": self.required_authority,
            "recommended_probes": list(self.recommended_probes),
            "status": self.status,
            "resolution": self.resolution,
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UnknownRecord:
        return cls(
            unknown_id=str(data["unknown_id"]),
            question=str(data["question"]),
            severity=str(data["severity"]),
            domain=str(data["domain"]),
            required_authority=str(data["required_authority"]),
            recommended_probes=tuple(data.get("recommended_probes", ())),
            status=str(data.get("status", "open")),
            resolution=data.get("resolution"),
            supporting_evidence=tuple(data.get("supporting_evidence", ())),
            contradicting_evidence=tuple(data.get("contradicting_evidence", ())),
            created_at=str(data.get("created_at", "")),
            resolved_at=data.get("resolved_at"),
        )


@dataclass
class EvidenceLedger:
    """Append-only evidence plus the unknown lifecycle that consumes it.

    Evidence records are append-only by convention: the ledger never mutates a
    stored record, so a resolution can always be re-audited against the exact
    evidence that justified it.
    """

    created_at: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[UnknownRecord] = field(default_factory=list)

    # -- evidence -----------------------------------------------------------

    def add_evidence(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Validate and append one evidence record.

        The record is checked against ``evidence-record.schema.json`` *and*
        against the ledger's own rule: authority must be explicit. A record
        without an authority is rejected rather than defaulted, because a
        default authority is exactly how static claims quietly become
        observations.
        """
        payload = dict(record)
        missing = [name for name in _REQUIRED_EVIDENCE_FIELDS if name not in payload]
        if missing:
            raise LedgerPolicyError(
                "evidence_missing_fields",
                "补齐必填字段后重试",
                f"evidence record missing {missing}",
            )
        authority = payload.get("authority")
        if authority not in {"observation", "inference", "external_claim", "human_assertion"}:
            raise LedgerPolicyError(
                "evidence_authority_invalid",
                "authority 必须是 observation/inference/external_claim/human_assertion 之一",
                f"invalid authority {authority!r}",
            )
        validate_or_raise(payload, _evidence_schema(), subject="evidence record")
        if any(e.get("evidence_id") == payload["evidence_id"] for e in self.evidence):
            raise LedgerPolicyError(
                "evidence_id_conflict",
                "使用新的 evidence_id 或更新既有记录",
                f"duplicate evidence_id {payload['evidence_id']!r}",
            )
        self.evidence.append(payload)
        return payload

    def evidence_by_id(self, evidence_id: str) -> dict[str, Any] | None:
        for record in self.evidence:
            if record.get("evidence_id") == evidence_id:
                return record
        return None

    def _require_evidence(self, evidence_id: str) -> dict[str, Any]:
        record = self.evidence_by_id(evidence_id)
        if record is None:
            raise LedgerPolicyError(
                "evidence_not_found",
                "先 add_evidence 再引用",
                f"unknown evidence_id {evidence_id!r}",
            )
        return record

    # -- unknowns -----------------------------------------------------------

    def record_unknown(
        self,
        *,
        question: str,
        severity: str,
        domain: str,
        recommended_probes: Sequence[str] = (),
        required_authority: str = OBSERVATION,
        created_at: str = "",
        unknown_id: str | None = None,
    ) -> UnknownRecord:
        """Register an open question. Idempotent by ``unknown_id`` when given."""
        if severity not in SEVERITIES:
            raise LedgerPolicyError(
                "unknown_severity_invalid",
                f"severity 必须是 {SEVERITIES} 之一",
                f"invalid severity {severity!r}",
            )
        if required_authority not in {"observation", "inference", "external_claim", "human_assertion"}:
            raise LedgerPolicyError(
                "unknown_authority_invalid",
                "required_authority 必须是四级证据权威之一",
                f"invalid required_authority {required_authority!r}",
            )
        if unknown_id is None:
            unknown_id = "unk-" + _canonical_digest({"question": question, "domain": domain})[:12]
        if any(u.unknown_id == unknown_id for u in self.unknowns):
            raise LedgerPolicyError(
                "unknown_id_conflict",
                "使用新的 unknown_id",
                f"duplicate unknown_id {unknown_id!r}",
            )
        record = UnknownRecord(
            unknown_id=unknown_id,
            question=question,
            severity=severity,
            domain=domain,
            required_authority=required_authority,
            recommended_probes=tuple(recommended_probes),
            created_at=created_at or self.created_at,
        )
        self.unknowns.append(record)
        return record

    def update_unknown(
        self,
        unknown_id: str,
        *,
        status: str,
        resolution: str | None = None,
        supporting: Sequence[str] = (),
        contradicting: Sequence[str] = (),
        resolved_at: str = "",
    ) -> UnknownRecord:
        """Move an unknown through its lifecycle under the evidence contract.

        Resolving requires *both* evidence sides to be declared (invariant 1)
        and at least one observation-grade supporting record (invariant 2).
        """
        record = self._unknown(unknown_id)
        if status not in UNKNOWN_STATUSES:
            raise LedgerPolicyError(
                "unknown_status_invalid",
                f"status 必须是 {UNKNOWN_STATUSES} 之一",
                f"invalid status {status!r}",
            )
        if status == "resolved":
            if not supporting or not contradicting:
                raise LedgerPolicyError(
                    "resolution_needs_two_sided_evidence",
                    "消解 unknown 必须同时声明 supporting 与 contradicting 证据 ID；只报喜的证据不构成结论",
                    f"{unknown_id}: supporting={list(supporting)} contradicting={list(contradicting)}",
                )
            for evidence_id in (*supporting, *contradicting):
                self._require_evidence(evidence_id)
            authorities = {self.evidence_by_id(e_id)["authority"] for e_id in supporting}  # type: ignore[index]
            if not authorities & _RESOLUTION_AUTHORITIES:
                raise LedgerPolicyError(
                    "resolution_requires_observation",
                    "resolution 只认 observation 级证据；请补充运行期/工具观察证据，或保持 open",
                    f"{unknown_id}: supporting authorities={sorted(authorities)}",
                )
            if not resolution:
                raise LedgerPolicyError(
                    "resolution_text_required",
                    "resolved 状态必须附带 resolution 说明",
                    f"{unknown_id}: empty resolution",
                )
        updated = UnknownRecord(
            unknown_id=record.unknown_id,
            question=record.question,
            severity=record.severity,
            domain=record.domain,
            required_authority=record.required_authority,
            recommended_probes=record.recommended_probes,
            status=status,
            resolution=resolution,
            supporting_evidence=tuple(supporting),
            contradicting_evidence=tuple(contradicting),
            created_at=record.created_at,
            resolved_at=(resolved_at or self.created_at) if status == "resolved" else None,
        )
        self.unknowns[self.unknowns.index(record)] = updated
        return updated

    def _unknown(self, unknown_id: str) -> UnknownRecord:
        for record in self.unknowns:
            if record.unknown_id == unknown_id:
                return record
        raise LedgerPolicyError(
            "unknown_not_found",
            "先 record_unknown",
            f"unknown {unknown_id!r} not in ledger",
        )

    def list_unknowns(self, status: str | None = None) -> list[UnknownRecord]:
        if status is None:
            return list(self.unknowns)
        return [u for u in self.unknowns if u.status == status]

    # -- audit ---------------------------------------------------------------

    def audit_residual_unknowns(self) -> dict[str, Any]:
        """Residual audit: what is still open, and what it blocks.

        This is the mechanical executor of "no finding != proof of safety":
        the counts say how much of the question space is actually closed, and
        ``blocking`` is the list a verification gate must refuse to ignore.
        """
        open_records = [u for u in self.unknowns if u.status == "open"]
        blocking = [u for u in open_records if u.severity == "blocking"]
        return {
            "total": len(self.unknowns),
            "open": len(open_records),
            "resolved": len([u for u in self.unknowns if u.status == "resolved"]),
            "wont_resolve": len([u for u in self.unknowns if u.status == "wont_resolve"]),
            "blocking": [u.to_dict() for u in blocking],
            "open_by_domain": _count_by(open_records, lambda u: u.domain),
            "open_by_severity": _count_by(open_records, lambda u: u.severity),
        }

    # -- serialization --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "evidence": list(self.evidence),
            "unknowns": [u.to_dict() for u in self.unknowns],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EvidenceLedger:
        return cls(
            created_at=str(data.get("created_at", "")),
            evidence=[dict(e) for e in data.get("evidence", [])],
            unknowns=[UnknownRecord.from_dict(u) for u in data.get("unknowns", [])],
        )


def gate_for_verified(ledger: EvidenceLedger) -> list[str]:
    """Blockers that prevent any conclusion from being marked ``verified``.

    An empty list means the ledger has nothing blocking; a non-empty list is
    the exact set of reasons the claim cannot be made yet. Callers must treat
    a non-empty result as a hard stop, not a warning.
    """
    audit = ledger.audit_residual_unknowns()
    blockers: list[str] = []
    for record in audit["blocking"]:
        blockers.append(
            f"blocking unknown 未消解: {record['unknown_id']} ({record['domain']}): {record['question']}"
        )
    return blockers


def _count_by(records: Iterable[UnknownRecord], key: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        bucket = str(key(record))  # type: ignore[operator]
        counts[bucket] = counts.get(bucket, 0) + 1
    return counts


def _evidence_schema() -> Mapping[str, Any]:
    from pea.validation import default_registry

    return default_registry().get(EVIDENCE_SCHEMA)
