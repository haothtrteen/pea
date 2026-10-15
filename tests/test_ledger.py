"""Evidence ledger tests: the invariants that make "verified" mean something.

Every test name maps to an invariant from the D5 parity plan. The two that
matter most: a resolution needs two-sided evidence, and only
observation-grade evidence can ground one.
"""
from __future__ import annotations

import json

import pytest

from pea.ledger import (
    EvidenceLedger,
    LedgerPolicyError,
    gate_for_verified,
)


def _evidence(evidence_id: str, authority: str = "observation", kind: str = "tool_output") -> dict:
    return {
        "evidence_id": evidence_id,
        "kind": kind,
        "source": "pea.test",
        "observed_at": "2026-10-13T00:00:00+00:00",
        "authority": authority,
        "limitations": [],
    }


@pytest.fixture
def ledger() -> EvidenceLedger:
    return EvidenceLedger(created_at="2026-10-13T00:00:00+00:00")


class TestEvidenceIntake:
    def test_valid_record_is_accepted(self, ledger: EvidenceLedger) -> None:
        record = ledger.add_evidence(_evidence("ev-1"))
        assert record["authority"] == "observation"
        assert ledger.evidence_by_id("ev-1") is record

    def test_missing_required_field_is_rejected(self, ledger: EvidenceLedger) -> None:
        broken = _evidence("ev-1")
        broken.pop("observed_at")
        with pytest.raises(LedgerPolicyError, match="evidence_missing_fields"):
            ledger.add_evidence(broken)

    def test_invalid_authority_is_rejected_not_defaulted(self, ledger: EvidenceLedger) -> None:
        with pytest.raises(LedgerPolicyError, match="evidence_authority_invalid"):
            ledger.add_evidence(_evidence("ev-1", authority="trusted_bro"))

    def test_invalid_kind_is_rejected_by_schema(self, ledger: EvidenceLedger) -> None:
        with pytest.raises(Exception, match="evidence record violates its schema"):
            ledger.add_evidence(_evidence("ev-1", kind="vibes"))

    def test_duplicate_evidence_id_is_rejected(self, ledger: EvidenceLedger) -> None:
        ledger.add_evidence(_evidence("ev-1"))
        with pytest.raises(LedgerPolicyError, match="evidence_id_conflict"):
            ledger.add_evidence(_evidence("ev-1"))


class TestUnknownLifecycle:
    def test_record_and_list(self, ledger: EvidenceLedger) -> None:
        unknown = ledger.record_unknown(
            question="iOS 构建是否暴露同构攻击路径？",
            severity="blocking",
            domain="exposure",
            recommended_probes=["构建 iOS canary 后重扫"],
        )
        assert unknown.status == "open"
        assert unknown.unknown_id.startswith("unk-")
        assert len(ledger.list_unknowns()) == 1
        assert ledger.list_unknowns(status="resolved") == []

    def test_invalid_severity_is_rejected(self, ledger: EvidenceLedger) -> None:
        with pytest.raises(LedgerPolicyError, match="unknown_severity_invalid"):
            ledger.record_unknown(question="q", severity="meh", domain="d")

    def test_duplicate_unknown_id_is_rejected(self, ledger: EvidenceLedger) -> None:
        ledger.record_unknown(question="q", severity="important", domain="d", unknown_id="unk-fixed")
        with pytest.raises(LedgerPolicyError, match="unknown_id_conflict"):
            ledger.record_unknown(question="q2", severity="important", domain="d", unknown_id="unk-fixed")

    def test_update_unknown_not_in_ledger(self, ledger: EvidenceLedger) -> None:
        with pytest.raises(LedgerPolicyError, match="unknown_not_found"):
            ledger.update_unknown("unk-nope", status="open")


class TestResolutionInvariants:
    def test_resolution_without_contradicting_evidence_is_refused(self, ledger: EvidenceLedger) -> None:
        ledger.add_evidence(_evidence("ev-support"))
        unknown = ledger.record_unknown(question="q?", severity="blocking", domain="exposure")
        with pytest.raises(LedgerPolicyError, match="resolution_needs_two_sided_evidence"):
            ledger.update_unknown(
                unknown.unknown_id,
                status="resolved",
                resolution="已验证无暴露",
                supporting=["ev-support"],
                contradicting=[],
            )

    def test_resolution_on_inference_alone_is_refused(self, ledger: EvidenceLedger) -> None:
        ledger.add_evidence(_evidence("ev-doc", authority="external_claim", kind="source_document"))
        ledger.add_evidence(_evidence("ev-doc2", authority="inference", kind="inference"))
        unknown = ledger.record_unknown(question="q?", severity="important", domain="exposure")
        with pytest.raises(LedgerPolicyError, match="resolution_requires_observation"):
            ledger.update_unknown(
                unknown.unknown_id,
                status="resolved",
                resolution="文档称已防护",
                supporting=["ev-doc", "ev-doc2"],
                contradicting=["ev-doc"],
            )

    def test_resolution_citing_missing_evidence_is_refused(self, ledger: EvidenceLedger) -> None:
        unknown = ledger.record_unknown(question="q?", severity="important", domain="exposure")
        with pytest.raises(LedgerPolicyError, match="evidence_not_found"):
            ledger.update_unknown(
                unknown.unknown_id,
                status="resolved",
                resolution="x",
                supporting=["ev-ghost"],
                contradicting=["ev-ghost2"],
            )

    def test_resolution_requires_text(self, ledger: EvidenceLedger) -> None:
        ledger.add_evidence(_evidence("ev-obs"))
        unknown = ledger.record_unknown(question="q?", severity="important", domain="exposure")
        with pytest.raises(LedgerPolicyError, match="resolution_text_required"):
            ledger.update_unknown(
                unknown.unknown_id,
                status="resolved",
                supporting=["ev-obs"],
                contradicting=["ev-obs"],
            )

    def test_observation_grounded_resolution_succeeds(self, ledger: EvidenceLedger) -> None:
        ledger.add_evidence(_evidence("ev-obs"))
        ledger.add_evidence(_evidence("ev-probe", authority="inference", kind="inference"))
        unknown = ledger.record_unknown(question="q?", severity="blocking", domain="exposure")
        updated = ledger.update_unknown(
            unknown.unknown_id,
            status="resolved",
            resolution="运行期观察确认行为符合预期；推理证据记录了反驳路径的检验",
            supporting=["ev-obs"],
            contradicting=["ev-probe"],
            resolved_at="2026-10-14T00:00:00+00:00",
        )
        assert updated.status == "resolved"
        assert updated.resolved_at == "2026-10-14T00:00:00+00:00"
        assert updated.supporting_evidence == ("ev-obs",)

    def test_wont_resolve_needs_no_evidence(self, ledger: EvidenceLedger) -> None:
        unknown = ledger.record_unknown(question="q?", severity="informational", domain="exposure")
        updated = ledger.update_unknown(unknown.unknown_id, status="wont_resolve")
        assert updated.status == "wont_resolve"


class TestAuditAndGate:
    def test_audit_counts_and_blocking_list(self, ledger: EvidenceLedger) -> None:
        ledger.record_unknown(question="b1", severity="blocking", domain="exposure", unknown_id="unk-b1")
        ledger.record_unknown(question="i1", severity="important", domain="licensing", unknown_id="unk-i1")
        ledger.record_unknown(question="f1", severity="informational", domain="platform", unknown_id="unk-f1")
        audit = ledger.audit_residual_unknowns()
        assert audit["total"] == 3
        assert audit["open"] == 3
        assert [u["unknown_id"] for u in audit["blocking"]] == ["unk-b1"]
        assert audit["open_by_domain"] == {"exposure": 1, "licensing": 1, "platform": 1}
        assert audit["open_by_severity"] == {"blocking": 1, "important": 1, "informational": 1}

    def test_gate_blocks_while_blocking_unknown_is_open(self, ledger: EvidenceLedger) -> None:
        ledger.record_unknown(question="b1", severity="blocking", domain="exposure", unknown_id="unk-b1")
        blockers = gate_for_verified(ledger)
        assert len(blockers) == 1
        assert "unk-b1" in blockers[0]

    def test_gate_clears_after_resolution(self, ledger: EvidenceLedger) -> None:
        ledger.add_evidence(_evidence("ev-obs"))
        ledger.add_evidence(_evidence("ev-contra", authority="inference", kind="inference"))
        unknown = ledger.record_unknown(question="b1", severity="blocking", domain="exposure")
        ledger.update_unknown(
            unknown.unknown_id,
            status="resolved",
            resolution="双向证据齐备",
            supporting=["ev-obs"],
            contradicting=["ev-contra"],
        )
        assert gate_for_verified(ledger) == []

    def test_gate_ignores_non_blocking_open_unknowns(self, ledger: EvidenceLedger) -> None:
        ledger.record_unknown(question="i1", severity="important", domain="licensing", unknown_id="unk-i1")
        assert gate_for_verified(ledger) == []


class TestSerialization:
    def test_json_round_trip_preserves_everything(self, ledger: EvidenceLedger) -> None:
        ledger.add_evidence(_evidence("ev-1"))
        unknown = ledger.record_unknown(
            question="q?",
            severity="blocking",
            domain="exposure",
            recommended_probes=["probe-a"],
        )
        ledger.update_unknown(unknown.unknown_id, status="open")
        restored = EvidenceLedger.from_dict(json.loads(json.dumps(ledger.to_dict(), ensure_ascii=False)))
        assert restored.to_dict() == ledger.to_dict()
        assert gate_for_verified(restored) == gate_for_verified(ledger)
