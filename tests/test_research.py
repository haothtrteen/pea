"""WP5 研究通道验收：research-record 合同 + 离线全 unknown + 门控纪律。

原则（方案 §5）：权威级恒为 external_claim；搜索结果不得直接变成候选
（必须过 candidate-review 门）；无 transport 时全部结论 unknown，不空谈。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pea import research  # noqa: E402
from pea.capintel import IntelCandidate, IntelQuery, fetch_capability_intel  # noqa: E402
from pea.validation import validate_or_raise  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "research-record.schema.json").read_text(encoding="utf-8"))


def _ok_intel_result(family: str = "js_obfuscation"):
    """A successful retrieval with one candidate (as a transport would give)."""
    from pea.capintel import CapabilityIntelResult

    candidate = IntelCandidate(
        source_url="https://github.com/javascript-obfuscator/javascript-obfuscator",
        title="javascript-obfuscator",
        snippet="A tool for JS protection; BSD-2-Clause; active maintenance",
        retrieved_at="2026-10-15T00:00:00+00:00",
    )
    query = IntelQuery(family=family, keywords=("obfuscator",))
    return CapabilityIntelResult(query=query, status="ok", candidates=(candidate,))


def _offline_result(family: str = "js_obfuscation"):
    return fetch_capability_intel(IntelQuery(family=family), transport=None, now="2026-10-15T00:00:00+00:00")


class ResearchRecordContractTests(unittest.TestCase):
    def test_record_conforms_to_the_schema(self):
        record = research.record_from_intel(
            _ok_intel_result(),
            question="js 混淆候选在 BSD-2-Clause 下是否可用？",
            checks={"license": "verified", "maintenance": "active", "platform": "confirmed"},
            applicability="applicable",
            decision="accepted",
            decision_reason="许可证已核实、维护活跃、平台匹配；仍需项目回归与 fixture 实测",
            limitations=["未做源码审计", "性能未实测"],
            now="2026-10-15T00:00:00+00:00",
        )
        validate_or_raise(record.to_dict(), SCHEMA, subject="research record")

    def test_authority_is_a_schema_constant(self):
        """权威级恒为 external_claim：不是默认值，是合同常量。"""
        self.assertEqual(SCHEMA["properties"]["authority"]["const"], "external_claim")
        self.assertEqual(research.AUTHORITY, "external_claim")
        record = research.make_record(question="q", family="f", decision_reason="r")
        self.assertEqual(record.authority, "external_claim")

    def test_offline_retrieval_yields_an_all_unknown_record(self):
        """无 transport 时照常工作：来源为空、三项核对全 unknown、
        适用性 unknown、结论 deferred 并写明原因——不空谈，不假装查过。"""
        record = research.record_from_intel(_offline_result(), question="离线时还能下结论吗？")
        validate_or_raise(record.to_dict(), SCHEMA, subject="offline research record")
        self.assertEqual(record.sources, ())
        self.assertEqual(record.checks, {"license": "unknown", "maintenance": "unknown", "platform": "unknown"})
        self.assertEqual(record.applicability, "unknown")
        self.assertEqual(record.decision, "deferred")
        self.assertIn("network_unavailable", record.decision_reason)


class ResearchGateTests(unittest.TestCase):
    def test_acceptance_with_unknown_checks_is_refused(self):
        """机械门：核对全 unknown 却 accepted = 造假，构造时即拒绝。"""
        with self.assertRaises(research.ResearchRecordError) as ctx:
            research.make_record(
                question="q",
                family="f",
                checks={"license": "unknown", "maintenance": "unknown", "platform": "unknown"},
                applicability="unknown",
                decision="accepted",
                decision_reason="看起来不错",
            )
        self.assertEqual(ctx.exception.reason, "acceptance_with_unknowns")

    def test_decision_requires_a_written_reason(self):
        with self.assertRaises(research.ResearchRecordError) as ctx:
            research.make_record(question="q", family="f", decision="rejected")
        self.assertEqual(ctx.exception.reason, "decision_reason_missing")

    def test_rejection_is_allowed_with_unknowns(self):
        """拒绝不需要把 unknown 消成 decided：以未知为由拒绝是诚实结论。"""
        record = research.make_record(
            question="q",
            family="f",
            decision="rejected",
            decision_reason="三项核对全部 unknown：无法支持采用，先拒绝",
        )
        self.assertEqual(record.decision, "rejected")

    def test_retrieval_candidates_are_sources_not_candidates(self):
        """检索结果进记录的是'来源'字段；记录类型里没有候选队列的入口。"""
        record = research.record_from_intel(_ok_intel_result(), question="来源去哪了？")
        self.assertEqual(len(record.sources), 1)
        self.assertEqual(record.sources[0].url, "https://github.com/javascript-obfuscator/javascript-obfuscator")
        self.assertFalse(hasattr(record, "candidates"))


if __name__ == "__main__":
    unittest.main()
