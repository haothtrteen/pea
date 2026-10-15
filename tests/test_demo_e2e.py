"""End-to-end demo tests: the whole defense-engineering loop, start to finish.

These tests run the real composition (recon -> capability mapping -> plan ->
attack simulation -> ledger -> report) against the checked-in canary. The
canary itself is guarded by ``test_canary_matches_builder`` so the fixture
cannot silently drift from ``demo/build_canary.py``.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

import pytest

from pea.cli import main
from pea.demo import run_demo

ROOT = Path(__file__).resolve().parents[1]
CANARY = ROOT / "demo" / "canary-flutter-licensing"
REQUEST = ROOT / "examples" / "protection-request.flutter-licensing.example.json"


def _load_request() -> dict:
    return json.loads(REQUEST.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def demo_result():
    return run_demo(_load_request(), CANARY, now="2026-10-13T00:00:00+00:00")


class TestAuthorizedWalkthrough:
    def test_every_stage_produced_output(self, demo_result) -> None:
        assert demo_result.recon is not None
        assert demo_result.artifact_scan is not None
        assert demo_result.secret_scan is not None
        assert demo_result.symbol_scan is not None
        assert demo_result.attack_simulation is not None
        assert demo_result.plan["status"] in {"needs_user_review", "blocked"}
        assert demo_result.ledger_audit["total"] >= 1

    def test_recon_located_the_planted_authorization_logic(self, demo_result) -> None:
        assert demo_result.recon is not None
        hit_paths = {hit.path for hit in demo_result.recon.pattern_hits}
        assert "lib/auth/license_validator.dart" in hit_paths
        assert "lib/auth/license_store.dart" in hit_paths

    def test_secret_scan_hits_canary_bait_without_leaking_it(self, demo_result) -> None:
        """The planted fake key/endpoint are located by pattern name only."""
        assert demo_result.secret_scan is not None
        patterns = {(h.path, h.pattern) for h in demo_result.secret_scan.hits}
        assert ("lib/auth/license_store.dart", "hardcoded_credential") in patterns
        assert ("lib/auth/license_store.dart", "hardcoded_endpoint") in patterns
        report = demo_result.report_markdown
        assert "hardcoded_credential" in report
        # 脱敏纪律：埋点内容不出现在报告任何位置
        assert "CANARY-FAKE-KEY" not in report
        assert "license.example-canary.invalid" not in report

    def test_domains_degrade_honestly_without_artifacts(self, demo_result) -> None:
        """No build output: artifact manifest and string-symbol scan say
        unknown/not_run instead of fabricating a pass."""
        assert demo_result.artifact_scan is not None
        assert demo_result.symbol_scan is not None
        assert any("未发现" in u for u in demo_result.artifact_scan.unknowns)
        assert demo_result.symbol_scan.findings[0]["status"] == "unknown"
        assert demo_result.symbol_scan.coverage["state"] == "not_run"
        domains = demo_result.bundle["domains"]
        # M3 收官：七个域全部接入，其中三个新域随 manifest 为空同样降级为
        # unknown/not_run——新域的加入必须放大"未评估"而不是制造新结论。
        assert set(domains) == {
            "artifact_manifest",
            "secret_scan",
            "string_symbol_scan",
            "native_check",
            "dart_aot_check",
            "build_integration",
            "candidate_review",
        }
        assert demo_result.bundle["domains"]["native_check"]["findings"][0]["status"] == "unknown"
        assert demo_result.bundle["domains"]["dart_aot_check"]["findings"][0]["status"] == "unknown"
        # canary 的 build.gradle 现在声明了三个 ABI，但无产物：声明与产物的
        # 比对执行了却无法完成（partial），且结论是 unknown——声明存在从不
        # 等于产物存在。
        assert demo_result.bundle["domains"]["build_integration"]["coverage"]["state"] == "partial"
        assert demo_result.bundle["domains"]["build_integration"]["findings"][0]["id"] == "build-integration-no-artifacts"

    def test_candidate_review_gates_the_real_catalog(self, demo_result) -> None:
        """The gate runs against the checked-in catalog on every walkthrough,
        and its documented decisions hold: pending-license candidates stay
        blocked, the design-pattern entry stays production-eligible."""
        assert demo_result.candidate_review is not None
        decisions = {r.candidate_id: r.decision for r in demo_result.candidate_review.reviews}
        assert decisions["pyarmor"] == "blocked"
        assert decisions["fdartvmp"] == "blocked"
        assert decisions["logic-extraction-pattern"] == "production_eligible"
        report = demo_result.report_markdown
        assert "候选门控" in report

    def test_intel_channel_is_not_attempted_when_offline(self, demo_result) -> None:
        """No transport injected: the retrieval channel records an explicit
        not_attempted instead of an empty result that reads as 'nothing
        found'."""
        channel = demo_result.bundle["capability_intel"]
        assert channel["status"] == "not_attempted"
        assert "未检索" in channel["reason"]
        assert "capability_intel" not in demo_result.bundle["domains"]


class TestIntelChannelInjected:
    """With a transport injected, the retrieval result joins the domain set
    as claims - and the demo still never labels it verified."""

    def test_injected_transport_yields_external_claims(self) -> None:
        from pea.capintel import IntelResponse

        def transport(url: str) -> IntelResponse:
            return IntelResponse(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=b"analyst note: blutter recovers class structure from libapp.so",
            )

        result = run_demo(
            _load_request(),
            CANARY,
            now="2026-10-13T00:00:00+00:00",
            intel_transport=transport,
        )

        intel = result.bundle["domains"]["capability_intel"]
        assert result.bundle["capability_intel"]["status"] == "ok"
        assert intel["findings"][0]["evidence"][0]["authority"] == "external_claim"
        assert "能力情报" in result.report_markdown

    def test_recon_reports_no_release_artifact_as_unknown(self, demo_result) -> None:
        assert demo_result.recon is not None
        assert any("未发现构建产物" in u for u in demo_result.recon.unknowns)

    def test_attack_simulation_covers_dart_path_with_three_steps(self, demo_result) -> None:
        assert demo_result.attack_simulation is not None
        dart_steps = [
            s for s in demo_result.attack_simulation["capability_steps"]
            if s["capability_family"] == "dart_aot_snapshot_analysis"
        ]
        assert len(dart_steps) == 3
        assert demo_result.attack_simulation["success_criteria"]["interpretation_rule"] == "cost_delta_only"
        assert demo_result.attack_simulation["sandbox"]["read_only_artifacts"] is True

    def test_budget_sums_to_declared_total(self, demo_result) -> None:
        assert demo_result.attack_simulation is not None
        minutes = [s["time_budget_minutes"] for s in demo_result.attack_simulation["capability_steps"]]
        assert sum(minutes) == demo_result.attack_simulation["sandbox"]["time_budget_minutes"]

    def test_gate_blocks_verified_while_blocking_unknown_open(self, demo_result) -> None:
        assert demo_result.gate_blockers, "a plan-only walkthrough must never clear the verified gate"
        assert any("未发现构建产物" in b for b in demo_result.gate_blockers)

    def test_remediation_section_orders_highest_exposure_first(self, demo_result) -> None:
        """The founding principle as mechanics: T1 (one-click tooling) is
        repaired before content, runtime and algorithm layers."""
        from pea.tiers import TIER_ORDER

        report = demo_result.report_markdown
        assert "## 5. 修复优先级（由高到低）" in report
        groups = demo_result.bundle["remediation_groups"]
        assert groups, "authorized walkthrough must produce remediation groups"
        tiers = [g["exposure_tier"] for g in groups]
        ranks = [TIER_ORDER.index(t) for t in tiers]
        assert ranks == sorted(ranks), f"remediation not in exposure order: {tiers}"
        assert tiers[0] == "tool_efficiency"
        # T1 首条行动来自能力映射，且引用 blutter 类自检建议
        first_actions = groups[0]["actions"]
        assert any("能力映射" in a for a in first_actions)
        # 各来源行动均可溯源：能力映射 / 侦察 / 产物清单 / 秘密扫描 / 字符串符号
        all_actions = [a for g in groups for a in g["actions"]]
        assert any("[产物清单]" in a for a in all_actions)
        assert any("[秘密扫描]" in a for a in all_actions)
        # 报告正文按同样顺序呈现
        assert report.index("T1 工具放大层") < report.index("T2 静态内容层")
        assert report.index("T2 静态内容层") < report.index("T3 运行期行为层")

    def test_attack_steps_follow_exposure_order(self, demo_result) -> None:
        assert demo_result.attack_simulation is not None
        from pea.tiers import TIER_ORDER

        tiers = [s.get("exposure_tier") for s in demo_result.attack_simulation["capability_steps"]]
        ranks = [TIER_ORDER.index(t) for t in tiers if t in TIER_ORDER]
        assert ranks == sorted(ranks)

    def test_bundle_is_json_serializable_and_complete(self, demo_result) -> None:
        blob = json.dumps(demo_result.bundle, ensure_ascii=False)
        assert '"recon"' in blob and '"attack_simulation"' in blob
        assert '"domains"' in blob
        assert '"secret_scan"' in blob
        assert demo_result.bundle["demo"]["mode"] == "plan_only"

    def test_report_marks_measured_vs_designed(self, demo_result) -> None:
        report = demo_result.report_markdown
        assert "[实测]" in report and "[设计]" in report
        assert "cost_delta_only" in report
        assert "不得标 verified" in report
        assert "lib/auth/license_validator.dart" in report

    def test_deterministic_output_for_fixed_clock(self) -> None:
        first = run_demo(_load_request(), CANARY, now="2026-10-13T00:00:00+00:00")
        second = run_demo(_load_request(), CANARY, now="2026-10-13T00:00:00+00:00")
        assert first.bundle == second.bundle
        assert first.report_markdown == second.report_markdown


class TestUnauthorizedWalkthrough:
    def test_no_scan_happens_without_authorization(self) -> None:
        request = _load_request()
        request["authorization"] = "not_confirmed"
        result = run_demo(request, CANARY, now="2026-10-13T00:00:00+00:00")
        assert result.recon is None
        assert result.artifact_scan is None
        assert result.secret_scan is None
        assert result.symbol_scan is None
        assert result.attack_simulation is None
        assert result.plan["status"] == "blocked"
        assert any("授权" in b for b in result.gate_blockers)
        assert "未执行侦察" in result.report_markdown
        assert "未运行多域侦察" in result.report_markdown


class TestCanaryFixture:
    def test_canary_matches_builder(self) -> None:
        """The checked-in fixture must equal what build_canary.py generates."""
        sys.path.insert(0, str(ROOT / "demo"))
        try:
            import build_canary
        finally:
            sys.path.remove(str(ROOT / "demo"))
        expected_files = set(build_canary.FILES)
        actual_files = {
            path.relative_to(CANARY).as_posix()
            for path in CANARY.rglob("*")
            if path.is_file()
        }
        assert actual_files == expected_files, f"canary drift: extra={actual_files - expected_files}, missing={expected_files - actual_files}"
        for rel, content in build_canary.FILES.items():
            assert (CANARY / rel).read_text(encoding="utf-8") == content, f"content drift in {rel}"

    def test_canary_artifacts_match_builder(self) -> None:
        """The checked-in synthetic artifacts must equal what
        build_canary_artifacts.py generates - byte-identical, so the L2 layer
        always measures exactly the bytes the manifest pins."""
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            import build_canary_artifacts as builder
        finally:
            sys.path.remove(str(ROOT / "scripts"))
        with tempfile.TemporaryDirectory() as tmp:
            rows = builder.build(Path(tmp))
        checked_in = ROOT / "demo" / "canary-artifacts"
        actual_files = {
            path.relative_to(checked_in).as_posix()
            for path in checked_in.rglob("*")
            if path.is_file()
        }
        assert actual_files == {row["path"] for row in rows}, f"artifact drift: {actual_files ^ {row['path'] for row in rows}}"
        for row in rows:
            data = (checked_in / row["path"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == row["sha256"], f"byte drift in {row['path']}"
        manifest = json.loads((ROOT / "demo" / "canary-artifacts.manifest.json").read_text(encoding="utf-8"))
        assert [row["path"] for row in manifest["artifacts"]] == [row["path"] for row in rows]


class TestCli:
    def test_cli_demo_writes_report_and_bundle(self, tmp_path: Path) -> None:
        out = tmp_path / "out"
        code = main([
            "demo",
            "--request", str(REQUEST),
            "--project", str(CANARY),
            "--out", str(out),
        ])
        assert code == 0
        report = (out / "report.md").read_text(encoding="utf-8")
        bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
        assert report.startswith("# PEA 原型 1.0 Demo 报告")
        assert bundle["attack_simulation"]["simulation_id"].startswith("atk-")

    def test_cli_demo_unauthorized_exits_4(self, tmp_path: Path, capsys) -> None:
        request_path = tmp_path / "unauthorized.json"
        request = _load_request()
        request["authorization"] = "not_confirmed"
        request_path.write_text(json.dumps(request), encoding="utf-8")
        code = main(["demo", "--request", str(request_path), "--project", str(CANARY)])
        assert code == 4
        assert "未确认" in capsys.readouterr().out

    def test_cli_demo_prints_report_to_stdout_without_out(self, capsys) -> None:
        code = main(["demo", "--request", str(REQUEST), "--project", str(CANARY)])
        assert code == 0
        assert "# PEA 原型 1.0 Demo 报告" in capsys.readouterr().out
