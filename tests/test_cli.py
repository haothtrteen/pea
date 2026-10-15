"""CLI surface tests.

The CLI is what users actually touch, so its exit codes and error text are part
of the contract: a malformed request must fail loudly (exit 2), a blocked plan
must be distinguishable from a generated one (exit 4), and the intake command
must stay usable non-interactively for CI.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import ClassVar

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pea.cli import main  # noqa: E402
from pea.planner import load_catalog  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CATALOG = load_catalog(ROOT / "catalog" / "catalog.seed.json")
REQUEST = json.loads((ROOT / "examples" / "protection-request.example.json").read_text(encoding="utf-8"))


class CatalogCommandTests(unittest.TestCase):
    def test_catalog_lists_entries(self):
        self.assertEqual(main(["catalog"]), 0)

    def test_catalog_json_is_machine_readable(self):
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["catalog", "--json"]), 0)
        entries = json.loads(buffer.getvalue())
        self.assertEqual(len(entries), len(CATALOG))

    def test_search_returns_three_when_nothing_matches(self):
        self.assertEqual(main(["search", "--target", "cobol", "--goal", "obfuscation"]), 3)


class PlanCommandTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def _write(self, payload: object, name: str = "request.json") -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_plan_writes_a_schema_valid_document(self):
        out = self.tmp / "plan.json"
        self.assertEqual(main(["plan", "--request", str(self._write(REQUEST)), "--out", str(out)]), 0)
        plan = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(plan["strategy"], "existing_tool")
        self.assertTrue(all("basis" in score for score in plan["candidate_scores"]))

    def test_malformed_request_fails_loudly_with_exit_two(self):
        import io
        from contextlib import redirect_stderr

        for payload in (
            dict(REQUEST, targets=[]),
            dict(REQUEST, goals=["not_a_goal"]),
            {k: v for k, v in REQUEST.items() if k != "project_path"},
            dict(REQUEST, surprise=True),
        ):
            with self.subTest(payload=sorted(k for k in payload if k not in REQUEST) or "missing-field"):
                buffer = io.StringIO()
                with redirect_stderr(buffer):
                    code = main(["plan", "--request", str(self._write(payload))])
                self.assertEqual(code, 2)
                self.assertIn("violates its schema", buffer.getvalue())

    def test_blocked_plan_exits_four(self):
        blocked = dict(REQUEST, authorization="not_confirmed")
        out = self.tmp / "blocked.json"
        self.assertEqual(main(["plan", "--request", str(self._write(blocked)), "--out", str(out)]), 4)
        plan = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(plan["status"], "blocked")
        self.assertEqual(plan["selected_catalog_ids"], [])

    def test_unreadable_request_exits_two(self):
        self.assertEqual(main(["plan", "--request", str(self.tmp / "missing.json")]), 2)


class IntakeCommandTests(unittest.TestCase):
    def test_intake_reports_missing_answers_without_a_tty(self):
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["intake", "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["profile"]["posture"], "insufficient_information")
        self.assertIn("distribution", payload["profile"]["unknowns"])

    def test_intake_prefilled_from_request_derives_posture(self):
        import io
        import tempfile
        from contextlib import redirect_stdout

        request = self._internal_android_request()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "request.json"
            path.write_text(json.dumps(request), encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["intake", "--from", str(path), "--format", "json"])
        self.assertEqual(code, 0)
        profile = json.loads(buffer.getvalue())["profile"]
        self.assertEqual(profile["posture"], "controlled_environment_hardening")
        self.assertTrue(profile["client_side_hardening_allowed"])
        self.assertTrue(profile["client_side_hardening_requires_approval"])

    def test_intake_writes_completed_request(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            request = self._internal_android_request()
            source = Path(tmp) / "request.json"
            source.write_text(json.dumps(request), encoding="utf-8")
            target = Path(tmp) / "out.json"
            self.assertEqual(main(["intake", "--from", str(source), "--out", str(target)]), 0)
            written = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(written["distribution"], "internal_controlled")

    @staticmethod
    def _internal_android_request() -> dict:
        return {
            "schema_version": "1.0",
            "project_path": "./app",
            "authorization": "owner",
            "targets": ["android"],
            "goals": ["obfuscation"],
            "offline_required": True,
            "execution_mode": "plan_only",
            "distribution": "internal_controlled",
            "audience": "team",
            "device_control": "managed_devices",
            "update_channel": "signed_updates",
            "secret_can_leave_client": "no",
            "threat_model": "competent_reverse_engineer",
            "test_baseline": "partial",
            "assets": "授权决策算法",
            "languages": ["kotlin 2.0"],
            "cross_platform_requirements": "仅 Android 10+",
        }


class TestbenchCommandTests(unittest.TestCase):
    def test_testbench_reports_tier_without_installing_anything(self):
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["testbench"]), 0)
        out = buffer.getvalue()
        assert "本次可执行到" in out
        assert "T4" in out  # the architectural answer is always stated

    def test_testbench_json_is_machine_readable(self):
        import io
        import json as json_module
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["testbench", "--json"]), 0)
        payload = json_module.loads(buffer.getvalue())
        assert payload["reachable_tier"] in {"T1", "T2", "T3"}
        assert payload["unknowns"], "a bare testbench must declare unknowns"


class BriefCommandTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def test_brief_composes_the_handoff(self):
        out = self.tmp / "brief.json"
        exit_code = main(
            [
                "brief",
                "--request",
                str(ROOT / "examples" / "protection-request.flutter-licensing.example.json"),
                "--project",
                str(ROOT / "demo" / "canary-flutter-licensing"),
                "--baseline",
                str(ROOT / "demo" / "canary-flutter-licensing" / "lib" / "main.dart"),
                "--no-testbench",
                "--out",
                str(out),
            ]
        )
        self.assertEqual(exit_code, 0)
        brief = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(brief["brief_id"].startswith("mb-"))
        # anchors come from the project scan (redacted), not a static list
        self.assertTrue(brief["objective_anchors"])
        # no testbench reconnaissance: environment is a named unknown
        self.assertEqual(brief["environment"]["reachable_tier"], "unknown")
        self.assertTrue(brief["environment"]["deferred_steps"])
        self.assertEqual(brief["evidence_return"]["ledger_tool"], "pea.ledger_record")

    def test_brief_refuses_unconfirmed_authorization_with_exit_four(self):
        request = dict(REQUEST)
        request["authorization"] = "not_confirmed"
        source = self.tmp / "request.json"
        source.write_text(json.dumps(request), encoding="utf-8")
        exit_code = main(
            [
                "brief",
                "--request",
                str(source),
                "--project",
                str(ROOT / "demo" / "canary-flutter-licensing"),
                "--baseline",
                str(ROOT / "demo" / "canary-flutter-licensing" / "lib" / "main.dart"),
                "--no-testbench",
            ]
        )
        self.assertEqual(exit_code, 4)


class LedgerCommandTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.store = self.tmp / "store"

    def _evidence_file(self, payload: dict, name: str = "evidence.json") -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _evidence(self, evidence_id: str, *, tier: str = "T0") -> dict:
        return {
            "evidence_id": evidence_id,
            "kind": "tool_output",
            "source": "rea@user-machine",
            "observed_at": "2026-10-14T12:00:00+00:00",
            "authority": "observation",
            "limitations": ["cli test"],
            "redacted_summary": "脱敏摘要",
            "environment": {"environment_tier": tier},
        }

    def test_record_query_audit_gate_export_flow(self):
        import io
        from contextlib import redirect_stdout

        record = self._evidence_file(self._evidence("ev-cli-1"))
        self.assertEqual(main(["ledger", "record", "--run", "cli-run", "--store", str(self.store), "--evidence", str(record)]), 0)

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["ledger", "query", "--run", "cli-run", "--store", str(self.store), "--kind", "tool_output"]), 0)
        queried = json.loads(buffer.getvalue())
        self.assertEqual(queried["coverage"]["evidence_returned"], 1)

        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["ledger", "audit", "--run", "cli-run", "--store", str(self.store)]), 0)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["ledger", "gate", "--run", "cli-run", "--store", str(self.store)]), 0)
        self.assertEqual(json.loads(buffer.getvalue())["status"], "verified")

        out_dir = self.tmp / "exported"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(["ledger", "export", "--run", "cli-run", "--store", str(self.store), "--out", str(out_dir), "--overwrite"]), 0
            )
        self.assertTrue((out_dir / "ledger.json").is_file())
        self.assertTrue((out_dir / "ledger.md").is_file())

    def test_evidence_without_authority_is_refused(self):
        record = self._evidence_file(
            {
                "evidence_id": "ev-cli-bad",
                "kind": "tool_output",
                "source": "rea@user-machine",
                "observed_at": "2026-10-14T12:00:00+00:00",
                "limitations": ["cli test"],
                "redacted_summary": "无 authority",
            }
        )
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(main(["ledger", "record", "--run", "cli-run", "--store", str(self.store), "--evidence", str(record)]), 2)
        self.assertIn("evidence_missing_fields", buffer.getvalue())

    def test_evidence_with_invented_authority_is_refused(self):
        """An authority outside the four-grade vocabulary is refused - a
        defaulted or invented authority is how static claims quietly become
        observations."""
        payload = self._evidence("ev-cli-bad-2")
        payload["authority"] = "trust_me"
        record = self._evidence_file(payload)
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(main(["ledger", "record", "--run", "cli-run", "--store", str(self.store), "--evidence", str(record)]), 2)
        self.assertIn("evidence_authority_invalid", buffer.getvalue())

    def test_unknown_run_is_a_named_refusal(self):
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(main(["ledger", "audit", "--run", "no-such-run", "--store", str(self.store)]), 2)
        self.assertIn("run_id_unknown", buffer.getvalue())

    def test_resolve_requires_two_sided_evidence(self):
        # A blocking unknown plus one-sided evidence: the CLI must refuse with
        # the ledger's own policy code, not accept the resolution.
        unknown_evidence = self._evidence_file(
            {
                "evidence_id": "ev-cli-unk",
                "kind": "test_result",
                "source": "pea.recon",
                "observed_at": "2026-10-14T12:00:00+00:00",
                "authority": "observation",
                "limitations": ["cli test"],
                "redacted_summary": "unknown 产生源",
                "environment": {"environment_tier": "T0"},
            }
        )
        self.assertEqual(main(["ledger", "record", "--run", "cli-run", "--store", str(self.store), "--evidence", str(unknown_evidence)]), 0)
        # record an unknown through the ledger runtime directly (the CLI has
        # no unknown-recording subcommand; evidence that produces one stays open)
        from pea.ledger import EvidenceLedger

        ledger_path = self.store / "cli-run.json"
        target = EvidenceLedger.from_dict(json.loads(ledger_path.read_text(encoding="utf-8")))
        target.record_unknown(
            question="hook 步骤需要 T2 环境，本次测试台不可达",
            severity="blocking",
            domain="dart_aot_snapshot_analysis",
            required_authority="observation",
        )
        ledger_path.write_text(json.dumps(target.to_dict(), ensure_ascii=False), encoding="utf-8")

        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(
                main(
                    [
                        "ledger",
                        "resolve",
                        "--run",
                        "cli-run",
                        "--store",
                        str(self.store),
                        "--unknown",
                        target.list_unknowns()[0].unknown_id,
                        "--supporting",
                        "ev-cli-unk",
                    ]
                ),
                2,
            )
        self.assertIn("resolution_needs_two_sided_evidence", buffer.getvalue())


class FieldCommandTests(unittest.TestCase):
    """The D7 loop end to end through the CLI: a cracked package is scanned
    read-only, the diff is intake'd, and the response plan stays server-side.
    """

    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.baseline = self.tmp / "baseline"
        self.cracked = self.tmp / "cracked"
        (self.baseline / "lib" / "arm64-v8a").mkdir(parents=True)
        (self.cracked / "lib" / "arm64-v8a").mkdir(parents=True)
        (self.baseline / "lib" / "arm64-v8a" / "libapp.so").write_bytes(b"original-snapshot")
        (self.cracked / "lib" / "arm64-v8a" / "libapp.so").write_bytes(b"patched-snapshot!!")
        (self.cracked / "lib" / "arm64-v8a" / "libpatch.so").write_bytes(b"extra-native")

    def test_intake_then_respond_flow(self):
        import io
        from contextlib import redirect_stdout

        intake_path = self.tmp / "intake.json"
        self.assertEqual(
            main(["field", "intake", "--cracked", str(self.cracked), "--baseline", str(self.baseline), "--out", str(intake_path)]),
            0,
        )
        intake = json.loads(intake_path.read_text(encoding="utf-8"))
        self.assertEqual([d["change"] for d in intake["diffs"]], ["modified", "added"])

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["field", "respond", "--intake", str(intake_path)]), 0)
        response = json.loads(buffer.getvalue())
        self.assertEqual(response["posture"], "server_side_available")
        self.assertTrue(response["measures"])
        # every measure is triggered by a diff fact, and every plan carries the
        # non-regression test that protects legitimate users
        triggers = {m["trigger_artifact"] for m in response["measures"]}
        self.assertIn("lib/arm64-v8a/libapp.so", triggers)
        scenarios = {t["scenario"] for t in response["negative_tests"]}
        self.assertIn("legitimate_variant_unaffected", scenarios)

    def test_intake_refuses_a_missing_root_with_exit_two(self):
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = main(["field", "intake", "--cracked", str(self.tmp / "nope"), "--baseline", str(self.baseline)])
        self.assertEqual(code, 2)
        self.assertIn("cracked path is not a directory", buffer.getvalue())

    def test_respond_declines_an_offline_posture_instead_of_emptying(self):
        import io
        from contextlib import redirect_stdout

        intake_path = self.tmp / "intake.json"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(["field", "intake", "--cracked", str(self.cracked), "--baseline", str(self.baseline), "--out", str(intake_path)]),
                0,
            )
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["field", "respond", "--intake", str(intake_path), "--offline-required"]), 0)
        response = json.loads(buffer.getvalue())
        self.assertEqual(response["posture"], "declined_offline_only")
        self.assertEqual(response["measures"], [])

    def test_respond_missing_intake_file_exits_two(self):
        code = main(["field", "respond", "--intake", str(self.tmp / "no-such-intake.json")])
        self.assertEqual(code, 2)


class ProtectCommandTests(unittest.TestCase):
    """``pea protect`` — the one-sentence run. The adapter is faked (the real
    tool install is verify_loop's integration job); the CLI plumbing, the
    single human decision, the gate output and the report are what's under
    test here."""

    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.project = self.tmp / "proj"
        self.project.mkdir()
        (self.project / "package.json").write_text(json.dumps({"name": "x", "scripts": {"test": "node --test"}}), encoding="utf-8")
        (self.project / "license.js").write_text("const KEY = 'sk-live-cli';\nmodule.exports = { KEY };\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def _fake_adapter(self):
        from pea.adapters.base import ApplyPreview, ApplyResult

        class FakeAdapter:
            manifest: ClassVar[dict[str, str]] = {"tool_id": "fake", "tool_version": "0.0.0"}

            def inspect(self, target):
                from pea.adapters.base import AdapterInspect

                return AdapterInspect(applies=True, tool_id="fake", tool_version="0.0.0", reason="fake")

            def preview(self, plan, workspace):
                return ApplyPreview(
                    argv=("fake",), affected_files=("license.js",), output_destination=str(workspace),
                    expected_side_effects=("fake",), tool_id="fake", tool_version="0.0.0", options={},
                )

            def apply(self, preview, workspace):
                target = workspace / "license.js"
                target.write_text(target.read_text(encoding="utf-8") + "\n// protected\n", encoding="utf-8")
                return ApplyResult(outputs=(str(target),), exit_code=0, tool_id="fake", tool_version="0.0.0")

        return FakeAdapter()

    def test_protect_runs_one_shot_and_writes_a_report(self):
        import io
        from contextlib import redirect_stdout
        from unittest.mock import patch

        from pea import adapters as adapters_mod
        from pea import protect as protect_mod

        fake = self._fake_adapter()
        with patch.object(adapters_mod, "adapter_for", return_value=fake), patch.object(
            protect_mod, "adapter_for", return_value=fake
        ):
            store = self.tmp / "store"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["protect", str(self.project), "--store", str(store), "--yes"])
        self.assertEqual(code, 0)
        out = buffer.getvalue()
        self.assertIn("验证结果：pass", out)
        self.assertIn("original_intact", out)
        # the user's project is untouched
        self.assertEqual((self.project / "license.js").read_text(encoding="utf-8").count("// protected"), 0)
        reports = list((store / "runs").glob("*/protect-report.json"))
        self.assertEqual(len(reports), 1)
        report = json.loads(reports[0].read_text(encoding="utf-8"))
        self.assertEqual(report["verify"]["status"], "pass")
        self.assertGreater(report["compare"]["size"]["delta_pct"], 0)

    def test_protect_refuses_a_missing_target(self):
        code = main(["protect", str(self.tmp / "no-such-dir"), "--yes"])
        self.assertEqual(code, 2)

    def test_approve_without_pending_reports_zero(self):
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["approve", "--store", str(self.tmp / "empty-store")])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
