"""Tests for the structured intake and the posture it derives.

The point of these tests is not coverage; it is to lock in the guardrails:
* an unconfirmed authorization never produces a protection recommendation;
* no posture ever claims absolute security;
* client-side hardening is never auto-enabled;
* missing information is reported as unknown, never guessed.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from pea.intake import (  # noqa: E402
    QUESTIONS,
    answers_from_request,
    apply_profile_to_request,
    blocking_questions,
    derive_profile,
    pending_questions,
)
from pea.planner import build_plan, load_catalog  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CATALOG = load_catalog(ROOT / "catalog" / "catalog.seed.json")

# A complete, internally consistent set of answers, reused across tests.
BASE_ANSWERS = {
    "authorization": "owner",
    "assets": "授权决策算法",
    "distribution": "internal_controlled",
    "audience": "team",
    "device_control": "managed_devices",
    "platforms": ["android-arm64"],
    "languages": ["kotlin 2.0"],
    "offline_required": "true",
    "update_channel": "signed_updates",
    "secret_can_leave_client": "no",
    "threat_model": "competent_reverse_engineer",
    "test_baseline": "partial",
    "performance_budget_percent": "8",
    "allowed_spdx_licenses": ["BSD-2-Clause", "MIT", "Apache-2.0"],
    "allow_network": "false",
}


class AuthorizationGateTests(unittest.TestCase):
    def test_unconfirmed_authorization_yields_no_recommendation(self):
        profile = derive_profile({"authorization": "not_confirmed"})
        self.assertEqual(profile.posture, "insufficient_information")
        self.assertEqual(profile.recommended_goals, ())
        self.assertFalse(profile.client_side_hardening_allowed)
        self.assertIn("确认项目所有权或书面授权", profile.hard_gate_checks)
        # every other question is reported as unknown rather than skipped
        self.assertIn("distribution", profile.unknowns)
        self.assertIn("platforms", profile.unknowns)

    def test_missing_authorization_is_treated_as_unconfirmed(self):
        profile = derive_profile({})
        self.assertEqual(profile.posture, "insufficient_information")


class PostureTests(unittest.TestCase):
    def test_internal_controlled_managed_devices(self):
        profile = derive_profile(BASE_ANSWERS)
        self.assertEqual(profile.posture, "controlled_environment_hardening")
        self.assertTrue(profile.client_side_hardening_allowed)
        self.assertTrue(profile.client_side_hardening_requires_approval)

    def test_attacker_controlled_device_has_no_trustworthy_signal(self):
        answers = dict(BASE_ANSWERS, distribution="mass_offline", device_control="attacker_controlled",
                       cross_platform_requirements="仅支持 Android 10+，无桌面端计划")
        profile = derive_profile(answers)
        self.assertEqual(profile.posture, "no_trustworthy_client_signal")
        self.assertIn("关键授权决策必须落在服务端或可信边界", profile.hard_gate_checks)

    def test_secret_can_leave_and_online_prefers_server_side(self):
        answers = dict(BASE_ANSWERS, offline_required="false", secret_can_leave_client="yes",
                       distribution="saas", device_control="unknown_devices")
        profile = derive_profile(answers)
        self.assertEqual(profile.posture, "server_side_first")
        self.assertIn("logic_extraction", profile.recommended_goals)

    def test_mass_offline_is_cost_raising_only(self):
        answers = dict(BASE_ANSWERS, distribution="mass_offline",
                       device_control="unknown_devices", secret_can_leave_client="no",
                       cross_platform_requirements="Android 10+ / Windows 10+ 行为一致，Linux 仅最佳努力")
        profile = derive_profile(answers)
        self.assertEqual(profile.posture, "cost_raising_only")
        self.assertTrue(any("提高的是谁的成本" in g for g in profile.hard_gate_checks))

    def test_mass_offline_without_compat_matrix_stays_at_intake_gate(self):
        """Mass offline distribution must define its compatibility matrix first."""
        answers = dict(BASE_ANSWERS, distribution="mass_offline", device_control="unknown_devices")
        profile = derive_profile(answers)
        self.assertEqual(profile.posture, "insufficient_information")
        self.assertIn("cross_platform_requirements", profile.unknowns)
        self.assertEqual(profile.recommended_goals, ())

    def test_incomplete_intake_never_recommends(self):
        answers = dict(BASE_ANSWERS)
        answers.pop("threat_model")
        profile = derive_profile(answers)
        self.assertEqual(profile.posture, "insufficient_information")
        self.assertEqual(profile.recommended_goals, ())
        self.assertIn("threat_model", profile.unknowns)


class GuardrailTests(unittest.TestCase):
    """These assertions are the whole reason the module exists."""

    def _postures(self):
        scenarios = [
            {},
            {"authorization": "owner"},
            dict(BASE_ANSWERS),
            dict(BASE_ANSWERS, distribution="mass_offline", device_control="attacker_controlled"),
            dict(BASE_ANSWERS, distribution="mass_offline", device_control="unknown_devices"),
            dict(BASE_ANSWERS, distribution="saas", device_control="unknown_devices",
                 offline_required="false", secret_can_leave_client="yes"),
            dict(BASE_ANSWERS, test_baseline="none"),
        ]
        return [derive_profile(s) for s in scenarios]

    def test_no_posture_claims_absolute_security(self):
        for profile in self._postures():
            joined = " ".join(profile.warnings)
            self.assertIn("只能提高分析成本", joined)
            self.assertIn("不构成绝对保证", joined)

    def test_client_side_hardening_always_requires_explicit_approval(self):
        for profile in self._postures():
            self.assertTrue(profile.client_side_hardening_requires_approval)

    def test_offline_secret_that_cannot_move_warns_about_residual_risk(self):
        answers = dict(BASE_ANSWERS, distribution="mass_offline",
                       device_control="unknown_devices", secret_can_leave_client="no")
        profile = derive_profile(answers)
        self.assertTrue(any("残余风险" in w for w in profile.warnings))

    def test_no_test_baseline_blocks_transformation(self):
        answers = dict(BASE_ANSWERS, test_baseline="none")
        profile = derive_profile(answers)
        self.assertTrue(any("回归测试基线" in g for g in profile.hard_gate_checks))

    def test_missing_update_channel_warns(self):
        answers = dict(BASE_ANSWERS)
        answers.pop("update_channel")
        profile = derive_profile(answers)
        self.assertTrue(any("可信更新通道" in w for w in profile.warnings))


class QuestionFlowTests(unittest.TestCase):
    def test_device_control_not_asked_for_internal_controlled(self):
        pending = {q.id for q in pending_questions({"authorization": "owner", "distribution": "internal_controlled"})}
        self.assertNotIn("device_control", pending)

    def test_device_control_asked_once_distributed_to_others(self):
        pending = {q.id for q in pending_questions({"authorization": "owner", "distribution": "mass_offline"})}
        self.assertIn("device_control", pending)

    def test_cross_platform_requirements_only_for_mass_or_multi_platform(self):
        single = {q.id for q in pending_questions({"authorization": "owner", "platforms": ["android-arm64"]})}
        multi = {q.id for q in pending_questions({"authorization": "owner", "platforms": ["android-arm64", "windows-x64"]})}
        self.assertNotIn("cross_platform_requirements", single)
        self.assertIn("cross_platform_requirements", multi)

    def test_everything_but_authorization_is_moot_before_authorization(self):
        pending = {q.id for q in pending_questions({})}
        self.assertEqual(pending, {"authorization"})

    def test_complete_answers_leave_nothing_pending(self):
        self.assertEqual(pending_questions(BASE_ANSWERS), [])

    def test_optional_questions_do_not_block_progress(self):
        answers = {k: v for k, v in BASE_ANSWERS.items()
                   if k not in {"performance_budget_percent", "allowed_spdx_licenses", "allow_network"}}
        self.assertTrue(pending_questions(answers))  # still offered to the user
        self.assertEqual(blocking_questions(answers), [])  # but nothing blocks

    def test_question_ids_are_unique(self):
        ids = [q.id for q in QUESTIONS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_blocking_questions_are_always_reported_as_unknowns(self):
        """Invariant: anything PEA insists on asking must show up as unknown.

        Without this, a caller could be told "answer these" while the derived
        profile silently claims to know the answer. ``authorization`` is
        excluded because it is the gate, not an unknown fact about the project.
        """
        scenarios = [
            {},
            {"authorization": "owner"},
            dict(BASE_ANSWERS),
            dict(BASE_ANSWERS, distribution="mass_offline", device_control="unknown_devices"),
            dict(BASE_ANSWERS, distribution="mass_offline", platforms=["android-arm64", "windows-x64"]),
            dict(BASE_ANSWERS, distribution="saas", device_control="unknown_devices",
                 offline_required="false", secret_can_leave_client="yes"),
        ]
        for scenario in scenarios:
            with self.subTest(scenario=scenario.get("distribution")):
                blocking = {q.id for q in blocking_questions(scenario)} - {"authorization"}
                unknowns = set(derive_profile(scenario).unknowns)
                self.assertTrue(blocking <= unknowns, f"blocking {blocking - unknowns} not reported as unknown")


class RequestInteropTests(unittest.TestCase):
    def test_answers_from_request_lifts_known_fields(self):
        request = json.loads((ROOT / "examples" / "protection-request.example.json").read_text(encoding="utf-8"))
        answers = answers_from_request(request)
        self.assertEqual(answers["authorization"], "owner")
        self.assertEqual(answers["platforms"], ["javascript", "nodejs"])
        self.assertEqual(answers["offline_required"], True)

    def test_apply_profile_merges_goals_without_duplicates(self):
        profile = derive_profile(BASE_ANSWERS)
        request = {"goals": ["obfuscation"]}
        updated = apply_profile_to_request(request, profile)
        self.assertIn("obfuscation", updated["goals"])
        self.assertEqual(len(updated["goals"]), len(set(updated["goals"])))
        for goal in profile.recommended_goals:
            self.assertIn(goal, updated["goals"])


class PlanIntegrationTests(unittest.TestCase):
    def test_plan_carries_posture_and_unknowns(self):
        request = {
            "schema_version": "1.0",
            "project_path": "./x",
            "authorization": "owner",
            "targets": ["javascript"],
            "goals": ["obfuscation"],
            "offline_required": True,
            "execution_mode": "plan_only",
        }
        plan = build_plan(request, CATALOG)
        self.assertIn("deployment_posture", plan)
        self.assertEqual(plan["deployment_posture"], "insufficient_information")
        self.assertIn("distribution", plan["intake_unknowns"])
        self.assertTrue(any("intake 信息不完整" in r for r in plan["risks"]))
        self.assertTrue(any("只能提高分析成本" in r for r in plan["risks"]))

    def test_explicit_profile_overrides_derivation(self):
        request = {
            "schema_version": "1.0",
            "project_path": "./x",
            "authorization": "owner",
            "targets": ["android"],
            "goals": ["obfuscation"],
            "offline_required": True,
            "execution_mode": "plan_only",
        }
        profile = derive_profile(BASE_ANSWERS)
        plan = build_plan(request, CATALOG, profile=profile)
        self.assertEqual(plan["deployment_posture"], "controlled_environment_hardening")
        self.assertEqual(plan["intake_unknowns"], [])
        self.assertTrue(plan["client_side_hardening"]["allowed"])
        self.assertTrue(plan["client_side_hardening"]["requires_explicit_approval"])

    def test_plan_remains_deterministic_with_profile(self):
        request = json.loads((ROOT / "examples" / "protection-request.example.json").read_text(encoding="utf-8"))
        profile = derive_profile(BASE_ANSWERS)
        self.assertEqual(build_plan(request, CATALOG, profile), build_plan(request, CATALOG, profile))


if __name__ == "__main__":
    unittest.main()
