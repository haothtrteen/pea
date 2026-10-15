import json
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from pea.planner import build_plan, load_catalog, search_catalog  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CATALOG = load_catalog(ROOT / "catalog" / "catalog.seed.json")


class CatalogTests(unittest.TestCase):
    def test_javascript_obfuscator_is_discoverable(self):
        results = search_catalog(["javascript"], ["obfuscation"], CATALOG)
        ids = {item["id"] for item in results}
        self.assertIn("javascript-obfuscator", ids)

    def test_research_only_is_excluded_by_default(self):
        results = search_catalog(["dotnet-framework"], ["obfuscation"], CATALOG)
        self.assertNotIn("confuserex-legacy", {item["id"] for item in results})

    def test_research_only_can_be_shown_explicitly(self):
        results = search_catalog(["dotnet-framework"], ["obfuscation"], CATALOG, include_research=True)
        self.assertIn("confuserex-legacy", {item["id"] for item in results})


class PlanTests(unittest.TestCase):
    def test_request_selects_js_tool_when_license_matches(self):
        request = json.loads((ROOT / "examples" / "protection-request.example.json").read_text(encoding="utf-8"))
        plan = build_plan(request, CATALOG)
        self.assertEqual(plan["strategy"], "existing_tool")
        self.assertEqual(plan["selected_catalog_ids"], ["javascript-obfuscator"])
        self.assertEqual(plan["status"], "needs_user_review")

    def test_unconfirmed_authorization_blocks(self):
        request = {
            "schema_version": "1.0",
            "project_path": "./somewhere",
            "authorization": "not_confirmed",
            "targets": ["javascript"],
            "goals": ["obfuscation"],
            "offline_required": True,
            "execution_mode": "plan_only"
        }
        plan = build_plan(request, CATALOG)
        self.assertEqual(plan["status"], "blocked")
        self.assertEqual(plan["strategy"], "no_safe_match")

    def test_unverified_license_is_not_selected_for_production_plan(self):
        request = {
            "schema_version": "1.0",
            "project_path": "./somewhere",
            "authorization": "owner",
            "targets": ["python"],
            "goals": ["obfuscation"],
            "offline_required": True,
            "execution_mode": "plan_only"
        }
        plan = build_plan(request, CATALOG)
        self.assertNotIn("pyarmor", plan["selected_catalog_ids"])
        self.assertEqual(plan["status"], "blocked")

    def test_no_existing_tool_can_suggest_extraction(self):
        request = {
            "schema_version": "1.0",
            "project_path": "./somewhere",
            "authorization": "owner",
            "targets": ["unknown-target"],
            "goals": ["logic_extraction"],
            "offline_required": False,
            "execution_mode": "plan_only"
        }
        plan = build_plan(request, CATALOG)
        self.assertEqual(plan["strategy"], "logic_extraction")
        self.assertEqual(plan["status"], "needs_user_review")

    def test_plan_is_deterministic(self):
        request = json.loads((ROOT / "examples" / "protection-request.example.json").read_text(encoding="utf-8"))
        self.assertEqual(build_plan(request, CATALOG), build_plan(request, CATALOG))


class TargetMatchingTests(unittest.TestCase):
    """Regression tests for the explicit target-precedence rule in _target_matches."""

    def setUp(self):
        from pea.planner import _target_matches
        self.matches = _target_matches

    def test_all_covers_every_target(self):
        self.assertTrue(self.matches({"all"}, {"rust", "zig"}))
        self.assertTrue(self.matches({"all"}, set()))

    def test_declared_target_matches_request(self):
        self.assertTrue(self.matches({"java", "kotlin"}, {"kotlin"}))

    def test_unknown_target_never_matches_concrete_request(self):
        # An entry that does not know its own platform support is not a match,
        # even when the requested target happens to be named too.
        self.assertFalse(self.matches({"unknown", "javascript"}, {"javascript"}))

    def test_empty_request_matches_nothing(self):
        self.assertFalse(self.matches({"javascript"}, set()))

    def test_unrelated_target_does_not_match(self):
        self.assertFalse(self.matches({"javascript"}, {"rust"}))


if __name__ == "__main__":
    unittest.main()
