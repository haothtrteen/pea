"""Attack-simulation generator tests: mechanical derivation and red lines.

The generator's contract is enforced twice - by its own logic here, and by
``attack-simulation.schema.json`` on output (cross-checked against the
dev-only ``jsonschema`` library, matching the project's contract-gate style).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from pea.attacksim import (
    ArtifactRef,
    capability_families,
    design_attack_simulation,
    load_capability_map,
    select_capability_families,
)

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
CAPABILITY_MAP = load_capability_map()


def _validator() -> Draft202012Validator:
    resources = [
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in (
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        )
        if "$id" in schema
    ]
    registry = Registry().with_resources(resources)
    schema = json.loads((SCHEMA_DIR / "attack-simulation.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=registry)


def _flutter_kwargs() -> dict:
    return dict(
        baseline=ArtifactRef(path="build/baseline/app-release.apk", sha256="a" * 64),
        protected=ArtifactRef(path="build/protected/app-release.apk", sha256="b" * 64),
        languages=["dart", "kotlin"],
        platforms=["android", "ios"],
        goals=["licensing_hardening"],
        has_authorization_logic=True,
        plan_id="plan-test000001",
    )


class TestFlutterScenario:
    def test_generated_plan_conforms_to_schema(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        errors = list(_validator().iter_errors(sim))
        assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)

    def test_dart_family_splits_into_three_recorded_paths(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        dart_steps = [s for s in sim["capability_steps"] if s["capability_family"] == "dart_aot_snapshot_analysis"]
        assert [s["step_id"] for s in dart_steps] == ["A1", "A2", "A3"]
        assert {s["applies_to"] for s in dart_steps} == {"both", "protected_only"}

    def test_steps_are_ordered_by_exposure_tier(self) -> None:
        """Founding principle as mechanics: the cheapest-to-reach exposure
        (one-click tooling) is tested first, algorithm-level analysis last."""
        from pea.tiers import TIER_ORDER

        sim = design_attack_simulation(**_flutter_kwargs())
        tiers = [s.get("exposure_tier") for s in sim["capability_steps"]]
        ranks = [TIER_ORDER.index(t) for t in tiers if t in TIER_ORDER]
        assert ranks == sorted(ranks), f"steps not in exposure order: {tiers}"
        assert tiers[0] == "tool_efficiency"

    def test_step_ids_are_renumbered_after_ordering(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        assert [s["step_id"] for s in sim["capability_steps"]] == [f"A{i}" for i in range(1, len(sim["capability_steps"]) + 1)]

    def test_runtime_family_selected_because_of_authorization_logic(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        families = {s["capability_family"] for s in sim["capability_steps"]}
        assert "runtime_process_observation" in families

    def test_every_step_traces_to_a_recorded_observation(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        observations = {
            m["capability_family"]: m["observations"]
            for m in CAPABILITY_MAP["mappings"]
        }
        for step in sim["capability_steps"]:
            family_observations = observations[step["capability_family"]]
            quoted = step["method"].split("：", 1)[1] if "：" in step["method"] else step["method"]
            assert any(quoted in obs or obs in step["method"] for obs in family_observations), (
                f"{step['step_id']}: method does not quote a recorded observation"
            )

    def test_real_device_step_declares_device_in_sandbox(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        assert "device" in sim["sandbox"]
        assert "禁止使用生产设备" in sim["sandbox"]["device"]

    def test_budget_is_fully_allocated_and_positive(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs(), time_budget_minutes=90)
        minutes = [s["time_budget_minutes"] for s in sim["capability_steps"]]
        assert all(m >= 1 for m in minutes)
        assert sum(minutes) == 90
        assert sim["sandbox"]["time_budget_minutes"] == 90


class TestRedLines:
    def test_interpretation_rule_is_never_absolute(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        assert sim["success_criteria"]["interpretation_rule"] in {"cost_delta_only", "tool_failure_is_not_success"}

    def test_tool_failure_step_must_mean_unknown(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        for step in sim["capability_steps"]:
            if step["expected_observation"] == "error_or_unavailable":
                assert step["failure_meaning"] == "unknown"

    def test_differential_comparison_requires_both_roles(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs())
        assert sim["success_criteria"]["comparison"] == "differential_baseline_vs_protected"
        roles = {a["role"] for a in sim["target_artifacts"]}
        assert roles == {"unprotected_baseline", "protected_candidate"}

    def test_absolute_mode_without_protected_candidate(self) -> None:
        sim = design_attack_simulation(
            baseline=ArtifactRef(path="build/app-release.apk"),
            protected=None,
            languages=["dart"],
            platforms=["android"],
            goals=["licensing_hardening"],
            has_authorization_logic=True,
        )
        assert sim["success_criteria"]["comparison"] == "absolute_only"
        assert sim["success_criteria"]["interpretation_rule"] == "tool_failure_is_not_success"
        assert any("无 baseline" in lim or "缺少 unprotected baseline" in lim for lim in sim["limitations"])

    def test_no_families_no_plan_refuses_to_emit(self) -> None:
        with pytest.raises(ValueError, match="no capability family"):
            design_attack_simulation(
                baseline=ArtifactRef(path="x"),
                protected=None,
                languages=[],
                platforms=[],
                goals=[],
            )

    def test_budget_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="time_budget_minutes"):
            design_attack_simulation(**_flutter_kwargs(), time_budget_minutes=0)


class TestSelectionRules:
    def test_selected_families_exist_in_capability_map(self) -> None:
        families = select_capability_families(["dart", "c"], ["android", "web"], ["licensing_hardening"], has_authorization_logic=True)
        known = capability_families(CAPABILITY_MAP)
        assert families
        assert set(families) <= known

    def test_selection_is_deterministic_and_ordered(self) -> None:
        first = select_capability_families(["dart"], ["android"], [], has_authorization_logic=False)
        second = select_capability_families(["dart"], ["android"], [], has_authorization_logic=False)
        assert first == second
        assert first[0] == "dart_aot_snapshot_analysis"  # language signal precedes platform

    def test_runtime_family_only_when_relevant(self) -> None:
        without = select_capability_families(["kotlin"], ["android"], [], has_authorization_logic=False)
        with_goal = select_capability_families(["kotlin"], ["android"], ["licensing_hardening"], has_authorization_logic=False)
        with_signal = select_capability_families(["kotlin"], ["android"], [], has_authorization_logic=True)
        assert "runtime_process_observation" not in without
        assert "runtime_process_observation" in with_goal
        assert "runtime_process_observation" in with_signal

    def test_simulation_id_is_deterministic(self) -> None:
        first = design_attack_simulation(**_flutter_kwargs())
        second = design_attack_simulation(**_flutter_kwargs())
        assert first["simulation_id"] == second["simulation_id"]
        assert first["simulation_id"].startswith("atk-")

    def test_simulation_id_can_be_overridden(self) -> None:
        sim = design_attack_simulation(**_flutter_kwargs(), simulation_id="atk-fixed-0001")
        assert sim["simulation_id"] == "atk-fixed-0001"

    def test_generic_family_gets_one_minimal_step(self) -> None:
        sim = design_attack_simulation(
            baseline=ArtifactRef(path="b"),
            protected=None,
            languages=["rust"],
            platforms=[],
            goals=[],
        )
        steps = sim["capability_steps"]
        assert len(steps) == 1
        assert steps[0]["capability_family"] == "native_binary_inspection"
        assert steps[0]["time_budget_minutes"] == 180

    def test_differential_mode_adds_comparison_family(self) -> None:
        sim = design_attack_simulation(
            baseline=ArtifactRef(path="b"),
            protected=ArtifactRef(path="p"),
            languages=["rust"],
            platforms=[],
            goals=[],
        )
        families = [s["capability_family"] for s in sim["capability_steps"]]
        assert families == ["native_binary_inspection", "artifact_and_function_comparison"]
