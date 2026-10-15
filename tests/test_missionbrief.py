"""Mission brief tests: the third ring's hand-off artifact.

The brief is what PEA gives the user's agent before a live-fire exercise.
These tests pin the properties that make it trustworthy: the embedded plan
still obeys the attack-simulation contract, steps the testbench cannot reach
are *deferred to unknown* (never dropped, never passed), and the
evidence-return contract is explicit.
"""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from pea.attacksim import (
    MISSION_RED_LINES,
    ArtifactRef,
    _defer_reason,
    design_mission_brief,
)
from pea.mcpserver import ToolContext, call_tool

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"


def _validator(name: str) -> Draft202012Validator:
    resources = [
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in (
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        )
        if "$id" in schema
    ]
    return Draft202012Validator(
        json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8")),
        registry=Registry().with_resources(resources),
    )


BASELINE = ArtifactRef(path="build/baseline/app-release.apk", sha256="a" * 64)
PROTECTED = ArtifactRef(path="build/protected/app-release-obfuscated.apk", sha256="b" * 64)
ANCHORS = ("libapp.so 存在 _kDartVmSnapshotInstructions 锚点",)


def _brief(**overrides):
    kwargs = dict(
        baseline=BASELINE,
        protected=PROTECTED,
        languages=["dart"],
        platforms=["android"],
        goals=["licensing_hardening"],
        has_authorization_logic=True,
        objective_anchors=ANCHORS,
        environment={"reachable_tier": "T2", "tier_basis": ["T2 root 模拟器可达"]},
    )
    kwargs.update(overrides)
    return design_mission_brief(**kwargs)


# ---------------------------------------------------------------------------
# Contract conformance
# ---------------------------------------------------------------------------


def test_brief_conforms_to_mission_brief_schema():
    errors = list(_validator("mission-brief.schema.json").iter_errors(_brief()))
    assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)


def test_embedded_simulation_conforms_to_attack_simulation_schema():
    brief = _brief()
    errors = list(_validator("attack-simulation.schema.json").iter_errors(brief["simulation"]))
    assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)


def test_brief_id_matches_simulation_id():
    brief = _brief()
    assert brief["simulation_id"] == brief["simulation"]["simulation_id"]
    assert brief["brief_id"].startswith("mb-")


def test_brief_id_is_deterministic():
    assert _brief()["brief_id"] == _brief()["brief_id"]


# ---------------------------------------------------------------------------
# Environment tiering: deferred, never dropped, never passed
# ---------------------------------------------------------------------------


def test_steps_above_reachable_tier_are_deferred_to_unknown():
    brief = _brief(environment={"reachable_tier": "T1", "tier_basis": ["T1 桌面"]})
    deferred = {d["step_id"]: d for d in brief["environment"]["deferred_steps"]}
    hook_steps = [s for s in brief["simulation"]["capability_steps"] if s["environment_tier"] == "T2"]
    assert hook_steps, "the dart family must carry a T2 runtime-hook step"
    for step in hook_steps:
        assert step["step_id"] in deferred, f"{step['step_id']} must be deferred, not silently dropped"
        assert deferred[step["step_id"]]["required_tier"] == "T2"
    # every deferred step is also a declared unknown: silence is not evidence
    assert any("步骤 A3" in u and "unknown" in u for u in brief["unknowns"])
    # the step itself stays in the plan (deferred != deleted)
    assert len(brief["simulation"]["capability_steps"]) >= len(hook_steps)


def test_reachable_environment_defers_nothing():
    brief = _brief(environment={"reachable_tier": "T2", "tier_basis": ["T2 root 模拟器可达"]})
    assert brief["environment"]["deferred_steps"] == []


def test_missing_environment_is_named_unknown_not_refusal():
    brief = _brief(environment=None)
    assert brief["environment"]["reachable_tier"] == "unknown"
    assert any("未侦察测试台" in b for b in brief["environment"]["tier_basis"])
    # every non-static step is deferred: unknown is the honest answer
    non_static = [s for s in brief["simulation"]["capability_steps"] if s["environment_tier"] != "T0"]
    assert non_static
    deferred_ids = {d["step_id"] for d in brief["environment"]["deferred_steps"]}
    assert {s["step_id"] for s in non_static} <= deferred_ids
    assert any("测试台未侦察" in u for u in brief["unknowns"])


def test_t4_step_is_always_deferred_as_an_architectural_answer():
    reason = _defer_reason("T4", "T3")
    assert reason is not None and "服务端迁移" in reason and "架构答案" in reason


def test_defer_reason_none_when_environment_suffices():
    assert _defer_reason("T0", "unknown") is None  # static needs no reconnaissance
    assert _defer_reason("T2", "T3") is None
    assert _defer_reason("T1", "T1") is None


# ---------------------------------------------------------------------------
# The five elements
# ---------------------------------------------------------------------------


def test_tool_families_carry_tier_and_research_date():
    brief = _brief()
    families = {f["capability_family"]: f for f in brief["tool_families"]}
    assert "dart_aot_snapshot_analysis" in families
    assert families["dart_aot_snapshot_analysis"]["exposure_tier"] == "tool_efficiency"
    assert families["dart_aot_snapshot_analysis"]["research_date"], "the capability map's research date must travel with the brief"


def test_red_lines_are_fixed_and_cover_the_contract():
    brief = _brief()
    assert brief["red_lines"] == list(MISSION_RED_LINES)
    joined = "\n".join(brief["red_lines"])
    assert "书面授权" in joined
    assert "只读" in joined
    assert "生产设备" in joined
    assert "unknown" in joined
    assert "不分发、不安装、不执行" in joined


def test_evidence_return_contract_requires_observation_and_environment():
    contract = _brief()["evidence_return"]
    assert contract["ledger_tool"] == "pea.ledger_record"
    assert contract["authority_required"] == "observation"
    assert contract["environment_required"] is True
    for field_name in ("tool_name", "tool_version", "artifact_digest", "redacted_summary", "environment"):
        assert field_name in contract["required_fields"], field_name


def test_missing_anchors_are_declared_unknown():
    brief = _brief(objective_anchors=[])
    assert brief["objective_anchors"] == []
    assert any("未提供目标锚点" in u for u in brief["unknowns"])


def test_plan_id_travels_when_given():
    assert _brief(plan_id="plan-abc")["plan_id"] == "plan-abc"


# ---------------------------------------------------------------------------
# MCP surface
# ---------------------------------------------------------------------------


def _ctx(**kwargs) -> ToolContext:
    base = {"authorized_root": None, "authorization": "owner"}
    base.update(kwargs)
    return ToolContext(**base)


def test_mcp_design_mission_brief_runs():
    result = call_tool(
        "pea.design_mission_brief",
        {
            "baseline": {"path": "build/baseline/app-release.apk", "sha256": "a" * 64},
            "protected": {"path": "build/protected/app-release.apk", "sha256": "b" * 64},
            "languages": ["dart"],
            "platforms": ["android"],
            "goals": ["licensing_hardening"],
            "has_authorization_logic": True,
            "objective_anchors": list(ANCHORS),
            "environment": {"reachable_tier": "T1", "tier_basis": ["T1 桌面"]},
        },
        _ctx(),
    )
    assert result.ok, result.detail
    assert result.data["brief_id"].startswith("mb-")
    assert result.data["environment"]["deferred_steps"], "T1 testbench must defer the T2 hook step"


def test_mcp_design_mission_brief_rejects_non_object_environment():
    result = call_tool(
        "pea.design_mission_brief",
        {
            "baseline": {"path": "b.apk", "sha256": "a" * 64},
            "languages": ["dart"],
            "platforms": ["android"],
            "environment": "T2",
        },
        _ctx(),
    )
    assert not result.ok and result.error == "environment_invalid"
