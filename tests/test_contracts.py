"""Contract conformance gates.

These tests make ``schemas/`` the single source of truth: every catalog entry,
example and tool declaration must validate against its JSON Schema. A failure
here means the data drifted from the contract, which is exactly what the
architecture spec forbids ("Schema 是唯一真源").

They deliberately do NOT change planner behaviour; they only guard the data.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
CATALOG_DIR = Path(__file__).resolve().parents[1] / "catalog"
EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"
MCP_DIR = Path(__file__).resolve().parents[1] / "mcp"


def _build_registry() -> Registry:
    """Register every schema by its $id so relative $refs resolve across files."""
    resources = [
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in (
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        )
        if "$id" in schema
    ]
    return Registry().with_resources(resources)


REGISTRY = _build_registry()


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=REGISTRY)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Catalog entries
# --------------------------------------------------------------------------

CATALOG_ENTRIES = _load(CATALOG_DIR / "catalog.seed.json")


@pytest.mark.parametrize("entry", CATALOG_ENTRIES, ids=lambda e: e.get("id", "?"))
def test_catalog_entry_conforms_to_schema(entry: dict) -> None:
    errors = list(_validator("catalog-entry.schema.json").iter_errors(entry))
    assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)


def test_catalog_seed_is_a_json_array() -> None:
    assert isinstance(CATALOG_ENTRIES, list)
    assert len(CATALOG_ENTRIES) > 0


def test_catalog_ids_are_unique() -> None:
    ids = [entry["id"] for entry in CATALOG_ENTRIES]
    assert len(ids) == len(set(ids)), f"duplicate catalog ids: {ids}"


def test_catalog_gate_actually_rejects_invalid_entries() -> None:
    """Negative test: the gate must fail, not merely pass, on a bad entry."""
    broken = dict(CATALOG_ENTRIES[0])
    broken.pop("license")  # required field
    errors = list(_validator("catalog-entry.schema.json").iter_errors(broken))
    assert errors, "schema gate did not reject an entry missing 'license'"


# --------------------------------------------------------------------------
# Examples
# --------------------------------------------------------------------------

EXAMPLE_SCHEMAS = {
    "protection-request.example.json": "protection-request.schema.json",
    "protection-request.internal-android.example.json": "protection-request.schema.json",
    "protection-request.flutter-licensing.example.json": "protection-request.schema.json",
    "protection-plan.example.json": "protection-plan.schema.json",
    "fdartvmp-research-review.example.json": "research-candidate-review.schema.json",
    "attack-simulation.flutter-licensing.example.json": "attack-simulation.schema.json",
    "field-response.example.json": "field-response.schema.json",
}


@pytest.mark.parametrize("example,schema", sorted(EXAMPLE_SCHEMAS.items()))
def test_example_conforms_to_schema(example: str, schema: str) -> None:
    errors = list(_validator(schema).iter_errors(_load(EXAMPLES_DIR / example)))
    assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)


def test_exposure_findings_example_conforms_to_schema() -> None:
    """The findings example is an envelope; each finding validates on its own."""
    envelope = _load(EXAMPLES_DIR / "exposure-findings.example.json")
    validator = _validator("exposure-finding.schema.json")
    for finding in envelope["findings"]:
        errors = list(validator.iter_errors(finding))
        assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)


# --------------------------------------------------------------------------
# Adversarial attack-simulation plans
# --------------------------------------------------------------------------

ATTACK_SIMULATIONS = sorted(EXAMPLES_DIR.glob("attack-simulation*.example.json"))


@pytest.mark.parametrize("path", ATTACK_SIMULATIONS, ids=lambda p: p.name)
def test_attack_simulation_semantic_gates(path: Path) -> None:
    """Red lines that JSON Schema cannot express, enforced here instead.

    * a differential comparison needs both an unprotected baseline and a
      protected candidate - comparing an artifact against nothing proves
      nothing;
    * every step must trace back to a capability family that actually exists
      in the capability map: attack methods are retrieved facts, never model
      improvisation;
    * attack steps may never claim protection success from tool failure;
    * an environment-tiered step that needs a tier the testbench cannot reach
      is an unknown, never a pass (the tier value itself is schema-gated;
      this gate keeps the *pairing* honest: a tier above T0 may never carry a
      claim that only static analysis could support).
    """
    plan = _load(path)
    roles = {artifact["role"] for artifact in plan["target_artifacts"]}
    if plan["success_criteria"]["comparison"] == "differential_baseline_vs_protected":
        assert roles == {"unprotected_baseline", "protected_candidate"}, roles
    families = {m["capability_family"] for m in _load(CATALOG_DIR / "rea-capability-defense-map.json")["mappings"]}
    for step in plan["capability_steps"]:
        assert step["capability_family"] in families, f"{step['step_id']}: unknown capability family"
        if step["expected_observation"] == "error_or_unavailable":
            assert step["failure_meaning"] == "unknown", (
                f"{step['step_id']}: tool failure must mean unknown, never protection success"
            )


def test_attack_simulation_schema_rejects_unknown_environment_tier() -> None:
    """Negative gate: a step may not name an environment tier outside T0-T4."""
    plan = _load(EXAMPLES_DIR / "attack-simulation.flutter-licensing.example.json")
    plan["capability_steps"][0] = dict(plan["capability_steps"][0], environment_tier="T9")
    errors = list(_validator("attack-simulation.schema.json").iter_errors(plan))
    assert errors, "schema gate accepted an environment_tier outside the T0-T4 ladder"


def test_evidence_record_schema_rejects_invalid_environment() -> None:
    """Negative gate: the environment block is declared or absent, never guessed.

    A record without ``environment`` stays valid (the field is optional); an
    environment block with an out-of-ladder tier or a missing tier is refused,
    because "unknown tier" must be spelled ``unknown`` rather than left blank.
    """
    validator = _validator("evidence-record.schema.json")
    base = {
        "evidence_id": "ev-test",
        "kind": "tool_output",
        "source": "rea@test",
        "observed_at": "2026-10-14T00:00:00+00:00",
        "authority": "observation",
        "limitations": [],
    }
    assert not list(validator.iter_errors(base)), "a record without environment must stay valid"
    bad_tier = dict(base, environment={"environment_tier": "T9"})
    assert list(validator.iter_errors(bad_tier)), "schema gate accepted an out-of-ladder environment tier"
    missing_tier = dict(base, environment={"environment_note": "no tier declared"})
    assert list(validator.iter_errors(missing_tier)), "schema gate accepted an environment block without a tier"


# --------------------------------------------------------------------------
# D7: field response (crack intake + server-side goalpost)
# --------------------------------------------------------------------------


def test_field_response_example_semantic_gates() -> None:
    """Red lines JSON Schema cannot express, enforced here instead.

    * every measure must be a server-side action - a code push into the
      cracked package is the exact failure mode the design froze out;
    * the negative tests must include the legitimate-variant case (the
      no-collateral red line);
    * an offline-only posture must be declined, not answered with an empty
      plan that reads as "nothing to do".
    """
    plan = _load(EXAMPLES_DIR / "field-response.example.json")
    server_side_kinds = {"server_side_goalpost_move", "challenge_rotation", "protocol_rotation", "attestation_tightening"}
    for measure in plan["measures"]:
        assert measure["kind"] in server_side_kinds, f"{measure['measure_id']}: not a server-side action"
        assert measure["rollout"] in {"gray", "full"}
    scenarios = {t["scenario"] for t in plan["negative_tests"]}
    assert "legitimate_variant_unaffected" in scenarios, "the no-collateral red line can never be dropped"
    if plan["posture"] == "declined_offline_only":
        assert plan["measures"] == [], "a declined plan must not carry measures"


def test_crack_intake_example_keeps_authority_levels_separate() -> None:
    """The diff is an observation; the layer attribution is an inference;
    the two must never travel under one label."""
    findings = _load(EXAMPLES_DIR / "crack-intake.example.json")["findings"]
    categories = {f["category"] for f in findings}
    assert "field_incident_diff" in categories
    for finding in findings:
        for record in finding.get("evidence", []):
            if finding["category"] == "field_incident_diff":
                assert record["authority"] == "observation", finding["id"]
            if finding["category"] == "field_incident_layer_attribution":
                assert record["authority"] == "inference", finding["id"]


# --------------------------------------------------------------------------
# REA capability -> defense map
# --------------------------------------------------------------------------

def test_capability_defense_map_has_unified_structure() -> None:
    data = _load(CATALOG_DIR / "rea-capability-defense-map.json")
    mappings = data["mappings"]
    assert isinstance(mappings, list) and mappings
    key_sets = {tuple(sorted(m.keys())) for m in mappings}
    assert len(key_sets) == 1, f"inconsistent mapping shapes: {key_sets}"


def test_capability_map_declares_exposure_tiers() -> None:
    """Every capability family must carry the exposure tier it amplifies.

    The tier is the repair-order input: the demo's remediation section and the
    attack-simulation step order are derived from it, so a family without a
    tier would silently drop out of the "highest exposure first" ordering.
    """
    from pea.tiers import TIER_ORDER

    data = _load(CATALOG_DIR / "rea-capability-defense-map.json")
    for mapping in data["mappings"]:
        tier = mapping.get("exposure_tier")
        assert tier in TIER_ORDER, f"{mapping['capability_family']}: exposure_tier {tier!r} not in {TIER_ORDER}"


# --------------------------------------------------------------------------
# MCP tool contract
# --------------------------------------------------------------------------

def test_mcp_tool_contract_declares_effects_and_approval() -> None:
    contract = _load(MCP_DIR / "tool-contract.json")
    tools = contract["tools"]
    assert tools, "mcp/tool-contract.json declares no tools"
    for tool in tools:
        name = tool.get("name", "<unnamed>")
        assert name.startswith("pea."), f"{name}: tool names must be pea.* namespaced"
        assert "purpose" in tool, f"{name}: missing purpose"
        assert "side_effects" in tool, f"{name}: missing side_effects"
        assert "approval" in tool, f"{name}: missing approval requirement"
        assert isinstance(tool["side_effects"], list), f"{name}: side_effects must be a list"


def test_mcp_tool_contract_conforms_to_schema() -> None:
    """R5: the tool contract itself is now schema-gated, not just spot-checked.

    Before this gate the contract file was the only data in the repo without a
    schema; drift (a tool without approval, a side effect outside the
    registry) could only be caught by hand-written per-field asserts.
    """
    contract = _load(MCP_DIR / "tool-contract.json")
    errors = list(_validator("tool-contract.schema.json").iter_errors(contract))
    assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)


def test_tool_contract_schema_rejects_unregistered_side_effect() -> None:
    """Negative gate: an unknown side effect must fail, not pass silently."""
    contract = _load(MCP_DIR / "tool-contract.json")
    contract["tools"][0] = dict(contract["tools"][0], side_effects=["teleports_files"])
    errors = list(_validator("tool-contract.schema.json").iter_errors(contract))
    assert errors, "schema gate accepted a side effect outside the registry"


def test_tool_contract_schema_rejects_unnamespaced_tool() -> None:
    contract = _load(MCP_DIR / "tool-contract.json")
    contract["tools"][0] = dict(contract["tools"][0], name="assess_project")
    errors = list(_validator("tool-contract.schema.json").iter_errors(contract))
    assert errors, "schema gate accepted a tool without the pea.* namespace"


def test_mcp_tool_names_are_unique() -> None:
    contract = _load(MCP_DIR / "tool-contract.json")
    names = [t["name"] for t in contract["tools"]]
    assert len(names) == len(set(names)), f"duplicate tool names: {names}"


def test_mutating_tools_must_declare_approval() -> None:
    """A tool that writes files or spawns processes cannot be approval-free.

    One narrow exemption, added by WP1: a tool whose only mutating effect is
    ``spawn_process`` and whose permissions pin the process scope to the
    fixed read-only probe set (``process:probe:<fixed_readonly_probes>``)
    is a detection-only environment probe - it runs no project code and
    touches no project data, so there is no workspace to authorize. The
    exemption reads the permission string as the boundary it declares; it
    is not a general escape hatch for spawn_process.
    """
    contract = _load(MCP_DIR / "tool-contract.json")
    effects = {t["name"]: t for t in _load(MCP_DIR / "tool-effects.json")["tools"]}
    mutating = {"temporary_workspace_write", "output_file_write", "bounded_filesystem_write", "spawn_process"}
    fixed_probe = "process:probe:<fixed_readonly_probes>"
    for tool in contract["tools"]:
        effects_set = set(tool.get("side_effects", []))
        if not effects_set & mutating:
            continue
        permissions = set(effects[tool["name"]].get("permissions", []))
        if effects_set == {"spawn_process"} and fixed_probe in permissions:
            continue
        assert tool.get("approval") not in (None, "none"), (
            f"{tool['name']}: mutating tool must require approval"
        )


# --------------------------------------------------------------------------
# M4: registry generation gates (tool-contract.json + tool-effects.json)
# --------------------------------------------------------------------------

def test_tool_contract_matches_the_registry() -> None:
    """The contract file is generated from src/pea/tooleffects.py; drift
    between the checked-in JSON and the registry fails the gate."""
    from pea import tooleffects

    contract = _load(MCP_DIR / "tool-contract.json")
    assert contract == tooleffects.contract_document(), "tool-contract.json drifted from the registry"


def test_tool_effects_matches_the_registry() -> None:
    from pea import tooleffects

    effects = _load(MCP_DIR / "tool-effects.json")
    assert effects == tooleffects.effects_document(), "tool-effects.json drifted from the registry"


def test_every_tool_effects_entry_conforms_to_schema() -> None:
    effects = _load(MCP_DIR / "tool-effects.json")
    validator = _validator("tool-effects.schema.json")
    for entry in effects["tools"]:
        errors = list(validator.iter_errors(entry))
        assert not errors, f"{entry['name']}: {'; '.join(str(e.message) for e in errors)}"


def test_contract_and_effects_cover_the_same_tools() -> None:
    from pea import tooleffects

    contract = {t["name"]: t for t in _load(MCP_DIR / "tool-contract.json")["tools"]}
    effects = {t["name"]: t for t in _load(MCP_DIR / "tool-effects.json")["tools"]}
    assert set(contract) == set(effects), "contract and effects declare different tool sets"
    for name, entry in contract.items():
        assert entry["approval"] == effects[name]["approval"], name
        coarse = {tooleffects._EFFECT_SIDE_EFFECT_MAP[e] for e in entry["side_effects"]} or {"none"}
        assert set(effects[name]["side_effects"]) == coarse, name
