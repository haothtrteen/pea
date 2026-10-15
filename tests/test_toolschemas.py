"""Contract gates for the tools/list surface (Phase 4 WP1).

``mcp/tool-schemas.json`` is the hand-maintained source of the protocol
surface: the ``inputSchema`` every MCP client sees. These gates keep it
locked to the two generated contracts:

* the tool set equals ``tool-contract.json``'s (a schema-less tool would
  make the protocol surface lie about callability);
* each schema is a valid Draft 2020-12 schema and rejects unknown fields,
  so a client can never smuggle arguments a handler never reads;
* each schema's ``required`` equals the contract's ``input_required`` -
  the registry and the protocol surface cannot disagree about what a
  call must carry;
* ``toolschemas.mcp_tool_definitions()`` - the exact payload the stdio
  server hands to ``tools/list`` - carries zero drift against the
  effects registry (names, order, purposes).

A missing schema is a hard error, not an omission: a tool listed without
a constructable argument shape is worse than a tool not listed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from pea import tooleffects, toolschemas

ROOT = Path(__file__).resolve().parents[1]
MCP_DIR = ROOT / "mcp"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestSchemaContractAlignment:
    def test_schema_tool_set_equals_the_contract_tool_set(self) -> None:
        contract_names = {t["name"] for t in _load(MCP_DIR / "tool-contract.json")["tools"]}
        schema_names = set(_load(MCP_DIR / "tool-schemas.json")["tools"])
        assert schema_names == contract_names, (
            "tool-schemas.json and tool-contract.json declare different tool sets"
        )

    @pytest.mark.parametrize("name", sorted(tooleffects.TOOL_EFFECTS))
    def test_each_schema_is_a_valid_draft_2020_12_schema(self, name: str) -> None:
        schema = _load(MCP_DIR / "tool-schemas.json")["tools"][name]
        Draft202012Validator.check_schema(schema)

    @pytest.mark.parametrize("name", sorted(tooleffects.TOOL_EFFECTS))
    def test_schema_required_equals_contract_input_required(self, name: str) -> None:
        schema = _load(MCP_DIR / "tool-schemas.json")["tools"][name]
        contract = {t["name"]: t for t in _load(MCP_DIR / "tool-contract.json")["tools"]}
        assert set(schema.get("required", [])) == set(contract[name]["input_required"]), name

    @pytest.mark.parametrize("name", sorted(tooleffects.TOOL_EFFECTS))
    def test_schema_rejects_unknown_fields(self, name: str) -> None:
        schema = _load(MCP_DIR / "tool-schemas.json")["tools"][name]
        assert schema.get("additionalProperties") is False, (
            f"{name}: the protocol surface must reject arguments no handler reads"
        )


class TestToolListSurface:
    def test_definitions_cover_the_registry_in_order(self) -> None:
        definitions = toolschemas.mcp_tool_definitions()
        assert [d["name"] for d in definitions] == list(tooleffects.TOOL_EFFECTS)
        assert len(definitions) == len(tooleffects.TOOL_EFFECTS)

    def test_purposes_come_from_the_effects_registry(self) -> None:
        for definition in toolschemas.mcp_tool_definitions():
            assert definition["description"] == tooleffects.effects_for(definition["name"]).contract.purpose

    def test_input_schemas_come_from_the_contract_file(self) -> None:
        schemas = _load(MCP_DIR / "tool-schemas.json")["tools"]
        for definition in toolschemas.mcp_tool_definitions():
            assert definition["inputSchema"] == schemas[definition["name"]]

    def test_missing_schema_is_a_hard_error(self, tmp_path: Path) -> None:
        """A tool without a schema must fail loudly, not list unconstructably."""
        partial = tmp_path / "tool-schemas.json"
        first = next(iter(tooleffects.TOOL_EFFECTS))
        partial.write_text(
            json.dumps({"tools": {first: _load(MCP_DIR / "tool-schemas.json")["tools"][first]}}),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="no input schema for contracted tool"):
            toolschemas.mcp_tool_definitions(partial)

    def test_schema_required_helper_matches_the_file(self) -> None:
        for name in tooleffects.TOOL_EFFECTS:
            assert toolschemas.schema_required(name) == _load(MCP_DIR / "tool-schemas.json")["tools"][name].get("required", [])


class TestSchemaEnforcesCallShape:
    """The schemas must actually reject malformed calls (they are gates,
    not documentation): a missing required field and an unknown field
    both fail validation through pea.validation."""

    def test_missing_required_field_is_rejected(self) -> None:
        from pea.validation import validate

        schema = _load(MCP_DIR / "tool-schemas.json")["tools"]["pea.scan_secrets"]
        violations = validate({}, schema)
        assert violations, "an empty call against a required-field tool must violate"

    def test_unknown_field_is_rejected(self) -> None:
        from pea.validation import validate

        schema = _load(MCP_DIR / "tool-schemas.json")["tools"]["pea.scan_secrets"]
        violations = validate({"project_path": "/tmp", "authorization": "owner", "surprise": 1}, schema)
        assert any(v.keyword == "additionalProperties" and "surprise" in v.message for v in violations), (
            "additionalProperties:false must reject unknown fields"
        )


#: approval class -> the argument fields its enforcement point reads.
#: Mirrors ``mcpserver._enforce_approval``; a new approval class must be
#: added here too - an unmapped class fails the gate rather than silently
#: skipping the check.
APPROVAL_FIELDS = {
    "workspace_scope_confirmation": ("authorization",),
    "explicit_user_confirmation": ("explicit_user_approval",),
    "valid_scoped_one_time_token": ("approval_token",),
    "test_command_preview_required": ("preview_confirmed",),
    "artifact_scope_confirmation": ("preview_confirmed",),
}
#: Classes that need no caller input: offline stays legal (the handler
#: degrades to a named unknown), and none is the pure-function class.
CALLER_INPUT_FREE = {"none", "network_policy_if_online"}


class TestProtocolSurfaceExpressesApproval:
    """A contract whose approval requirement cannot be expressed through
    the tool's own input schema is a lie the protocol surface cannot
    honour: the MCP caller has no field to travel the confirmation
    through, so every call is refused before the handler runs.

    ``pea.check_testbench`` shipped in 0.5.0 with exactly this break
    (workspace_scope_confirmation over an argument-free probe tool, whose
    handler touches no project tree); WP1 corrected four tools the same
    way and this gate keeps the class of break from coming back.
    """

    @pytest.mark.parametrize("name", sorted(tooleffects.TOOL_EFFECTS))
    def test_approval_requirement_is_expressible(self, name: str) -> None:
        effect = tooleffects.effects_for(name)
        if effect.approval in CALLER_INPUT_FREE:
            return
        props = set(_load(MCP_DIR / "tool-schemas.json")["tools"][name].get("properties", {}))
        if effect.approval == "output_path_and_overwrite_confirmation":
            assert props & {"output_dir", "out"}, f"{name}: overwrite confirmation has no output field to confirm"
            return
        required = APPROVAL_FIELDS.get(effect.approval)
        assert required is not None, f"{name}: approval class {effect.approval!r} is not mapped in the gate - add it"
        missing = set(required) - props
        assert not missing, f"{name}: approval={effect.approval} cannot be expressed; schema lacks {sorted(missing)}"
