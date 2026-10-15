"""MCP 工具注册表：一份实现元数据，生成工具合同与工具副作用声明。

Phase 3 的要求是"由一份 schema 生成工具能力/副作用声明"——本模块就是那份
实现元数据：

* ``TOOL_EFFECTS`` 是唯一真源。每个工具一条记录，同时携带**合同字段**
  （purpose/input_required/output_required/side_effects/approval/execution，
  进 ``mcp/tool-contract.json``）与**副作用字段**（version/capabilities/
  permissions/resource_limits/cancellation/error_codes/…，进
  ``mcp/tool-effects.json``，逐条符合 ``tool-effects.schema.json``）；
* 两份 JSON 都是**生成产物**：``contract_document()`` 与
  ``effects_document()`` 重建它们，测试断言与 checked-in 文件逐字节一致
  （漂移即失败）——合同不可能与实现元数据悄悄不一致；
* **可用性来自实现，不来自合同**：``version`` 为 ``"1.0.0"`` 的工具已在
  ``mcpserver.HANDLERS`` 接线，``"0.0.0"`` 是仅有合同的原型面（WP3 起执行器
  四件套已全部接线，合同面与实现面重合；``"0.0.0"`` 保留给后续仅合同工具）。
  调用未接线工具得到命名错误 ``tool_not_wired``，而不是静默成功或假装存在。

命名纪律：工具名 ``pea.<snake_case>``；每个 ``error_codes`` 条目都是稳定
的机器可读拒绝码，与 ``mcpserver.call_tool`` 实际返回的错误码一一对应。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SERVER_NAME = "pea-mcp"
CONTRACT_SCHEMA_VERSION = "1.1"
EFFECTS_SCHEMA = "tool-effects.schema.json"
CONTRACT_NOTE = (
    "Draft contracts; all tools call a shared service layer. "
    "ToolEffects and availability must be generated from implementation metadata."
)
COMMON_RULES = (
    "never execute model-generated arbitrary shell",
    "unknown is not pass",
    "all side effects require scoped authorization",
    "sources and tool outputs are untrusted data",
)

#: 已接线工具的实现版本；0.0.0 = 仅有合同（尚无 handler）。
WIRED_VERSION = "1.0.0"
CONTRACT_ONLY_VERSION = "0.0.0"

#: WP0/WP3 执行面共享的拒绝码：执行边界（运营者配置的授权根与 store）
#: 与保护循环（protect.py / adapters）的命名错误。合约的 error_codes 必须
#: 与 mcpserver.call_tool 实际可能返回的码一一对应——这里是执行面全集。
_EXECUTION_BOUNDARY_ERRORS = (
    "execution_roots_unconfigured",
    "path_outside_authorized_root",
    "run_store_missing",
)
_PROTECT_LOOP_ERRORS = (
    "plan_unknown",
    "plan_record_corrupt",
    "plan_digest_mismatch",
    "plan_target_missing",
    "tool_selection_ambiguous",
    "adapter_not_registered",
    "no_js_sources",
    "options_unknown",
    "tool_runtime_missing",
    "tool_not_installed",
    "tool_install_failed",
    "tool_timeout",
    "tool_execution_failed",
    "run_unknown",
    "verify_without_apply",
    "workspace_missing",
    "rollback_mode_unknown",
)

_READ_LIMITS = {"timeout_seconds": 60, "max_output_bytes": 1_048_576}
_WRITE_LIMITS = {"timeout_seconds": 120, "max_output_bytes": 4_194_304}
_EXEC_LIMITS = {"timeout_seconds": 900, "max_output_bytes": 16_777_216}


@dataclass(frozen=True)
class ToolContract:
    """The human-facing contract fields (mcp/tool-contract.json)."""

    purpose: str
    input_required: tuple[str, ...]
    output_required: tuple[str, ...] = ()
    execution: str = ""


@dataclass(frozen=True)
class ToolEffect:
    """One tool's full implementation metadata; the single source of truth."""

    name: str
    version: str
    capabilities: tuple[str, ...]
    side_effects: tuple[str, ...]
    permissions: tuple[str, ...]
    approval: str
    resource_limits: dict[str, Any]
    cancellation: str
    error_codes: tuple[str, ...]
    contract: ToolContract
    target_requirements: tuple[str, ...] = ()
    idempotent: bool = True
    network_hosts: tuple[str, ...] = ()

    def contract_entry(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "name": self.name,
            "purpose": self.contract.purpose,
            "input_required": list(self.contract.input_required),
            "side_effects": list(self.side_effects),
            "approval": self.approval,
        }
        if self.contract.output_required:
            entry["output_required"] = list(self.contract.output_required)
        if self.contract.execution:
            entry["execution"] = self.contract.execution
        return entry

    def effects_entry(self) -> dict[str, Any]:
        coarse = []
        for effect in self.side_effects:
            mapped = _EFFECT_SIDE_EFFECT_MAP.get(effect)
            if mapped is None:
                raise ValueError(f"{self.name}: side effect {effect!r} has no coarse mapping")
            if mapped not in coarse:
                coarse.append(mapped)
        if not coarse:
            coarse = ["none"]
        entry: dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "capabilities": list(self.capabilities),
            "side_effects": coarse,
            "permissions": list(self.permissions),
            "approval": self.approval,
            "resource_limits": dict(self.resource_limits),
            "cancellation": self.cancellation,
            "error_codes": list(self.error_codes),
            "idempotent": self.idempotent,
        }
        if self.target_requirements:
            entry["target_requirements"] = list(self.target_requirements)
        if self.network_hosts:
            entry["network_hosts"] = list(self.network_hosts)
        return entry


#: The two schemas speak different side-effect vocabularies by design: the
#: contract's is finer (``bounded_artifact_read`` vs ``bounded_filesystem_read``,
#: ``optional_network_read``), while ``tool-effects.schema.json`` carries the
#: coarse REA-style capability vocabulary used for MCP effect negotiation.
#: The registry stores the fine vocabulary; this documented map derives the
#: coarse one. Nothing is invented: every fine effect maps to a strictly
#: broader coarse effect.
_EFFECT_SIDE_EFFECT_MAP = {
    "bounded_filesystem_read": "bounded_filesystem_read",
    "bounded_artifact_read": "bounded_filesystem_read",
    "optional_network_read": "network_read",
    "approval_state_write": "approval_state_write",
    "temporary_workspace_write": "bounded_filesystem_write",
    "output_file_write": "bounded_filesystem_write",
    "bounded_filesystem_write": "bounded_filesystem_write",
    "spawn_process": "spawn_process",
}

_COMMON_READ_ERRORS = (
    "unknown_tool",
    "tool_not_wired",
    "authorization_not_confirmed",
    "path_outside_authorized_root",
    "handler_failed",
)


def _tool(
    *,
    name: str,
    version: str,
    purpose: str,
    input_required: tuple[str, ...],
    side_effects: tuple[str, ...],
    approval: str,
    capabilities: tuple[str, ...],
    permissions: tuple[str, ...],
    error_codes: tuple[str, ...],
    output_required: tuple[str, ...] = (),
    execution: str = "",
    target_requirements: tuple[str, ...] = (),
    idempotent: bool = True,
    network_hosts: tuple[str, ...] = (),
    resource_limits: dict[str, Any] | None = None,
    cancellation: str = "cooperative_checkpoint",
) -> ToolEffect:
    return ToolEffect(
        name=name,
        version=version,
        capabilities=capabilities,
        side_effects=side_effects,
        permissions=permissions,
        approval=approval,
        resource_limits=resource_limits or _READ_LIMITS,
        cancellation=cancellation,
        error_codes=error_codes,
        contract=ToolContract(
            purpose=purpose,
            input_required=input_required,
            output_required=output_required,
            execution=execution,
        ),
        target_requirements=target_requirements,
        idempotent=idempotent,
        network_hosts=network_hosts,
    )


# ---------------------------------------------------------------------------
# The registry. Order is stable: original contract tools first, then the M3
# domain tools, then the M5 ledger tools (wired in M5 against pea.ledger).
# ---------------------------------------------------------------------------

TOOL_EFFECTS: dict[str, ToolEffect] = {
    tool.name: tool
    for tool in (
        # -- original 13 (prose ported verbatim from the hand-written contract)
        _tool(
            name="pea.assess_project",
            version=WIRED_VERSION,
            purpose="Read-only project profile under an explicitly authorized root.",
            input_required=("project_path", "authorization"),
            side_effects=("bounded_filesystem_read",),
            approval="workspace_scope_confirmation",
            capabilities=("read_only_project_profile", "language_and_build_detection"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=_COMMON_READ_ERRORS,
            execution="never run project scripts",
            output_required=("profile", "findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.map_exposure",
            version=WIRED_VERSION,
            purpose="Map approved artifacts and project metadata to observable exposure surfaces.",
            input_required=("target_manifest", "targets"),
            side_effects=("bounded_filesystem_read",),
            approval="workspace_scope_confirmation",
            capabilities=("capability_map_with_exposure_tiers", "tier_ordering"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=_COMMON_READ_ERRORS,
            output_required=("findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.search_catalog",
            version=WIRED_VERSION,
            purpose="Search local catalog and optionally discover official sources.",
            input_required=("targets", "goals"),
            side_effects=("optional_network_read",),
            approval="network_policy_if_online",
            capabilities=("local_catalog_search", "optional_online_discovery"),
            permissions=("filesystem:read:<catalog>", "network:read:<allowlist>"),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "handler_failed",
                "network_unavailable",
                "blocked_domain",
                "all_sources_failed",
            ),
            execution="online results enter review queue only",
            output_required=("candidates", "coverage", "unknowns"),
            network_hosts=("localhost",),
        ),
        _tool(
            name="pea.inspect_candidate",
            version=WIRED_VERSION,
            purpose=(
                "Inspect official metadata, license, versions, dependencies and declared side "
                "effects without running installers."
            ),
            input_required=("candidate_id_or_url",),
            side_effects=("optional_network_read", "bounded_artifact_read"),
            approval="network_policy_if_online",
            capabilities=("candidate_metadata_review", "license_and_dependency_surface"),
            permissions=("filesystem:read:<catalog>", "network:read:<allowlist>"),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "candidate_unknown",
                "handler_failed",
                "network_unavailable",
                "blocked_domain",
            ),
            output_required=("sources", "license_status", "version", "capability_matrix", "unknowns"),
        ),
        _tool(
            name="pea.plan_protection",
            version=WIRED_VERSION,
            purpose=(
                "Generate ranked protection options and verification gates; no changes are applied. "
                "When a run store is configured the plan is persisted there, annotated with the "
                "execution target (project_path) and its content digest - the digest is what review "
                "and apply re-verify, so a changed plan never rides an old approval."
            ),
            input_required=("request", "profile", "catalog_snapshot"),
            side_effects=(),
            approval="none",
            capabilities=("plan_generation", "exclusion_and_risk_declaration", "plan_persistence"),
            permissions=(),
            error_codes=("unknown_tool", "tool_not_wired", "handler_failed"),
            output_required=(
                "plan_id",
                "plan_digest",
                "status",
                "options",
                "exclusions",
                "risks",
                "verification_gates",
                "rollback",
            ),
        ),
        _tool(
            name="pea.review_plan",
            version=WIRED_VERSION,
            purpose=(
                "Preview the exact approval scope for one plan (target, affected files, tool version, "
                "side effects) and park at awaiting_approval; issue the short-lived one-time token only "
                "when a trusted-channel approval event for the exact scope fingerprint exists. A "
                "model-supplied Boolean is intent, never approval."
            ),
            input_required=("plan_id", "explicit_user_approval"),
            side_effects=("approval_state_write",),
            approval="explicit_user_confirmation",
            capabilities=("approval_token_issuance", "plan_digest_freeze", "approval_scope_preview"),
            permissions=("approval:issue_token",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "explicit_approval_missing",
                "approval_authority_missing",
                *_EXECUTION_BOUNDARY_ERRORS,
                *_PROTECT_LOOP_ERRORS,
                "handler_failed",
            ),
            output_required=("plan_digest", "approval_token", "expires_at", "affected_files"),
            idempotent=False,
        ),
        _tool(
            name="pea.apply_plan",
            version=WIRED_VERSION,
            purpose=(
                "Execute only registered adapters with structured argv in an isolated workspace. The "
                "one-time token is consumed here (replay/expiry/scope changes are refusals at the "
                "consumption point), the target is snapshotted into the managed workspace first, and "
                "the plan digest is re-verified against the stored record."
            ),
            input_required=("plan_id", "approval_token", "expected_plan_digest"),
            side_effects=("temporary_workspace_write", "spawn_process"),
            approval="valid_scoped_one_time_token",
            capabilities=("controlled_execution", "snapshot_before_mutate"),
            permissions=("workspace:write:<isolated>", "process:spawn:<registered_adapter>"),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "approval_authority_missing",
                "token_unknown",
                "token_replayed",
                "token_expired",
                "scope_mismatch",
                *_EXECUTION_BOUNDARY_ERRORS,
                *_PROTECT_LOOP_ERRORS,
                "handler_failed",
            ),
            output_required=("run_id", "status", "artifact_manifest", "cleanup_status"),
            idempotent=False,
            resource_limits=_EXEC_LIMITS,
            cancellation="cleanup_on_cancel",
        ),
        _tool(
            name="pea.verify_output",
            version=WIRED_VERSION,
            purpose=(
                "Run reviewed tests and output checks; report pass/fail/unknown per gate. An external "
                "tool exiting 0 is at most 'the tool reported success' - never a finding that "
                "protection worked. A failed gate discards the managed output and records the recovery."
            ),
            input_required=("run_id", "test_profile"),
            side_effects=("spawn_process",),
            approval="test_command_preview_required",
            capabilities=("verification_execution", "three_state_gates"),
            permissions=("process:spawn:<previewed_command>",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "test_preview_missing",
                "test_command_invalid",
                *_EXECUTION_BOUNDARY_ERRORS,
                "run_unknown",
                "verify_without_apply",
                "handler_failed",
            ),
            output_required=("status", "gates", "metrics", "evidence", "unknowns"),
            resource_limits=_EXEC_LIMITS,
            cancellation="cleanup_on_cancel",
        ),
        _tool(
            name="pea.compare_results",
            version=WIRED_VERSION,
            purpose=(
                "Compare approved baseline and protected result without inferring security from "
                "missing evidence. The read-only analysis stack runs on both sides: observed findings "
                "are counted, unknown-shaped records listed separately, runtime overhead stays a "
                "declared unknown."
            ),
            input_required=("baseline_run_id", "candidate_run_id"),
            side_effects=("bounded_artifact_read",),
            approval="artifact_scope_confirmation",
            capabilities=("result_comparison", "missing_evidence_is_not_success"),
            permissions=("artifact:read:<approved_run_scope>",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "artifact_scope_unconfirmed",
                *_EXECUTION_BOUNDARY_ERRORS,
                "run_unknown",
                "workspace_missing",
                "handler_failed",
            ),
            output_required=("semantic_diff", "performance_diff", "exposure_diff", "coverage"),
        ),
        _tool(
            name="pea.export_report",
            version=WIRED_VERSION,
            purpose="Write a redacted Markdown/JSON report, manifests and rollback instructions.",
            input_required=("run_id", "output_dir"),
            side_effects=("output_file_write",),
            approval="output_path_and_overwrite_confirmation",
            capabilities=("report_rendering", "redacted_export"),
            permissions=("filesystem:write:<confirmed_output_dir>",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "output_overwrite_not_confirmed",
                "handler_failed",
            ),
            output_required=("report_paths", "artifact_hashes"),
            idempotent=False,
            resource_limits=_WRITE_LIMITS,
            cancellation="cleanup_on_cancel",
        ),
        _tool(
            name="pea.rollback",
            version=WIRED_VERSION,
            purpose=(
                "Delete PEA-owned temporary workspace or revert only PEA-created patch. Never touches the "
                "user's project; the recovery itself is recorded, including its own failure - a "
                "best-effort rollback reports honestly instead of faking a green light."
            ),
            input_required=("run_id", "mode"),
            side_effects=("bounded_filesystem_write",),
            approval="explicit_user_confirmation",
            capabilities=("scoped_rollback",),
            permissions=("filesystem:delete:<pea_owned_paths>",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "explicit_approval_missing",
                *_EXECUTION_BOUNDARY_ERRORS,
                "run_unknown",
                "rollback_mode_unknown",
                "handler_failed",
            ),
            output_required=("status", "reverted_paths", "cleanup_evidence"),
            idempotent=False,
            cancellation="cleanup_on_cancel",
        ),
        _tool(
            name="pea.design_attack_simulation",
            version=WIRED_VERSION,
            purpose=(
                "Derive a minimal sandboxed adversarial self-test plan from the capability map; steps "
                "come from capability families, never from free-form model improvisation. The plan "
                "is read-only over artifacts and time-budgeted."
            ),
            input_required=("baseline", "languages", "platforms"),
            side_effects=(),
            approval="none",
            capabilities=("attack_simulation_design", "tier_ordered_steps"),
            permissions=(),
            error_codes=("unknown_tool", "tool_not_wired", "handler_failed"),
            execution=(
                "emits a plan only; executing attack steps happens under pea.verify_output with "
                "previewed commands"
            ),
            output_required=("simulation", "capability_steps", "sandbox", "success_criteria", "limitations", "unknowns"),
        ),
        _tool(
            name="pea.design_mission_brief",
            version=WIRED_VERSION,
            purpose=(
                "Compose the live-fire mission brief (third ring §2): the attack simulation plus "
                "objective anchors, testbench environment tiering (steps the environment cannot reach "
                "are deferred to unknown), tool families with research dates, fixed red lines and the "
                "evidence-return contract. Emits a brief only; the user's agent drives the user's own "
                "REA installation."
            ),
            input_required=("baseline", "languages", "platforms"),
            side_effects=(),
            approval="none",
            capabilities=("mission_brief_design", "environment_tiering", "evidence_contract_handoff"),
            permissions=(),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "environment_invalid",
                "handler_failed",
            ),
            execution="emits a brief only; no attack tool is bundled, installed or executed",
            output_required=("brief", "simulation", "environment", "red_lines", "evidence_return", "unknowns"),
        ),
        _tool(
            name="pea.demo_run",
            version=WIRED_VERSION,
            purpose=(
                "End-to-end prototype walkthrough (v1.0 demo): read-only recon, capability-derived "
                "exposure mapping, plan generation, attack-simulation design and evidence ledger "
                "assembly, then a Markdown/JSON report. Composes the pure functions; performs no "
                "protection transform."
            ),
            input_required=("request", "project_path", "authorization"),
            side_effects=("bounded_filesystem_read", "output_file_write"),
            approval="output_path_and_overwrite_confirmation",
            capabilities=("end_to_end_walkthrough", "domain_composition"),
            permissions=("filesystem:read:<authorized_root>", "filesystem:write:<confirmed_output_dir>"),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "authorization_not_confirmed",
                "output_overwrite_not_confirmed",
                "handler_failed",
            ),
            execution="read-only over the project; writes only the requested report outputs",
            output_required=("recon", "plan", "attack_simulation", "ledger", "report_paths"),
            resource_limits=_WRITE_LIMITS,
        ),
        # -- M3 domain tools (seven domains; recon is served by assess_project)
        _tool(
            name="pea.scan_artifacts",
            version=WIRED_VERSION,
            purpose="Enumerate shippable artifacts under the authorized root with SHA-256 fingerprints.",
            input_required=("project_path", "authorization"),
            side_effects=("bounded_filesystem_read",),
            approval="workspace_scope_confirmation",
            capabilities=("artifact_manifest", "digest_fingerprinting"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=_COMMON_READ_ERRORS,
            output_required=("artifacts", "findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.scan_secrets",
            version=WIRED_VERSION,
            purpose="Scan static files for secret material; hits record pattern names and lines only.",
            input_required=("project_path", "authorization"),
            side_effects=("bounded_filesystem_read",),
            approval="workspace_scope_confirmation",
            capabilities=("secret_pattern_scan", "redacted_hits"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=_COMMON_READ_ERRORS,
            output_required=("hits", "findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.scan_strings_symbols",
            version=WIRED_VERSION,
            purpose="Extract strings and symbol-shaped leaks from manifest binaries; counts only, never content.",
            input_required=("project_path", "authorization"),
            side_effects=("bounded_filesystem_read",),
            approval="workspace_scope_confirmation",
            capabilities=("string_symbol_scan", "leak_pattern_counts"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=_COMMON_READ_ERRORS,
            output_required=("profiles", "findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.check_native",
            version=WIRED_VERSION,
            purpose="Structurally read ELF/PE/Mach-O containers for hardening gaps (stack/NX/PIE/RELRO/strip).",
            input_required=("project_path", "authorization"),
            side_effects=("bounded_artifact_read",),
            approval="workspace_scope_confirmation",
            capabilities=("native_structure_check", "hardening_gap_labels"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=_COMMON_READ_ERRORS,
            output_required=("profiles", "findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.check_dart_aot",
            version=WIRED_VERSION,
            purpose="Probe Dart snapshot containers for anchors and object-pool shapes; obfuscation stays unknown.",
            input_required=("project_path", "authorization"),
            side_effects=("bounded_artifact_read",),
            approval="workspace_scope_confirmation",
            capabilities=("dart_snapshot_probe", "no_recovery_rate_claims"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=_COMMON_READ_ERRORS,
            output_required=("snapshots", "findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.check_build_integration",
            version=WIRED_VERSION,
            purpose="Compare build declarations against observed artifacts; a declaration is never proof of a build.",
            input_required=("project_path", "authorization"),
            side_effects=("bounded_filesystem_read",),
            approval="workspace_scope_confirmation",
            capabilities=("build_declaration_compare", "abi_coverage_check"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=_COMMON_READ_ERRORS,
            output_required=("configs", "checks", "findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.check_testbench",
            version=WIRED_VERSION,
            purpose=(
                "Reconnoiter the local testbench environment (adb devices, AVD images, frida-server "
                "reachability, docker/redroid); detection only - installs nothing, starts nothing, and a "
                "missing environment is a named unknown, never a pass."
            ),
            input_required=(),
            side_effects=("spawn_process",),
            # WP1 correction: this was "workspace_scope_confirmation", but the
            # handler takes no project path (observe_testbench() is
            # argument-free), probes only the local machine with fixed
            # read-only commands, and the tool-schemas surface carries no
            # fields through which a caller could supply a workspace
            # authorization - so the MCP protocol surface could not express
            # the contract's own requirement and every call would have been
            # refused as authorization_not_confirmed. The honest class is
            # none: detection only, no project data touched. (The CLI path
            # never routed through approval; this is the first surface that
            # exercises the contract end to end.)
            approval="none",
            capabilities=("environment_recon", "tier_reachability"),
            permissions=("process:probe:<fixed_readonly_probes>",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "probe_failed",
                "handler_failed",
            ),
            output_required=("reachable_tier", "devices", "avds", "findings", "coverage", "unknowns"),
            resource_limits=_EXEC_LIMITS,
        ),
        _tool(
            name="pea.intake_cracked_artifact",
            version=WIRED_VERSION,
            purpose=(
                "Cracked-package intake (D7): read-only scan of the cracked build plus a manifest "
                "digest diff against the original to locate what changed. Diff facts are "
                "observations; layer attributions are inferences; added files are unknowns."
            ),
            input_required=("cracked_path", "baseline_path", "authorization"),
            side_effects=("bounded_filesystem_read",),
            approval="workspace_scope_confirmation",
            capabilities=("crack_intake", "manifest_diff"),
            permissions=("filesystem:read:<authorized_root>",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "authorization_not_confirmed",
                "path_outside_authorized_root",
                "intake_path_invalid",
                "handler_failed",
            ),
            output_required=("diffs", "findings", "coverage", "unknowns"),
        ),
        _tool(
            name="pea.design_field_response",
            version=WIRED_VERSION,
            purpose=(
                "Field response plan (D7): the server-side moving goalpost - rotate the "
                "challenge/protocol/verification rules only a client still executing the original "
                "logic can answer. Never pushes code into the cracked package; declined outright "
                "for offline-only postures; mandatory negative tests include legitimate variants."
            ),
            input_required=("intake",),
            side_effects=(),
            approval="none",
            capabilities=("field_response_design", "goalpost_rotation", "negative_test_design"),
            permissions=(),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "intake_invalid",
                "handler_failed",
            ),
            output_required=("response", "measures", "negative_tests", "red_lines", "unknowns"),
        ),
        _tool(
            name="pea.review_candidate",
            version=WIRED_VERSION,
            purpose="Gate a catalog candidate through license/maintenance/evidence/trust; block beats everything.",
            input_required=("candidate_id",),
            side_effects=("bounded_filesystem_read",),
            approval="none",
            capabilities=("candidate_gating", "documented_decisions"),
            permissions=("filesystem:read:<catalog>",),
            error_codes=("unknown_tool", "tool_not_wired", "candidate_unknown", "handler_failed"),
            output_required=("review", "decision", "claims"),
        ),
        _tool(
            name="pea.fetch_capability_intel",
            version=WIRED_VERSION,
            purpose=(
                "Retrieve capability intelligence for one family under a domain allowlist; offline is a "
                "named unknown, never an empty success."
            ),
            input_required=("keywords",),
            side_effects=("optional_network_read",),
            approval="network_policy_if_online",
            capabilities=("capability_intel_retrieval", "allowlist_enforcement"),
            permissions=("network:read:<allowlist>",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "handler_failed",
                "network_unavailable",
                "blocked_domain",
                "redirect_out_of_allowlist",
                "transport_error",
                "http_error",
                "oversized_response",
                "unknown_mime",
                "empty_result",
                "all_sources_failed",
            ),
            output_required=("candidates", "status", "reason", "unknowns"),
            network_hosts=(
                "github.com",
                "raw.githubusercontent.com",
                "kanxue.com",
                "52pojie.cn",
                "docs.flutter.dev",
                "api.flutter.dev",
                "github.io",
            ),
        ),
        # -- M5 ledger tools (wired in M5 against the pea.ledger runtime)
        _tool(
            name="pea.ledger_record",
            version=WIRED_VERSION,
            purpose="Append one evidence record to the run ledger; unknown-producing evidence stays open.",
            input_required=("run_id", "evidence"),
            side_effects=("approval_state_write",),
            approval="explicit_user_confirmation",
            capabilities=("evidence_appending",),
            permissions=("ledger:append:<run_scope>",),
            error_codes=(
                "unknown_tool",
                "run_id_invalid",
                "evidence_invalid",
                "evidence_missing_fields",
                "evidence_authority_invalid",
                "evidence_id_conflict",
                "unknown_severity_invalid",
                "unknown_authority_invalid",
                "unknown_id_conflict",
                "explicit_approval_missing",
                "handler_failed",
            ),
            output_required=("evidence_id", "ledger_digest"),
            idempotent=False,
        ),
        _tool(
            name="pea.ledger_query",
            version=WIRED_VERSION,
            purpose="Query ledger evidence and unknowns by id, status or capability family.",
            input_required=("run_id", "filters"),
            side_effects=("bounded_filesystem_read",),
            # WP1 correction: read-only ledger query. The handler reads the
            # run's ledger from the context registry/store (run scope), never
            # a project tree, and the protocol surface carries only run_id /
            # filters - no field through which a workspace authorization
            # could travel, so every MCP call would be refused before the
            # handler ran. The CLI's ledger query never routed through
            # approval either. The honest class is none.
            approval="none",
            capabilities=("ledger_query",),
            permissions=("ledger:read:<run_scope>",),
            error_codes=(
                "unknown_tool",
                "run_id_invalid",
                "run_id_unknown",
                "filters_invalid",
                "authorization_not_confirmed",
                "path_outside_authorized_root",
                "handler_failed",
            ),
            output_required=("records", "unknowns", "coverage"),
        ),
        _tool(
            name="pea.ledger_audit_unknowns",
            version=WIRED_VERSION,
            purpose="Audit residual unknowns; blocking unknowns keep the verified gate closed.",
            input_required=("run_id",),
            side_effects=("bounded_filesystem_read",),
            # WP1 correction: read-only ledger audit/gate - see pea.ledger_query
            # for why workspace_scope_confirmation was not expressible here.
            approval="none",
            capabilities=("residual_unknown_audit",),
            permissions=("ledger:read:<run_scope>",),
            error_codes=(
                "unknown_tool",
                "run_id_invalid",
                "run_id_unknown",
                "authorization_not_confirmed",
                "path_outside_authorized_root",
                "handler_failed",
            ),
            output_required=("residual_unknowns", "blocking", "coverage"),
        ),
        _tool(
            name="pea.ledger_gate",
            version=WIRED_VERSION,
            purpose="Evaluate the verified gate mechanically; any blocking unknown blocks, no discretion.",
            input_required=("run_id",),
            side_effects=("bounded_filesystem_read",),
            # WP1 correction: read-only ledger audit/gate - see pea.ledger_query
            # for why workspace_scope_confirmation was not expressible here.
            approval="none",
            capabilities=("verified_gate",),
            permissions=("ledger:read:<run_scope>",),
            error_codes=(
                "unknown_tool",
                "run_id_invalid",
                "run_id_unknown",
                "authorization_not_confirmed",
                "path_outside_authorized_root",
                "handler_failed",
            ),
            output_required=("status", "blockers"),
        ),
        _tool(
            name="pea.ledger_resolve",
            version=WIRED_VERSION,
            purpose="Resolve an open unknown against cited evidence; resolution without evidence is refused.",
            input_required=("run_id", "unknown_id", "evidence_id"),
            side_effects=("approval_state_write",),
            approval="explicit_user_confirmation",
            capabilities=("unknown_resolution", "evidence_bound_resolution"),
            permissions=("ledger:write:<run_scope>",),
            error_codes=(
                "unknown_tool",
                "run_id_invalid",
                "run_id_unknown",
                "explicit_approval_missing",
                "unknown_not_found",
                "unknown_status_invalid",
                "resolution_needs_two_sided_evidence",
                "resolution_requires_observation",
                "resolution_text_required",
                "evidence_not_found",
                "handler_failed",
            ),
            output_required=("unknown", "status"),
            idempotent=False,
        ),
        _tool(
            name="pea.ledger_export",
            version=WIRED_VERSION,
            purpose="Export the run ledger as redacted Markdown/JSON with digests.",
            input_required=("run_id", "output_dir"),
            side_effects=("output_file_write",),
            approval="output_path_and_overwrite_confirmation",
            capabilities=("ledger_export",),
            permissions=("filesystem:write:<confirmed_output_dir>",),
            error_codes=(
                "unknown_tool",
                "run_id_invalid",
                "run_id_unknown",
                "output_dir_missing",
                "output_overwrite_not_confirmed",
                "handler_failed",
            ),
            output_required=("export_paths", "ledger_digest"),
            idempotent=False,
            resource_limits=_WRITE_LIMITS,
        ),
        # -- WP2 task orchestrator tools (Phase 4 §3): durable assessment
        # tasks. The store root comes from the environment (PEA_TASK_STORE /
        # CLI --store), never from a tool argument - a caller-supplied path
        # would let a call write outside the configured store.
        _tool(
            name="pea.run_assessment",
            version=WIRED_VERSION,
            purpose=(
                "Create and run a durable assessment task: authorization gate, read-only analysis "
                "domains, plan generation, attack-simulation design, evidence ledger, verified gate "
                "and report - every step persisted so an interrupted run resumes instead of "
                "restarting. Planning only; no protection transform is executed. An unpassed "
                "authorization gate parks the task at the gate instead of scanning."
            ),
            input_required=("request", "project_path", "authorization"),
            side_effects=("bounded_filesystem_read", "bounded_filesystem_write"),
            approval="workspace_scope_confirmation",
            capabilities=("task_orchestration", "durable_resume", "failure_isolation"),
            permissions=("filesystem:read:<authorized_root>", "filesystem:write:<task_store>"),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "authorization_not_confirmed",
                "path_outside_authorized_root",
                "request_invalid",
                "task_store_missing",
                "handler_failed",
            ),
            execution=(
                "read-only over the project; writes only the task store under the "
                "environment-configured root (PEA_TASK_STORE)"
            ),
            output_required=("task_id", "status", "steps"),
            idempotent=False,
            resource_limits=_WRITE_LIMITS,
        ),
        _tool(
            name="pea.get_task",
            version=WIRED_VERSION,
            purpose=(
                "Load one assessment task's entity: lifecycle status plus the step table with "
                "per-step status, input/output digests and recovery points."
            ),
            input_required=("task_id",),
            side_effects=("bounded_filesystem_read",),
            # Read-only over the task store (PEA's own state), never over a
            # project tree - same correction class as the ledger read tools.
            approval="none",
            capabilities=("task_status_query",),
            permissions=("filesystem:read:<task_store>",),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "task_id_invalid",
                "task_id_unknown",
                "handler_failed",
            ),
            output_required=("task",),
        ),
        _tool(
            name="pea.list_tasks",
            version=WIRED_VERSION,
            purpose="List assessment tasks in the store, oldest first, with lifecycle status and step counts.",
            input_required=(),
            side_effects=("bounded_filesystem_read",),
            approval="none",
            capabilities=("task_listing",),
            permissions=("filesystem:read:<task_store>",),
            error_codes=("unknown_tool", "tool_not_wired", "handler_failed"),
            output_required=("tasks",),
        ),
        _tool(
            name="pea.resume_task",
            version=WIRED_VERSION,
            purpose=(
                "Resume a parked or failed assessment task from its recorded state: steps whose "
                "input digest is unchanged are not re-run, the rest run. The recorded request is "
                "immutable - resume re-confirms the workspace scope but never rewrites the task's "
                "evidence basis (a new authorization means a new task)."
            ),
            input_required=("task_id", "authorization"),
            side_effects=("bounded_filesystem_read", "bounded_filesystem_write"),
            approval="workspace_scope_confirmation",
            capabilities=("task_resume", "durable_resume"),
            permissions=("filesystem:read:<authorized_root>", "filesystem:write:<task_store>"),
            error_codes=(
                "unknown_tool",
                "tool_not_wired",
                "authorization_not_confirmed",
                "path_outside_authorized_root",
                "task_id_invalid",
                "task_id_unknown",
                "task_already_done",
                "task_store_missing",
                "handler_failed",
            ),
            output_required=("task_id", "status", "steps"),
            idempotent=False,
            resource_limits=_WRITE_LIMITS,
        ),
    )
}


def effects_for(name: str) -> ToolEffect:
    """Look up one tool's metadata; an unknown name is a named refusal."""
    try:
        return TOOL_EFFECTS[name]
    except KeyError:
        raise KeyError(f"unknown_tool: {name}") from None


def contract_document() -> dict[str, Any]:
    """Rebuild the full mcp/tool-contract.json payload from the registry."""
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "server": SERVER_NAME,
        "contract_note": CONTRACT_NOTE,
        "common_rules": list(COMMON_RULES),
        "tools": [tool.contract_entry() for tool in TOOL_EFFECTS.values()],
    }


def effects_document() -> dict[str, Any]:
    """Rebuild the full mcp/tool-effects.json payload from the registry.

    Each element of ``tools`` individually conforms to
    ``schemas/tool-effects.schema.json``; the wrapper records provenance.
    """
    return {
        "generated_from": "src/pea/tooleffects.py",
        "schema": EFFECTS_SCHEMA,
        "tools": [tool.effects_entry() for tool in TOOL_EFFECTS.values()],
    }


def wired_tools() -> tuple[str, ...]:
    """Tools whose implementation version says they are wired (availability
    metadata; the dispatcher cross-checks this against its handler table)."""
    return tuple(name for name, tool in TOOL_EFFECTS.items() if tool.version == WIRED_VERSION)


def contract_only_tools() -> tuple[str, ...]:
    return tuple(name for name, tool in TOOL_EFFECTS.items() if tool.version == CONTRACT_ONLY_VERSION)
