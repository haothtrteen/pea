"""MCP 组合层：把已落地的纯函数服务编排成契约里的工具面。

这是 CLI 与 MCP 共用的 service layer（Phase 3 第一句话的落地）：

* **处理器表** ``HANDLERS`` 是实现元数据——合同里有什么工具由
  ``tooleffects.TOOL_EFFECTS`` 说，哪些工具**真的能调用**由本模块说。
  调用未接线工具返回命名错误 ``tool_not_wired``（WP3 起执行器四件套已
  全部接线，合同面与实现面重合；该分支作为守卫生效），合同面与实现面
  的差距是显式的，不是假装都能用；
* **审批在执行前强制**：``call_tool`` 按合同的 ``approval`` 字段逐类检查
  （授权确认 / 显式确认 / 输出覆盖确认 / 一次性令牌），不满足即命名拒绝，
  处理器根本不会运行；
* **任何失败都是命名错误**：``ToolResult.error`` 是稳定机器码，详情在
  ``detail``。没有"静默成功"——工具抛异常也是 ``handler_failed`` 带异常
  类型，不是 OK。

离线纪律原样保留：``fetch_capability_intel`` 未注入 transport 时走
capintel 的离线默认（``network_unavailable``/``not_attempted`` 命名
unknown），未检索不是空结果。
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea import (
    adapters,
    approval,
    artifactscan,
    attacksim,
    buildint,
    candidatereview,
    capintel,
    dartaotcheck,
    demo,
    fieldresponse,
    ledger,
    nativecheck,
    planner,
    protect,
    recon,
    secretscan,
    symbolscan,
    taskrun,
    testbench,
    tiers,
    tooleffects,
)
from pea.approval import ApprovalAuthority, ApprovalError, ApprovalScope, args_digest
from pea.candidatereview import DEFAULT_CATALOG_PATH
from pea.capintel import IntelQuery, IntelResponse

AUTHORIZED_VALUES = {"owner", "written_authorization"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ToolRefusal(Exception):
    """A handler's named refusal: the error code is stable and machine-readable."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ToolContext:
    """Everything a tool call needs from its environment; all injectable."""

    authorized_root: Path | None = None
    authorization: str = "not_confirmed"
    approvals: ApprovalAuthority | None = None
    transport: Callable[[str], IntelResponse] | None = None
    catalog_path: Path | None = None
    now: str | None = None
    output_write_confirmed: bool = False
    explicit_approval: bool = False
    #: Per-run evidence ledgers. The registry is the runtime home between
    #: calls; ``ledger_store`` (when set) persists each ledger as JSON so a
    #: later process can continue the same run.
    ledgers: dict[str, ledger.EvidenceLedger] = field(default_factory=dict)
    ledger_store: Path | None = None
    #: Root of the assessment-task store (``.pea/tasks`` by convention).
    #: Environment-configured (``PEA_TASK_STORE``), never a tool argument:
    #: a caller-supplied path would let a call write outside the store the
    #: operator configured. ``None`` means no store - assessment tools
    #: refuse with ``task_store_missing`` instead of inventing a location.
    task_store: Path | None = None
    #: WP0 execution boundary: operator-configured roots (``PEA_AUTHORIZED_ROOTS``
    #: on the MCP face; the CLI passes the user's own target directly - the
    #: CLI *is* the trusted channel). Empty means the execution face is
    #: closed: the four executors refuse with ``execution_roots_unconfigured``
    #: instead of falling back to a caller-supplied path. Read-only analysis
    #: tools keep the parameter-as-root behavior for backward compatibility.
    execution_roots: tuple[Path, ...] = ()
    #: Root of the protection-loop store (plans, runs, approval events;
    #: ``PEA_RUN_STORE`` by convention). Environment-configured like the task
    #: store - never a tool argument.
    run_store: Path | None = None


@dataclass(frozen=True)
class ToolResult:
    """A named outcome: ok with data, or refused/failed with a stable code."""

    ok: bool
    tool: str
    data: Any = None
    error: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"ok": self.ok, "tool": self.tool}
        if self.ok:
            payload["data"] = self.data
        else:
            payload["error"] = self.error
            payload["detail"] = self.detail
        return payload


# ---------------------------------------------------------------------------
# Handlers: each wraps one landed pure-function service. They receive the
# validated arguments and the context; approval enforcement happened before
# they run, so a handler never re-cheaks policy.
# ---------------------------------------------------------------------------


def _require_root(ctx: ToolContext) -> Path:
    if ctx.authorized_root is None:
        raise ToolRefusal("authorization_not_confirmed", "authorized_root missing from context")
    return ctx.authorized_root


def _require_run_store(ctx: ToolContext) -> Path:
    """The execution loop's store root (plans, runs, approval events).

    Same discipline as the task store: environment-configured, never a tool
    argument. Without it the executors refuse - run state never lands in an
    unconfigured location.
    """
    if ctx.run_store is None:
        raise ToolRefusal(
            "run_store_missing",
            "context carries no run store; set PEA_RUN_STORE (MCP) or pass --store (CLI) before using the executors",
        )
    return ctx.run_store


def _plan_store(ctx: ToolContext) -> protect.PlanStore:
    return protect.PlanStore(_require_run_store(ctx) / "plans")


def _run_store(ctx: ToolContext) -> protect.RunStore:
    return protect.RunStore(_require_run_store(ctx) / "runs")


def _require_execution_face(ctx: ToolContext) -> None:
    """The execution face must be open before any executor runs.

    With no operator-configured roots the face is closed - the refusal is
    the same regardless of the arguments, because nothing about the call
    can establish the boundary the operator did not configure.
    """
    if not ctx.execution_roots:
        raise ToolRefusal(
            "execution_roots_unconfigured",
            "执行面未配置授权根（PEA_AUTHORIZED_ROOTS / CLI --root）；执行器整体关闭，不静默回退到调用方路径",
        )


def _require_execution_root(ctx: ToolContext, target: str | Path) -> Path:
    """The WP0 execution boundary: an executor's target must sit inside an
    operator-configured root.

    No roots configured is a named refusal (``execution_roots_unconfigured``)
    - the execution face stays closed rather than silently falling back to a
    caller-supplied path. A target outside every configured root is
    ``path_outside_authorized_root``. Read-only analysis tools do not come
    through here; their parameter-as-root behavior is unchanged.
    """
    _require_execution_face(ctx)
    candidate = Path(str(target)).expanduser().resolve()
    for raw in ctx.execution_roots:
        root = Path(raw).expanduser().resolve()
        if candidate == root or root in candidate.parents:
            return candidate
    configured = ", ".join(str(Path(raw).expanduser().resolve()) for raw in ctx.execution_roots)
    raise ToolRefusal(
        "path_outside_authorized_root",
        f"目标 {candidate} 不在运营者配置的授权根内（{configured}）",
    )


def _scan(args: dict[str, Any], ctx: ToolContext) -> artifactscan.ArtifactScanResult:
    return artifactscan.observe_artifacts(_require_root(ctx), now=ctx.now)


def _h_assess_project(args: dict[str, Any], ctx: ToolContext) -> Any:
    return recon.observe(_require_root(ctx), now=ctx.now).to_dict()


def _h_map_exposure(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Capability map annotated with exposure tiers (T1 tool amplification
    first). Read-only over the bundled map; project-specific findings come
    from the domain tools."""
    capability_map = attacksim.load_capability_map()
    families = sorted(attacksim.capability_families(capability_map))
    return {
        "capability_map": capability_map,
        "tier_order": list(tiers.TIER_ORDER),
        "families": [
            {"family": family, "exposure_tier": attacksim.family_tier(family, capability_map)} for family in families
        ],
    }


def _h_search_catalog(args: dict[str, Any], ctx: ToolContext) -> Any:
    catalog = planner.load_catalog(ctx.catalog_path) if ctx.catalog_path else planner.load_catalog()
    results = planner.search_catalog(
        list(args.get("targets", [])),
        list(args.get("goals", [])),
        catalog,
        include_research=bool(args.get("include_research", False)),
    )
    return {"candidates": results, "coverage": {"state": "complete_for_scope"}, "unknowns": []}


def _catalog_entry(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    catalog = candidatereview.load_catalog(ctx.catalog_path or DEFAULT_CATALOG_PATH)
    wanted = args.get("candidate_id") or args.get("candidate_id_or_url")
    for entry in catalog:
        if entry.get("id") == wanted:
            return entry
    raise ToolRefusal("candidate_unknown", f"no catalog entry with id {wanted!r}")


def _h_inspect_candidate(args: dict[str, Any], ctx: ToolContext) -> Any:
    entry = _catalog_entry(args, ctx)
    review = candidatereview.review_entry(entry)
    return {"entry": entry, "review": review.to_dict()}


def _h_review_candidate(args: dict[str, Any], ctx: ToolContext) -> Any:
    entry = _catalog_entry(args, ctx)
    review = candidatereview.review_entry(entry)
    return {"review": review.to_dict(), "decision": review.decision}


def _h_fetch_capability_intel(args: dict[str, Any], ctx: ToolContext) -> Any:
    query = IntelQuery(
        family=str(args.get("family", "")),
        keywords=tuple(args.get("keywords", ())),
        domains=tuple(args.get("domains", ())),
    )
    result = capintel.fetch_capability_intel(query, transport=ctx.transport, now=ctx.now)
    return result.to_dict()


def _h_plan_protection(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Generate a plan and (when a run store is configured) persist it.

    The plan is annotated with the execution target (``project_path``) and
    its content digest before it is stored, so the review/apply pair can
    recompute the digest from the stored record and detect any change. The
    target is part of the digest: re-scoping a plan is a new plan, and an
    approval issued for one target never covers another.
    """
    catalog = planner.load_catalog(ctx.catalog_path) if ctx.catalog_path else planner.load_catalog()
    plan = planner.build_plan(dict(args.get("request", {})), catalog)
    target = args.get("project_path")
    if target:
        plan["project_path"] = str(Path(str(target)).expanduser())
    plan["plan_digest"] = protect.plan_digest(plan)
    if ctx.run_store is not None:
        _plan_store(ctx).save(plan)
    return plan


def _review_scope(ctx: ToolContext, args: dict[str, Any]) -> tuple[dict[str, Any], str, Path, Any]:
    """Load the stored plan and derive the approval scope review needs.

    Returns ``(plan, plan_digest, project_path, preview)``. The plan digest
    is recomputed from the stored record - never taken from the caller - so
    a tampered or drifted plan is caught here, before any approval scope is
    derived from it.
    """
    store = _plan_store(ctx)
    plan_id = str(args.get("plan_id", ""))
    try:
        plan = store.load(plan_id)
    except protect.ProtectError as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None
    digest = protect.plan_digest(plan)
    if plan.get("plan_digest") and plan["plan_digest"] != digest:
        raise ToolRefusal(
            "plan_record_corrupt",
            f"计划 {plan_id!r} 记录的 digest 与重算值不一致——存储记录被改过",
        )
    stated = args.get("expected_plan_digest")
    if stated and str(stated) != digest:
        raise ToolRefusal(
            "plan_digest_mismatch",
            f"调用方声明的计划 digest {stated!r} 与存储记录重算值 {digest!r} 不一致",
        )
    project_raw = plan.get("project_path")
    if not project_raw:
        raise ToolRefusal(
            "plan_target_missing",
            "计划没有记录 project_path（plan_protection 的 project_path 参数）；执行面拒绝无目标计划",
        )
    project = _require_execution_root(ctx, str(project_raw))
    plan = dict(plan, project_path=str(project))
    try:
        tool_id = protect.select_tool(plan)
        adapter = adapters.adapter_for(tool_id)
        preview = adapter.preview(plan, project)
    except (protect.ProtectError, adapters.AdapterError) as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None
    return plan, digest, project, preview


def _h_review_plan(args: dict[str, Any], ctx: ToolContext) -> Any:
    """The approval gate: preview the exact scope, then require a trusted
    approval event before any token exists.

    Two-step by design (WP0 §2.2): this handler only ever *previews*. If an
    unconsumed approval event for the exact scope fingerprint exists - one
    produced by a trusted channel (``pea approve`` / ``pea protect``
    interactive confirmation) - the one-time token is issued and the event
    is consumed (one approval, one token). Otherwise the run parks at
    ``awaiting_approval`` with the fingerprint and the full preview written
    to the store for the operator's channel to display. A model-supplied
    Boolean is intent, never approval.
    """
    if ctx.approvals is None:
        raise ToolRefusal("approval_authority_missing", "context carries no ApprovalAuthority")
    _require_run_store(ctx)
    _require_execution_face(ctx)
    _plan, digest, project, preview = _review_scope(ctx, args)
    tool = tooleffects.effects_for("pea.apply_plan")
    covered_args = {
        "plan_id": args.get("plan_id"),
        "expected_plan_digest": digest,
        "authorized_root": str(project),
    }
    fingerprint = approval.scope_fingerprint(
        tool="pea.apply_plan",
        plan_digest=digest,
        artifact_digest=str(args.get("artifact_digest", "")),
        args_digest=approval.args_digest(covered_args),
        tool_version=tool.version,
        authorized_root=project,
        target_path=project,
    )
    preview_payload = {
        "status": "awaiting_approval",
        "fingerprint": fingerprint,
        "plan_id": args.get("plan_id"),
        "plan_digest": digest,
        "tool": {"id": preview.tool_id, "version": preview.tool_version},
        "target_path": str(project),
        "affected_files": list(preview.affected_files),
        "output_destination": preview.output_destination,
        "expected_side_effects": list(preview.expected_side_effects),
        "options": dict(preview.options),
        "approve_hint": f"pea approve --fingerprint {fingerprint}",
    }
    event = ctx.approvals.approval_for(fingerprint)
    if event is None:
        # Park at the gate. The pending preview is what the trusted channel
        # shows the operator; nothing was applied and no token exists yet.
        pending_dir = _require_run_store(ctx) / "approvals"
        pending_dir.mkdir(parents=True, exist_ok=True)
        pending_path = pending_dir / f"pending-{fingerprint}.json"
        pending_path.write_text(
            json.dumps({**preview_payload, "decided_by": "operator"}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return preview_payload
    try:
        token = ctx.approvals.issue(
            tool="pea.apply_plan",
            plan_digest=digest,
            artifact_digest=str(args.get("artifact_digest", "")),
            args_digest=approval.args_digest(covered_args),
            tool_version=tool.version,
            authorized_root=project,
            target_path=project,
            approval_event=event,
        )
    except approval.ApprovalError as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None
    return {
        "status": "approved",
        "plan_digest": digest,
        "approval_token": token.token_id,
        "expires_at": token.scope.expires_at.isoformat(),
        "scope": token.scope.to_dict(),
        "affected_files": list(preview.affected_files),
        "tool": {"id": preview.tool_id, "version": preview.tool_version},
    }


def _h_apply_plan(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Snapshot the target into the managed workspace, then apply the
    reviewed adapter. The token was consumed by dispatch (replay/expiry/
    scope all refused at the consumption point); the plan digest is
    re-verified here against the stored record, and the target must sit
    inside an operator-configured root (WP0).
    """
    _require_run_store(ctx)
    _require_execution_face(ctx)
    plan_id = str(args.get("plan_id", ""))
    try:
        plan = _plan_store(ctx).load(plan_id)
    except protect.ProtectError as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None
    digest = protect.plan_digest(plan)
    if plan.get("plan_digest") and plan["plan_digest"] != digest:
        raise ToolRefusal("plan_record_corrupt", f"计划 {plan_id!r} 记录的 digest 与重算值不一致")
    stated = str(args.get("expected_plan_digest", ""))
    if stated != digest:
        raise ToolRefusal(
            "plan_digest_mismatch",
            f"expected_plan_digest={stated!r} 与存储计划重算值 {digest!r} 不一致——计划变化即拒绝",
        )
    project = _require_execution_root(ctx, str(plan.get("project_path", "")))
    plan = dict(plan, project_path=str(project))
    try:
        run = protect.start_run(
            plan,
            project,
            store=_run_store(ctx),
            now=ctx.now or _utc_now(),
            approval_fingerprint=str(args.get("approval_token", "")),
        )
        outcome = protect.apply_run(run.run_id, store=_run_store(ctx), now=ctx.now or _utc_now())
    except protect.ProtectError as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None
    outcome["plan_digest"] = digest
    return outcome


def _h_verify_output(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Independent verification of a protected workspace.

    The gates are three-state; an external tool exiting 0 is at most "the
    tool reported success", never a finding that protection worked. A failed
    gate discards the managed output and records the recovery - the failed
    run is never left half-applied.
    """
    _require_run_store(ctx)
    _require_execution_face(ctx)
    run_id = str(args.get("run_id", ""))
    try:
        run = _run_store(ctx).load_run(run_id)
    except protect.ProtectError as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None
    _require_execution_root(ctx, run.project_path)
    command = args.get("test_command")
    if command is not None:
        if not isinstance(command, list) or not command or not all(isinstance(c, str) and c for c in command):
            raise ToolRefusal("test_command_invalid", "test_command 必须是非空字符串数组（结构化 argv，不经 shell）")
        command = [str(c) for c in command]
    try:
        outcome = protect.verify_run(run_id, store=_run_store(ctx), test_command=command)
    except protect.ProtectError as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None
    outcome["test_profile"] = str(args.get("test_profile", ""))
    return outcome


def _h_compare_results(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Before/after diff measured with the read-only analysis stack.

    The same domains the assessment uses run on both sides; observed
    findings are counted, unknown-shaped records are listed separately, and
    runtime overhead stays a declared unknown. A count that does not move
    is an honest measurement, not a failure and not a success claim.
    """
    _require_run_store(ctx)
    _require_execution_face(ctx)
    store = _run_store(ctx)
    try:
        for run_id in (str(args.get("baseline_run_id", "")), str(args.get("candidate_run_id", ""))):
            _require_execution_root(ctx, store.load_run(run_id).project_path)
        return protect.compare_runs(
            str(args.get("baseline_run_id", "")),
            str(args.get("candidate_run_id", "")),
            store=store,
        )
    except protect.ProtectError as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None


def _h_rollback(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Discard or restore the managed workspace - never the user's project.

    The recovery itself is recorded, including its own failure: a
    best-effort rollback reports honestly instead of faking a green light.
    """
    _require_run_store(ctx)
    _require_execution_face(ctx)
    try:
        run = _run_store(ctx).load_run(str(args.get("run_id", "")))
        _require_execution_root(ctx, run.project_path)
        return protect.rollback_run(
            str(args.get("run_id", "")), store=_run_store(ctx), mode=str(args.get("mode", "discard"))
        )
    except protect.ProtectError as exc:
        raise ToolRefusal(exc.reason, exc.detail) from None


def _h_design_attack_simulation(args: dict[str, Any], ctx: ToolContext) -> Any:
    baseline = attacksim.ArtifactRef(
        path=str(args.get("baseline", {}).get("path", "")),
        sha256=args.get("baseline", {}).get("sha256"),
    )
    protected_raw = args.get("protected")
    protected = (
        attacksim.ArtifactRef(
            path=str(protected_raw.get("path", "")),
            sha256=protected_raw.get("sha256"),
        )
        if protected_raw
        else None
    )
    return attacksim.design_attack_simulation(
        baseline=baseline,
        protected=protected,
        languages=[str(x) for x in args.get("languages", [])],
        platforms=[str(x) for x in args.get("platforms", [])],
        goals=[str(x) for x in args.get("goals", [])],
        has_authorization_logic=bool(args.get("has_authorization_logic", False)),
        recon_unknowns=[str(x) for x in args.get("recon_unknowns", [])],
        time_budget_minutes=int(args.get("time_budget_minutes", 180)),
        plan_id=args.get("plan_id"),
    )


def _h_design_mission_brief(args: dict[str, Any], ctx: ToolContext) -> Any:
    """The mission brief: the attack plan plus environment tiering, anchors,
    tool families, red lines and the evidence-return contract.

    ``environment`` accepts the output of ``pea.check_testbench`` verbatim;
    when it is absent the brief still emits - with ``reachable_tier=unknown``
    and every non-static step deferred - because a missing environment is a
    named unknown, not a reason to refuse the hand-off.
    """
    baseline = attacksim.ArtifactRef(
        path=str(args.get("baseline", {}).get("path", "")),
        sha256=args.get("baseline", {}).get("sha256"),
    )
    protected_raw = args.get("protected")
    protected = (
        attacksim.ArtifactRef(
            path=str(protected_raw.get("path", "")),
            sha256=protected_raw.get("sha256"),
        )
        if protected_raw
        else None
    )
    environment = args.get("environment")
    if environment is not None and not isinstance(environment, dict):
        raise ToolRefusal("environment_invalid", "environment 必须是 pea.check_testbench 的输出对象")
    return attacksim.design_mission_brief(
        baseline=baseline,
        protected=protected,
        languages=[str(x) for x in args.get("languages", [])],
        platforms=[str(x) for x in args.get("platforms", [])],
        goals=[str(x) for x in args.get("goals", [])],
        has_authorization_logic=bool(args.get("has_authorization_logic", False)),
        objective_anchors=[str(x) for x in args.get("objective_anchors", [])],
        environment=environment,
        recon_unknowns=[str(x) for x in args.get("recon_unknowns", [])],
        time_budget_minutes=int(args.get("time_budget_minutes", 180)),
        plan_id=args.get("plan_id"),
        brief_id=args.get("brief_id"),
    )


def _h_export_report(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Write the already-rendered redacted report (and bundle) to the
    confirmed output directory. Redaction happened upstream at render time;
    this tool never re-derives content, it only persists what it was given."""
    out_dir = Path(str(args.get("output_dir", "")))
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    markdown = args.get("markdown")
    if markdown:
        report_path = out_dir / "report.md"
        report_path.write_text(str(markdown), encoding="utf-8")
        paths.append(str(report_path))
    bundle = args.get("bundle")
    if bundle is not None:
        bundle_path = out_dir / "bundle.json"
        bundle_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        paths.append(str(bundle_path))
    if not paths:
        raise ToolRefusal("nothing_to_export", "pass markdown and/or bundle")
    return {"report_paths": paths}


def _h_demo_run(args: dict[str, Any], ctx: ToolContext) -> Any:
    result = demo.run_demo(
        dict(args.get("request", {})),
        _require_root(ctx),
        catalog_path=ctx.catalog_path,
        now=ctx.now,
        intel_transport=ctx.transport,
    )
    payload = {"bundle": result.bundle, "report_markdown": result.report_markdown}
    out_dir = args.get("out")
    if out_dir:
        target = Path(str(out_dir))
        target.mkdir(parents=True, exist_ok=True)
        (target / "report.md").write_text(result.report_markdown, encoding="utf-8")
        (target / "bundle.json").write_text(json.dumps(result.bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        payload["report_paths"] = [str(target / "report.md"), str(target / "bundle.json")]
    return payload


def _h_scan_artifacts(args: dict[str, Any], ctx: ToolContext) -> Any:
    return _scan(args, ctx).to_dict()


def _h_scan_secrets(args: dict[str, Any], ctx: ToolContext) -> Any:
    return secretscan.observe_secrets(_require_root(ctx), now=ctx.now).to_dict()


def _h_scan_strings_symbols(args: dict[str, Any], ctx: ToolContext) -> Any:
    return symbolscan.observe_strings_symbols(_scan(args, ctx), now=ctx.now).to_dict()


def _h_check_native(args: dict[str, Any], ctx: ToolContext) -> Any:
    return nativecheck.observe_native(_scan(args, ctx), now=ctx.now).to_dict()


def _h_check_dart_aot(args: dict[str, Any], ctx: ToolContext) -> Any:
    return dartaotcheck.observe_dart_aot(_scan(args, ctx), now=ctx.now).to_dict()


def _h_check_build_integration(args: dict[str, Any], ctx: ToolContext) -> Any:
    return buildint.verify_build_integration(_scan(args, ctx), now=ctx.now).to_dict()


def _h_check_testbench(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Reconnoiter the local testbench environment (the T0-T4 ladder).

    Unlike the project domains this handler takes no project root: the
    subject is the machine itself. The probes are fixed, read-only commands
    (``adb devices -l``, ``pidof frida-server``, ``docker images``) - the
    domain never installs or starts anything, and a probe that cannot run is
    reported as an omission plus an unknown, never as a negative result.
    """
    try:
        result = testbench.observe_testbench(now=ctx.now)
    except Exception as exc:  # a probe crash is a named failure, not a zero
        raise ToolRefusal("probe_failed", f"{type(exc).__name__}: {exc}") from None
    return result.to_dict()


def _require_inside_root(ctx: ToolContext, raw_path: str, field: str) -> Path:
    """Resolve a caller path that must live inside the authorized root.

    Both the cracked package and the baseline must be inside the same
    authorized root: a path that escapes it is a named refusal, never a
    silent scan of somewhere else.
    """
    root = _require_root(ctx)
    from pea.fswalk import WalkBoundaryError, is_inside, resolve_root

    try:
        candidate = resolve_root(raw_path)
    except WalkBoundaryError as exc:
        raise ToolRefusal("path_outside_authorized_root", f"{field}: {exc}") from None
    if not is_inside(root, candidate):
        raise ToolRefusal("path_outside_authorized_root", f"{field} escapes the authorized root: {candidate}")
    return candidate


def _h_intake_cracked_artifact(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Cracked-package intake (D7 §4.1): scan the cracked build, diff its
    manifest against the original, locate what changed.

    Both roots must sit inside the authorized root. The diff facts are
    observations; the layer attributions travel as inferences, and added
    files are unknowns - never assumed payloads.
    """
    cracked = _require_inside_root(ctx, str(args.get("cracked_path", "")), "cracked_path")
    baseline = _require_inside_root(ctx, str(args.get("baseline_path", "")), "baseline_path")
    try:
        result = fieldresponse.intake_cracked_artifact(cracked, baseline, now=ctx.now)
    except fieldresponse.FieldResponseBoundaryError as exc:
        raise ToolRefusal("intake_path_invalid", str(exc)) from None
    return result.to_dict()


def _h_design_field_response(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Field response plan (D7 §4.2): the server-side moving goalpost.

    ``offline_required=True`` declines the plan - with no server posture
    there is no goalpost to move, and an empty plan would pretend otherwise.
    The intake payload comes from ``pea.intake_cracked_artifact``.
    """
    intake = args.get("intake")
    if not isinstance(intake, dict):
        raise ToolRefusal("intake_invalid", "intake 必须是 pea.intake_cracked_artifact 的输出对象")
    return fieldresponse.design_field_response(
        intake,
        offline_required=bool(args.get("offline_required", False)),
        plan_id=args.get("plan_id"),
        response_id=args.get("response_id"),
    )


# ---------------------------------------------------------------------------
# M5 ledger tools: the evidence contract enforced through the tool surface.
#
# The runtime core lives in pea.ledger (pure, in-memory). These handlers add
# what a tool surface must add: run-scoped storage (registry plus optional
# persistence), named refusals carrying the ledger's own policy codes, and an
# export whose redaction discipline matches the rest of the system - render
# what the record itself declared redacted, never invent a summary.
# ---------------------------------------------------------------------------

#: A run id names both the in-memory ledger and (when a store is configured)
#: its persisted file, so it is validated as a filename component before use.
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _require_run_id(args: dict[str, Any]) -> str:
    run_id = str(args.get("run_id", "")).strip()
    if not _RUN_ID_PATTERN.match(run_id):
        raise ToolRefusal(
            "run_id_invalid",
            "run_id 必须是 1-64 个字符、字母数字开头、仅含 [A-Za-z0-9._-]"
            "（它同时是账本名与落盘文件名）",
        )
    return run_id


def _ledger_for(ctx: ToolContext, run_id: str, *, create: bool) -> ledger.EvidenceLedger:
    """Resolve a run's ledger: in-memory registry, then persisted store,
    then (only when create=True) a fresh one. An unknown run is a named
    refusal, never an empty ledger that reads as "nothing to see"."""
    if run_id in ctx.ledgers:
        return ctx.ledgers[run_id]
    if ctx.ledger_store is not None:
        path = ctx.ledger_store / f"{run_id}.json"
        if path.is_file():
            restored = ledger.EvidenceLedger.from_dict(json.loads(path.read_text(encoding="utf-8")))
            ctx.ledgers[run_id] = restored
            return restored
    if not create:
        raise ToolRefusal("run_id_unknown", f"run {run_id!r} 没有账本；先追加证据或记录 unknown")
    fresh = ledger.EvidenceLedger(created_at=ctx.now or "")
    ctx.ledgers[run_id] = fresh
    _persist_ledger(ctx, run_id, fresh)
    return fresh


def _persist_ledger(ctx: ToolContext, run_id: str, target: ledger.EvidenceLedger) -> None:
    if ctx.ledger_store is None:
        return
    ctx.ledger_store.mkdir(parents=True, exist_ok=True)
    (ctx.ledger_store / f"{run_id}.json").write_text(
        json.dumps(target.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _ledger_digest(target: ledger.EvidenceLedger) -> str:
    blob = json.dumps(target.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _h_ledger_record(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Append evidence (and optionally the unknown it produced).

    The evidence rules are the ledger's, not this handler's: missing fields,
    a missing or invalid authority and a duplicate id are all named refusals
    with the policy code from pea.ledger - a default authority is exactly how
    static claims quietly become observations.
    """
    run_id = _require_run_id(args)
    target = _ledger_for(ctx, run_id, create=True)
    record = args.get("evidence")
    if not isinstance(record, dict):
        raise ToolRefusal("evidence_invalid", "evidence 必须是对象")
    try:
        stored = target.add_evidence(record)
        payload: dict[str, Any] = {
            "evidence_id": stored["evidence_id"],
            "evidence_count": len(target.evidence),
            "ledger_digest": _ledger_digest(target),
        }
        question = args.get("unknown")
        if isinstance(question, dict):
            unknown = target.record_unknown(
                question=str(question.get("question", "")),
                severity=str(question.get("severity", "blocking")),
                domain=str(question.get("domain", "unspecified")),
                recommended_probes=[str(p) for p in question.get("recommended_probes", ())],
                required_authority=str(question.get("required_authority", ledger.OBSERVATION)),
                created_at=ctx.now or "",
            )
            payload["unknown_id"] = unknown.unknown_id
            payload["open_unknowns"] = len(target.list_unknowns(status="open"))
    except ledger.LedgerPolicyError as exc:
        raise ToolRefusal(exc.code, exc.detail or exc.remediation) from None
    _persist_ledger(ctx, run_id, target)
    return payload


def _h_ledger_query(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Query the run ledger; the coverage block declares what was filtered.

    "capability family" in the contract is the record/unknown ``domain``
    (the domain keys are the capability families). A filtered query reports
    totals alongside the returned slice, so "not returned" can never be
    misread as "does not exist".
    """
    run_id = _require_run_id(args)
    target = _ledger_for(ctx, run_id, create=False)
    filters = args.get("filters") or {}
    if not isinstance(filters, dict):
        raise ToolRefusal("filters_invalid", "filters 必须是对象")
    evidence = list(target.evidence)
    if "evidence_id" in filters:
        wanted = str(filters["evidence_id"])
        evidence = [e for e in evidence if e.get("evidence_id") == wanted]
    for field_name in ("kind", "authority"):
        if field_name in filters:
            evidence = [e for e in evidence if e.get(field_name) == filters[field_name]]
    unknowns = target.list_unknowns(status=filters.get("status"))
    if "domain" in filters:
        unknowns = [u for u in unknowns if u.domain == filters["domain"]]
    if "unknown_id" in filters:
        wanted_id = str(filters["unknown_id"])
        unknowns = [u for u in unknowns if u.unknown_id == wanted_id]
    return {
        "records": evidence,
        "unknowns": [u.to_dict() for u in unknowns],
        "coverage": {
            "evidence_total": len(target.evidence),
            "evidence_returned": len(evidence),
            "unknowns_total": len(target.unknowns),
            "unknowns_returned": len(unknowns),
            "filters": {str(k): filters[k] for k in sorted(filters)},
        },
    }


def _h_ledger_audit_unknowns(args: dict[str, Any], ctx: ToolContext) -> Any:
    """The residual audit: what is still open, and what it blocks.

    The coverage note is the honest boundary of this tool: the audit sees
    recorded unknowns only. A run with an empty ledger audits as "nothing
    open" - which is a statement about what was recorded, never proof that
    nothing remains unknown.
    """
    run_id = _require_run_id(args)
    target = _ledger_for(ctx, run_id, create=False)
    audit = target.audit_residual_unknowns()
    return {
        "residual_unknowns": {k: v for k, v in audit.items() if k != "blocking"},
        "blocking": audit["blocking"],
        "coverage": {
            "evidence_total": len(target.evidence),
            "unknowns_total": audit["total"],
            "open": audit["open"],
            "resolved": audit["resolved"],
            "wont_resolve": audit["wont_resolve"],
            "open_by_domain": audit["open_by_domain"],
            "open_by_severity": audit["open_by_severity"],
            "scope": "残留审计只覆盖已记录的 unknown；空账本审计为'没有未决项'是对记录范围的陈述，不是'没有问题'的证明",
        },
    }


def _h_ledger_gate(args: dict[str, Any], ctx: ToolContext) -> Any:
    """The verified gate, mechanically.

    The audit that produced the verdict travels with the result, so the
    gate is re-checkable after the fact: anyone can see exactly which
    blocking unknowns held the gate closed, without re-running anything.
    """
    run_id = _require_run_id(args)
    target = _ledger_for(ctx, run_id, create=False)
    blockers = ledger.gate_for_verified(target)
    audit = target.audit_residual_unknowns()
    return {
        "status": "verified" if not blockers else "blocked",
        "blockers": blockers,
        "audit": {
            "total": audit["total"],
            "open": audit["open"],
            "resolved": audit["resolved"],
            "wont_resolve": audit["wont_resolve"],
            "blocking_count": len(audit["blocking"]),
            "open_by_domain": audit["open_by_domain"],
            "open_by_severity": audit["open_by_severity"],
        },
        "gate_rule": "任何 blocking unknown 未消解即 blocked；verified 只表示账本内没有阻塞项，不证明覆盖完整",
    }


def _h_ledger_resolve(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Move an unknown through its lifecycle against cited evidence.

    The two-sided-evidence rule and the observation-grade requirement are
    enforced by pea.ledger, so a resolution that cites only supporting
    evidence - or only documentation-grade evidence - is refused here with
    the policy code, not accepted with a warning.
    """
    run_id = _require_run_id(args)
    target = _ledger_for(ctx, run_id, create=False)
    supporting = [str(x) for x in args.get("supporting", [])]
    contradicting = [str(x) for x in args.get("contradicting", [])]
    # The contract names the field "evidence_id"; treat it as supporting-side
    # input for compatibility. It never satisfies the contradicting side.
    single = args.get("evidence_id")
    if single:
        supporting.extend(str(x) for x in (single if isinstance(single, list) else [single]))
    try:
        updated = target.update_unknown(
            str(args.get("unknown_id", "")),
            status=str(args.get("status", "resolved")),
            resolution=args.get("resolution"),
            supporting=supporting,
            contradicting=contradicting,
        )
    except ledger.LedgerPolicyError as exc:
        raise ToolRefusal(exc.code, exc.detail or exc.remediation) from None
    _persist_ledger(ctx, run_id, target)
    return {
        "unknown": updated.to_dict(),
        "status": updated.status,
        "ledger_digest": _ledger_digest(target),
    }


def _h_ledger_export(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Export the run ledger as complete JSON plus redacted Markdown.

    Redaction discipline, same as the domains: the Markdown renders each
    record's declared ``redacted_summary``; a record without one is marked
    as such, never silently summarized. The JSON carries the complete
    records - machine audit needs the bytes, and hiding them would make the
    digest meaningless.
    """
    run_id = _require_run_id(args)
    target = _ledger_for(ctx, run_id, create=False)
    out_dir = Path(str(args.get("output_dir", "")))
    if not str(args.get("output_dir", "")):
        raise ToolRefusal("output_dir_missing", "pass output_dir")
    out_dir.mkdir(parents=True, exist_ok=True)
    digest = _ledger_digest(target)
    audit = target.audit_residual_unknowns()
    gate_blockers = ledger.gate_for_verified(target)
    payload = {
        "run_id": run_id,
        "exported_at": ctx.now or "",
        "ledger_digest": digest,
        "redaction_note": "Markdown 只渲染记录声明的 redacted_summary；未声明的记录显式标注，不代为总结。JSON 携带完整记录供机器审计。",
        "audit": audit,
        "gate": {"status": "verified" if not gate_blockers else "blocked", "blockers": gate_blockers},
        "ledger": target.to_dict(),
    }
    json_path = out_dir / "ledger.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path = out_dir / "ledger.md"
    md_path.write_text(_ledger_markdown(payload), encoding="utf-8")
    return {
        "export_paths": [str(json_path), str(md_path)],
        "ledger_digest": digest,
        "audit": audit,
        "gate": payload["gate"],
    }


def _ledger_markdown(payload: dict[str, Any]) -> str:
    """Render the exported ledger for humans: redacted summaries, declared."""
    run = payload["ledger"]
    audit = payload["audit"]
    gate = payload["gate"]
    lines = [
        f"# Evidence Ledger — run `{payload['run_id']}`",
        "",
        f"- exported_at: {payload['exported_at']}",
        f"- ledger_digest: `{payload['ledger_digest']}`",
        f"- gate: **{gate['status']}**",
        "",
        "## Residual unknowns",
        "",
        f"- total {audit['total']} / open {audit['open']} / resolved {audit['resolved']} / wont_resolve {audit['wont_resolve']}",
        f"- open by domain: {audit['open_by_domain'] or '{}'}",
        f"- open by severity: {audit['open_by_severity'] or '{}'}",
        "",
    ]
    if audit["blocking"]:
        lines += ["### Blocking (gate stays closed)", ""]
        lines += [f"- `{b['unknown_id']}` ({b['domain']}, {b['severity']}): {b['question']}" for b in audit["blocking"]]
        lines.append("")
    else:
        lines += ["No blocking unknowns recorded. 这是对记录范围的陈述，不是覆盖完整的证明。", ""]
    lines += ["## Evidence", ""]
    if run["evidence"]:
        lines += ["| evidence_id | kind | authority | redacted_summary |", "| --- | --- | --- | --- |"]
        for record in run["evidence"]:
            summary = record.get("redacted_summary") or "*(未声明 redacted_summary，原始字段见 JSON 导出)*"
            lines.append(f"| `{record.get('evidence_id', '')}` | {record.get('kind', '')} | {record.get('authority', '')} | {summary} |")
    else:
        lines += ["*(账本无证据记录)*"]
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# WP2 task orchestrator tools: durable assessment tasks (Phase 4 §3).
#
# The orchestrator (pea.taskrun) owns the workflow; these handlers add what
# a tool surface must add: the store comes from the context (never from a
# task argument), named refusals carry the task boundary codes, and the
# summary shape re-reads recorded step outputs instead of re-deriving
# evidence.
# ---------------------------------------------------------------------------


def _require_task_store(ctx: ToolContext) -> taskrun.TaskStore:
    if ctx.task_store is None:
        raise ToolRefusal(
            "task_store_missing",
            "context carries no task store; set PEA_TASK_STORE (MCP) or pass --store (CLI) before running assessment tasks",
        )
    return taskrun.TaskStore(ctx.task_store)


def _require_task_id(args: dict[str, Any]) -> str:
    task_id = str(args.get("task_id", "")).strip()
    if not taskrun.valid_task_id(task_id):
        raise ToolRefusal("task_id_invalid", "task_id 必须是 task- 前缀加 8 位十六进制（它同时是 store 下的目录名）")
    return task_id


def _load_task_or_refuse(store: taskrun.TaskStore, task_id: str) -> taskrun.AssessmentTask:
    try:
        return store.load_task(task_id)
    except taskrun.TaskBoundaryError:
        raise ToolRefusal("task_id_unknown", f"task {task_id!r} 不在 store 中") from None


def _step_output_or_none(task: taskrun.AssessmentTask, store: taskrun.TaskStore, step_id: str) -> dict[str, Any] | None:
    try:
        return store.load_step(task.task_id, step_id)
    except (taskrun.TaskBoundaryError, OSError, json.JSONDecodeError):
        return None


def _task_payload(task: taskrun.AssessmentTask, store: taskrun.TaskStore, *, include_steps: bool) -> dict[str, Any]:
    """The task summary: lifecycle, step table, and (when asked) the report.

    ``report_markdown`` is the recorded step output - the same bytes the
    report step persisted - never a re-render.
    """
    payload: dict[str, Any] = {
        "task_id": task.task_id,
        "status": task.status,
        "created_at": task.created_at,
        "project_path": task.project_path,
        "store": str(store.task_dir(task.task_id)),
        "step_counts": {
            "total": len(task.steps),
            "done": sum(1 for s in task.steps if s.status == taskrun.STEP_DONE),
            "failed": sum(1 for s in task.steps if s.status == taskrun.STEP_FAILED),
            "skipped_dep": sum(1 for s in task.steps if s.status == taskrun.STEP_SKIPPED_DEP),
            "pending": sum(1 for s in task.steps if s.status == taskrun.STEP_PENDING),
        },
    }
    if include_steps:
        payload["steps"] = [s.to_dict() for s in task.steps]
        report = _step_output_or_none(task, store, "report")
        if report is not None:
            payload["report_markdown"] = report.get("report_markdown")
    return payload


def _h_run_assessment(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Create and run one assessment task to a terminal or parked state.

    The analysis root is the authorized root (the same scope every other
    project tool uses); the request is recorded verbatim as the task's
    evidence basis. An unpassed authorization gate parks the task at the
    gate - the summary says so instead of returning a scan that never ran.
    """
    root = _require_root(ctx)
    store = _require_task_store(ctx)
    request = args.get("request")
    if not isinstance(request, dict):
        raise ToolRefusal("request_invalid", "request 必须是对象（保护请求；授权状态同时写在顶层 authorization）")
    task = taskrun.run_assessment(
        request,
        root,
        store=store,
        catalog_path=ctx.catalog_path,
        time_budget_minutes=int(args.get("time_budget_minutes", 180)),
        now=ctx.now,
    )
    return _task_payload(task, store, include_steps=True)


def _h_get_task(args: dict[str, Any], ctx: ToolContext) -> Any:
    store = _require_task_store(ctx)
    task_id = _require_task_id(args)
    task = _load_task_or_refuse(store, task_id)
    return _task_payload(task, store, include_steps=True)


def _h_list_tasks(args: dict[str, Any], ctx: ToolContext) -> Any:
    store = _require_task_store(ctx)
    return {"tasks": [_task_payload(task, store, include_steps=False) for task in store.list_tasks()]}


def _h_resume_task(args: dict[str, Any], ctx: ToolContext) -> Any:
    """Resume a parked or failed task from its recorded state.

    Two immutability rules, both enforced here: the recorded project path
    is the evidence basis, so a stated scope that disagrees with it is a
    refusal (not a silent switch of subject); and the recorded request is
    never rewritten by the resume call, so a new authorization means a new
    task, not an edit of this one.
    """
    store = _require_task_store(ctx)
    task_id = _require_task_id(args)
    task = _load_task_or_refuse(store, task_id)
    if ctx.authorized_root is not None:
        recorded = Path(task.project_path).resolve()
        stated = ctx.authorized_root.resolve()
        if recorded != stated:
            raise ToolRefusal(
                "path_outside_authorized_root",
                f"任务记录的项目路径 {task.project_path!r} 与本次调用的授权根 {stated} 不一致；恢复不得切换分析对象",
            )
    try:
        resumed = taskrun.resume_task(
            task_id,
            store=store,
            catalog_path=ctx.catalog_path,
            time_budget_minutes=int(args.get("time_budget_minutes", 180)),
            now=ctx.now,
        )
    except taskrun.TaskBoundaryError as exc:
        raise ToolRefusal("task_already_done", str(exc)) from None
    return _task_payload(resumed, store, include_steps=True)


HANDLERS: dict[str, Callable[[dict[str, Any], ToolContext], Any]] = {
    "pea.assess_project": _h_assess_project,
    "pea.map_exposure": _h_map_exposure,
    "pea.search_catalog": _h_search_catalog,
    "pea.inspect_candidate": _h_inspect_candidate,
    "pea.plan_protection": _h_plan_protection,
    "pea.review_plan": _h_review_plan,
    "pea.apply_plan": _h_apply_plan,
    "pea.verify_output": _h_verify_output,
    "pea.compare_results": _h_compare_results,
    "pea.rollback": _h_rollback,
    "pea.design_attack_simulation": _h_design_attack_simulation,
    "pea.design_mission_brief": _h_design_mission_brief,
    "pea.export_report": _h_export_report,
    "pea.demo_run": _h_demo_run,
    "pea.scan_artifacts": _h_scan_artifacts,
    "pea.scan_secrets": _h_scan_secrets,
    "pea.scan_strings_symbols": _h_scan_strings_symbols,
    "pea.check_native": _h_check_native,
    "pea.check_dart_aot": _h_check_dart_aot,
    "pea.check_build_integration": _h_check_build_integration,
    "pea.check_testbench": _h_check_testbench,
    "pea.intake_cracked_artifact": _h_intake_cracked_artifact,
    "pea.design_field_response": _h_design_field_response,
    "pea.review_candidate": _h_review_candidate,
    "pea.fetch_capability_intel": _h_fetch_capability_intel,
    "pea.ledger_record": _h_ledger_record,
    "pea.ledger_query": _h_ledger_query,
    "pea.ledger_audit_unknowns": _h_ledger_audit_unknowns,
    "pea.ledger_gate": _h_ledger_gate,
    "pea.ledger_resolve": _h_ledger_resolve,
    "pea.ledger_export": _h_ledger_export,
    "pea.run_assessment": _h_run_assessment,
    "pea.get_task": _h_get_task,
    "pea.list_tasks": _h_list_tasks,
    "pea.resume_task": _h_resume_task,
}


def available_tools() -> tuple[str, ...]:
    """Availability from implementation metadata - never from the contract."""
    return tuple(sorted(HANDLERS))


# ---------------------------------------------------------------------------
# Dispatch with approval enforcement.
# ---------------------------------------------------------------------------


def _token_root(ctx: ToolContext, args: dict[str, Any]) -> Path:
    """The authorized root a one-time token's expected scope is built from.

    The stored plan is authoritative when a run store is configured: the
    plan's recorded target *is* the approved scope, derived from the
    operator-configured store - never established by the call payload. A
    missing or unreadable plan falls through to the context root (and a
    missing plan is a named refusal in the handler anyway); the explicit
    ``authorized_root`` argument stays as the last-resort compatibility
    path for surfaces without a store.
    """
    if ctx.run_store is not None:
        try:
            plan = protect.PlanStore(ctx.run_store / "plans").load(str(args.get("plan_id", "")))
        except protect.ProtectError:
            plan = None
        if plan and plan.get("project_path"):
            return Path(str(plan["project_path"])).expanduser().resolve()
    if ctx.authorized_root is not None:
        return ctx.authorized_root.resolve()
    return Path(str(args.get("authorized_root", "."))).resolve()


def _enforce_approval(effect: tooleffects.ToolEffect, args: dict[str, Any], ctx: ToolContext) -> str | None:
    """Return a named refusal code, or None when the call may proceed."""
    kind = effect.approval
    if kind == "none":
        return None
    if kind == "workspace_scope_confirmation":
        if ctx.authorization not in AUTHORIZED_VALUES or ctx.authorized_root is None:
            return "authorization_not_confirmed"
        target = Path(str(args.get("project_path") or ctx.authorized_root)).resolve()
        root = ctx.authorized_root.resolve()
        if target != root and root not in target.parents:
            return "path_outside_authorized_root"
        return None
    if kind == "network_policy_if_online":
        # Offline stays legal: the handler degrades to a named unknown.
        return None
    if kind == "explicit_user_confirmation":
        if not (ctx.explicit_approval or args.get("explicit_user_approval") is True):
            return "explicit_approval_missing"
        return None
    if kind == "output_path_and_overwrite_confirmation":
        out_dir = args.get("output_dir") or args.get("out")
        if out_dir and Path(str(out_dir)).exists() and not ctx.output_write_confirmed:
            return "output_overwrite_not_confirmed"
        return None
    if kind == "valid_scoped_one_time_token":
        if ctx.approvals is None:
            return "approval_authority_missing"
        token_id = str(args.get("approval_token", ""))
        if not token_id:
            return "token_unknown"
        resolved_root = _token_root(ctx, args)
        expected = ApprovalScope(
            tool=effect.name,
            plan_digest=str(args.get("expected_plan_digest", "")),
            artifact_digest=str(args.get("expected_artifact_digest", "")),
            args_digest=args_digest(
                {
                    "plan_id": args.get("plan_id"),
                    "expected_plan_digest": args.get("expected_plan_digest"),
                    "authorized_root": str(resolved_root),
                }
            ),
            tool_version=effect.version,
            authorized_root=str(resolved_root),
            target_path=str(resolved_root),
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )
        try:
            ctx.approvals.consume(token_id, expected)
        except ApprovalError as exc:
            return exc.reason
        return None
    if kind in {"test_command_preview_required", "artifact_scope_confirmation"}:
        # The previewed command / artifact scope must be explicitly confirmed
        # by the caller - never implied. The codes match the contract's
        # declared error_codes for these tools.
        if not args.get("preview_confirmed"):
            return "test_preview_missing" if kind == "test_command_preview_required" else "artifact_scope_unconfirmed"
        return None
    return "unknown_approval_kind"


def call_tool(name: str, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Dispatch one tool call with contract and approval enforcement."""
    try:
        effect = tooleffects.effects_for(name)
    except KeyError:
        return ToolResult(ok=False, tool=name, error="unknown_tool", detail=f"no contract entry for {name!r}")
    handler = HANDLERS.get(name)
    if handler is None:
        return ToolResult(
            ok=False,
            tool=name,
            error="tool_not_wired",
            detail="contract-only tool: implementation lands in a later phase (executor: Phase 4)",
        )
    refusal = _enforce_approval(effect, args, ctx)
    if refusal is not None:
        return ToolResult(ok=False, tool=name, error=refusal, detail=f"approval={effect.approval}")
    try:
        data = handler(args, ctx)
    except ToolRefusal as exc:
        return ToolResult(ok=False, tool=name, error=exc.reason, detail=exc.detail)
    except Exception as exc:
        return ToolResult(ok=False, tool=name, error="handler_failed", detail=f"{type(exc).__name__}: {exc}")
    return ToolResult(ok=True, tool=name, data=data)


def describe_tools() -> list[dict[str, Any]]:
    """The tool surface with availability - what an MCP client would list."""
    surface = []
    for name, effect in tooleffects.TOOL_EFFECTS.items():
        surface.append(
            {
                "name": name,
                "purpose": effect.contract.purpose,
                "approval": effect.approval,
                "side_effects": list(effect.side_effects),
                "available": name in HANDLERS,
                "version": effect.version,
            }
        )
    return surface
