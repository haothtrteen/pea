"""Offline PEA prototype CLI: catalog search and plan generation only."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .planner import DEFAULT_CATALOG, build_plan, load_catalog, search_catalog

if TYPE_CHECKING:
    from .mcpserver import ToolContext

#: Default ledger store, relative to the current directory. The store is the
#: CLI's persistence point: every ``pea ledger`` invocation loads the run's
#: ledger from here and writes it back, so a run survives across processes.
DEFAULT_LEDGER_STORE = ".pea/ledgers"

#: Default task store for the WP2 orchestrator, relative to the current
#: directory. One directory per task (``task-XXXXXXXX/``) holding the task
#: entity plus one JSON file per completed step; every write is atomic.
DEFAULT_TASK_STORE = ".pea/tasks"

#: Default run store for the protection execution loop (WP3/WP6): plans,
#: runs and approval events live under one operator-configurable root.
DEFAULT_PROTECT_STORE = ".pea/protect"


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pea", description="PEA offline planning prototype (no code transformation is executed).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_catalog = sub.add_parser("catalog", help="List local catalog entries")
    p_catalog.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    p_catalog.add_argument("--json", action="store_true", help="Print full JSON")

    p_search = sub.add_parser("search", help="Search the local catalog")
    p_search.add_argument("--target", required=True, help="e.g. javascript, python, android")
    p_search.add_argument("--goal", required=True, help="e.g. obfuscation, logic_extraction, function_virtualization")
    p_search.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    p_search.add_argument("--include-research", action="store_true", help="Include research-only candidates in output")

    p_plan = sub.add_parser("plan", help="Create a non-executing protection plan from request JSON")
    p_plan.add_argument("--request", required=True, help="Path to protection request JSON")
    p_plan.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    p_plan.add_argument("--out", help="Optional output JSON path")

    p_intake = sub.add_parser(
        "intake",
        help="Structured intake interview: establish distribution, audience, device control and platforms",
    )
    p_intake.add_argument("--from", dest="from_request", help="Pre-fill answers from a protection request JSON")
    p_intake.add_argument("--out", help="Write the completed request JSON here")
    p_intake.add_argument("--format", choices=("text", "json"), default="text")

    p_demo = sub.add_parser(
        "demo",
        help="Prototype 1.0 end-to-end walkthrough: recon -> plan -> attack self-test -> evidence ledger -> report",
    )
    p_demo.add_argument("--request", required=True, help="Path to protection request JSON")
    p_demo.add_argument("--project", required=True, help="Authorized project root to scan (read-only)")
    p_demo.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    p_demo.add_argument("--out", help="Output directory for report.md and bundle.json")
    p_demo.add_argument("--budget", type=int, default=180, help="Attack-simulation time budget in minutes")

    p_testbench = sub.add_parser(
        "testbench",
        help="Reconnoiter the local testbench environment (adb/AVD/frida/docker); detection only, installs nothing",
    )
    p_testbench.add_argument("--json", action="store_true", help="Print full JSON")

    p_brief = sub.add_parser(
        "brief",
        help="Compose the live-fire mission brief: scan the project, tier the testbench, emit the hand-off for your REA-driven agent",
    )
    p_brief.add_argument("--request", required=True, help="Path to protection request JSON")
    p_brief.add_argument("--project", required=True, help="Authorized project root to scan (read-only)")
    p_brief.add_argument("--baseline", required=True, help="Unprotected baseline artifact path (digest is pinned automatically)")
    p_brief.add_argument("--protected", help="Protected candidate artifact path (omit for absolute-only mode)")
    p_brief.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    p_brief.add_argument("--out", help="Write the mission brief JSON here")
    p_brief.add_argument("--budget", type=int, default=180, help="Attack-simulation time budget in minutes")
    p_brief.add_argument("--no-testbench", action="store_true", help="Skip testbench reconnaissance (environment tier becomes unknown)")

    p_ledger = sub.add_parser("ledger", help="Run-scoped evidence ledger (M5): record / query / audit / gate / resolve / export")
    ledger_sub = p_ledger.add_subparsers(dest="ledger_command", required=True)

    def _ledger_common(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--run", required=True, help="Run id (also the ledger filename)")
        parser.add_argument("--store", default=DEFAULT_LEDGER_STORE, help=f"Ledger store directory (default: {DEFAULT_LEDGER_STORE})")

    p_lr = ledger_sub.add_parser("record", help="Append one evidence record (and optionally an unknown) to the run ledger")
    _ledger_common(p_lr)
    p_lr.add_argument("--evidence", required=True, help="Path to an evidence-record JSON file")

    p_lq = ledger_sub.add_parser("query", help="Query ledger evidence and unknowns by id, status or domain")
    _ledger_common(p_lq)
    p_lq.add_argument("--status", choices=("open", "resolved", "wont_resolve"), help="Filter unknowns by lifecycle status")
    p_lq.add_argument("--domain", help="Filter unknowns by domain (capability family)")
    p_lq.add_argument("--kind", help="Filter evidence by kind")

    p_la = ledger_sub.add_parser("audit", help="Residual audit: what is still open, and what it blocks")
    _ledger_common(p_la)

    p_lg = ledger_sub.add_parser("gate", help="Evaluate the verified gate mechanically; any blocking unknown blocks")
    _ledger_common(p_lg)

    p_ls = ledger_sub.add_parser("resolve", help="Resolve an open unknown against cited two-sided evidence")
    _ledger_common(p_ls)
    p_ls.add_argument("--unknown", required=True, help="unknown_id to move through its lifecycle")
    p_ls.add_argument("--status", choices=("open", "resolved", "wont_resolve"), default="resolved")
    p_ls.add_argument("--resolution", help="Resolution text (required for status=resolved)")
    p_ls.add_argument("--supporting", nargs="*", default=[], help="Supporting evidence ids")
    p_ls.add_argument("--contradicting", nargs="*", default=[], help="Contradicting evidence ids")

    p_le = ledger_sub.add_parser("export", help="Export the run ledger as redacted Markdown/JSON with digests")
    _ledger_common(p_le)
    p_le.add_argument("--out", required=True, help="Output directory")
    p_le.add_argument("--overwrite", action="store_true", help="Confirm overwriting existing exports")

    p_field = sub.add_parser("field", help="Field feedback loop (D7): cracked-package intake and the server-side response plan")
    field_sub = p_field.add_subparsers(dest="field_command", required=True)
    p_fi = field_sub.add_parser("intake", help="Scan a cracked package (read-only) and diff its manifest against the original build")
    p_fi.add_argument("--cracked", required=True, help="Cracked package root (read-only)")
    p_fi.add_argument("--baseline", required=True, help="Original build root (read-only)")
    p_fi.add_argument("--out", help="Write the intake result JSON here")

    p_fr = field_sub.add_parser("respond", help="Design the server-side response plan from an intake result")
    p_fr.add_argument("--intake", required=True, help="Path to the intake result JSON (from pea field intake)")
    p_fr.add_argument("--offline-required", action="store_true", help="Declare an offline-only posture: the plan is declined, not emitted empty")
    p_fr.add_argument("--out", help="Write the field response JSON here")

    p_task = sub.add_parser(
        "task",
        help="Task orchestrator (WP2): durable assessment tasks - run / status / list / resume / report",
    )
    task_sub = p_task.add_subparsers(dest="task_command", required=True)

    def _task_common(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--store",
            default=DEFAULT_TASK_STORE,
            help=f"Task store directory (default: {DEFAULT_TASK_STORE})",
        )

    p_tr = task_sub.add_parser(
        "run",
        help="Create and run an assessment task: gate -> domains -> plan -> attack design -> ledger -> gate -> report",
    )
    p_tr.add_argument("--request", required=True, help="Path to protection request JSON")
    p_tr.add_argument("--project", required=True, help="Authorized project root to scan (read-only)")
    p_tr.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    p_tr.add_argument("--budget", type=int, default=180, help="Attack-simulation time budget in minutes")
    _task_common(p_tr)
    p_tr.add_argument("--out", help="Also write report.md and bundle.json here (the task store keeps everything regardless)")

    p_tst = task_sub.add_parser("status", help="Show one task's lifecycle status and step table")
    p_tst.add_argument("task_id", help="Task id (task-XXXXXXXX)")
    _task_common(p_tst)

    p_tl = task_sub.add_parser("list", help="List tasks in the store, oldest first")
    _task_common(p_tl)

    p_trs = task_sub.add_parser("resume", help="Resume a parked/failed task; done steps with unchanged inputs are not re-run")
    p_trs.add_argument("task_id", help="Task id (task-XXXXXXXX)")
    p_trs.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    p_trs.add_argument("--budget", type=int, default=180, help="Attack-simulation time budget in minutes")
    _task_common(p_trs)

    p_trep = task_sub.add_parser("report", help="Export one task's recorded report and bundle")
    p_trep.add_argument("task_id", help="Task id (task-XXXXXXXX)")
    p_trep.add_argument("--out", required=True, help="Output directory")
    _task_common(p_trep)

    sub.add_parser(
        "mcp-server",
        help="Run the PEA MCP server over stdio (optional extra: mcp>=2.0). tools/list is contract-driven; calls go through the same approval gates as the CLI",
    )

    # -- WP3/WP6: the execution loop reaches the CLI (the trusted channel) --
    p_protect = sub.add_parser(
        "protect",
        help="One-shot protection run: plan -> preview -> interactive approval -> isolated apply -> verify -> diff -> report. The only human decision is the final y/N",
    )
    p_protect.add_argument("project_path", help="Target project root (the protection subject; never modified - the run works in a PEA-managed workspace)")
    p_protect.add_argument("--store", default=DEFAULT_PROTECT_STORE, help=f"Run store directory (default: {DEFAULT_PROTECT_STORE})")
    p_protect.add_argument("--request", default=None, help="Path to a protection request JSON; fields override the derived defaults")
    p_protect.add_argument("--yes", action="store_true", help="Pre-approve the previewed scope non-interactively (for CI; the preview is still printed)")
    p_protect.add_argument("--json", action="store_true", help="Print the machine-readable report JSON")

    p_approve = sub.add_parser(
        "approve",
        help="Operator approval channel (WP0): show a pending protection scope and register the approval event the MCP face needs",
    )
    p_approve.add_argument("--store", default=DEFAULT_PROTECT_STORE, help=f"Run store directory (default: {DEFAULT_PROTECT_STORE})")
    p_approve.add_argument("--fingerprint", default=None, help="Approve exactly this scope fingerprint (default: the single pending one)")
    p_approve.add_argument("--yes", action="store_true", help="Approve non-interactively after showing the scope")
    return parser


def _run_intake(args: argparse.Namespace) -> int:
    """Walk the intake questionnaire, then report the derived posture.

    Interactive when stdin is a TTY; otherwise it reports what is still missing
    so the command stays usable in CI and pipes.
    """
    from .intake import (
        answers_from_request,
        blocking_questions,
        derive_profile,
        pending_questions,
    )

    answers: dict[str, object] = {}
    if args.from_request:
        request = json.loads(Path(args.from_request).expanduser().resolve().read_text(encoding="utf-8"))
        answers.update(answers_from_request(request))

    interactive = sys.stdin.isatty() and args.format != "json"
    if interactive:
        print("PEA intake —— 先弄清给谁用、在哪跑、受不受控，再谈保护方案。\n")
        for question in pending_questions(answers):
            print(f"· {question.prompt}")
            print(f"  为什么问：{question.why}")
            if question.choices:
                print(f"  可选：{' / '.join(question.choices)}")
            raw = input("  > ").strip()
            if raw:
                if question.multi:
                    answers[question.id] = [p.strip() for p in raw.split(",") if p.strip()]
                else:
                    answers[question.id] = raw
            print()
    else:
        missing = pending_questions(answers)
        blocking = blocking_questions(answers)
        if missing and args.format == "text":
            if blocking:
                print(f"intake 未完成，还有 {len(blocking)} 个必答项：")
            else:
                print("intake 必答项已齐，以下为可跳过项（留空即按默认假设处理）：")
            for question in missing:
                tag = "必答" if question in blocking else "可跳过"
                print(f"  [{tag}] {question.id}: {question.prompt}")
                print(f"      为什么问：{question.why}")
                if question.choices:
                    print(f"      可选：{' / '.join(question.choices)}")

    profile = derive_profile(answers)

    if args.format == "json":
        _print_json({"answers": answers, "profile": profile.to_dict()})
    else:
        print("\n=== 推导出的部署姿态 ===")
        print(f"posture : {profile.posture}")
        print(f"理由    : {profile.posture_rationale}")
        print(f"置信度  : {profile.confidence}")
        if profile.recommended_goals:
            print(f"建议目标: {', '.join(profile.recommended_goals)}")
        if profile.assumptions:
            print("\n已作的假设（需你确认）：")
            for item in profile.assumptions:
                print(f"  - {item}")
        if profile.unknowns:
            print("\n仍未知（不得当作已确认）：")
            for item in profile.unknowns:
                print(f"  - {item}")
        print("\n硬门槛：")
        for gate in profile.hard_gate_checks:
            print(f"  - {gate}")
        print("\n警告：")
        for warning in profile.warnings:
            print(f"  - {warning}")
        print(
            f"\n客户端加固: allowed={profile.client_side_hardening_allowed} "
            f"requires_explicit_approval={profile.client_side_hardening_requires_approval}"
        )

    if args.out:
        from .intake import apply_profile_to_request

        request = {
            "schema_version": "1.0",
            "project_path": "./somewhere",
            "authorization": answers.get("authorization", "not_confirmed"),
            "targets": answers.get("platforms", []),
            "languages": answers.get("languages", []),
            "goals": [],
            "offline_required": str(answers.get("offline_required", "")).lower() == "true",
            "execution_mode": "plan_only",
            "distribution": answers.get("distribution"),
            "audience": answers.get("audience"),
            "device_control": answers.get("device_control"),
            "update_channel": answers.get("update_channel"),
            "secret_can_leave_client": answers.get("secret_can_leave_client"),
            "threat_model": answers.get("threat_model"),
            "test_baseline": answers.get("test_baseline"),
        }
        request = apply_profile_to_request(request, profile)
        request = {k: v for k, v in request.items() if v not in (None, "", [])}
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\n请求已写入: {out_path}")
        print(f"下一步: pea plan --request {out_path}")
    return 0


def _run_demo(args: argparse.Namespace) -> int:
    """Run the prototype-1.0 walkthrough and write the report/bundle.

    Exit code 4 mirrors ``plan``: the run completed, but authorization was
    never confirmed, so nothing was scanned and no plan may proceed.
    """
    from .demo import run_demo

    request = json.loads(Path(args.request).expanduser().resolve().read_text(encoding="utf-8"))
    result = run_demo(
        request,
        args.project,
        catalog_path=args.catalog,
        time_budget_minutes=args.budget,
    )
    if args.out:
        out_dir = Path(args.out).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / "report.md"
        bundle_path = out_dir / "bundle.json"
        report_path.write_text(result.report_markdown, encoding="utf-8")
        bundle_path.write_text(
            json.dumps(result.bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Report : {report_path}")
        print(f"Bundle : {bundle_path}")
    else:
        print(result.report_markdown)
    audit = result.ledger_audit
    print(
        f"demo summary: plan={result.plan['status']} "
        f"unknowns={audit['open']}open/{len(audit['blocking'])}blocking "
        f"gate={'blocked' if result.gate_blockers else 'clear'}",
        file=sys.stderr,
    )
    if result.recon is None:
        return 4
    return 0


def _run_testbench(args: argparse.Namespace) -> int:
    """Reconnoiter the local testbench; the output mirrors the project domains."""
    from .testbench import observe_testbench

    result = observe_testbench()
    if args.json:
        _print_json(result.to_dict())
    else:
        print("测试台环境侦察（只检测，不安装、不启动任何组件）\n")
        print(f"adb            : {'可用 ' + str(result.adb_path) if result.adb_available else '不可用（PATH 未找到）'}")
        print(f"docker         : {result.docker_note}")
        if result.devices:
            for device in result.devices:
                frida = {True: "运行中", False: "未运行", None: "未知"}[device.frida_server_running]
                print(f"设备           : {device.serial} [{device.state}/{device.kind}] frida-server={frida}（{device.frida_note}）")
        else:
            print("设备           : 无在线设备")
        if result.avds:
            print(f"AVD 镜像       : {', '.join(a.name for a in result.avds)}（未启动）")
        if result.redroid_images:
            print(f"redroid 镜像   : {', '.join(result.redroid_images)}（未启动）")
        print(f"\n本次可执行到   : {result.reachable_tier}")
        for line in result.tier_basis:
            print(f"  - {line}")
        if result.unknowns:
            print("\n仍未知（不得当作已确认）：")
            for item in result.unknowns:
                print(f"  - {item}")
        if result.coverage["omissions"]:
            print("\n探测未完成项：")
            for item in result.coverage["omissions"]:
                print(f"  - {item}")
        print("\n完整输出: pea testbench --json")
    return 0


def fria_note(device: object) -> str:
    return str(getattr(device, "frida_note", ""))


def _run_brief(args: argparse.Namespace) -> int:
    """Compose the mission brief: project scan + testbench tiering + hand-off.

    Exit code 4 mirrors ``demo``/``plan``: the run completed, but
    authorization was never confirmed, so nothing was scanned.
    """
    from . import recon, testbench
    from .attacksim import ArtifactRef, design_mission_brief

    request = json.loads(Path(args.request).expanduser().resolve().read_text(encoding="utf-8"))
    if request.get("authorization") not in {"owner", "written_authorization"}:
        print("pea: error: authorization 未确认（需要 owner 或 written_authorization）；拒绝扫描", file=sys.stderr)
        return 4

    project = Path(args.project).expanduser().resolve()
    scan = recon.observe(project)

    # Anchors are observations of this artifact, never a static tool list:
    # key artifacts (snapshot containers) plus redacted authorization-pattern
    # locations are what an analyst would actually reach for first.
    anchors: list[str] = []
    for artifact in scan.key_artifacts:
        anchors.append(f"{artifact.path}: {artifact.kind}（{artifact.size_bytes} 字节）")
    for hit in scan.pattern_hits[:10]:
        anchors.append(f"{hit.path}:{hit.line} 命中授权相关模式 {hit.pattern}（内容脱敏）")

    environment: dict[str, object] | None = None
    if not args.no_testbench:
        environment = testbench.observe_testbench().to_dict()

    baseline_path = Path(args.baseline).expanduser().resolve()
    baseline = ArtifactRef(path=str(baseline_path), sha256=_sha256_of(baseline_path))
    protected = None
    if args.protected:
        protected_path = Path(args.protected).expanduser().resolve()
        protected = ArtifactRef(path=str(protected_path), sha256=_sha256_of(protected_path))

    goals = [str(g) for g in request.get("goals", [])]
    brief = design_mission_brief(
        baseline=baseline,
        protected=protected,
        languages=[o.language for o in scan.languages],
        platforms=list(scan.platforms),
        goals=goals,
        has_authorization_logic=bool(scan.pattern_hits) or "licensing_hardening" in goals,
        objective_anchors=anchors,
        environment=environment,
        recon_unknowns=list(scan.unknowns),
        time_budget_minutes=args.budget,
    )

    output = json.dumps(brief, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"Mission brief : {out_path}")
    else:
        print(output, end="")
    env = brief["environment"]
    print(
        f"brief summary: id={brief['brief_id']} steps={len(brief['simulation']['capability_steps'])} "
        f"reachable={env['reachable_tier']} deferred={len(env['deferred_steps'])} "
        f"unknowns={len(brief['unknowns'])}",
        file=sys.stderr,
    )
    print(
        "\n下一步：把本简报交给你的 agent，由它驱动你自己环境里的 REA 执行；"
        "每步观察经 pea.ledger_record 入账（authority=observation，必须带 environment 块）。",
        file=sys.stderr,
    )
    return 0


def _ledger_context(store: str) -> ToolContext:
    """A ToolContext wired to the CLI's ledger store.

    The handlers are the same composition layer the MCP surface uses - the CLI
    adds no second implementation. Approval is the user's own shell action
    here; the MCP face enforces it mechanically for agents.
    """
    from datetime import datetime, timezone

    from .mcpserver import ToolContext

    store_path = Path(store).expanduser().resolve()
    store_path.mkdir(parents=True, exist_ok=True)
    return ToolContext(
        ledger_store=store_path,
        now=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def _run_ledger(args: argparse.Namespace) -> int:
    from .mcpserver import (
        ToolRefusal,
        _h_ledger_audit_unknowns,
        _h_ledger_export,
        _h_ledger_gate,
        _h_ledger_query,
        _h_ledger_record,
        _h_ledger_resolve,
    )

    ctx = _ledger_context(args.store)
    try:
        if args.ledger_command == "record":
            evidence = json.loads(Path(args.evidence).expanduser().resolve().read_text(encoding="utf-8"))
            payload = _h_ledger_record({"run_id": args.run, "evidence": evidence}, ctx)
            _print_json(payload)
        elif args.ledger_command == "query":
            filters: dict[str, object] = {}
            if args.status:
                filters["status"] = args.status
            if args.domain:
                filters["domain"] = args.domain
            if args.kind:
                filters["kind"] = args.kind
            _print_json(_h_ledger_query({"run_id": args.run, "filters": filters}, ctx))
        elif args.ledger_command == "audit":
            payload = _h_ledger_audit_unknowns({"run_id": args.run}, ctx)
            _print_json(payload)
            if payload["blocking"]:
                return 3
        elif args.ledger_command == "gate":
            payload = _h_ledger_gate({"run_id": args.run}, ctx)
            _print_json(payload)
            return 0 if payload["status"] == "verified" else 3
        elif args.ledger_command == "resolve":
            payload = _h_ledger_resolve(
                {
                    "run_id": args.run,
                    "unknown_id": args.unknown,
                    "status": args.status,
                    "resolution": args.resolution,
                    "supporting": list(args.supporting),
                    "contradicting": list(args.contradicting),
                },
                ctx,
            )
            _print_json(payload)
        elif args.ledger_command == "export":
            payload = _h_ledger_export(
                {
                    "run_id": args.run,
                    "output_dir": args.out,
                    "overwrite": bool(args.overwrite),
                },
                ctx,
            )
            _print_json(payload)
    except ToolRefusal as exc:
        print(f"pea ledger: {exc.reason}: {exc.detail}", file=sys.stderr)
        return 2
    return 0


def _run_field(args: argparse.Namespace) -> int:
    """D7 field feedback loop: cracked intake and the response plan."""
    from .fieldresponse import FieldResponseBoundaryError, design_field_response, intake_cracked_artifact

    if args.field_command == "intake":
        try:
            result = intake_cracked_artifact(args.cracked, args.baseline)
        except FieldResponseBoundaryError as exc:
            print(f"pea field: error: {exc}", file=sys.stderr)
            return 2
        output = json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.out:
            out_path = Path(args.out).expanduser().resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output, encoding="utf-8")
            print(f"Intake : {out_path}")
        else:
            print(output, end="")
        modified = [d for d in result.diffs if d.change == "modified"]
        print(
            f"intake summary: diffs={len(result.diffs)} modified={len(modified)} "
            f"unknowns={len(result.unknowns)}",
            file=sys.stderr,
        )
        print(
            "\n下一步：pea field respond --intake <intake.json>；diff 事实是 observation，"
            "层归属是推断，新增文件是 unknown——三者的权威等级不同，入账时不可混写。",
            file=sys.stderr,
        )
        return 0

    # respond
    intake = json.loads(Path(args.intake).expanduser().resolve().read_text(encoding="utf-8"))
    response = design_field_response(intake, offline_required=args.offline_required)
    output = json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"Response: {out_path}")
    else:
        print(output, end="")
    print(
        f"response summary: posture={response['posture']} measures={len(response['measures'])} "
        f"negative_tests={len(response['negative_tests'])}",
        file=sys.stderr,
    )
    if response["posture"] == "declined_offline_only":
        print(
            "本机制仅对有服务端姿态可用；纯离线应用在计划推导时挡掉（拒绝即交付物）。",
            file=sys.stderr,
        )
    else:
        print(
            "\n红线：中性失效（服务器不再配合破解包）、不误杀合法用户（负向测试通过后才全量）、"
            "不往破解包推送代码。灰度由部署方掌握，PEA 不执行。",
            file=sys.stderr,
        )
    return 0


def _task_store_path(store: str) -> Path:
    path = Path(store).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _print_task_summary(task: Any, store_path: Path) -> None:
    """The human-readable task summary; the JSON goes to stdout."""
    counts = {
        "done": sum(1 for s in task.steps if s.status == "done"),
        "failed": sum(1 for s in task.steps if s.status == "failed"),
        "skipped": sum(1 for s in task.steps if s.status == "skipped-dep"),
    }
    print(
        f"task summary: id={task.task_id} status={task.status} "
        f"steps={counts['done']}done/{counts['failed']}failed/{counts['skipped']}skipped "
        f"store={store_path / task.task_id}",
        file=sys.stderr,
    )
    for state in task.steps:
        marker = {"done": " ", "failed": "!", "skipped-dep": "-", "pending": ".", "running": "~"}.get(state.status, "?")
        line = f"  [{marker}] {state.id:20s} {state.status}"
        if state.error:
            line += f"  ({state.error})"
        print(line, file=sys.stderr)


def _export_task_report(task: Any, store_path: Path, out_dir: str) -> int:
    """Write the recorded report step's markdown and bundle to out_dir."""
    from .taskrun import TaskStore

    store = TaskStore(store_path)
    try:
        report = store.load_step(task.task_id, "report")
    except Exception as exc:  # TaskBoundaryError when the step never ran
        print(f"pea task: error: task {task.task_id} 没有已完成的 report 步骤（{exc}）", file=sys.stderr)
        return 2
    target = Path(out_dir).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    report_path = target / "report.md"
    bundle_path = target / "bundle.json"
    report_path.write_text(str(report.get("report_markdown", "")), encoding="utf-8")
    bundle_path.write_text(
        json.dumps(report.get("bundle"), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Report : {report_path}")
    print(f"Bundle : {bundle_path}")
    return 0


def _run_task(args: argparse.Namespace) -> int:
    """WP2 task orchestrator CLI: the same library the MCP tools call.

    Exit codes mirror the rest of the CLI: 0 done, 3 blocked (gate closed
    or parked at the authorization gate - the step table names the reason),
    4 authorization never confirmed (nothing scanned, no task created),
    2 named boundary errors.
    """
    from .taskrun import TaskBoundaryError, TaskStore, list_tasks, resume_task, run_assessment

    store_path = _task_store_path(args.store)
    store = TaskStore(store_path)

    if args.task_command == "list":
        tasks = list_tasks(store=store)
        _print_json(
            {
                "store": str(store_path),
                "count": len(tasks),
                "tasks": [
                    {
                        "task_id": t.task_id,
                        "status": t.status,
                        "created_at": t.created_at,
                        "project_path": t.project_path,
                        "steps": {s.id: s.status for s in t.steps},
                    }
                    for t in tasks
                ],
            }
        )
        return 0

    if args.task_command == "status":
        try:
            task = store.load_task(args.task_id)
        except TaskBoundaryError as exc:
            print(f"pea task: error: {exc}", file=sys.stderr)
            return 2
        _print_json(task.to_dict())
        return 0 if task.status == "done" else 3

    if args.task_command == "report":
        try:
            task = store.load_task(args.task_id)
        except TaskBoundaryError as exc:
            print(f"pea task: error: {exc}", file=sys.stderr)
            return 2
        return _export_task_report(task, store_path, args.out)

    if args.task_command == "run":
        request = json.loads(Path(args.request).expanduser().resolve().read_text(encoding="utf-8"))
        if request.get("authorization") not in {"owner", "written_authorization"}:
            print(
                "pea: error: authorization 未确认（需要 owner 或 written_authorization）；未创建任务、拒绝扫描",
                file=sys.stderr,
            )
            return 4
        task = run_assessment(
            request,
            args.project,
            store=store,
            catalog_path=args.catalog,
            time_budget_minutes=args.budget,
        )
    else:  # resume
        try:
            task = resume_task(
                args.task_id,
                store=store,
                catalog_path=args.catalog,
                time_budget_minutes=args.budget,
            )
        except TaskBoundaryError as exc:
            print(f"pea task: error: {exc}", file=sys.stderr)
            return 2

    _print_task_summary(task, store_path)
    if args.out and task.step("report").status == "done":
        code = _export_task_report(task, store_path, args.out)
        if code != 0:
            return code
    elif args.out:
        print(f"pea task: report 步骤未完成（{task.step('report').status}），无报告可导出", file=sys.stderr)
    return 0 if task.status == "done" else 3


def _protect_context(store: Path, target: Path) -> Any:
    """The CLI's execution context. The CLI *is* the trusted channel: the
    user's own shell is where approval happens, so the target is the
    execution root and the interactive confirmation registers the event."""
    from datetime import datetime, timezone

    from .approval import ApprovalAuthority
    from .mcpserver import ToolContext

    return ToolContext(
        authorized_root=target,
        authorization="owner",
        approvals=ApprovalAuthority(event_store=store / "approvals"),
        now=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        explicit_approval=True,
        execution_roots=(target,),
        run_store=store,
    )


def _derive_protect_request(target: Path, overrides: dict[str, Any] | None) -> dict[str, Any]:
    """The one-shot request: conservative defaults a project owner can mean
    by ``pea protect <path>``, overridable field by field via --request."""
    request: dict[str, Any] = {
        "schema_version": "1.0",
        "project_path": str(target),
        "authorization": "owner",
        "targets": ["javascript"],
        "languages": ["javascript"],
        "goals": ["obfuscation", "licensing_hardening"],
        "offline_required": True,
        "allow_network": False,
        "execution_mode": "apply_after_approval",
        "threat_model": "competent_reverse_engineer",
        "test_baseline": "partial",
    }
    if overrides:
        request.update(overrides)
    request["project_path"] = str(target)
    return request


def _confirm(prompt: str, *, assume_yes: bool) -> bool:
    if assume_yes:
        print(f"{prompt} [pre-approved via --yes]")
        return True
    if not sys.stdin.isatty():
        print(f"{prompt} [refused: non-interactive without --yes]", file=sys.stderr)
        return False
    answer = input(f"{prompt} [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _render_preview(review: dict[str, Any]) -> str:
    lines = [
        "=== 审批预览（批准即批准这个精确范围） ===",
        f"计划 digest : {review['plan_digest']}",
        f"指纹        : {review['fingerprint']}",
        f"工具        : {review['tool']['id']} @ {review['tool']['version']}",
        f"目标        : {review['target_path']}",
        f"受影响文件  : {len(review['affected_files'])} 个",
        "预期副作用  :",
    ]
    lines += [f"  - {item}" for item in review["expected_side_effects"]]
    files = review["affected_files"]
    shown = files[:10] + (["…"] if len(files) > 10 else [])
    lines += [f"  {name}" for name in shown]
    return "\n".join(lines)


def _run_protect(args: argparse.Namespace) -> int:
    """``pea protect <path>`` — the one-sentence protection run.

    One command, one human decision (the final y/N on the exact preview):
    plan → preview → trusted approval → isolated apply → independent
    verify → before/after diff → report. The user's project is never
    written; everything happens in the PEA-managed workspace under the
    run store.
    """
    from . import mcpserver
    from . import protect as protect_mod

    target = Path(args.project_path).expanduser().resolve()
    if not target.is_dir():
        print(f"pea protect: 目标目录不存在：{target}", file=sys.stderr)
        return 2
    store = Path(args.store).expanduser().resolve()
    overrides = None
    if args.request:
        overrides = json.loads(Path(args.request).expanduser().resolve().read_text(encoding="utf-8"))
    request = _derive_protect_request(target, overrides)
    ctx = _protect_context(store, target)

    def call(name: str, call_args: dict[str, Any]) -> Any:
        result = mcpserver.call_tool(name, call_args, ctx)
        if not result.ok:
            print(f"pea protect: {name} 被拒绝（{result.error}）{('：' + result.detail) if result.detail else ''}", file=sys.stderr)
            raise SystemExit(2)
        return result.data

    # 1-2. Plan + scope preview (parks at the approval gate).
    plan = call(
        "pea.plan_protection",
        {"request": request, "profile": {}, "catalog_snapshot": {}, "project_path": str(target)},
    )
    if plan["status"] == "blocked" or not plan["selected_catalog_ids"]:
        print("pea protect: 没有满足硬约束的候选——只有计划，没有执行。", file=sys.stderr)
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 4
    review = call("pea.review_plan", {"plan_id": plan["plan_id"], "explicit_user_approval": True})
    if review.get("status") != "awaiting_approval":
        print("pea protect: 意外状态（期望 awaiting_approval）", file=sys.stderr)
        return 2

    print(_render_preview(review))
    print(f"计划选项    : {json.dumps(review['options'], ensure_ascii=False)}")
    if not _confirm("批准执行以上精确范围？", assume_yes=args.yes):
        print("已取消；未执行任何变换，未产生任何运行。")
        return 3

    # 3. Trusted-channel approval: the interactive confirmation registers
    #    the event the same way ``pea approve`` does for the MCP face.
    ctx.approvals.register_approval(fingerprint=review["fingerprint"], decided_by="cli:protect")
    issued = call("pea.review_plan", {"plan_id": plan["plan_id"], "explicit_user_approval": True})
    token = issued["approval_token"]

    # 4. Isolated apply (snapshot + managed workspace; original untouched).
    applied = call(
        "pea.apply_plan",
        {"plan_id": plan["plan_id"], "approval_token": token, "expected_plan_digest": issued["plan_digest"]},
    )
    run_id = applied["run_id"]
    print(f"已应用（run {run_id}，工具 {applied['tool_id']} @ {applied['tool_version']}）")

    # 5. Independent verification (three-state gates; exit 0 is not success).
    verify = call("pea.verify_output", {"run_id": run_id, "test_profile": "project-tests", "preview_confirmed": True})
    for gate in verify["gates"]:
        print(f"  门 {gate['name']:<28} {gate['status']}: {gate['detail']}")
    print(f"验证结果：{verify['status']}")

    # 6. Before/after diff against a snapshot-only baseline run.
    baseline = protect_mod.start_baseline_run(plan, target, store=protect_mod.RunStore(store / "runs"), now=ctx.now)
    compare = call(
        "pea.compare_results",
        {"baseline_run_id": baseline.run_id, "candidate_run_id": run_id, "preview_confirmed": True},
    )
    size = compare["size"]
    print(f"体积：{size['baseline_bytes']} → {size['candidate_bytes']} 字节（{size['delta_pct']}%）")
    print(f"暴露面差分：{json.dumps(compare['exposure'], ensure_ascii=False)}")
    print("运行时开销：unknown（未实测；见适配器 manifest 限制字段）")

    report = {
        "generated_at": ctx.now,
        "plan_id": plan["plan_id"],
        "plan_digest": issued["plan_digest"],
        "run_id": run_id,
        "baseline_run_id": baseline.run_id,
        "tool": {"id": applied["tool_id"], "version": applied["tool_version"]},
        "affected_files": issued.get("affected_files", []),
        "verify": verify,
        "compare": compare,
        "honest_notes": [
            "客户端校验混淆后仍是客户端校验；不因混淆变权威",
            "运行时开销未实测，记为 unknown",
            "observed findings 计数变化是观察，不是'保护有效'的结论",
        ],
    }
    report_path = store / "runs" / run_id / "protect-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"报告：{report_path}")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if verify["status"] == "pass" else 1


def _run_approve(args: argparse.Namespace) -> int:
    """``pea approve`` — the operator's approval channel for the MCP face.

    Shows the pending scope(s) recorded by ``pea.review_plan``; confirming
    registers the trusted approval event exactly one token will be minted
    from. The MCP agent can request the preview; only this channel can
    approve it."""
    from .approval import ApprovalAuthority

    store = Path(args.store).expanduser().resolve()
    pending_dir = store / "approvals"
    pendings = sorted(pending_dir.glob("pending-*.json"))
    if args.fingerprint:
        pendings = [p for p in pendings if p.stem.removeprefix("pending-") == args.fingerprint]
        if not pendings:
            print(f"pea approve: 没有待审批项匹配指纹 {args.fingerprint}", file=sys.stderr)
            return 3
    elif not pendings:
        print("pea approve: 当前没有待审批的保护范围。")
        return 0
    authority = ApprovalAuthority(event_store=pending_dir)
    approved = 0
    for path in pendings:
        payload = json.loads(path.read_text(encoding="utf-8"))
        print(_render_preview(payload))
        if not _confirm("登记此范围的审批事件？", assume_yes=args.yes):
            print("跳过。")
            continue
        event = authority.register_approval(fingerprint=payload["fingerprint"], decided_by="cli:approve")
        print(f"已登记审批事件 {event.event_id}；下一次 pea.review_plan 将据此签发一次性令牌。")
        path.unlink()  # consumed: the pending scope is now an event
        approved += 1
    return 0 if approved else 3


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "catalog":
            entries = load_catalog(args.catalog)
            if args.json:
                _print_json(entries)
            else:
                print(f"PEA catalog: {len(entries)} entries\n")
                for entry in entries:
                    state = entry.get("verification_status", "unknown")
                    lic = entry.get("license", {}).get("status", "unknown")
                    maintenance = entry.get("maintenance", {}).get("state", "unknown")
                    print(f"- {entry['id']}: {entry['name']} [{entry['category']}] | {state} | license={lic} | maintenance={maintenance}")
            return 0
        if args.command == "search":
            results = search_catalog([args.target], [args.goal], load_catalog(args.catalog), include_research=args.include_research)
            _print_json({"target": args.target, "goal": args.goal, "count": len(results), "results": results})
            return 0 if results else 3
        if args.command == "intake":
            return _run_intake(args)
        if args.command == "demo":
            return _run_demo(args)
        if args.command == "testbench":
            return _run_testbench(args)
        if args.command == "brief":
            return _run_brief(args)
        if args.command == "ledger":
            return _run_ledger(args)
        if args.command == "field":
            return _run_field(args)
        if args.command == "task":
            return _run_task(args)
        if args.command == "protect":
            return _run_protect(args)
        if args.command == "approve":
            return _run_approve(args)
        if args.command == "mcp-server":
            # Delegated to mcpstdio: the SDK is an optional dependency, and a
            # missing SDK must surface as installation guidance (exit 2), not
            # an ImportError traceback on the CLI's error path.
            from . import mcpstdio

            return mcpstdio.main([])
        if args.command == "plan":
            request_path = Path(args.request).expanduser().resolve()
            request = json.loads(request_path.read_text(encoding="utf-8"))
            plan = build_plan(request, load_catalog(args.catalog))
            output = json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            if args.out:
                out_path = Path(args.out).expanduser().resolve()
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(output, encoding="utf-8")
                print(f"Plan written: {out_path}")
                print(f"strategy={plan['strategy']} status={plan['status']} plan_id={plan['plan_id']}")
            else:
                print(output, end="")
            return 0 if plan["status"] != "blocked" else 4
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"pea: error: {exc}", file=sys.stderr)
        return 2
    parser.error("unhandled command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
