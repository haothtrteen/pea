"""WP4 执行闭环端到端验证：七步走通 + 八条判据机械核验。

用法::

    python3 scripts/verify_loop.py                 # 全量七步 + 八条判据
    python3 scripts/verify_loop.py --json          # JSON 结果（机器可读）
    python3 scripts/verify_loop.py --keep          # 保留运行现场便于复查
    python3 scripts/verify_loop.py --out PATH      # 报告写出到文件

退出码：0=八条判据全部通过；1=有判据失败。未执行 ≠ 通过：node/npm 或
固定版本工具不可用时以明确错误退出（2），不产出任何绿灯。

与 ``verify_real.py`` 同纪律：本脚本**单独触发，不进默认 CI**（它要装
真实工具、跑真实 node 子进程）。``make check`` 的绿灯不依赖本脚本。

七步（方案 §4.2，每步证据入报告）：
  1 基线：canary 构建 + 跑测试
  2 计划：适配器选择与变换清单
  3 审批：预览 + 真实审批事件（本进程即操作者可信通道）
  4 执行：受管工作区内混淆
  5 功能验证：三门 + 变换有效性门
  6 测量：前后差分（独立基线运行）
  7 失败演练：人为使测试失败 → PEA 拒收 → 恢复证据

八条判据（方案 §4.3）：全部机械核验，不含"看起来难多了"式判断。
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pea import protect  # noqa: E402
from pea.approval import ApprovalAuthority  # noqa: E402
from pea.mcpserver import ToolContext, call_tool  # noqa: E402

CANARY = ROOT / "demo" / "canary-js-licensing"


def _fail(msg: str) -> None:
    raise RuntimeError(msg)


def _shutil_ok() -> None:
    if shutil.which("node") is None:
        _fail("node 不在 PATH 上——闭环需要真实 Node 运行时（这是集成验证，不是绿灯的来源）")
    if shutil.which("npm") is None:
        _fail("npm 不在 PATH 上——固定版本工具安装需要 npm")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WP4 执行闭环端到端验证（七步 + 八条判据）")
    parser.add_argument("--json", action="store_true", help="打印机器可读 JSON 报告")
    parser.add_argument("--keep", action="store_true", help="保留运行现场")
    parser.add_argument("--out", default=None, help="报告写出到文件")
    args = parser.parse_args(argv)

    _shutil_ok()
    report: dict[str, object] = {"steps": {}, "criteria": {}, "honest_notes": []}
    try:
        _run_loop(report, keep=args.keep)
    except Exception as exc:
        report["fatal"] = f"{type(exc).__name__}: {exc}"
        print(f"verify_loop: 未完成——{report['fatal']}", file=sys.stderr)
        _emit(report, args)
        return 1
    ok = all(v.get("pass") for v in report["criteria"].values())  # type: ignore[union-attr]
    _emit(report, args)
    return 0 if ok else 1


def _emit(report: dict[str, object], args: argparse.Namespace) -> None:
    if args.out:
        Path(args.out).expanduser().resolve().write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    criteria = report.get("criteria", {})
    if isinstance(criteria, dict):
        for name, item in criteria.items():
            if isinstance(item, dict):
                mark = "PASS" if item.get("pass") else "FAIL"
                print(f"  [{mark}] {name}: {item.get('detail', '')}")
    fatal = report.get("fatal")
    if fatal:
        print(f"fatal: {fatal}")
    print("八条判据：" + ("全部通过" if all(v.get("pass") for v in criteria.values() if isinstance(v, dict)) else "存在失败——见上"))


def _run_loop(report: dict[str, object], *, keep: bool) -> None:
    workspace_root = Path(tempfile.mkdtemp(prefix="pea-verify-loop-"))
    store_root = workspace_root / "store"
    steps: dict[str, object] = report["steps"]  # type: ignore[assignment]

    # -- 步 1：基线（canary 拷入工作区，跑原测试） -------------------------
    project = workspace_root / "canary"
    shutil.copytree(CANARY, project, ignore=shutil.ignore_patterns("node_modules"))
    baseline_proc = _run_node_tests(project)
    steps["1_baseline"] = {
        "tests_rc": baseline_proc,
        "secret_findings": _secret_count(project),
    }
    if baseline_proc != 0:
        _fail("canary 基线测试未通过——测量载体坏了，闭环数据不可信")

    # -- 步 2：计划 --------------------------------------------------------
    ctx = ToolContext(
        authorized_root=project,
        authorization="owner",
        approvals=ApprovalAuthority(event_store=store_root / "approvals"),
        now=_utc_now(),
        explicit_approval=True,
        execution_roots=(project,),
        run_store=store_root,
    )

    def call(name: str, call_args: dict[str, object]) -> dict[str, object]:
        result = call_tool(name, call_args, ctx)
        if not result.ok:
            _fail(f"{name} 被拒绝（{result.error}）：{result.detail}")
        return result.data  # type: ignore[return-value]

    plan = call(
        "pea.plan_protection",
        {
            "request": {
                "schema_version": "1.0",
                "project_path": str(project),
                "authorization": "owner",
                "targets": ["javascript"],
                "languages": ["javascript"],
                "goals": ["licensing_hardening", "obfuscation"],
                "offline_required": True,
                "allow_network": False,
                "execution_mode": "apply_after_approval",
                "threat_model": "competent_reverse_engineer",
                "test_baseline": "full",
            },
            "profile": {},
            "catalog_snapshot": {},
            "project_path": str(project),
        },
    )
    if not plan.get("selected_catalog_ids"):
        _fail(f"计划没有候选（status={plan.get('status')}）——闭环需要 javascript-obfuscator 通过硬门控")
    steps["2_plan"] = {"plan_id": plan["plan_id"], "selected": plan["selected_catalog_ids"]}

    # -- 步 3：审批（预览 → 真实审批事件） ---------------------------------
    review = call("pea.review_plan", {"plan_id": plan["plan_id"], "explicit_user_approval": True})
    if review.get("status") != "awaiting_approval":
        _fail("审查未按预期停在审批门")
    pending_file = store_root / "approvals" / f"pending-{review['fingerprint']}.json"
    if not pending_file.is_file():
        _fail("待审批预览未落盘——操作者通道没有可展示的范围")
    # 本脚本即操作者进程（与 pea protect --yes 同语义）：确认后登记事件。
    ctx.approvals.register_approval(fingerprint=str(review["fingerprint"]), decided_by="cli:verify-loop")
    issued = call("pea.review_plan", {"plan_id": plan["plan_id"], "explicit_user_approval": True})
    steps["3_approval"] = {
        "fingerprint": review["fingerprint"],
        "affected_files": list(review["affected_files"]),
        "token_issued": bool(issued.get("approval_token")),
    }

    # -- 步 4：执行（受管工作区内混淆） ------------------------------------
    applied = call(
        "pea.apply_plan",
        {
            "plan_id": plan["plan_id"],
            "approval_token": str(issued["approval_token"]),
            "expected_plan_digest": str(issued["plan_digest"]),
        },
    )
    run_id = str(applied["run_id"])
    apply_stage = protect.RunStore(store_root / "runs").load_stage(run_id, "apply") or {}
    steps["4_apply"] = {
        "run_id": run_id,
        "tool": f"{applied['tool_id']} @ {applied['tool_version']}",
        "exit_code": apply_stage.get("exit_code"),
        "outputs": len(applied.get("outputs", [])),
    }

    # -- 步 5：独立验证（三门 + 变换有效性门） ------------------------------
    verify = call("pea.verify_output", {"run_id": run_id, "test_profile": "project-tests", "preview_confirmed": True})
    steps["5_verify"] = {"status": verify["status"], "gates": {g["name"]: g["status"] for g in verify["gates"]}}
    if verify["status"] != "pass":
        _fail(f"保护后验证未通过（{verify['status']}）——闭环在门上停住，这是设计行为")

    # -- 步 6：测量（独立基线运行 + 前后差分） ------------------------------
    baseline_run = protect.start_baseline_run(
        plan, project, store=protect.RunStore(store_root / "runs"), now=_utc_now()
    )
    compare = call(
        "pea.compare_results",
        {"baseline_run_id": baseline_run.run_id, "candidate_run_id": run_id, "preview_confirmed": True},
    )
    steps["6_compare"] = {
        "baseline_run_id": baseline_run.run_id,
        "size": compare["size"],
        "exposure": compare["exposure"],
        "runtime_overhead": compare["runtime_overhead"],
    }

    # -- 步 7：失败演练（人为使测试失败 → 拒收 → 恢复） ----------------------
    drill_plan = dict(plan)
    drill_run = protect.start_run(
        drill_plan, project, store=protect.RunStore(store_root / "runs"), now=_utc_now(), approval_fingerprint="drill"
    )
    original_adapter_for = protect.adapter_for
    try:
        protect.apply_run(drill_run.run_id, store=protect.RunStore(store_root / "runs"), now=_utc_now())
    finally:
        protect.adapter_for = original_adapter_for
    drill_workspace = Path(drill_run.workspace)
    (drill_workspace / "license.test.js").write_text(
        "const { test } = require('node:test');\n"
        "test('drill: 人为失败', () => { require('node:assert').strictEqual(1, 2); });\n",
        encoding="utf-8",
    )
    drill_verify = protect.verify_run(drill_run.run_id, store=protect.RunStore(store_root / "runs"))
    drill_rollback = protect.RunStore(store_root / "runs").load_stage(drill_run.run_id, "rollback") or {}
    steps["7_failure_drill"] = {
        "verify_status": drill_verify["status"],
        "recovery_recorded": "recovery" in drill_verify,
        "rollback": drill_rollback.get("status"),
        "workspace_discarded": not drill_workspace.exists(),
    }

    # -- 八条判据（§4.3，全部机械核验） -------------------------------------
    snapshot = protect.RunStore(store_root / "runs").load_stage(run_id, "snapshot") or {}
    report["criteria"] = {
        "original_intact": {
            "pass": protect.verify_manifest(project, snapshot),
            "detail": "原工程文件 digest 与快照复验一致",
        },
        "tool_really_ran": {
            "pass": bool(apply_stage.get("tool_version")) and apply_stage.get("exit_code") == 0,
            "detail": f"工具 {applied['tool_id']} @ {applied['tool_version']}，exit={apply_stage.get('exit_code')}",
        },
        "protected_outputs_exist": {
            "pass": all(Path(p).is_file() for p in applied.get("outputs", [])),
            "detail": f"{len(applied.get('outputs', []))} 个产物核验",
        },
        "function_preserved": {
            "pass": baseline_proc == 0 and verify["status"] == "pass",
            "detail": f"基线测试 rc={baseline_proc}；保护后验证 {verify['status']}",
        },
        "measurable_effect": {
            "pass": verify["status"] == "pass" and compare["size"]["delta_bytes"] != 0,
            "detail": f"体积变化 {compare['size']['delta_pct']}%",
        },
        "overhead_declared": {
            "pass": compare["runtime_overhead"]["status"] == "unknown",
            "detail": "体积精确实测；运行时 declared unknown + manifest 限制引用（不猜）",
        },
        "failure_handled_safely": {
            "pass": drill_verify["status"] == "fail"
            and drill_rollback.get("status") == "pass"
            and not drill_workspace.exists(),
            "detail": f"演练验证 {drill_verify['status']}，恢复 {drill_rollback.get('status')}，现场已清理",
        },
        "report_reproducible": {
            "pass": all(
                key in apply_stage
                for key in ("tool_version", "exit_code", "outputs")
            )
            and bool(review.get("fingerprint")),
            "detail": "工具版本、执行记录、产物、审批指纹已入档",
        },
    }
    report["run_root"] = str(store_root / "runs")
    report["honest_notes"] = [
        "客户端校验混淆后仍是客户端校验；不因混淆变权威",
        "exposure 计数变化是观察，不是'保护有效'的结论",
        "实测归因（canary）：明文秘密在产物中消失，但顶层标识符名默认不重命名（上游 renameGlobals 默认关），凭据命名形态仍被启发式命中——secret 计数 1→1 是命名形态残留，不是明文泄漏",
        "运行时开销 declared unknown；benchmark 属后续版本",
    ]
    if not keep:
        shutil.rmtree(workspace_root, ignore_errors=True)
    else:
        print(f"现场保留于 {workspace_root}")


def _run_node_tests(project: Path) -> int:
    import subprocess

    proc = subprocess.run(["npm", "test"], cwd=str(project), capture_output=True, text=True, timeout=300, check=False)
    return proc.returncode


def _secret_count(path: Path) -> int:
    from pea.secretscan import observe_secrets

    result = observe_secrets(path, now=_utc_now())
    return sum(1 for f in result.findings if (f.get("status") if isinstance(f, dict) else f.status) == "observed")


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


if __name__ == "__main__":
    raise SystemExit(main())
