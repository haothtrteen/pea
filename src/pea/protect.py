"""Protection execution loop (WP3): the single implementation behind the
four executor tools, the orchestrator's execution steps and ``pea protect``.

Everything here obeys one shape: **the user's project is never the
workspace**. A protection run

1. snapshots the target into a PEA-managed workspace (digest manifest
   pinned first - that manifest is what rollback and every later claim
   about "the original stayed intact" is checked against);
2. applies the reviewed adapter's transformation inside that workspace
   (structured argv, no shell, contract resource limits, no network);
3. verifies the output *independently* - an external tool exiting 0 says
   at most "the tool reported success", never "protection succeeded";
4. compares before/after with the read-only analysis stack (the same
   domains the assessment uses - no second opinion about what the bytes
   mean);
5. rolls back by discarding or restoring the *managed* workspace only.
   A failure never requires a destructive git reset on the user's repo.

Durability follows the task-orchestrator pattern: one directory per run,
one JSON file per stage, atomic writes. Resume of a *mutating* step is
safe by construction: the workspace is rebuilt from the snapshot before
any replay, so replaying an interrupted apply is equivalent to running
it once (the snapshot rebuild is the idempotence, not a promise about
the tool).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pea.adapters import AdapterError, adapter_for

#: Run status values. ``awaiting_approval`` is a waiting state, not a
#: failure: the run is parked at the approval gate, nothing was applied.
RUN_PLANNED = "planned"
RUN_AWAITING_APPROVAL = "awaiting_approval"
RUN_APPLYING = "applying"
RUN_VERIFYING = "verifying"
RUN_COMPLETED = "completed"
RUN_FAILED = "failed"
RUN_RECOVERED = "recovered"


class ProtectError(Exception):
    """A named protection-loop failure. ``reason`` is stable, never prose."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# Plan store: plans are durable, addressed by the planner's plan_id.
# ---------------------------------------------------------------------------


def plan_digest(plan: Mapping[str, Any]) -> str:
    """Digest of a plan's content.

    The ``plan_digest`` field itself is excluded: a stored plan carries its
    own digest, and digesting the digest would make the value unreproducible.
    Everything else - including ``project_path``, the approved target - is
    content: changing the target changes the digest, so a re-scoped plan
    cannot ride an approval issued for another one.
    """
    payload = {k: v for k, v in dict(plan).items() if k != "plan_digest"}
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class PlanStore:
    """Filesystem store for protection plans: one JSON file per plan."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()

    def save(self, plan: Mapping[str, Any]) -> str:
        plan_id = str(plan.get("plan_id") or "")
        if not plan_id:
            raise ProtectError("plan_id_missing", "计划没有 plan_id，无法持久化")
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / f"{plan_id}.json"
        _atomic_write_json(path, dict(plan))
        return plan_id

    def load(self, plan_id: str) -> dict[str, Any]:
        path = self.root / f"{plan_id}.json"
        if not path.is_file():
            raise ProtectError("plan_unknown", f"计划 {plan_id!r} 不在 {self.root}")
        return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Managed workspace: the snapshot that makes rollback and replay honest.
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_manifest(source: Path) -> dict[str, Any]:
    """Digest manifest of the target: the evidence basis for every claim."""
    files: dict[str, str] = {}
    for path in sorted(source.rglob("*")):
        if not path.is_file() or _is_excluded(path):
            continue
        files[str(path.relative_to(source))] = _sha256_file(path)
    return {"file_count": len(files), "files": files}


def verify_manifest(source: Path, manifest: Mapping[str, Any]) -> bool:
    """Mechanical check: the recorded files still match their digests."""
    recorded = manifest.get("files") or {}
    for rel, want in recorded.items():
        path = source / rel
        if not path.is_file() or _sha256_file(path) != want:
            return False
    return True


def _is_excluded(path: Path) -> bool:
    parts = set(path.parts)
    return bool(parts & {"node_modules", ".git", "dist", "coverage", ".pea"})


def rebuild_workspace(source: Path, workspace: Path) -> dict[str, Any]:
    """Recreate the managed workspace from the target (snapshot rebuild).

    Called before any mutating replay: the workspace is a derived copy,
    so wiping and re-copying it makes an interrupted apply safe to
    re-run. The user's project is read here, never written.
    """
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, workspace, ignore=shutil.ignore_patterns("node_modules", ".git", "dist", "coverage", ".pea"))
    return snapshot_manifest(workspace)


# ---------------------------------------------------------------------------
# The run record: durable, one directory per run, one file per stage.
# ---------------------------------------------------------------------------


@dataclass
class ProtectionRun:
    """One protection execution: plan, workspace, stage evidence."""

    run_id: str
    status: str
    plan_id: str
    project_path: str
    workspace: str
    created_at: str
    tool_id: str = ""
    tool_version: str = ""
    approval_fingerprint: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "plan_id": self.plan_id,
            "project_path": self.project_path,
            "workspace": self.workspace,
            "created_at": self.created_at,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "approval_fingerprint": self.approval_fingerprint,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProtectionRun:
        return cls(
            run_id=str(data["run_id"]),
            status=str(data.get("status", RUN_PLANNED)),
            plan_id=str(data.get("plan_id", "")),
            project_path=str(data.get("project_path", "")),
            workspace=str(data.get("workspace", "")),
            created_at=str(data.get("created_at", "")),
            tool_id=str(data.get("tool_id", "")),
            tool_version=str(data.get("tool_version", "")),
            approval_fingerprint=str(data.get("approval_fingerprint", "")),
            note=str(data.get("note", "")),
        )


class RunStore:
    """Durable runs under a store root; stage payloads as step files."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()

    def run_dir(self, run_id: str) -> Path:
        return self.root / run_id

    def new_run_id(self) -> str:
        return f"run-{uuid.uuid4().hex[:8]}"

    def save_run(self, run: ProtectionRun) -> None:
        path = self.run_dir(run.run_id) / "run.json"
        _atomic_write_json(path, run.to_dict())

    def load_run(self, run_id: str) -> ProtectionRun:
        path = self.run_dir(run_id) / "run.json"
        if not path.is_file():
            raise ProtectError("run_unknown", f"运行 {run_id!r} 不在 {self.root}")
        return ProtectionRun.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def save_stage(self, run_id: str, stage: str, payload: Mapping[str, Any]) -> str:
        path = self.run_dir(run_id) / f"{stage}.json"
        _atomic_write_json(path, dict(payload))
        return _sha256_file(path)

    def load_stage(self, run_id: str, stage: str) -> dict[str, Any] | None:
        path = self.run_dir(run_id) / f"{stage}.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The four executor operations (one implementation, three consumers).
# ---------------------------------------------------------------------------


def select_tool(plan: Mapping[str, Any]) -> str:
    """The plan's selected catalog id - one adapter, no improvisation."""
    selected = [str(i) for i in plan.get("selected_catalog_ids") or ()]
    if len(selected) != 1:
        raise ProtectError("tool_selection_ambiguous", f"计划选择了 {len(selected)} 个候选，执行器只接受唯一确定的选择")
    return selected[0]


def start_run(
    plan: Mapping[str, Any],
    project_path: str | Path,
    *,
    store: RunStore,
    now: str,
    approval_fingerprint: str = "",
) -> ProtectionRun:
    """Create a run record (no side effects yet) for an approved plan."""
    tool_id = select_tool(plan)
    run = ProtectionRun(
        run_id=store.new_run_id(),
        status=RUN_AWAITING_APPROVAL if not approval_fingerprint else RUN_PLANNED,
        plan_id=str(plan.get("plan_id", "")),
        project_path=str(project_path),
        workspace="",
        created_at=now,
        tool_id=tool_id,
        approval_fingerprint=approval_fingerprint,
    )
    run.workspace = str(store.run_dir(run.run_id) / "workspace")
    store.save_run(run)
    store.save_stage(run.run_id, "plan", dict(plan))
    return run


def start_baseline_run(
    plan: Mapping[str, Any],
    project_path: str | Path,
    *,
    store: RunStore,
    now: str,
) -> ProtectionRun:
    """A snapshot-only run: the pristine side of every comparison.

    The baseline carries no transformation - it is the managed copy the
    candidate run is measured against, so "what changed" is a diff of two
    recorded states, never an assertion about the original directory.
    """
    run = start_run(plan, project_path, store=store, now=now, approval_fingerprint="baseline")
    manifest = rebuild_workspace(Path(run.project_path), Path(run.workspace))
    store.save_stage(run.run_id, "snapshot", manifest)
    run.status = RUN_PLANNED
    run.note = "baseline：仅快照，无变换"
    store.save_run(run)
    return run


def apply_run(run_id: str, *, store: RunStore, now: str) -> dict[str, Any]:
    """Snapshot the target, then apply the adapter in the managed workspace.

    The workspace is rebuilt from the target first (snapshot rebuild), so
    a re-entered apply after a crash is equivalent to a first apply: the
    idempotence is the rebuild, not a claim about the external tool.
    """
    run = store.load_run(run_id)
    plan = store.load_stage(run_id, "plan") or {}
    workspace = Path(run.workspace)
    manifest = rebuild_workspace(Path(run.project_path), workspace)
    store.save_stage(run_id, "snapshot", manifest)
    adapter = adapter_for(select_tool(plan))
    preview = adapter.preview(plan, workspace)
    store.save_stage(run_id, "preview", _preview_dict(preview))
    run.status = RUN_APPLYING
    store.save_run(run)
    try:
        result = adapter.apply(preview, workspace)
    except AdapterError as exc:
        run.status = RUN_FAILED
        run.note = f"{exc.reason}: {exc.detail}"
        store.save_run(run)
        store.save_stage(run_id, "apply", {"status": "failed", "reason": exc.reason, "detail": exc.detail})
        raise ProtectError(exc.reason, exc.detail) from None
    store.save_stage(
        run_id,
        "apply",
        {
            "status": "applied",
            "tool_id": result.tool_id,
            "tool_version": result.tool_version,
            "exit_code": result.exit_code,
            "outputs": list(result.outputs),
            "log_tail": list(result.log_tail),
        },
    )
    run.status = RUN_VERIFYING
    store.save_run(run)
    return {
        "run_id": run_id,
        "status": run.status,
        "tool_id": result.tool_id,
        "tool_version": result.tool_version,
        "outputs": list(result.outputs),
        "workspace": str(workspace),
    }


def verify_run(run_id: str, *, store: RunStore, test_command: list[str] | None = None) -> dict[str, Any]:
    """Independently check the protected workspace: build + regression + integrity.

    Four three-state gates (pass / fail / unknown) - an external exit code is
    evidence about the tool's own report, never a finding about protection.
    ``transformation_effective`` is the anti-fake-success gate: outputs that
    are byte-identical to the snapshot mean the transform did nothing, no
    matter what exit code the tool reported. A failed verification triggers
    the managed-workspace rollback: the failed output is discarded, the
    recovery itself is recorded.
    """
    run = store.load_run(run_id)
    applied = store.load_stage(run_id, "apply")
    if applied is None or applied.get("status") != "applied":
        raise ProtectError("verify_without_apply", "没有已应用的产物可验证")
    workspace = Path(run.workspace)
    gates: list[dict[str, Any]] = []

    # Gate 1: snapshot integrity - the recorded originals still match.
    snapshot = store.load_stage(run_id, "snapshot") or {}
    original_intact = verify_manifest(Path(run.project_path), snapshot)
    gates.append(
        {
            "name": "original_intact",
            "status": "pass" if original_intact else "fail",
            "detail": "原工程文件 digest 与快照一致" if original_intact else "原工程文件与快照不一致——恢复被破坏",
        }
    )

    # Gate 2: protected outputs exist.
    outputs = [Path(p) for p in applied.get("outputs") or ()]
    outputs_exist = all(p.is_file() for p in outputs)
    gates.append(
        {
            "name": "protected_outputs_exist",
            "status": "pass" if outputs_exist else "fail",
            "detail": f"{len(outputs)} 个混淆产物就位" if outputs_exist else "声明存在的产物缺失",
        }
    )

    # Gate 3: the project's own regression suite on the protected output.
    command = test_command or _detect_test_command(workspace)
    if command is None:
        gates.append(
            {
                "name": "regression_tests",
                "status": "unknown",
                "detail": "未检测到项目测试命令（package.json 无 scripts.test）；未运行 = unknown，不是通过",
            }
        )
        tests_passed = None
    else:
        try:
            proc = subprocess.run(
                command,
                shell=False,
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            gates.append({"name": "regression_tests", "status": "unknown", "detail": f"测试命令无法运行：{exc}"})
            tests_passed = None
        else:
            tests_passed = proc.returncode == 0
            gates.append(
                {
                    "name": "regression_tests",
                    "status": "pass" if tests_passed else "fail",
                    "detail": f"{' '.join(command)} → rc={proc.returncode}",
                }
            )

    # Gate 4: the transformation had a measurable effect. An external tool
    # exiting 0 says at most "the tool reported success"; if every declared
    # output is byte-identical to the snapshot, the transform did nothing
    # and the run must not read as protected.
    snapshot_files = (snapshot or {}).get("files") or {}
    changed = 0
    for out in outputs:
        if not out.is_file():
            continue  # a missing output is gate 2's finding, not this gate's
        try:
            rel = str(out.relative_to(workspace))
        except ValueError:
            continue
        recorded = snapshot_files.get(rel)
        if recorded is None or _sha256_file(out) != recorded:
            changed += 1
    if outputs and changed == 0:
        gates.append(
            {
                "name": "transformation_effective",
                "status": "fail",
                "detail": f"{len(outputs)} 个产物与快照逐字节一致——变换没有可测效果；exit 0 不代表保护生效",
            }
        )
    elif changed:
        gates.append(
            {
                "name": "transformation_effective",
                "status": "pass",
                "detail": f"{changed}/{len(outputs)} 个产物内容相对快照有变化",
            }
        )
    else:
        gates.append(
            {"name": "transformation_effective", "status": "unknown", "detail": "没有可比对内容的产物"}
        )

    failed = [g for g in gates if g["status"] == "fail"]
    outcome: dict[str, Any] = {
        "status": "fail" if failed else ("unknown" if any(g["status"] == "unknown" for g in gates) else "pass"),
        "gates": gates,
        "tests_passed": tests_passed,
    }
    store.save_stage(run_id, "verify", outcome)
    if failed:
        # Failure handling is part of verification: discard the managed
        # output, record the recovery, never leave a half-applied run.
        recovery = rollback_run(run_id, store=store, mode="discard")
        run = store.load_run(run_id)
        run.note = f"验证失败（{', '.join(g['name'] for g in failed)}）；已按失败路径恢复受管工作区"
        store.save_run(run)
        outcome["recovery"] = recovery
        # Re-persist: the recorded stage must carry the recovery evidence
        # too, not just the in-memory answer the caller sees.
        store.save_stage(run_id, "verify", outcome)
    return outcome


def _detect_test_command(workspace: Path) -> list[str] | None:
    """The project's own test command, structured - never a shell string."""
    package = workspace / "package.json"
    if package.is_file():
        try:
            scripts = json.loads(package.read_text(encoding="utf-8")).get("scripts") or {}
        except (json.JSONDecodeError, OSError):
            scripts = {}
        if "test" in scripts:
            return ["npm", "test"]
    if any(workspace.glob("*.test.js")) or any(workspace.glob("test/*.test.js")):
        return ["node", "--test"]
    return None


def compare_runs(baseline_run_id: str, candidate_run_id: str, *, store: RunStore) -> dict[str, Any]:
    """Before/after diff: manifests plus the read-only analysis stack.

    The same secret/symbol domains the assessment uses run on both
    sides - "what changed in exposure" is measured, not asserted. Size
    delta is computed exactly; runtime overhead stays a declared unknown
    (the adapter manifest records why: 15-80% upstream warnings are not
    a measurement of *this* project).
    """
    baseline_dir = Path(store.load_run(baseline_run_id).workspace)
    candidate_dir = Path(store.load_run(candidate_run_id).workspace)
    if not baseline_dir.is_dir() or not candidate_dir.is_dir():
        raise ProtectError("workspace_missing", "对比运行的工作区不在磁盘上")

    from pea.artifactscan import observe_artifacts
    from pea.secretscan import observe_secrets
    from pea.symbolscan import observe_strings_symbols

    now = _utc_now()
    baseline_scan = observe_artifacts(baseline_dir, now=now)
    candidate_scan = observe_artifacts(candidate_dir, now=now)
    baseline_secrets = observe_secrets(baseline_dir, now=now)
    candidate_secrets = observe_secrets(candidate_dir, now=now)
    baseline_symbols = observe_strings_symbols(baseline_scan, now=now)
    candidate_symbols = observe_strings_symbols(candidate_scan, now=now)

    def _field(f: Any, name: str) -> Any:
        return f.get(name) if isinstance(f, dict) else getattr(f, name, None)

    def observed(items: Any) -> int:
        """Count *observed* findings only.

        A domain that reports "nothing to scan" records an unknown-shaped
        entry; counting it as an exposure finding would inflate the
        baseline and fake a delta. Unknowns are reported separately.
        """
        return sum(1 for f in items if _field(f, "status") == "observed")

    def unknown_count(items: Any) -> int:
        return sum(1 for f in items if _field(f, "status") == "unknown")

    baseline_size = sum(f.stat().st_size for f in baseline_dir.rglob("*") if f.is_file())
    candidate_size = sum(f.stat().st_size for f in candidate_dir.rglob("*") if f.is_file())
    outcome = {
        "size": {
            "baseline_bytes": baseline_size,
            "candidate_bytes": candidate_size,
            "delta_bytes": candidate_size - baseline_size,
            "delta_pct": round((candidate_size - baseline_size) / baseline_size * 100, 2) if baseline_size else None,
        },
        "exposure": {
            "secret_findings_observed": {
                "baseline": observed(baseline_secrets.findings),
                "candidate": observed(candidate_secrets.findings),
            },
            "symbol_findings_observed": {
                "baseline": observed(baseline_symbols.findings),
                "candidate": observed(candidate_symbols.findings),
            },
            "unknown_shaped_records": {
                "baseline": unknown_count(baseline_secrets.findings) + unknown_count(baseline_symbols.findings),
                "candidate": unknown_count(candidate_secrets.findings) + unknown_count(candidate_symbols.findings),
            },
        },
        "runtime_overhead": {
            "status": "unknown",
            "reason": "未实测运行时开销；上游文档警示部分配置减速 15–80%（见适配器 manifest 限制字段）——记为 unknown，不猜",
        },
        "semantic_note": "observed findings 计数变化是观察，不是'保护有效'的结论；计数不变（如字符串数组编码后秘密模式仍命中）是如实测量——有效结论由验收判据显式声明",
    }
    store.save_stage(candidate_run_id, "compare", outcome)
    return outcome


def rollback_run(run_id: str, *, store: RunStore, mode: str = "discard") -> dict[str, Any]:
    """Discard or restore the managed workspace - never the user's project.

    ``discard`` removes the PEA-owned workspace; ``restore`` rebuilds it
    from the target snapshot. Either way the outcome is recorded: a
    best-effort recovery reports its own result honestly, including
    failure.
    """
    if mode not in {"discard", "restore"}:
        raise ProtectError("rollback_mode_unknown", f"未知回滚模式：{mode!r}")
    run = store.load_run(run_id)
    workspace = Path(run.workspace)
    reverted: list[str] = []
    try:
        if mode == "discard":
            if workspace.is_dir():
                shutil.rmtree(workspace)
                reverted.append(str(workspace))
        else:
            rebuild_workspace(Path(run.project_path), workspace)
            reverted.append(str(workspace))
        status = "pass"
        detail = f"已按 {mode} 处理受管工作区"
    except OSError as exc:
        status = "fail"
        detail = f"恢复失败（{type(exc).__name__}: {exc}）——受管工作区可能处于中间态，需人工检查"
    outcome = {"status": status, "mode": mode, "reverted_paths": reverted, "detail": detail}
    store.save_stage(run_id, "rollback", outcome)
    if status == "pass":
        run = store.load_run(run_id)
        if run.status in {RUN_APPLYING, RUN_VERIFYING}:
            run.status = RUN_RECOVERED
            store.save_run(run)
    return outcome


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _preview_dict(preview: Any) -> dict[str, Any]:
    return {
        "argv": list(preview.argv),
        "affected_files": list(preview.affected_files),
        "output_destination": preview.output_destination,
        "expected_side_effects": list(preview.expected_side_effects),
        "tool_id": preview.tool_id,
        "tool_version": preview.tool_version,
        "options": dict(preview.options),
    }


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")
