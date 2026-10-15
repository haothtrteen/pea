"""WP2 tests: the task orchestrator - demo equivalence, resume, honest failure.

Four properties are pinned here, each one a rule the design states and the
implementation must not silently drop:

1. **Equivalence.** The orchestrator runs the demo's workflow, so on the
   canary every analysis field of its bundle - and the report markdown -
   equals ``demo.run_demo``'s. Only the metadata block differs (it records
   the orchestrator, not the demo).
2. **Resume.** A crash loses at most the step in flight: done steps with
   unchanged input digests are not re-run, a failed step retries from
   itself, and a re-run domain drags its soft consumers along (soft deps
   feed the digest).
3. **Honest failure.** A failed domain never fabricates a pass and never
   aborts the walk: the ledger records it as a *blocking* unknown (the
   severity is the orchestrator's rule, not domain wording), the verified
   gate stays closed, the report skips itself when a truth-rendering
   input is missing, and a merely optional domain renders as 未运行.
4. **The gate parks.** Without stated authorization nothing is read:
   every later step is skipped-dep with the named reason and the store
   holds nothing but the gate's own output.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pea import taskrun
from pea.cli import main
from pea.demo import run_demo
from pea.mcpserver import ToolContext, call_tool
from pea.taskrun import (
    _STEP_SPECS,
    STEP_DONE,
    STEP_FAILED,
    STEP_PENDING,
    STEP_RUNNING,
    STEP_SKIPPED_DEP,
    TASK_BLOCKED,
    TASK_CREATED,
    TASK_DONE,
    TASK_RUNNING,
    WORKFLOW,
    TaskBoundaryError,
    TaskStore,
)

ROOT = Path(__file__).resolve().parents[1]
CANARY = ROOT / "demo" / "canary-flutter-licensing"
REQUEST = json.loads((ROOT / "examples" / "protection-request.flutter-licensing.example.json").read_text(encoding="utf-8"))
NOW = "2026-10-13T00:00:00+00:00"
STEP_COUNT = len(WORKFLOW)

#: The bundle fields the orchestrator must reproduce exactly from the demo.
#: The metadata block (``demo`` vs ``orchestrator``) and the capability-intel
#: channel (the orchestrator never queries it) differ on purpose.
SHARED_BUNDLE_FIELDS = (
    "request",
    "recon",
    "domains",
    "plan",
    "attack_simulation",
    "ledger",
    "ledger_audit",
    "gate_blockers",
    "remediation_groups",
)


def _boom(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("按测试注入的域失败")


def _counted(monkeypatch: pytest.MonkeyPatch, name: str, calls: dict[str, int]) -> None:
    """Wrap a taskrun-level domain function with a call counter."""
    original = getattr(taskrun, name)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        calls[name] = calls.get(name, 0) + 1
        return original(*args, **kwargs)

    monkeypatch.setattr(taskrun, name, wrapper)


def _flaky(monkeypatch: pytest.MonkeyPatch, name: str, calls: dict[str, int]) -> dict[str, bool]:
    """Wrap a domain function so its first call fails, the rest pass through."""
    original = getattr(taskrun, name)
    state = {"failed": False}

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        calls[name] = calls.get(name, 0) + 1
        if not state["failed"]:
            state["failed"] = True
            raise RuntimeError(f"{name} 首次调用按测试设定失败（注入的崩溃）")
        return original(*args, **kwargs)

    monkeypatch.setattr(taskrun, name, wrapper)
    return state


def _run(store: TaskStore, request: dict[str, Any] | None = None, **kwargs: Any) -> taskrun.AssessmentTask:
    return taskrun.run_assessment(request or REQUEST, CANARY, store=store, now=NOW, **kwargs)


def _unauthorized_request() -> dict[str, Any]:
    request = dict(REQUEST)
    request["authorization"] = "not_confirmed"
    return request


@pytest.fixture(scope="module")
def demo_result():
    return run_demo(REQUEST, CANARY, now=NOW)


@pytest.fixture(scope="module")
def walked(tmp_path_factory: pytest.TempPathFactory):
    """One full canary walk, shared by the read-only tests."""
    store = TaskStore(tmp_path_factory.mktemp("walked") / "tasks")
    task = _run(store)
    return task, store


@pytest.fixture
def store(tmp_path: Path) -> TaskStore:
    return TaskStore(tmp_path / "tasks")


def _gap_unknowns(ledger_product: dict[str, Any]) -> list[dict[str, Any]]:
    """The orchestrator's own gap unknowns, isolated from the domains'."""
    return [
        u
        for u in ledger_product["ledger"]["unknowns"]
        if u["severity"] == "blocking" and "未完成" in u["question"] and "不冒充通过" in u["question"]
    ]


# ---------------------------------------------------------------------------
# 1. Equivalence with the demo: same workflow, same bytes.
# ---------------------------------------------------------------------------


class TestEquivalenceWithDemo:
    def test_every_analysis_field_matches_the_demo(self, walked, demo_result) -> None:
        task, store = walked
        report = store.load_step(task.task_id, "report")
        for field in SHARED_BUNDLE_FIELDS:
            assert report["bundle"][field] == demo_result.bundle[field], field

    def test_report_markdown_is_byte_equal(self, walked, demo_result) -> None:
        task, store = walked
        report = store.load_step(task.task_id, "report")
        assert report["report_markdown"] == demo_result.report_markdown

    def test_metadata_block_records_the_orchestrator(self, walked) -> None:
        """The bundle says who ran it; that is the only intended difference."""
        task, store = walked
        bundle = store.load_step(task.task_id, "report")["bundle"]
        assert "demo" not in bundle
        assert bundle["orchestrator"]["version"] == taskrun.ORCHESTRATOR_VERSION
        assert bundle["orchestrator"]["mode"] == "plan_only"
        assert bundle["orchestrator"]["authorized"] is True

    def test_intel_channel_is_a_declared_unknown_not_an_empty_success(self, walked) -> None:
        task, store = walked
        bundle = store.load_step(task.task_id, "report")["bundle"]
        assert bundle["capability_intel"]["status"] == "not_attempted"
        assert "未检索" in bundle["capability_intel"]["reason"]

    def test_lifecycle_and_step_table(self, walked, demo_result) -> None:
        """Every step ran; the canary's blocking unknowns hold the gate -
        the same conclusion the demo's gate reaches."""
        task, store = walked
        assert [s.id for s in task.steps] == [spec.id for spec in WORKFLOW]
        assert all(s.status == STEP_DONE for s in task.steps)
        assert task.status == TASK_BLOCKED
        gate = store.load_step(task.task_id, "verified_gate")
        assert gate["status"] == "blocked"
        assert gate["blockers"] == demo_result.gate_blockers
        ledger_step = task.step("evidence_ledger")
        assert ledger_step.unknown_count == len(demo_result.ledger.to_dict()["unknowns"])

    def test_store_layout_is_one_file_per_completed_step(self, walked) -> None:
        task, store = walked
        task_dir = store.task_dir(task.task_id)
        assert (task_dir / "task.json").is_file()
        step_files = sorted(p.name for p in (task_dir / "steps").iterdir())
        assert step_files == sorted(f"{spec.id}.json" for spec in WORKFLOW)
        assert not list(task_dir.rglob("*.tmp")), "atomic writes must not leave temp files"


# ---------------------------------------------------------------------------
# 2. Resume: a crash loses at most the step in flight.
# ---------------------------------------------------------------------------


class TestResume:
    def test_crash_loses_at_most_the_step_in_flight(self, store, monkeypatch) -> None:
        calls: dict[str, int] = {}
        _flaky(monkeypatch, "observe_secrets", calls)
        _counted(monkeypatch, "observe", calls)
        _counted(monkeypatch, "observe_artifacts", calls)

        task = _run(store)
        assert task.step("secret_scan").status == STEP_FAILED
        assert "RuntimeError" in task.step("secret_scan").error
        assert task.step("report").status == STEP_SKIPPED_DEP
        assert "secret_scan" in task.step("report").error
        assert task.status == TASK_BLOCKED
        # 域失败不中断其他域
        assert task.step("symbol_scan").status == STEP_DONE
        # 账本仍是失败汇聚点
        ledger_product = store.load_step(task.task_id, "evidence_ledger")
        gap = _gap_unknowns(ledger_product)
        assert any(u["domain"] == "secret_scan" and "未完成（failed）" in u["question"] for u in gap)

        resumed = taskrun.resume_task(task.task_id, store=store, now=NOW)
        assert resumed.step("secret_scan").status == STEP_DONE
        assert resumed.step("report").status == STEP_DONE
        assert resumed.task_id == task.task_id
        # done 步骤零重跑：崩溃前完成的域各只被观察一次
        assert calls["observe"] == 1
        assert calls["observe_artifacts"] == 1
        assert calls["observe_secrets"] == 2  # 一次失败、一次恢复
        # 恢复后 gap unknown 被真实域报告取代
        ledger_after = store.load_step(resumed.task_id, "evidence_ledger")
        assert not any(u["domain"] == "secret_scan" for u in _gap_unknowns(ledger_after))

    def test_unchanged_inputs_re_run_nothing(self, store, monkeypatch) -> None:
        task = _run(store)
        calls: dict[str, int] = {}
        _counted(monkeypatch, "build_ledger", calls)
        _counted(monkeypatch, "observe", calls)
        _counted(monkeypatch, "render_markdown", calls)

        again = taskrun.run_assessment(REQUEST, CANARY, store=store, now=NOW, task=taskrun.get_task(task.task_id, store=store))
        assert calls == {}, "输入摘要未变时任何执行器都不该被调用"
        assert again.status == task.status

    def test_rerunning_a_domain_drags_its_soft_consumers(self, store, monkeypatch) -> None:
        """Soft-dep products feed the input digest: a domain re-run re-runs
        its soft consumers (the ledger), while the domain itself does not."""
        task = _run(store)
        before = store.load_step(task.task_id, "evidence_ledger")
        calls: dict[str, int] = {}
        _counted(monkeypatch, "build_ledger", calls)
        _counted(monkeypatch, "observe", calls)

        loaded = taskrun.get_task(task.task_id, store=store)
        loaded.step("recon").output_digest = "0" * 64  # 模拟上游域重跑后的新产物摘要
        store.save_task(loaded)
        rerun = taskrun.run_assessment(REQUEST, CANARY, store=store, now=NOW, task=loaded)

        assert calls.get("build_ledger") == 1, "账本（软消费者）应被带动重跑"
        assert calls.get("observe", 0) == 0, "recon 自身输入未变，不应重跑"
        assert rerun.step("recon").status == STEP_DONE
        # 输入相同则重跑产物逐字节相同（幂等）
        assert store.load_step(rerun.task_id, "evidence_ledger") == before

    def test_a_killed_process_resumes_from_the_in_flight_step(self, store, monkeypatch) -> None:
        """The design's acceptance, verbatim: "kill 进程后 resume_task 续跑
        成功". A SIGKILL leaves the in-flight step in ``running`` on disk -
        its input digest was flushed before execution started - so resume
        re-runs exactly that step and nothing that already finished.
        (KeyboardInterrupt is a BaseException: the scheduler's
        ``except Exception`` does not catch it, exactly like a signal.)
        """
        calls: dict[str, int] = {}
        _counted(monkeypatch, "observe", calls)
        original = taskrun.observe_artifacts

        def kill(*args: Any, **kwargs: Any) -> Any:
            calls["observe_artifacts"] = calls.get("observe_artifacts", 0) + 1
            if calls["observe_artifacts"] == 1:
                raise KeyboardInterrupt("simulated SIGKILL inside artifact_scan")
            return original(*args, **kwargs)

        monkeypatch.setattr(taskrun, "observe_artifacts", kill)
        with pytest.raises(KeyboardInterrupt):
            _run(store)

        killed = taskrun.list_tasks(store=store)[0]
        assert killed.status == TASK_RUNNING
        assert killed.step("recon").status == STEP_DONE
        assert killed.step("artifact_scan").status == STEP_RUNNING
        assert not store.step_path(killed.task_id, "artifact_scan").exists(), "在飞的一步没有产物"
        assert calls["observe"] == 1

        resumed = taskrun.resume_task(killed.task_id, store=store, now=NOW)
        assert resumed.task_id == killed.task_id, "恢复沿用同一任务，不新建"
        assert calls["observe"] == 1, "done 步骤零重跑"
        assert calls["observe_artifacts"] == 2, "在飞步从自身续跑（一次被杀、一次成功）"
        assert resumed.step("artifact_scan").status == STEP_DONE
        assert all(s.status == STEP_DONE for s in resumed.steps)

    def test_resume_of_done_task_refuses(self, store) -> None:
        task = _run(store)
        loaded = taskrun.get_task(task.task_id, store=store)
        loaded.status = TASK_DONE
        store.save_task(loaded)
        with pytest.raises(TaskBoundaryError, match="already done"):
            taskrun.resume_task(task.task_id, store=store)

    def test_resume_never_rewrites_the_recorded_request(self, store) -> None:
        """A task parked at the gate resumes into the same gate: the
        recorded request is the evidence basis, so an unauthorized task
        stays unauthorized until a *new* task is created."""
        task = _run(store, _unauthorized_request())
        assert task.status == TASK_BLOCKED
        resumed = taskrun.resume_task(task.task_id, store=store, now=NOW)
        assert resumed.status == TASK_BLOCKED
        assert resumed.request == _unauthorized_request()
        assert resumed.step("recon").status == STEP_SKIPPED_DEP
        assert "授权门未通过" in resumed.step("recon").error


# ---------------------------------------------------------------------------
# 3. Honest failure: no fabricated pass, no silent hole.
# ---------------------------------------------------------------------------


class TestFailureSemantics:
    def test_failed_domain_becomes_a_blocking_unknown(self, store, monkeypatch) -> None:
        monkeypatch.setattr(taskrun, "observe_native", _boom)
        task = _run(store)

        assert task.step("native_check").status == STEP_FAILED
        assert task.step("native_check").error == "RuntimeError: 按测试注入的域失败"
        # 账本汇编完成，且把未完成域记为 blocking unknown
        ledger_product = store.load_step(task.task_id, "evidence_ledger")
        gap = [u for u in _gap_unknowns(ledger_product) if u["domain"] == "native_check"]
        assert gap, "未评估的面必须阻塞， severity 是编排规则而非域措辞"
        assert "未完成（failed）" in gap[0]["question"]
        assert ledger_product["gate_blockers"], "blocking unknown 未消解，门必须保持关闭"
        gate = store.load_step(task.task_id, "verified_gate")
        assert gate["status"] == "blocked"
        assert task.status == TASK_BLOCKED
        # 其他域不中断；native_check 对报告只是软依赖，报告照常渲染
        assert task.step("secret_scan").status == STEP_DONE
        assert task.step("report").status == STEP_DONE
        report = store.load_step(task.task_id, "report")
        assert "未运行" in report["report_markdown"]
        assert "不冒充通过" in report["report_markdown"]
        # bundle 的 domains 只含已完成的域；缺失面在报告章节里诚实显示，不混入产物键
        assert "native_check" not in report["bundle"]["domains"]
        assert "native_check" in report["bundle"]["domains"] or "未运行" in report["report_markdown"]

    def test_report_skips_when_a_rendered_input_is_missing(self, store, monkeypatch) -> None:
        """The report is the success artifact: a missing truth-rendering
        input skips it (named) instead of rendering around a hole."""
        monkeypatch.setattr(taskrun, "observe_secrets", _boom)
        task = _run(store)

        assert task.step("secret_scan").status == STEP_FAILED
        assert task.step("report").status == STEP_SKIPPED_DEP
        assert "secret_scan" in task.step("report").error
        assert not (store.task_dir(task.task_id) / "steps" / "report.json").exists()
        # 失败被记录，但不是被跳过：账本与门仍然运行
        assert task.step("evidence_ledger").status == STEP_DONE
        assert task.step("verified_gate").status == STEP_DONE
        ledger_product = store.load_step(task.task_id, "evidence_ledger")
        assert any(u["domain"] == "secret_scan" and u["severity"] == "blocking" for u in ledger_product["ledger"]["unknowns"])

    def test_a_failed_domain_cascades_named_skips(self, store, monkeypatch) -> None:
        """Downstream steps are skipped-dep with the failing dep named -
        never silently dropped, never re-run against a missing input."""
        monkeypatch.setattr(taskrun, "observe_artifacts", _boom)
        task = _run(store)

        assert task.step("artifact_scan").status == STEP_FAILED
        for step_id in ("symbol_scan", "native_check", "dart_aot_check", "build_integration", "attack_simulation", "report"):
            state = task.step(step_id)
            assert state.status == STEP_SKIPPED_DEP, step_id
            assert "artifact_scan" in state.error, step_id
        # 跳过链上的每个面都成为 blocking unknown，且用 demo 的域键
        ledger_product = store.load_step(task.task_id, "evidence_ledger")
        gap_domains = {u["domain"] for u in _gap_unknowns(ledger_product)}
        assert {"artifact_manifest", "string_symbol_scan", "native_check", "dart_aot_check", "build_integration"} <= gap_domains


# ---------------------------------------------------------------------------
# 4. The authorization gate parks: no read before authorization.
# ---------------------------------------------------------------------------


class TestGateParks:
    def test_unauthorized_task_parks_at_the_gate(self, store, monkeypatch) -> None:
        calls: dict[str, int] = {}
        _counted(monkeypatch, "observe", calls)
        _counted(monkeypatch, "observe_artifacts", calls)
        _counted(monkeypatch, "observe_secrets", calls)

        task = _run(store, _unauthorized_request())

        assert task.step("authorization_gate").status == STEP_DONE
        assert calls == {}, "授权确认前零项目读取"
        for spec in WORKFLOW[1:]:
            state = task.step(spec.id)
            assert state.status == STEP_SKIPPED_DEP, spec.id
            assert "授权门未通过" in state.error, spec.id
        assert task.status == TASK_BLOCKED
        gate_output = store.load_step(task.task_id, "authorization_gate")
        assert gate_output["authorized"] is False
        assert gate_output["blocking"]["code"] == "authorization_not_confirmed"
        # 磁盘上只有审批门自己的产物
        files = sorted(p.name for p in (store.task_dir(task.task_id) / "steps").iterdir())
        assert files == ["authorization_gate.json"]

    def test_parking_is_idempotent(self, store) -> None:
        task = _run(store, _unauthorized_request())
        gate_spec = WORKFLOW[0]
        assert taskrun._gate_parks(task, store, gate_spec) is True
        assert taskrun._gate_parks(task, store, gate_spec) is True
        assert task.step("recon").status == STEP_SKIPPED_DEP
        assert "授权门未通过" in task.step("recon").error
        # 非审批门步骤与已授权任务的门都不会触发停车
        assert taskrun._gate_parks(task, store, WORKFLOW[1]) is False
        authorized = _run(store)
        assert taskrun._gate_parks(authorized, store, gate_spec) is False

    def test_pending_gate_does_not_park(self, store) -> None:
        task = taskrun.create_task(REQUEST, CANARY, store=store, now=NOW)
        assert task.status == TASK_CREATED
        assert all(s.status == STEP_PENDING for s in task.steps)
        assert not (store.task_dir(task.task_id) / "steps").exists()
        assert taskrun._gate_parks(task, store, WORKFLOW[0]) is False


# ---------------------------------------------------------------------------
# 5. The store: durable, atomic, named boundaries.
# ---------------------------------------------------------------------------


class TestTaskStore:
    def test_task_id_is_a_filename_component(self, store) -> None:
        assert taskrun.valid_task_id("task-12345678")
        assert taskrun.valid_task_id("task-abcdef01")
        for bad in ("", "task", "task-xyz", "task-1234567", "task-123456789", "TASK-12345678", "../escape", "task-1234567/"):
            assert not taskrun.valid_task_id(bad), bad
            with pytest.raises(TaskBoundaryError):
                store.task_dir(bad)

    def test_unknown_step_is_refused(self, store) -> None:
        with pytest.raises(TaskBoundaryError, match="unknown workflow step"):
            store.step_path("task-12345678", "not_a_step")

    def test_load_missing_task_is_named(self, store) -> None:
        with pytest.raises(TaskBoundaryError, match="not found"):
            store.load_task("task-deadbeef")

    def test_round_trip_and_digests(self, store) -> None:
        task = taskrun.create_task(REQUEST, CANARY, store=store, now=NOW)
        assert store.load_task(task.task_id) == task
        digest = store.save_step(task.task_id, "authorization_gate", {"authorized": True})
        assert len(digest) == 64 and digest == store.save_step(task.task_id, "authorization_gate", {"authorized": True})
        assert store.load_step(task.task_id, "authorization_gate") == {"authorized": True}
        assert not list(store.task_dir(task.task_id).rglob("*.tmp"))

    def test_list_tasks_is_sorted(self, store) -> None:
        first = taskrun.create_task(REQUEST, CANARY, store=store, now=NOW)
        second = taskrun.create_task(REQUEST, CANARY, store=store, now=NOW)
        assert first.task_id != second.task_id
        listed = [t.task_id for t in store.list_tasks()]
        assert listed == sorted([first.task_id, second.task_id])

    def test_task_json_records_the_full_step_table(self, walked) -> None:
        task, store = walked
        data = json.loads(store.task_path(task.task_id).read_text(encoding="utf-8"))
        assert data["orchestrator_version"] == taskrun.ORCHESTRATOR_VERSION
        assert [s["id"] for s in data["steps"]] == [spec.id for spec in WORKFLOW]
        assert data["project_path"] == str(CANARY)
        assert data["request"] == REQUEST
        # 步骤记录自描述：依赖随记录落盘，任务文件 alone 可还原其工作流形状
        by_id = {s["id"]: s for s in data["steps"]}
        assert by_id["recon"]["depends"] == ["authorization_gate"]
        assert by_id["recon"]["soft"] == []
        ledger_record = by_id["evidence_ledger"]
        assert ledger_record["depends"] == ["authorization_gate", "plan"]
        assert "attack_simulation" in ledger_record["soft"]
        assert by_id["report"]["depends"] == list(_STEP_SPECS["report"].depends)


# ---------------------------------------------------------------------------
# 6. The composition layer: the four tools over the same store.
# ---------------------------------------------------------------------------


def _ctx(**kwargs: Any) -> ToolContext:
    base: dict[str, Any] = {
        "authorized_root": CANARY,
        "authorization": "owner",
        "now": NOW,
        "task_store": None,
    }
    base.update(kwargs)
    return ToolContext(**base)


class TestCompositionLayer:
    def test_missing_store_refuses_every_task_tool(self, tmp_path: Path) -> None:
        ctx = _ctx()
        for name, args in (
            ("pea.run_assessment", {"request": REQUEST, "project_path": str(CANARY)}),
            ("pea.get_task", {"task_id": "task-12345678"}),
            ("pea.list_tasks", {}),
            ("pea.resume_task", {"task_id": "task-12345678", "authorization": "owner"}),
        ):
            result = call_tool(name, args, ctx)
            assert result.ok is False, name
            assert result.error == "task_store_missing", name

    def test_run_assessment_through_the_tool_surface(self, tmp_path: Path) -> None:
        ctx = _ctx(task_store=tmp_path / "tasks")
        result = call_tool("pea.run_assessment", {"request": REQUEST, "project_path": str(CANARY)}, ctx)
        assert result.ok, result.detail
        data = result.data
        assert data["status"] == TASK_BLOCKED  # canary 的 blocking unknown 顶住门
        assert data["project_path"] == str(CANARY)
        assert data["step_counts"] == {"total": STEP_COUNT, "done": STEP_COUNT, "failed": 0, "skipped_dep": 0, "pending": 0}
        assert len(data["steps"]) == STEP_COUNT
        assert data["report_markdown"].startswith("# PEA")

    def test_get_and_list(self, tmp_path: Path) -> None:
        ctx = _ctx(task_store=tmp_path / "tasks")
        run = call_tool("pea.run_assessment", {"request": REQUEST, "project_path": str(CANARY)}, ctx)
        task_id = run.data["task_id"]

        got = call_tool("pea.get_task", {"task_id": task_id}, ctx)
        assert got.ok and got.data["task_id"] == task_id
        assert got.data["steps"] == run.data["steps"]

        listed = call_tool("pea.list_tasks", {}, ctx)
        assert listed.ok
        assert [t["task_id"] for t in listed.data["tasks"]] == [task_id]
        assert "steps" not in listed.data["tasks"][0], "list 不回放步骤表"

    def test_get_task_refusals_are_named(self, tmp_path: Path) -> None:
        ctx = _ctx(task_store=tmp_path / "tasks")
        bad_id = call_tool("pea.get_task", {"task_id": "not-a-task-id"}, ctx)
        assert bad_id.error == "task_id_invalid"
        unknown = call_tool("pea.get_task", {"task_id": "task-12345678"}, ctx)
        assert unknown.error == "task_id_unknown"

    def test_resume_refuses_to_switch_the_analysis_subject(self, tmp_path: Path) -> None:
        ctx = _ctx(task_store=tmp_path / "tasks")
        run = call_tool("pea.run_assessment", {"request": REQUEST, "project_path": str(CANARY)}, ctx)
        task_id = run.data["task_id"]

        other_root = _ctx(task_store=tmp_path / "tasks", authorized_root=tmp_path)
        result = call_tool("pea.resume_task", {"task_id": task_id, "authorization": "owner"}, other_root)
        assert result.ok is False
        assert result.error == "path_outside_authorized_root"

    def test_resume_continues_a_gate_closed_task(self, tmp_path: Path) -> None:
        ctx = _ctx(task_store=tmp_path / "tasks")
        run = call_tool("pea.run_assessment", {"request": REQUEST, "project_path": str(CANARY)}, ctx)
        task_id = run.data["task_id"]
        resumed = call_tool("pea.resume_task", {"task_id": task_id, "authorization": "owner"}, ctx)
        assert resumed.ok, resumed.detail
        assert resumed.data["status"] == TASK_BLOCKED
        assert resumed.data["step_counts"]["done"] == STEP_COUNT

    def test_resume_of_done_task_refuses(self, tmp_path: Path) -> None:
        ctx = _ctx(task_store=tmp_path / "tasks")
        run = call_tool("pea.run_assessment", {"request": REQUEST, "project_path": str(CANARY)}, ctx)
        task_id = run.data["task_id"]
        store = TaskStore(ctx.task_store)
        done = store.load_task(task_id)
        done.status = TASK_DONE
        store.save_task(done)
        result = call_tool("pea.resume_task", {"task_id": task_id, "authorization": "owner"}, ctx)
        assert result.ok is False
        assert result.error == "task_already_done"

    def test_unauthorized_context_never_reaches_the_store(self, tmp_path: Path) -> None:
        ctx = _ctx(task_store=tmp_path / "tasks", authorization="not_confirmed")
        result = call_tool("pea.run_assessment", {"request": REQUEST, "project_path": str(CANARY)}, ctx)
        assert result.ok is False
        assert result.error == "authorization_not_confirmed"
        assert not (tmp_path / "tasks").exists() or not any((tmp_path / "tasks").glob("task-*"))


# ---------------------------------------------------------------------------
# 7. The CLI: the same library, exit-code discipline.
# ---------------------------------------------------------------------------


class TestCliTask:
    def _request_file(self, tmp_path: Path, request: dict[str, Any] | None = None) -> Path:
        path = tmp_path / "request.json"
        path.write_text(json.dumps(request or REQUEST, ensure_ascii=False), encoding="utf-8")
        return path

    def test_run_exports_report_and_bundle(self, tmp_path: Path) -> None:
        store = tmp_path / "tasks"
        out = tmp_path / "out"
        code = main(
            [
                "task",
                "run",
                "--request",
                str(self._request_file(tmp_path)),
                "--project",
                str(CANARY),
                "--store",
                str(store),
                "--out",
                str(out),
            ]
        )
        assert code == 3  # blocked：canary 的 blocking unknown 顶住 verified 门
        report = (out / "report.md").read_text(encoding="utf-8")
        bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
        assert report.startswith("# PEA")
        assert bundle["orchestrator"]["authorized"] is True
        assert report == bundle["report_markdown"]

    def test_run_unauthorized_refuses_without_creating_a_task(self, tmp_path: Path, capsys) -> None:
        request_path = tmp_path / "unauthorized.json"
        request_path.write_text(json.dumps(_unauthorized_request(), ensure_ascii=False), encoding="utf-8")
        store = tmp_path / "tasks"
        code = main(["task", "run", "--request", str(request_path), "--project", str(CANARY), "--store", str(store)])
        assert code == 4
        assert "未确认" in capsys.readouterr().err
        assert not any(store.glob("task-*")), "授权未确认不得创建任务"

    def test_status_list_report_round_trip(self, tmp_path: Path, capsys) -> None:
        store = tmp_path / "tasks"
        assert main(["task", "run", "--request", str(self._request_file(tmp_path)), "--project", str(CANARY), "--store", str(store)]) == 3

        assert main(["task", "list", "--store", str(store)]) == 0
        listed = json.loads(capsys.readouterr().out)
        assert listed["count"] == 1
        task_id = listed["tasks"][0]["task_id"]

        assert main(["task", "status", task_id, "--store", str(store)]) == 3
        status = json.loads(capsys.readouterr().out)
        assert status["task_id"] == task_id
        assert status["status"] == TASK_BLOCKED

        out = tmp_path / "export"
        assert main(["task", "report", task_id, "--store", str(store), "--out", str(out)]) == 0
        assert (out / "report.md").is_file()
        assert (out / "bundle.json").is_file()

    def test_report_without_a_report_step_is_a_named_error(self, tmp_path: Path, monkeypatch, capsys) -> None:
        """A task whose report step was skipped exports nothing - the CLI
        says so instead of writing an empty file."""
        store = TaskStore(tmp_path / "tasks")
        monkeypatch.setattr(taskrun, "observe_secrets", _boom)
        task = _run(store)
        assert task.step("report").status == STEP_SKIPPED_DEP

        code = main(["task", "report", task.task_id, "--store", str(store.root), "--out", str(tmp_path / "out")])
        assert code == 2
        assert "没有已完成的 report 步骤" in capsys.readouterr().err

    def test_status_unknown_id_is_a_named_boundary_error(self, tmp_path: Path, capsys) -> None:
        code = main(["task", "status", "task-12345678", "--store", str(tmp_path / "tasks")])
        assert code == 2
        assert "error" in capsys.readouterr().err
