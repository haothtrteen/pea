"""WP0 信任边界验收（方案 §2.3 五条，先钉后写）。

原则一句话：**模型给的 Boolean 不是授权**。执行类操作的授权根来自运营者
环境（PEA_AUTHORIZED_ROOTS），审批事件来自可信通道（CLI 交互确认 /
``pea approve``），二者都在模型控制面之外。这五条把该原则钉成机械判据：

1. agent 自述授权（owner + explicit_user_approval）请求执行 → 被拒；
2. 运营者配置根之外的路径 → path_outside_authorized_root；
3. 未配置 PEA_AUTHORIZED_ROOTS → 执行器 execution_roots_unconfigured，
   只读工具照常；
4. CLI 交互确认流程 → 审批事件登记 → 令牌签发成功；同指纹二次审批 → 拒绝；
5. 审批事件与令牌六元组任一不符 → 拒绝。
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from pea import protect
from pea.approval import ApprovalAuthority
from pea.mcpserver import ToolContext, call_tool

PLAN = {
    "plan_id": "plan-wp0",
    "selected_catalog_ids": ["javascript-obfuscator"],
}


def _js_project(root: Path) -> Path:
    proj = root / "proj"
    proj.mkdir(parents=True)
    (proj / "package.json").write_text(json.dumps({"name": "wp0", "scripts": {"test": "node --test"}}), encoding="utf-8")
    (proj / "license.js").write_text("const KEY = 'sk-live-wp0';\nmodule.exports = { KEY };\n", encoding="utf-8")
    return proj


def _save_plan(tmp_path: Path, project: Path) -> None:
    protect.PlanStore(tmp_path / "store" / "plans").save({**PLAN, "project_path": str(project)})


def _ctx(tmp_path: Path, *, roots: tuple[Path, ...], project: Path, event_store: Path | None = None, explicit: bool = True) -> ToolContext:
    return ToolContext(
        authorized_root=project,
        authorization="owner",
        approvals=ApprovalAuthority(secret=b"wp0-secret", event_store=event_store),
        now="2026-10-15T00:00:00+00:00",
        explicit_approval=explicit,
        execution_roots=roots,
        run_store=tmp_path / "store",
    )


class TestAgentCannotSelfAuthorize:
    def test_self_declared_authorization_cannot_execute(self, tmp_path) -> None:
        """§2.3-1: the agent sends owner + explicit_user_approval with valid
        arguments - review parks, no token exists, and a fabricated token is
        refused at the consumption point."""
        project = _js_project(tmp_path)
        _save_plan(tmp_path, project)
        ctx = _ctx(tmp_path, roots=(project,), project=project)

        parked = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)
        assert parked.ok, parked.detail
        assert parked.data["status"] == "awaiting_approval"
        assert "approval_token" not in parked.data

        # A forged token id never reaches a handler: consumption refuses it.
        forged = call_tool(
            "pea.apply_plan",
            {"plan_id": PLAN["plan_id"], "approval_token": "forged-token", "expected_plan_digest": "whatever"},
            ctx,
        )
        assert not forged.ok and forged.error == "token_unknown"

    def test_review_without_explicit_intent_is_refused(self, tmp_path) -> None:
        project = _js_project(tmp_path)
        _save_plan(tmp_path, project)
        ctx = _ctx(tmp_path, roots=(project,), project=project, explicit=False)
        result = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"]}, ctx)
        assert not result.ok and result.error == "explicit_approval_missing"


class TestConfiguredBoundary:
    def test_path_outside_configured_roots_is_refused(self, tmp_path) -> None:
        """§2.3-2: the plan's target must sit inside an operator-configured
        root; a plan scoped elsewhere is refused at review, before any
        approval scope is even derived."""
        inside = _js_project(tmp_path)
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        (outside / "license.js").write_text("const KEY = 'sk-live-out';\n", encoding="utf-8")
        protect.PlanStore(tmp_path / "store" / "plans").save({**PLAN, "project_path": str(outside)})
        ctx = _ctx(tmp_path, roots=(inside,), project=inside)

        result = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)
        assert not result.ok and result.error == "path_outside_authorized_root"

    def test_unconfigured_roots_close_the_execution_face(self, tmp_path) -> None:
        """§2.3-3: with PEA_AUTHORIZED_ROOTS unset the four executors refuse
        with execution_roots_unconfigured; the read-only face is unchanged."""
        project = _js_project(tmp_path)
        _save_plan(tmp_path, project)
        # A real token exists (issued through the trusted channel while roots
        # were configured) - the execution face is still closed without them.
        # The same authority instance carries the token: tokens are
        # per-process by design, and this test is about the root gate.
        configured = _ctx(tmp_path, roots=(project,), project=project, event_store=tmp_path / "approvals")
        parked = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, configured)
        configured.approvals.register_approval(fingerprint=parked.data["fingerprint"])
        issued = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, configured)
        token = issued.data["approval_token"]
        digest = issued.data["plan_digest"]

        ctx = dataclasses.replace(configured, execution_roots=())

        for tool, args in (
            ("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}),
            ("pea.apply_plan", {"plan_id": PLAN["plan_id"], "approval_token": token, "expected_plan_digest": digest}),
            ("pea.verify_output", {"run_id": "run-x", "test_profile": "p", "preview_confirmed": True}),
            ("pea.compare_results", {"baseline_run_id": "a", "candidate_run_id": "b", "preview_confirmed": True}),
            ("pea.rollback", {"run_id": "run-x", "mode": "discard", "explicit_user_approval": True}),
        ):
            result = call_tool(tool, args, ctx)
            assert not result.ok, f"{tool} must refuse with the execution face closed"
            assert result.error == "execution_roots_unconfigured", f"{tool}: {result.error}"

        read_only = call_tool("pea.scan_secrets", {"project_path": str(project), "authorization": "owner"}, ctx)
        assert read_only.ok, read_only.detail


class TestTrustedChannelFlow:
    def test_cli_confirmation_issues_one_token(self, tmp_path) -> None:
        """§2.3-4: the trusted channel registers the event; issuance
        succeeds exactly once - the event is consumed by the issuance, so a
        second review finds nothing to approve and parks again (one
        approval, one token)."""
        project = _js_project(tmp_path)
        _save_plan(tmp_path, project)
        ctx = _ctx(tmp_path, roots=(project,), project=project, event_store=tmp_path / "approvals")

        parked = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)
        fingerprint = parked.data["fingerprint"]

        ctx.approvals.register_approval(fingerprint=fingerprint, decided_by="cli:interactive")
        issued = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)
        assert issued.ok and issued.data["status"] == "approved"
        assert issued.data["approval_token"]

        # The event was consumed by the issuance: nothing left to approve.
        assert ctx.approvals.approval_for(fingerprint) is None
        second = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)
        assert second.ok and second.data["status"] == "awaiting_approval"
        assert "approval_token" not in second.data

    def test_operator_shell_approval_crosses_processes(self, tmp_path) -> None:
        """The same event store serves a *different* process: the operator's
        shell registers, the server-side authority finds it and issues."""
        project = _js_project(tmp_path)
        _save_plan(tmp_path, project)
        store = tmp_path / "approvals"
        ctx = _ctx(tmp_path, roots=(project,), project=project, event_store=store)
        parked = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)

        # A separate process (pea approve) writes the event to the same store.
        operator = ApprovalAuthority(event_store=store)
        operator.register_approval(fingerprint=parked.data["fingerprint"], decided_by="cli:approve")

        issued = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)
        assert issued.ok and issued.data["status"] == "approved"
        # consumed on disk: one approval, one token, even across processes
        assert operator.approval_for(parked.data["fingerprint"]) is None


class TestEventScopeBinding:
    def test_event_for_a_different_scope_is_refused(self, tmp_path) -> None:
        """§2.3-5: an event approving scope X cannot issue a token for scope
        Y - not even one field apart."""
        project = _js_project(tmp_path)
        _save_plan(tmp_path, project)
        ctx = _ctx(tmp_path, roots=(project,), project=project, event_store=tmp_path / "approvals")
        parked = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)

        other = ctx.approvals.register_approval(fingerprint="0" * 32, decided_by="cli:interactive")
        with pytest.raises(Exception) as exc:
            ctx.approvals.issue(
                tool="pea.apply_plan",
                plan_digest=parked.data["plan_digest"],
                artifact_digest="",
                args_digest="0" * 64,
                tool_version="1.0.0",
                authorized_root=project,
                target_path=project,
                approval_event=other,
            )
        assert exc.value.reason == "approval_scope_mismatch"

    def test_review_requires_a_plan_store(self, tmp_path) -> None:
        project = _js_project(tmp_path)
        ctx = ToolContext(
            authorized_root=project,
            authorization="owner",
            approvals=ApprovalAuthority(secret=b"wp0-secret"),
            explicit_approval=True,
            execution_roots=(project,),
            run_store=None,
        )
        result = call_tool("pea.review_plan", {"plan_id": PLAN["plan_id"], "explicit_user_approval": True}, ctx)
        assert not result.ok and result.error == "run_store_missing"
