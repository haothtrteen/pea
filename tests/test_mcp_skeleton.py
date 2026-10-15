"""Tests for the MCP skeleton: registry generation, approval tokens, dispatch.

Phase 3 acceptance, verbatim: "计划变化、令牌过期/重放、路径越界都拒绝."
Each of those gets a test here, plus the generation-drift guards that keep
the two contract JSONs equal to the registry, and the dispatch refusals
that keep unwired tools from pretending to exist.

WP0 adds the trust-boundary layer these tests now encode: token issuance
requires a trusted-channel approval event for the exact scope, and
review_plan parks at awaiting_approval until one exists. WP3 wired the
four executors, so the contract-only set is empty and the token flow runs
against the real gate instead of a simulated one.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

import pytest

from pea import mcpserver, protect, tooleffects
from pea.approval import ApprovalAuthority, ApprovalError, ApprovalScope, args_digest, scope_fingerprint
from pea.mcpserver import ToolContext, call_tool

ROOT = Path(__file__).resolve().parents[1]
CANARY = ROOT / "demo" / "canary-flutter-licensing"
REQUEST = json.loads((ROOT / "examples" / "protection-request.flutter-licensing.example.json").read_text(encoding="utf-8"))
NOW = "2026-10-13T00:00:00+00:00"

START = datetime(2026, 10, 13, tzinfo=timezone.utc)


def _authority(**kwargs) -> ApprovalAuthority:
    clock = kwargs.pop("clock", None) or (lambda: START)
    return ApprovalAuthority(secret=b"test-secret", clock=clock, **kwargs)


def _approve(authority: ApprovalAuthority, **scope) -> Any:
    """The trusted channel approves exactly ``scope``: register the event the
    fingerprint of those fields denotes and return it. WP0 made this a hard
    precondition of issuance - a caller's flags are intent, this is approval."""
    fingerprint = scope_fingerprint(
        tool=scope["tool"],
        plan_digest=scope["plan_digest"],
        artifact_digest=scope["artifact_digest"],
        args_digest=scope["args_digest"],
        tool_version=scope["tool_version"],
        authorized_root=scope["authorized_root"],
        target_path=scope["target_path"],
    )
    return authority.register_approval(fingerprint=fingerprint)


def _ctx(**kwargs) -> ToolContext:
    base = {
        "authorized_root": CANARY,
        "authorization": "owner",
        "approvals": _authority(),
        "now": NOW,
    }
    base.update(kwargs)
    return ToolContext(**base)


class TestRegistryGeneration:
    def test_availability_metadata_matches_the_handler_table(self) -> None:
        assert set(tooleffects.wired_tools()) == set(mcpserver.HANDLERS)
        assert set(tooleffects.contract_only_tools()) == set(tooleffects.TOOL_EFFECTS) - set(mcpserver.HANDLERS)

    def test_contract_only_tools_declare_a_zero_version(self) -> None:
        for name in tooleffects.contract_only_tools():
            assert tooleffects.effects_for(name).version == "0.0.0", name

    def test_error_codes_are_unique_and_namespaced(self) -> None:
        for name, tool in tooleffects.TOOL_EFFECTS.items():
            assert len(tool.error_codes) == len(set(tool.error_codes)), name
            for code in tool.error_codes:
                assert code == code.lower() and " " not in code, f"{name}: {code}"


class TestApprovalTokenLifecycle:
    #: The scope fields every issuance in this class covers. WP0: issuance
    #: additionally requires a trusted approval event for exactly these
    #: fields - the helper below registers it.
    SCOPE: ClassVar[dict[str, Any]] = {
        "tool": "pea.apply_plan",
        "plan_digest": "plan-abc",
        "artifact_digest": "art-abc",
        "args_digest": args_digest({"plan_id": "p1"}),
        "tool_version": "0.0.0",
        "authorized_root": CANARY,
        "target_path": CANARY,
    }

    def _issue(self, authority: ApprovalAuthority, **overrides) -> Any:
        scope = {**self.SCOPE, **overrides}
        event = _approve(authority, **scope)
        return authority.issue(**scope, approval_event=event)

    def _scope(self, **overrides) -> ApprovalScope:
        fields = {
            "tool": "pea.apply_plan",
            "plan_digest": "plan-abc",
            "artifact_digest": "art-abc",
            "args_digest": args_digest({"plan_id": "p1"}),
            "tool_version": "0.0.0",
            "authorized_root": str(CANARY),
            "target_path": str(CANARY),
            "issued_at": START,
            "expires_at": START + timedelta(seconds=900),
        }
        fields.update(overrides)
        return ApprovalScope(**fields)

    def test_issue_then_consume(self) -> None:
        authority = _authority()
        token = self._issue(authority)
        consumed = authority.consume(token.token_id, self._scope())
        assert consumed.plan_digest == "plan-abc"
        assert authority.outstanding() == ()

    def test_issuance_without_an_approval_event_is_refused(self) -> None:
        """WP0: the model's flags are not approval. Issuance requires a
        trusted-channel event for the exact scope."""
        authority = _authority()
        with pytest.raises(ApprovalError) as exc:
            authority.issue(**self.SCOPE)
        assert exc.value.reason == "approval_event_missing"

    def test_replay_is_refused(self) -> None:
        authority = _authority()
        token = self._issue(authority)
        authority.consume(token.token_id, self._scope())
        with pytest.raises(ApprovalError) as exc:
            authority.consume(token.token_id, self._scope())
        assert exc.value.reason == "token_replayed"

    def test_expiry_is_refused(self) -> None:
        now = {"t": START}
        authority = _authority(clock=lambda: now["t"])
        token = self._issue(authority)
        now["t"] = START + timedelta(seconds=901)
        with pytest.raises(ApprovalError) as exc:
            authority.consume(token.token_id, self._scope())
        assert exc.value.reason == "token_expired"

    def test_plan_change_is_refused(self) -> None:
        authority = _authority()
        token = self._issue(authority)
        with pytest.raises(ApprovalError) as exc:
            authority.consume(token.token_id, self._scope(plan_digest="plan-changed"))
        assert exc.value.reason == "scope_mismatch"
        assert "plan_digest" in exc.value.detail

    def test_argument_change_is_refused(self) -> None:
        authority = _authority()
        token = self._issue(authority)
        with pytest.raises(ApprovalError) as exc:
            authority.consume(token.token_id, self._scope(args_digest=args_digest({"plan_id": "p1", "extra": True})))
        assert exc.value.reason == "scope_mismatch"
        assert "args_digest" in exc.value.detail

    def test_tool_version_change_is_refused(self) -> None:
        authority = _authority()
        token = self._issue(authority, tool_version="1.0.0")
        with pytest.raises(ApprovalError) as exc:
            authority.consume(token.token_id, self._scope(tool_version="1.0.1"))
        assert exc.value.reason == "scope_mismatch"

    def test_path_escape_is_refused_at_issue(self, tmp_path) -> None:
        authority = _authority()
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        with pytest.raises(ApprovalError) as exc:
            authority.issue(**{**self.SCOPE, "target_path": outside})
        assert exc.value.reason == "path_outside_authorized_root"

    def test_different_root_at_consume_is_refused(self, tmp_path) -> None:
        authority = _authority()
        other = tmp_path / "other-root"
        other.mkdir()
        token = self._issue(authority)
        with pytest.raises(ApprovalError) as exc:
            authority.consume(token.token_id, self._scope(authorized_root=str(other), target_path=str(other)))
        assert exc.value.reason == "scope_mismatch"

    def test_unknown_token_is_refused(self) -> None:
        authority = _authority()
        with pytest.raises(ApprovalError) as exc:
            authority.consume("no-such-token", self._scope())
        assert exc.value.reason == "token_unknown"

    def test_two_issues_of_one_scope_get_distinct_ids(self) -> None:
        authority = _authority()
        # One approval, one token: two issuances of one scope need two events.
        first = self._issue(authority)
        second = self._issue(authority)
        assert first.token_id != second.token_id
        # consuming the first must not look like a replay of the second
        authority.consume(first.token_id, self._scope())
        authority.consume(second.token_id, self._scope())

    def test_one_event_issues_exactly_one_token(self, tmp_path) -> None:
        """The event is consumed by the issuance - a second issue for the
        same scope is refused even though the caller asks identically."""
        authority = _authority(event_store=tmp_path / "approvals")
        first = self._issue(authority)
        with pytest.raises(ApprovalError) as exc:
            authority.issue(**self.SCOPE)
        assert exc.value.reason == "approval_event_missing"
        assert first.token_id

    def test_event_for_a_different_scope_is_refused(self, tmp_path) -> None:
        authority = _authority(event_store=tmp_path / "approvals")
        event = _approve(authority, **{**self.SCOPE, "plan_digest": "plan-other"})
        with pytest.raises(ApprovalError) as exc:
            authority.issue(**self.SCOPE, approval_event=event)
        assert exc.value.reason == "approval_scope_mismatch"


class TestDispatch:
    def test_unknown_tool_is_a_named_refusal(self) -> None:
        result = call_tool("pea.does_not_exist", {}, _ctx())
        assert not result.ok and result.error == "unknown_tool"

    def test_all_contract_tools_are_wired(self) -> None:
        """WP3 §3.4: the four executors left the contract-only set - every
        contracted tool now has an implementation, and ``tool_not_wired``
        applies to none of them."""
        assert tooleffects.contract_only_tools() == ()
        assert set(tooleffects.wired_tools()) == set(mcpserver.HANDLERS)
        for name in ("pea.apply_plan", "pea.verify_output", "pea.compare_results", "pea.rollback"):
            assert tooleffects.effects_for(name).version == tooleffects.WIRED_VERSION, name

    def test_unwired_tool_refuses_without_burning_approval(self, monkeypatch) -> None:
        """A tool with no implementation must refuse before approval is
        consumed - otherwise a failed call would destroy a valid one-time
        approval for nothing. (WP3 wired every executor, so the guard is
        exercised synthetically by removing a handler.)"""
        monkeypatch.delitem(mcpserver.HANDLERS, "pea.apply_plan")
        ctx = _ctx(explicit_approval=True)
        result = call_tool(
            "pea.apply_plan",
            {"plan_id": "p1", "approval_token": "t", "expected_plan_digest": "d"},
            ctx,
        )
        assert not result.ok and result.error == "tool_not_wired"

    def test_read_only_tool_requires_authorization(self) -> None:
        result = call_tool("pea.check_native", {"project_path": str(CANARY)}, _ctx(authorization="not_confirmed"))
        assert not result.ok and result.error == "authorization_not_confirmed"

    def test_path_outside_authorized_root_is_refused(self, tmp_path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        result = call_tool("pea.check_native", {"project_path": str(outside)}, _ctx())
        assert not result.ok and result.error == "path_outside_authorized_root"

    def test_domain_tool_runs_on_the_canary(self) -> None:
        result = call_tool("pea.check_native", {"project_path": str(CANARY)}, _ctx())
        assert result.ok, result.detail
        # The canary has no build output: the domain degrades to a declared
        # unknown instead of a fabricated pass.
        assert result.data["coverage"]["state"] in {"not_run", "complete_for_scope"}
        assert any("未发现" in u or "no " in u.lower() for u in result.data["unknowns"]) or result.data["coverage"]["state"] == "not_run"

    def test_review_plan_requires_explicit_approval(self) -> None:
        result = call_tool("pea.review_plan", {"plan_id": "p1", "plan_digest": "d"}, _ctx())
        assert not result.ok and result.error == "explicit_approval_missing"

    def test_review_then_apply_token_flow(self, tmp_path, monkeypatch) -> None:
        """The WP0 gate end to end through dispatch: review parks at
        awaiting_approval until a trusted event exists; the event issues
        exactly one token; apply consumes it once - replay is refused at the
        consumption point."""
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "package.json").write_text(json.dumps({"name": "x", "scripts": {"test": "node --test"}}), encoding="utf-8")
        (proj / "license.js").write_text("const KEY = 'sk-live-x';\nmodule.exports = { KEY };\n", encoding="utf-8")
        plan = {
            "plan_id": "plan-test",
            "selected_catalog_ids": ["javascript-obfuscator"],
            "project_path": str(proj),
        }
        ctx = _ctx(
            authorized_root=proj,
            explicit_approval=True,
            execution_roots=(proj,),
            run_store=tmp_path / "store",
        )
        protect.PlanStore(tmp_path / "store" / "plans").save(plan)

        parked = call_tool("pea.review_plan", {"plan_id": "plan-test", "explicit_user_approval": True}, ctx)
        assert parked.ok, parked.detail
        assert parked.data["status"] == "awaiting_approval"
        assert "approval_token" not in parked.data
        assert parked.data["affected_files"] == ["license.js"]
        # the pending preview is on disk for the operator's channel
        assert (tmp_path / "store" / "approvals" / f"pending-{parked.data['fingerprint']}.json").is_file()

        # The trusted channel (the operator's own act) approves the exact scope.
        ctx.approvals.register_approval(fingerprint=parked.data["fingerprint"])
        issued = call_tool("pea.review_plan", {"plan_id": "plan-test", "explicit_user_approval": True}, ctx)
        assert issued.ok and issued.data["status"] == "approved"
        token = issued.data["approval_token"]
        digest = issued.data["plan_digest"]

        # Simulate an executor landing later with the same approval contract.
        monkeypatch.setitem(mcpserver.HANDLERS, "pea.apply_plan", lambda args, ctx: {"run_id": "run-1"})
        applied = call_tool(
            "pea.apply_plan",
            {"plan_id": "plan-test", "approval_token": token, "expected_plan_digest": digest},
            ctx,
        )
        assert applied.ok and applied.data == {"run_id": "run-1"}

        # replay: one-time means one-time
        replayed = call_tool(
            "pea.apply_plan",
            {"plan_id": "plan-test", "approval_token": token, "expected_plan_digest": digest},
            ctx,
        )
        assert not replayed.ok and replayed.error == "token_replayed"

    def test_unwired_tool_does_not_burn_the_token(self, tmp_path, monkeypatch) -> None:
        """Same guard at the token level: an unwired tool refuses before the
        one-time token is consumed."""
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "license.js").write_text("const KEY = 'sk-live-x';\n", encoding="utf-8")
        ctx = _ctx(
            authorized_root=proj,
            explicit_approval=True,
            execution_roots=(proj,),
            run_store=tmp_path / "store",
        )
        protect.PlanStore(tmp_path / "store" / "plans").save(
            {"plan_id": "plan-test", "selected_catalog_ids": ["javascript-obfuscator"], "project_path": str(proj)}
        )
        parked = call_tool("pea.review_plan", {"plan_id": "plan-test", "explicit_user_approval": True}, ctx)
        ctx.approvals.register_approval(fingerprint=parked.data["fingerprint"])
        issued = call_tool("pea.review_plan", {"plan_id": "plan-test", "explicit_user_approval": True}, ctx)
        token = issued.data["approval_token"]
        digest = issued.data["plan_digest"]
        monkeypatch.delitem(mcpserver.HANDLERS, "pea.apply_plan")
        result = call_tool(
            "pea.apply_plan",
            {"plan_id": "plan-test", "approval_token": token, "expected_plan_digest": digest},
            ctx,
        )
        assert not result.ok and result.error == "tool_not_wired"
        assert token in ctx.approvals.outstanding(), "token was consumed by an unwired tool"

    def test_changed_plan_digest_refuses_at_dispatch(self, tmp_path) -> None:
        """Two digest checks, both mechanical: the caller's stated digest
        must match the token scope (enforcement), and the stored plan's
        recomputed digest must match what was approved (handler)."""
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "license.js").write_text("const KEY = 'sk-live-x';\n", encoding="utf-8")
        ctx = _ctx(
            authorized_root=proj,
            explicit_approval=True,
            execution_roots=(proj,),
            run_store=tmp_path / "store",
        )
        store = protect.PlanStore(tmp_path / "store" / "plans")
        store.save({"plan_id": "plan-test", "selected_catalog_ids": ["javascript-obfuscator"], "project_path": str(proj)})
        parked = call_tool("pea.review_plan", {"plan_id": "plan-test", "explicit_user_approval": True}, ctx)
        ctx.approvals.register_approval(fingerprint=parked.data["fingerprint"])
        issued = call_tool("pea.review_plan", {"plan_id": "plan-test", "explicit_user_approval": True}, ctx)
        token = issued.data["approval_token"]
        digest = issued.data["plan_digest"]

        # 1. The call states a digest the token was never issued for.
        tampered = call_tool(
            "pea.apply_plan",
            {"plan_id": "plan-test", "approval_token": token, "expected_plan_digest": "plan-tampered"},
            ctx,
        )
        assert not tampered.ok and tampered.error == "scope_mismatch"
        assert token in ctx.approvals.outstanding(), "a refused consume must not burn the token"

        # 2. The stored plan itself changes after approval: the caller still
        #    states the approved digest (enforcement passes), and the
        #    handler's recomputation catches the drift.
        stored = store.load("plan-test")
        store.save({**stored, "risks": ["注入的变更"]})
        drifted = call_tool(
            "pea.apply_plan",
            {"plan_id": "plan-test", "approval_token": token, "expected_plan_digest": digest},
            ctx,
        )
        assert not drifted.ok and drifted.error == "plan_digest_mismatch"

    def test_export_report_refuses_unconfirmed_overwrite(self, tmp_path) -> None:
        out = tmp_path / "out"
        out.mkdir()
        (out / "report.md").write_text("old", encoding="utf-8")
        result = call_tool("pea.export_report", {"output_dir": str(out), "markdown": "new"}, _ctx())
        assert not result.ok and result.error == "output_overwrite_not_confirmed"

    def test_export_report_writes_when_confirmed(self, tmp_path) -> None:
        out = tmp_path / "out"
        out.mkdir()
        result = call_tool(
            "pea.export_report",
            {"output_dir": str(out), "markdown": "# report", "bundle": {"k": "v"}},
            _ctx(output_write_confirmed=True),
        )
        assert result.ok, result.detail
        assert (out / "report.md").read_text(encoding="utf-8") == "# report"
        assert json.loads((out / "bundle.json").read_text(encoding="utf-8")) == {"k": "v"}

    def test_demo_run_end_to_end(self, tmp_path) -> None:
        out = tmp_path / "demo-out"
        result = call_tool(
            "pea.demo_run",
            {"request": REQUEST, "project_path": str(CANARY), "out": str(out)},
            _ctx(output_write_confirmed=True),
        )
        assert result.ok, result.detail
        assert (out / "report.md").is_file() and (out / "bundle.json").is_file()
        bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
        assert set(bundle["domains"]) >= {
            "artifact_manifest",
            "secret_scan",
            "string_symbol_scan",
            "native_check",
            "dart_aot_check",
            "build_integration",
            "candidate_review",
        }

    def test_capability_intel_offline_is_a_named_unknown(self) -> None:
        result = call_tool("pea.fetch_capability_intel", {"family": "dart_aot_snapshot_analysis"}, _ctx())
        assert result.ok, result.detail
        assert result.data["status"] in {"network_unavailable", "not_attempted"}
        assert result.data["candidates"] == []

    def test_capability_intel_with_injected_transport_yields_external_claims(self) -> None:
        from pea.capintel import IntelResponse

        def transport(url: str) -> IntelResponse:
            return IntelResponse(status_code=200, headers={"content-type": "text/plain"}, body=b"dart snapshot analysis notes")

        result = call_tool(
            "pea.fetch_capability_intel",
            {"family": "dart_aot_snapshot_analysis"},
            _ctx(transport=transport),
        )
        assert result.ok, result.detail
        assert result.data["status"] == "ok"
        assert result.data["candidates"], "injected transport should yield candidates"
        assert all(c["authority"] == "external_claim" for c in result.data["candidates"])

    def test_candidate_review_gates_the_real_catalog(self) -> None:
        result = call_tool("pea.review_candidate", {"candidate_id": "pyarmor"}, _ctx())
        assert result.ok, result.detail
        assert result.data["decision"] == "blocked"

    def test_unknown_candidate_is_a_named_refusal(self) -> None:
        result = call_tool("pea.review_candidate", {"candidate_id": "no-such-tool"}, _ctx())
        assert not result.ok and result.error == "candidate_unknown"

    def test_check_testbench_runs_without_a_project_root(self) -> None:
        """The testbench domain observes the machine, not a project: no
        authorized root is required, and a bare CI machine reports an honest
        unknown environment instead of a fabricated tier."""
        result = call_tool("pea.check_testbench", {}, _ctx())
        assert result.ok, result.detail
        assert result.data["reachable_tier"] in {"T1", "T2", "T3"}
        assert result.data["unknowns"], "a bare testbench must declare unknowns"
        assert any(f["id"].startswith("testbench-") for f in result.data["findings"])

    def test_check_testbench_probe_crash_is_a_named_failure(self, monkeypatch) -> None:
        from pea import testbench as testbench_module

        def exploding(*args, **kwargs):
            raise RuntimeError("probe boom")

        monkeypatch.setattr(testbench_module, "observe_testbench", exploding)
        result = call_tool("pea.check_testbench", {}, _ctx())
        assert not result.ok and result.error == "probe_failed"

    def test_describe_tools_marks_availability(self) -> None:
        surface = {entry["name"]: entry for entry in mcpserver.describe_tools()}
        assert surface["pea.check_native"]["available"] is True
        assert surface["pea.check_testbench"]["available"] is True
        assert surface["pea.apply_plan"]["available"] is True
        assert surface["pea.verify_output"]["available"] is True
        assert surface["pea.compare_results"]["available"] is True
        assert surface["pea.rollback"]["available"] is True
        assert surface["pea.ledger_record"]["available"] is True
        assert surface["pea.ledger_gate"]["available"] is True

    def test_handler_failure_is_named_not_silent(self) -> None:
        # A malformed request must surface as handler_failed, never ok.
        result = call_tool("pea.plan_protection", {"request": {"targets": []}}, _ctx())
        assert not result.ok
        assert result.error == "handler_failed"


# ---------------------------------------------------------------------------
# M5: the ledger tools. The rules under test are pea.ledger's invariants
# surfaced through the tool face: explicit authority, two-sided evidence,
# observation-grade resolutions, and refusals that carry the policy code.
# ---------------------------------------------------------------------------


def _evidence(evidence_id: str, *, authority: str = "observation", summary: str | None = None) -> dict:
    record = {
        "evidence_id": evidence_id,
        "kind": "tool_output",
        "source": "pea.test",
        "observed_at": NOW,
        "authority": authority,
        "limitations": [],
    }
    if summary is not None:
        record["redacted_summary"] = summary
    return record


class TestLedgerTools:
    def _record(self, ctx: ToolContext, evidence_id: str, *, authority: str = "observation", summary: str | None = None) -> dict:
        result = call_tool(
            "pea.ledger_record",
            {"run_id": "run-1", "evidence": _evidence(evidence_id, authority=authority, summary=summary)},
            ctx,
        )
        assert result.ok, result.detail
        return result.data

    def test_record_query_audit_gate_resolve_flow(self, tmp_path) -> None:
        ctx = _ctx(explicit_approval=True, ledger_store=tmp_path / "ledgers")
        self._record(ctx, "ev-1")
        self._record(
            ctx,
            "ev-2",
            authority="inference",
            summary="native-check: libapp.so executable stack (redacted)",
        )
        recorded = call_tool(
            "pea.ledger_record",
            {
                "run_id": "run-1",
                "evidence": _evidence("ev-3"),
                "unknown": {
                    "question": "libapp.so 可执行栈是否真实暴露",
                    "severity": "blocking",
                    "domain": "native_check",
                    "recommended_probes": ["运行期验证"],
                },
            },
            ctx,
        )
        assert recorded.ok, recorded.detail
        unknown_id = recorded.data["unknown_id"]

        query = call_tool("pea.ledger_query", {"run_id": "run-1", "filters": {"authority": "observation"}}, ctx)
        assert query.ok, query.detail
        assert query.data["coverage"]["evidence_total"] == 3
        assert query.data["coverage"]["evidence_returned"] == 2, "only observation-grade records match"

        audit = call_tool("pea.ledger_audit_unknowns", {"run_id": "run-1"}, ctx)
        assert audit.ok, audit.detail
        assert audit.data["residual_unknowns"]["open"] == 1
        assert audit.data["blocking"][0]["unknown_id"] == unknown_id

        gate = call_tool("pea.ledger_gate", {"run_id": "run-1"}, ctx)
        assert gate.ok, gate.detail
        assert gate.data["status"] == "blocked"
        assert gate.data["audit"]["blocking_count"] == 1, "the audit travels with the verdict"
        assert any(unknown_id in b for b in gate.data["blockers"])

        # One-sided resolution: supporting only, no contradicting evidence.
        one_sided = call_tool(
            "pea.ledger_resolve",
            {"run_id": "run-1", "unknown_id": unknown_id, "supporting": ["ev-1"], "resolution": "栈可执行"},
            ctx,
        )
        assert not one_sided.ok and one_sided.error == "resolution_needs_two_sided_evidence"

        # Two-sided but no observation-grade support.
        no_observation = call_tool(
            "pea.ledger_resolve",
            {
                "run_id": "run-1",
                "unknown_id": unknown_id,
                "supporting": ["ev-2"],
                "contradicting": ["ev-2"],
                "resolution": "推断已足够",
            },
            ctx,
        )
        assert not no_observation.ok and no_observation.error == "resolution_requires_observation"

        resolved = call_tool(
            "pea.ledger_resolve",
            {
                "run_id": "run-1",
                "unknown_id": unknown_id,
                "supporting": ["ev-1"],
                "contradicting": ["ev-3"],
                "resolution": "运行期复测：栈标记为 NX，风险关闭",
            },
            ctx,
        )
        assert resolved.ok, resolved.detail
        assert resolved.data["status"] == "resolved"

        gate_after = call_tool("pea.ledger_gate", {"run_id": "run-1"}, ctx)
        assert gate_after.data["status"] == "verified"
        assert gate_after.data["blockers"] == []

    def test_record_requires_explicit_approval(self) -> None:
        result = call_tool("pea.ledger_record", {"run_id": "run-1", "evidence": _evidence("ev-1")}, _ctx())
        assert not result.ok and result.error == "explicit_approval_missing"

    def test_evidence_without_authority_is_refused(self) -> None:
        broken = _evidence("ev-1")
        broken.pop("authority")
        result = call_tool(
            "pea.ledger_record",
            {"run_id": "run-1", "evidence": broken},
            _ctx(explicit_approval=True),
        )
        assert not result.ok and result.error == "evidence_missing_fields"

    def test_evidence_with_invalid_authority_is_refused(self) -> None:
        result = call_tool(
            "pea.ledger_record",
            {"run_id": "run-1", "evidence": _evidence("ev-1", authority="guess")},
            _ctx(explicit_approval=True),
        )
        assert not result.ok and result.error == "evidence_authority_invalid"

    def test_duplicate_evidence_id_is_refused(self) -> None:
        ctx = _ctx(explicit_approval=True)
        self._record(ctx, "ev-1")
        result = call_tool("pea.ledger_record", {"run_id": "run-1", "evidence": _evidence("ev-1")}, ctx)
        assert not result.ok and result.error == "evidence_id_conflict"

    def test_query_on_unknown_run_is_a_named_refusal(self) -> None:
        result = call_tool("pea.ledger_query", {"run_id": "nope", "filters": {}}, _ctx())
        assert not result.ok and result.error == "run_id_unknown"

    def test_run_id_path_escape_is_refused(self) -> None:
        result = call_tool(
            "pea.ledger_record",
            {"run_id": "../../etc/passwd", "evidence": _evidence("ev-1")},
            _ctx(explicit_approval=True),
        )
        assert not result.ok and result.error == "run_id_invalid"

    def test_ledger_persists_across_contexts(self, tmp_path) -> None:
        store = tmp_path / "ledgers"
        first = _ctx(explicit_approval=True, ledger_store=store)
        self._record(first, "ev-1")
        second = _ctx(explicit_approval=True, ledger_store=store)
        query = call_tool("pea.ledger_query", {"run_id": "run-1", "filters": {}}, second)
        assert query.ok, query.detail
        assert [r["evidence_id"] for r in query.data["records"]] == ["ev-1"]

    def test_export_writes_redacted_markdown_and_complete_json(self, tmp_path) -> None:
        store = tmp_path / "ledgers"
        ctx = _ctx(explicit_approval=True, ledger_store=store)
        self._record(ctx, "ev-1", summary="libapp.so 可执行栈（已脱敏）")
        self._record(ctx, "ev-2")  # no redacted_summary declared
        out = tmp_path / "export"
        out.mkdir()
        result = call_tool(
            "pea.ledger_export",
            {"run_id": "run-1", "output_dir": str(out)},
            _ctx(output_write_confirmed=True, explicit_approval=True, ledger_store=store),
        )
        assert result.ok, result.detail
        exported = json.loads((out / "ledger.json").read_text(encoding="utf-8"))
        assert exported["ledger_digest"] == result.data["ledger_digest"]
        assert len(exported["ledger"]["evidence"]) == 2, "JSON carries the complete records"
        markdown = (out / "ledger.md").read_text(encoding="utf-8")
        assert "libapp.so 可执行栈（已脱敏）" in markdown
        assert "未声明 redacted_summary" in markdown, "a record without a declared summary is marked, never invented"
        assert "ev-2" in markdown

    def test_export_overwrite_requires_confirmation(self, tmp_path) -> None:
        store = tmp_path / "ledgers"
        ctx = _ctx(explicit_approval=True, ledger_store=store)
        self._record(ctx, "ev-1")
        out = tmp_path / "export"
        out.mkdir()
        first = call_tool(
            "pea.ledger_export",
            {"run_id": "run-1", "output_dir": str(out)},
            _ctx(output_write_confirmed=True, explicit_approval=True, ledger_store=store),
        )
        assert first.ok, first.detail
        second = call_tool(
            "pea.ledger_export",
            {"run_id": "run-1", "output_dir": str(out)},
            _ctx(explicit_approval=True, ledger_store=store),
        )
        assert not second.ok and second.error == "output_overwrite_not_confirmed"

    def test_resolve_unknown_unknown_is_refused(self) -> None:
        ctx = _ctx(explicit_approval=True)
        self._record(ctx, "ev-1")
        result = call_tool(
            "pea.ledger_resolve",
            {"run_id": "run-1", "unknown_id": "unk-nope", "supporting": ["ev-1"], "contradicting": ["ev-1"], "resolution": "x"},
            ctx,
        )
        assert not result.ok and result.error == "unknown_not_found"
