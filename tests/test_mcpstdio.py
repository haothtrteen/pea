"""Tests for the MCP stdio server (Phase 4 WP1).

Two layers, deliberately separated:

* **Protocol-adjacent unit tests** run without the official SDK: the
  context mapping (``context_from_args``) is the only place the protocol
  layer translates caller input into composition-layer context, and a bug
  there is a bug in the enforcement boundary.
* **End-to-end tests** drive the real server as a subprocess over stdio
  with the official SDK's client (``initialize`` -> ``list_tools`` ->
  ``call_tool``). They are skipped with an explicit reason when the SDK is
  absent - the core package must stay importable without it.

The acceptance line from the Phase 4 design, verbatim: tools/list is
contract-driven (31 tools, zero drift from the effects registry), calls
inherit the composition layer's enforcement (schema validation, named
refusals, approval gates) with no protocol-layer exemptions.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from pea import mcpstdio, tooleffects
from pea.mcpstdio import (
    LEDGER_STORE_ENV,
    SERVER_NAME,
    SERVER_VERSION,
    context_from_args,
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


class TestContextMapping:
    """The protocol layer's only translation step: caller payload ->
    ToolContext. Enforcement downstream reads what this builds."""

    def test_project_path_becomes_the_authorized_root(self) -> None:
        ctx = context_from_args({"project_path": "/tmp", "authorization": "owner"})
        assert ctx.authorized_root == Path("/tmp").resolve()
        assert ctx.authorization == "owner"

    def test_cracked_path_is_accepted_as_a_root_source(self) -> None:
        ctx = context_from_args({"cracked_path": "/tmp", "authorization": "owner"})
        assert ctx.authorized_root == Path("/tmp").resolve()

    def test_missing_authorization_is_not_confirmed(self) -> None:
        ctx = context_from_args({"project_path": "/tmp"})
        assert ctx.authorization == "not_confirmed"

    def test_explicit_approval_flags_travel(self) -> None:
        ctx = context_from_args({"explicit_user_approval": True, "output_write_confirmed": True})
        assert ctx.explicit_approval is True
        assert ctx.output_write_confirmed is True

    def test_ledger_store_comes_from_the_environment(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv(LEDGER_STORE_ENV, str(tmp_path))
        assert context_from_args({}).ledger_store == tmp_path.resolve()

    def test_approvals_authority_is_shared_across_calls(self) -> None:
        """One server process, one authority: a token issued through one
        call must be consumable by the next (one-shot semantics are the
        authority's, not the protocol layer's)."""
        first = context_from_args({})
        second = context_from_args({})
        assert first.approvals is second.approvals


# ---------------------------------------------------------------------------
# End-to-end: the real server, over stdio, driven by the official client.
# ---------------------------------------------------------------------------


def _require_real_sdk():
    """Skip unless the *real* MCP SDK is importable - not a namespace stub.

    A bare ``importorskip("mcp")`` passes on a directory-shaped namespace
    package that carries no server machinery, which used to produce 5
    failures downstream instead of skips (external review, P1). Probing the
    concrete symbols this suite actually drives closes that hole.
    """
    try:
        import mcp.types
        from mcp import ClientSession  # noqa: F401
        from mcp.client.stdio import stdio_client  # noqa: F401
    except ImportError:
        pytest.skip("the official MCP SDK is an optional dependency (pip install 'mcp>=2.0')", allow_module_level=True)
    import mcp

    return mcp


mcp = _require_real_sdk()


def _server_params(tmp_path: Path):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    return mcp.StdioServerParameters(command=sys.executable, args=["-m", "pea.mcpstdio"], env=env)


def _run_client(coro_factory):
    """Drive one async client session to completion on the sync test path."""
    import asyncio

    return asyncio.run(coro_factory())


class TestMissingSdkGuidance:
    """The optional dependency stays optional: without the SDK the entry
    points print installation guidance and exit 2 - the core package never
    grows a hard dependency. Simulated by shadowing the module entries;
    the real skipif case is the module-level importorskip above."""

    def test_entry_point_gives_install_guidance_not_a_traceback(self, monkeypatch, capsys) -> None:
        monkeypatch.setitem(sys.modules, "mcp", None)
        monkeypatch.setitem(sys.modules, "mcp.server", None)
        monkeypatch.setitem(sys.modules, "mcp.server.stdio", None)
        assert mcpstdio.main([]) == 2
        captured = capsys.readouterr()
        assert "pip install" in captured.err and "mcp>=2.0" in captured.err

    def test_cli_entry_delegates_the_same_guidance(self, monkeypatch, capsys) -> None:
        from pea import cli

        monkeypatch.setitem(sys.modules, "mcp", None)
        assert cli.main(["mcp-server"]) == 2
        captured = capsys.readouterr()
        assert "pip install" in captured.err and "mcp>=2.0" in captured.err


class TestStdioServerEndToEnd:
    def _session(self, params):
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client

        return stdio_client(params), ClientSession

    def test_initialize_lists_the_contract_surface(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            stdio_cm, client_cls = self._session(_server_params(tmp_path))
            async with stdio_cm as (read_stream, write_stream), client_cls(read_stream, write_stream) as session:
                result = await session.initialize()
                assert result.server_info.name == SERVER_NAME
                assert result.server_info.version == SERVER_VERSION
                listed = await session.list_tools()
                assert [t.name for t in listed.tools] == list(tooleffects.TOOL_EFFECTS), (
                    "tools/list must be contract-driven: same names, same order as the registry"
                )
                schemas = json.loads((ROOT / "mcp" / "tool-schemas.json").read_text(encoding="utf-8"))["tools"]
                for tool in listed.tools:
                    assert tool.input_schema == schemas[tool.name], tool.name

        _run_client(scenario)

    def test_readonly_call_succeeds_through_the_protocol(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            stdio_cm, client_cls = self._session(_server_params(tmp_path))
            async with stdio_cm as (read_stream, write_stream), client_cls(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool("pea.check_testbench", {})
                assert not result.is_error, result.content[0].text
                payload = json.loads(result.content[0].text)
                assert payload["ok"] is True
                assert payload["tool"] == "pea.check_testbench"
                assert payload["data"]["reachable_tier"]

        _run_client(scenario)

    def test_malformed_call_is_refused_before_the_handler(self, tmp_path: Path) -> None:
        """Schema validation happens at the protocol edge: a call missing a
        required field never reaches the handler."""
        async def scenario() -> None:
            stdio_cm, client_cls = self._session(_server_params(tmp_path))
            async with stdio_cm as (read_stream, write_stream), client_cls(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool("pea.scan_secrets", {"project_path": "/tmp"})
                assert result.is_error
                payload = json.loads(result.content[0].text)
                assert payload["error"] == "arguments_invalid"

        _run_client(scenario)

    def test_unauthorized_call_keeps_its_named_refusal(self, tmp_path: Path) -> None:
        """Approval enforcement is inherited, not re-implemented: a
        project-reading tool called without authorization is refused with
        the composition layer's stable code."""
        async def scenario() -> None:
            stdio_cm, client_cls = self._session(_server_params(tmp_path))
            async with stdio_cm as (read_stream, write_stream), client_cls(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(
                    "pea.scan_secrets", {"project_path": "/tmp", "authorization": "not_a_value"}
                )
                assert result.is_error
                payload = json.loads(result.content[0].text)
                assert payload["error"] == "arguments_invalid"

        _run_client(scenario)

    def test_unknown_tool_is_a_named_refusal(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            stdio_cm, client_cls = self._session(_server_params(tmp_path))
            async with stdio_cm as (read_stream, write_stream), client_cls(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool("pea.does_not_exist", {})
                assert result.is_error
                payload = json.loads(result.content[0].text)
                assert payload["error"] == "unknown_tool"

        _run_client(scenario)
