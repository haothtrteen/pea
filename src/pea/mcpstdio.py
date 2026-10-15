"""MCP stdio server（Phase 4 L1）：官方 SDK 之上的协议适配层。

本模块**只做协议**——JSON-RPC 传输、握手、tools/list、tools/call 的编解码
全部交给官方 ``mcp`` SDK；PEA 侧只写两件事：

* **工具发现是合同驱动的**：``tools/list`` 从 ``tooleffects.TOOL_EFFECTS``
  与 ``mcp/tool-schemas.json`` 生成，不从函数签名推导——协议面与合同面
  同源，契约门可以逐字段守卫漂移；
* **调用直达组合层**：参数先过 ``tool-schemas.json`` 校验（纯标准库校验
  器），再交给 ``mcpserver.call_tool``——审批强制、授权根检查、命名拒绝
  原样复用，协议层零豁免。

注册方式（官方 SDK v2）：``mcp.server.Server`` 暴露的是**低层请求处理器**
注册（``add_request_handler``，方法串 + 参数类型 + handler），高层装饰器
（``list_tools``/``call_tool``）在 ``MCPServer`` 上且不支持自定义
input_schema——本项目的 tools/list 必须是合同面，故选低层模式。handler
签名 ``(ctx, params) -> Result``，其中 ctx 是 ``ServerRequestContext``
（本层不需要握手状态，忽略即可）。

依赖纪律：官方 ``mcp`` SDK 是**可选依赖**（``[project.optional-dependencies]
mcp``），核心 ``pea`` 包保持纯标准库；本模块 import 失败时给出安装指引，
CLI 与组合层不受影响。
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea import mcpserver, tooleffects, toolschemas
from pea.approval import ApprovalAuthority
from pea.mcpserver import ToolContext, ToolResult

SERVER_NAME = "pea"
SERVER_VERSION = "0.7.0"

#: 环境变量：账本持久化目录（可选）。不设置时账本只在进程内有效。
LEDGER_STORE_ENV = "PEA_LEDGER_STORE"

#: 环境变量：任务编排器 store 根目录（WP2）。不设置时``pea.run_assessment``
#: / ``pea.resume_task`` / ``pea.get_task`` / ``pea.list_tasks`` 以命名拒绝
#: ``task_store_missing`` 响应——任务状态不落在未配置的位置。
TASK_STORE_ENV = "PEA_TASK_STORE"

#: 环境变量（WP0）：运营者配置的执行授权根列表（os.pathsep 分隔）。
#: 与 PEA_TASK_STORE / PEA_LEDGER_STORE 同纪律：根来自运营者配置，工具
#: 参数只能在根内选择、不得建立根。不设置时四个执行器以命名拒绝
#: ``execution_roots_unconfigured`` 响应——执行面整体关闭，不静默回退到
#: 调用方自述路径。只读分析面保持"参数即根"的既有行为（向后兼容）。
AUTHORIZED_ROOTS_ENV = "PEA_AUTHORIZED_ROOTS"

#: 环境变量（WP3）：保护执行循环的 store 根目录（plans / runs /
#: approvals）。不设置时执行器以 ``run_store_missing`` 拒绝。
RUN_STORE_ENV = "PEA_RUN_STORE"

_authority: ApprovalAuthority | None = None


def _process_authority() -> ApprovalAuthority:
    """The one-time-token authority for this server process.

    In-process by design: a token survives as long as the server process,
    which matches the one-shot semantics (replay, expiry, scope changes are
    all named refusals).

    WP0: the *approval-event* half is deliberately cross-process. Events
    live under the configured run store (``<run_store>/approvals``), so an
    operator's ``pea approve`` in their own shell can satisfy a token
    request that arrives later over MCP - the two processes share the
    store, never memory. Without a configured store there is no trusted
    channel to satisfy issuance, and the executors refuse anyway.
    """
    global _authority
    if _authority is None:
        store = os.environ.get(RUN_STORE_ENV)
        event_store = Path(store).expanduser().resolve() / "approvals" if store else None
        _authority = ApprovalAuthority(event_store=event_store)
    return _authority


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def context_from_args(args: dict[str, Any]) -> ToolContext:
    """Build the composition-layer context from a tools/call payload.

    The mapping mirrors what the CLI does for the same handlers, and only
    the protocol layer adds: path arguments become the authorized root,
    ``authorization`` becomes the confirmation level. A missing
    authorization is ``not_confirmed`` - the enforcement point downstream
    turns that into the named refusal ``authorization_not_confirmed``.

    WP0: the *execution* roots and the run store come from the operator's
    environment, never from the call payload - a caller-supplied path would
    let a call establish its own execution boundary. The read-only face
    keeps the parameter-as-root behavior for backward compatibility; the
    four executors enforce the configured roots at their own gate
    (``execution_roots_unconfigured`` / ``path_outside_authorized_root``).
    """
    authorization = str(args.get("authorization", "not_confirmed"))
    root_raw = args.get("project_path") or args.get("cracked_path") or args.get("authorized_root")
    root = Path(str(root_raw)).expanduser().resolve() if root_raw else None
    store = os.environ.get(LEDGER_STORE_ENV)
    task_store = os.environ.get(TASK_STORE_ENV)
    run_store = os.environ.get(RUN_STORE_ENV)
    roots_raw = os.environ.get(AUTHORIZED_ROOTS_ENV, "")
    execution_roots = tuple(Path(p).expanduser() for p in roots_raw.split(os.pathsep) if p) if roots_raw else ()
    return ToolContext(
        authorized_root=root,
        authorization=authorization,
        approvals=_process_authority(),
        now=_utc_now(),
        explicit_approval=bool(args.get("explicit_user_approval") is True),
        output_write_confirmed=bool(args.get("output_write_confirmed") is True),
        ledger_store=Path(store).expanduser().resolve() if store else None,
        task_store=Path(task_store).expanduser().resolve() if task_store else None,
        execution_roots=execution_roots,
        run_store=Path(run_store).expanduser().resolve() if run_store else None,
    )


def _text_result(payload: dict[str, Any], *, is_error: bool) -> Any:
    """A CallToolResult carrying a JSON payload - the code travels in text."""
    import mcp.types as mcp_types

    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
        is_error=is_error,
    )


def _error_result(name: str, code: str, detail: str) -> Any:
    """A named refusal: ``error`` is the stable machine code, not prose."""
    return _text_result({"error": code, "tool": name, "detail": detail}, is_error=True)


def _dispatch_call(name: str, arguments: dict[str, Any]) -> Any:
    """Validate against the contract surface, then dispatch to the
    composition layer. Approval enforcement, authorized-root checks and
    named refusals are all inherited from ``mcpserver.call_tool`` - the
    protocol layer grants no exemptions."""
    if not isinstance(arguments, dict):
        return _error_result(name, "arguments_invalid", "arguments must be a JSON object")
    effect = tooleffects.TOOL_EFFECTS.get(name)
    if effect is None:
        return _error_result(name, "unknown_tool", f"no contract entry for {name!r}")
    schema = toolschemas.load_tool_schemas().get(name)
    if schema is None:
        return _error_result(name, "tool_schema_missing", f"no input schema for contracted tool {name!r}")
    # Argument validation against the contract surface: a malformed call
    # never reaches a handler, and the violation text names the fields.
    try:
        from pea.validation import validate_or_raise

        validate_or_raise(arguments, schema, subject=f"{name} arguments")
    except Exception as exc:  # PeaContractError carries the field list
        return _error_result(name, "arguments_invalid", str(exc))
    result: ToolResult = mcpserver.call_tool(name, dict(arguments), context_from_args(dict(arguments)))
    if not result.ok:
        return _error_result(name, result.error or "handler_failed", result.detail or "")
    return _text_result(result.to_dict(), is_error=False)


def create_server() -> Any:
    """Build the MCP server with the two contract-driven handlers."""
    from mcp.server import Server
    from mcp.types import (
        CallToolRequestParams,
        ListToolsResult,
        PaginatedRequestParams,
        Tool,
    )

    server: Any = Server(SERVER_NAME, version=SERVER_VERSION)

    async def _on_list_tools(_ctx: Any, _params: Any) -> ListToolsResult:
        definitions = toolschemas.mcp_tool_definitions()
        # Tool's field is the snake_case ``input_schema`` (SDK v2); the
        # contract surface itself stays camelCase in tool-schemas.json so
        # the JSON contract and the MCP protocol shape stay in their own
        # canonical forms.
        return ListToolsResult(
            tools=[
                Tool(
                    name=definition["name"],
                    description=definition["description"],
                    input_schema=definition["inputSchema"],
                )
                for definition in definitions
            ]
        )

    async def _on_call_tool(_ctx: Any, params: CallToolRequestParams) -> Any:
        return _dispatch_call(params.name, dict(params.arguments or {}))

    server.add_request_handler("tools/list", PaginatedRequestParams, _on_list_tools)
    server.add_request_handler("tools/call", CallToolRequestParams, _on_call_tool)
    return server


def main(argv: list[str] | None = None) -> int:
    """Run the PEA MCP server over stdio (the default MCP transport)."""
    try:
        import asyncio

        import mcp.server.stdio as mcp_stdio
    except ImportError:
        print(
            "pea mcp-server: the official MCP SDK is not installed.\n"
            'Install the optional extra:  pip install "mcp>=2.0"\n'
            "(the core pea package stays dependency-free; this entry point\n"
            " is the only consumer of the SDK.)",
            file=sys.stderr,
        )
        return 2

    async def _serve() -> None:
        server = create_server()
        async with mcp_stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(_serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
