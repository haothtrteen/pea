"""MCP 协议面的合同真源：工具参数 schema 的加载与 tools/list 数据生成。

三份合同的分工（与 Phase 4 设计 §2 一致）：

* ``mcp/tool-contract.json``（生成产物）——工具的存在性、审批类别、副作用；
* ``mcp/tool-schemas.json``（手维护，本文档加载）——``tools/list`` 的
  ``inputSchema``，字段与类型以处理器实际读取为准；
* ``mcpserver.HANDLERS``——哪些工具真的可调用。

server 的 tools/list **只**从这里与注册表生成，不从函数签名推导——协议面
因此与合同面同源，契约门可以逐字段守卫漂移。本模块零第三方依赖（契约门
与 server 均可加载）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pea import tooleffects

TOOL_SCHEMAS_PATH = Path(__file__).resolve().parents[2] / "mcp" / "tool-schemas.json"


def load_tool_schemas(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the per-tool input schemas (the tools/list contract surface)."""
    source = path or TOOL_SCHEMAS_PATH
    data = json.loads(source.read_text(encoding="utf-8"))
    tools = data.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise ValueError(f"tool schemas at {source} carry no tools")
    return tools


def mcp_tool_definitions(path: Path | None = None) -> list[dict[str, Any]]:
    """Build MCP ``Tool`` objects for tools/list, contract-driven.

    The name/purpose come from the effects registry (the same source the
    contract JSON is generated from); the inputSchema comes from
    ``tool-schemas.json``. A tool missing a schema is a hard error here so a
    half-covered protocol surface fails loudly instead of listing a tool
    whose call arguments no client can construct.
    """
    schemas = load_tool_schemas(path)
    definitions: list[dict[str, Any]] = []
    for name, effect in tooleffects.TOOL_EFFECTS.items():
        schema = schemas.get(name)
        if schema is None:
            raise ValueError(f"no input schema for contracted tool {name!r}")
        definitions.append(
            {
                "name": name,
                "description": effect.contract.purpose,
                "inputSchema": schema,
            }
        )
    return definitions


def schema_required(name: str, path: Path | None = None) -> list[str]:
    """The schema's required fields for one tool (contract-gate helper)."""
    return list(load_tool_schemas(path)[name].get("required", []))
