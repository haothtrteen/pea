# 参与 PEA 开发

本仓库不是普通脚本集合——它把"每件能力都有合同、有副作用声明、有边界声明、有端到端验证"当机械门禁执行。提交前请读本文档；它比代码风格指南更重要。

## 开发环境

```bash
pip install -e ".[dev]"        # pytest / jsonschema / ruff / mypy（运行时本身零第三方依赖）
make check                     # ruff + mypy + 全量测试 + 契约门（CI 等价）
make verify-real               # L2 真实工兵层：对合成形态产物跑真实域（REA 纪律单独触发）
```

需要 Python 3.10+。`make check` 必须全绿才可提交；`make verify-real` 在触及产物解析、域实现或 canary 时运行。

## 不可协商的纪律

这些不是建议，是 CI 会挡住你的规则：

1. **Schema 是唯一真源**。`schemas/` 定义数据合同；`mcp/tool-contract.json` 与 `mcp/tool-effects.json` 是 `src/pea/tooleffects.py` 注册表的**生成产物**——改注册表后必须重新生成两份 JSON，否则契约门（漂移测试）失败。
2. **没有静默成功**。工具失败、域不可用、证据缺失，全部是命名错误或命名 unknown。`mcpserver.call_tool` 的处理器抛 `ToolRefusal(reason, detail)`，`reason` 必须是注册表 `error_codes` 里声明过的稳定机器码；未声明的拒绝码 = 合同漂移。
3. **unknown 不是 pass**。域 provider 不可用 → 该域结论记 `unknown`，计划中相应措施不得标 `verified`；退出码 0/1/2 三态，未评估不得窃取绿灯。
4. **证据权威显式化**。`ledger` 的每条证据必须显式声明 authority（observation / inference / external_claim / human_assertion），没有默认值；消解 unknown 必须双向证据且至少一条 observation 级。
5. **脱敏是声明式的**。报告/导出只渲染域产出的 `redacted_summary`；未声明的记录显式标注缺失，不代为总结、不静默包含原文。
6. **可用性来自实现**。合同里有什么工具由注册表说，哪些真的能调用由 `mcpserver.HANDLERS` 说；当前 35 个合同工具全部接线（0.7.0），`tool_not_wired` 作为守卫保留——新增合同工具而未实现时，调用返回该命名错误且不消耗审批令牌。
7. **诚实边界写进文档**。每个版本在 `CHANGELOG.md` 的"已知边界"里声明这版不能做什么。

## 代码约定

- 纯函数域优先：域实现（`recon` / `artifactscan` / `nativecheck` / …）保持无 IO 纯计算，IO 只发生在组合层（`mcpserver` / `demo` / CLI）与显式注入的 transport。
- 时间戳通过 `now` 参数注入，禁止在域内取系统时钟——确定性测试依赖它。
- 新增工具：在 `tooleffects.TOOL_EFFECTS` 注册（合同字段 + 副作用字段一次写全），在 `mcpserver.HANDLERS` 实现；`version` 用 `WIRED_VERSION（已接线；未接线为 CONTRACT_ONLY_VERSION，当前无使用者）`，未接线用 `CONTRACT_ONLY_VERSION`。
- 新增域：统一输出 `findings + coverage + unknowns`；覆盖度四态（`complete_for_scope` / `partial` / `unavailable` / `not_run`）；跳过即记录，理由进 `unknowns`。
- 类型标注全覆盖（mypy `disallow_untyped_defs = true`，见 `pyproject.toml`）；不添加运行时第三方依赖。

## 测试约定

- 每个行为至少一个命名断言；拒绝路径和快乐路径同样要有测试——**拒绝码的拼写就是合同**。
- 破坏性验证优先：能造"会咬人的钉子"就不造 happy path（参考 `tests/test_l2verify.py` 的 tamper 测试）。
- 端到端用 checked-in fixture（`demo/canary-flutter-licensing` + `demo/canary-artifacts`），fixture 与 builder 逐字节一致由漂移守卫断言；不要在测试里临时造项目结构。

## 提交约定

- Conventional Commits，中文描述，一个提交一个关注点：`feat:` / `fix:` / `docs:` / `chore:` / `test:`。
- 提交信息说清**为什么**与**验证状态**（跑了哪些门、结果如何），不只是改了什么。
- 不改写历史；不跳过 hook。

## 文档约定

- `README.md`（英文，GitHub 门面）与 `README_zh.md`（中文，维护基线）是门面；`docs/Prototype-1.0-Demo-zh-CN.md` 跟踪"对标方案落地了多少"；`CHANGELOG.md` 跟版本。四者数字（测试数、工具数、接线数）必须与代码一致——文档漂移和合同漂移同罪。
- `docs/REA-Parity-Plan-zh-CN.md` 是规划文档，保留历史判断；状态更新以块引用形式追加，不删原文。
