# 双 MCP 接线指南：同一 Agent 挂 PEA + REA 的实弹演练工作流

**日期：** 2026-10-14 · **性质：** 操作指南（P1 工作包 5，对应《第三环设计》§1–§2） · **状态来源：** 工作包 1–4 落地后的接入面 + WP1（Phase 4 L1：MCP stdio server）落地后的接入面

## 0. 这份文档是什么，不是什么

**是**：一次"实弹演练"（live-fire exercise）的完整接线方法——PEA 产出任务简报，你的 agent 驱动**你自己环境里的 REA** 执行攻击，观察结果经证据合同回流 PEA 账本，最后由 verified 门机械判定。

**不是**：PEA 内置攻击工具的使用说明。PEA 不捆绑、不安装、不执行任何攻击工具；REA 由用户自行拉取，用户与 REA 之间自行适用 REA 的许可。这与 REA 自己的纪律对称——REA 检测用户已装的 Ghidra/IDA 而不分发。

**当前接入面的诚实边界**：

| 形态 | 状态 | 本文档覆盖 |
| --- | --- | --- |
| PEA CLI（`pea brief` / `pea testbench` / `pea ledger` / `pea task` / `pea protect` / `pea approve`） | ✅ 已落地（0.4.0 后增量；`pea task` 随 WP2；`pea protect`/`pea approve` 随 WP3/WP6） | §2.1 |
| PEA 组合层（`pea.mcpserver.call_tool`，agent 以 Python 嵌入调用） | ✅ 已落地（35 工具合同、35 全接线；WP3 起执行器四件套接线） | §2.2 |
| PEA MCP stdio server 进程 | ✅ 已落地（WP1；官方 SDK 之上的协议适配层，`tools/list` 合同驱动） | §2.3 |
| PEA 任务编排器（`pea task` / `pea.run_assessment` 等四工具） | ✅ 已落地（WP2；任务落盘 + 输入摘要恢复 + 失败语义） | §2.4 |
| REA（用户环境自备） | 由用户拉取 | §3 |

## 1. 工作流全景

```
┌──────────────────────────── PEA（防御方工具）────────────────────────────┐
│                                                                        │
│  pea brief ──► 任务简报（mission-brief）                                │
│    │              · 目标锚点（来自对自家工件的域扫描，脱敏）              │
│    │              · 工具族（来自能力映射，附 research_date）             │
│    │              · 环境分层（testbench 侦察：本次可执行到 T 几）        │
│    │              · 判据与预算（内嵌 attack-simulation）                │
│    │              · 红线（六条固定文本）                                │
│    ▼                                                                   │
│  （你把简报交给你的 agent）                                              │
└────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────── 你的 Agent ────────────────────────────────┐
│  驱动 REA（用户环境自备的安装）执行简报中的能力步骤；                    │
│  每步观察按简报的 evidence_return 合同整理：                            │
│    authority=observation + environment 块（环境分层是观察的一部分）      │
└────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────── PEA（防御方工具）────────────────────────────┐
│  pea ledger record ──► 证据入账（evidence-record，append-only）          │
│  pea ledger audit   ──► 残留 unknown 审计                                │
│  pea ledger gate    ──► verified 门：任何 blocking unknown 未消解即 blocked│
│  pea ledger export  ──► 脱敏 Markdown + 完整 JSON（带 digest，可重审）    │
└────────────────────────────────────────────────────────────────────────┘
```

**分工的一句话**：工具是 REA 的；执行智能是你的 agent 的；方法论、环境分层与证据账本是 PEA 的。

## 2. PEA 侧接入

### 2.1 CLI（推荐入口）

```bash
# 1) 侦察测试台：本次能攻击到哪一层（只检测，不安装任何东西）
pea testbench

# 2) 生成任务简报（自动跑只读项目扫描拿锚点 + 测试台分层）
pea brief \
  --request examples/protection-request.flutter-licensing.example.json \
  --project ./your-app \
  --baseline build/baseline/app-release.apk \
  --protected build/protected/app-release-obfuscated.apk \
  --out build/mission-brief.json

# 3)（agent 驱动 REA 执行后）证据逐条入账
pea ledger record --run flutter-lic-2026-10-14 --evidence observations/A1.json

# 4) 审计与门禁
pea ledger audit --run flutter-lic-2026-10-14
pea ledger gate  --run flutter-lic-2026-10-14   # exit 0=verified, 3=blocked

# 5) 导出（脱敏 Markdown 给人，完整 JSON 给机器审计）
pea ledger export --run flutter-lic-2026-10-14 --out build/ledger-out --overwrite

# 6)（可选）把整条只读闭环作为可恢复任务跑：授权门→域→计划→账本→门→报告
pea task run --request examples/protection-request.flutter-licensing.example.json \
  --project ./your-app --store .pea/tasks --out build/task-out
#    退出码：0=done / 3=blocked（含审批门未过）/ 4=授权未确认（不建任务）/ 2=命名边界错误
```

账本持久化在 `--store` 目录（默认 `.pea/ledgers/`），run id 同时是文件名，跨进程延续同一场演练。任务 store 同理（默认 `.pea/tasks/`，每任务一个目录，输入摘要未变的 done 步骤恢复时不重跑；细节见 §2.4）。

### 2.2 组合层（agent 以 Python 嵌入）

与 MCP server 走**同一份实现**：`mcpstdio` 的 `tools/call` 最终就是这里的 `call_tool`，审批、命名拒绝、digest 纪律完全一致。嵌入调用适合你自己写 agent 的场景（少一个进程、少一次协议编解码）：

```python
from pea.mcpserver import ToolContext, call_tool

ctx = ToolContext(authorized_root=None, authorization="owner")

# 环境侦察 → 简报（environment 原样透传）
testbench = call_tool("pea.check_testbench", {}, ctx).data
brief = call_tool("pea.design_mission_brief", {
    "baseline": {"path": "build/baseline/app-release.apk", "sha256": "..."},
    "protected": {"path": "build/protected/app-release.apk", "sha256": "..."},
    "languages": ["dart"], "platforms": ["android"],
    "goals": ["licensing_hardening"], "has_authorization_logic": True,
    "objective_anchors": ["libapp.so 存在 _kDartVmSnapshotInstructions 锚点"],
    "environment": testbench,
}, ctx).data
```

写操作（`pea.ledger_record` / `pea.ledger_resolve`）在 MCP 面要求显式审批；CLI 面由你敲命令的动作本身满足。agent 嵌入调用时应自行实现同等确认，不要绕过。

### 2.3 MCP stdio server（WP1 落地；只认 MCP 配置的 agent 宿主用这个）

PEA 现在以标准 MCP server 进程运行，官方 SDK 承载 JSON-RPC，PEA 只写协议适配：

```bash
pip install "mcp>=2.0"        # 可选依赖组：pip install "pea[mcp]"
pea mcp-server                # stdio 传输；协议层零业务，零豁免
```

agent 宿主配置（以 stdio 为例）：

```json
{
  "mcpServers": {
    "pea": {
      "command": "pea",
      "args": ["mcp-server"],
      "env": {
        "PEA_LEDGER_STORE": "/path/to/run-ledgers",
        "PEA_TASK_STORE": "/path/to/assessment-tasks"
      }
    }
  }
}
```

协议面的三条硬事实（与组合层逐字同源）：

1. **`tools/list` 是合同驱动的**：35 个工具直接由 `tooleffects.TOOL_EFFECTS` 与 `mcp/tool-schemas.json` 生成，不从函数签名推导——契约门（`tests/test_toolschemas.py`）逐字段守卫协议面与合同面零漂移，包括"审批要求必须能被协议面表达"（WP1 修掉的 `check_testbench` 式断裂：合同要求授权确认、schema 却无字段可传，调用永远被拒）。
2. **`tools/call` 直达组合层**：参数先过 schema 校验（`additionalProperties:false`，多一个字段都进不去），再走 `mcpserver.call_tool`——审批强制、授权根检查、命名拒绝原样复用。协议层不实现任何业务，也没有任何豁免路径。
3. **零未接线工具（WP3 起）**：执行器四件套（`apply_plan` / `verify_output` / `compare_results` / `rollback`）已全部接线，`tool_not_wired` 不再适用于任何合同工具——但它作为守卫保留：将来新增合同工具而未接线时，调用仍返回该命名错误，而不是假装可用。执行面另有两道边界：执行授权根由 `PEA_AUTHORIZED_ROOTS` 环境注入（未配置即整体关闭），令牌签发必须挂可信通道产生的审批事件（`pea approve` / `pea protect` 的交互确认）——agent 能请求预览，不能自助审批。

调用形态（客户端视角）：`tools/call` 的 `arguments` 就是 §2.2 示例里 `call_tool` 的第二参数；成功返回 `{"ok": true, "tool": ..., "data": ...}`，拒绝返回 `{"error": "<命名码>", "tool": ..., "detail": ...}` 且 `isError=true`——**命名码原样透传，吞掉它的客户端比没有客户端更糟**。

写操作（`pea.ledger_record` / `pea.ledger_resolve`）在 MCP 面要求 `explicit_user_approval: true`；CLI 面由你敲命令的动作本身满足。agent 嵌入调用时应自行实现同等确认，不要绕过。

> 一次性令牌的进程边界：`review_plan` 签发的 `approval_token` 只在**同一 server 进程内**有效（重启即失效，重放/过期/范围变更都是命名拒绝）。WP2 任务编排器落地后，**任务与步骤产物**可跨进程续用（store 落盘 + 输入摘要恢复，`resume_task` 不重跑未变的 done 步骤），但审批令牌仍随进程生死——恢复一个 parked 任务不等于恢复一枚令牌。

### 2.4 任务编排器（WP2 落地；一次任务跑完整个只读闭环）

`pea.run_assessment` 把 §1 的全景固化为一条高层任务：授权门 → 侦察 → 七个只读域 → 计划 → 攻击自测设计 → 证据账本 → verified 门 → 报告。任务落盘在 store（CLI `--store`，MCP 由 `PEA_TASK_STORE` 环境配置——**永不来自工具参数**），每步一个 JSON 产物、原子写：

```bash
pea task run --request examples/protection-request.flutter-licensing.example.json \
    --project demo/canary-flutter-licensing --store .pea/tasks --out build/task-out
pea task list   --store .pea/tasks      # 任务清单（旧在前）
pea task status task-4512fc29 --store .pea/tasks
pea task resume task-4512fc29 --store .pea/tasks   # done 且输入未变的步骤不重跑
pea task report task-4512fc29 --store .pea/tasks --out build/task-out
```

组合层/MCP 面是同一实现的四个工具：`pea.run_assessment` / `pea.get_task` / `pea.list_tasks` / `pea.resume_task`。三条使用纪律：

1. **分析根 = 授权根**：`run_assessment` 不接受项目路径参数，扫的是 `authorized_root`；`resume_task` 发现记录的项目路径与本次授权根不一致时命名拒绝（`path_outside_authorized_root`）——恢复不得切换分析对象。
2. **失败不假绿灯**：任一域失败 → 账本记 blocking unknown（"未评估，不冒充通过"）、verified 门保持 blocked、报告在该输入缺失时跳过自己（skipped-dep）而不是渲染残缺文档；任务状态 `blocked` 是等待/失败态，不是"通过"。
3. **未授权停在审批门**：请求授权未确认时，13 个后续步骤全部 skipped-dep、磁盘上只有审批门自己的产物——授权确认前零项目读取。新授权 = 新任务（已记录请求永不被恢复改写）。

## 3. REA 侧接入（用户环境）

PEA 不代劳，但给出已验证的事实与顺序：

1. **按 REA 自己的文档拉取**：REA 的安装、引擎（Ghidra/IDA/Hopper）检测、设备连接都以 REA 文档为准。已核实：REA 通过用户自己的 `adb`（`REA_ADB_PATH`）检测并驱动已连接设备/模拟器，缺失时报 `capability_unavailable` 而不安装。
2. **环境投入两边共享**：你为 REA 攻击准备的模拟器/adb/frida-server，与 PEA 测试台侦察检测的是同一套——`pea testbench` 报 T2，就意味着 REA 的动态步骤有家可归。
3. **工具版本入账**：简报只引用能力族与 `research_date`；具体工具名与版本由你的 agent 解析 REA 实时 catalog，并作为 `tool_name`/`tool_version` 写入每条证据。

## 4. 证据回流合同（agent 必须遵守）

`pea.ledger_record` 对每条观察强制：

| 字段 | 要求 |
| --- | --- |
| `authority` | `observation`（第三方工具观察）；文档/推断只能 inform，不能充当 observation |
| `environment` | **必填块**：`environment_tier`（T0–T4/unknown）+ 可选 `variant`/`device`/`environment_note`；缺块即拒收 |
| `tool_name` / `tool_version` | 实际执行的工具与版本；"blutter 类工具"不是版本 |
| `artifact_digest` / `content_digest` | 打的就是这个版本——演练前用 manifest 钉死 |
| `redacted_summary` | 声明式脱敏：记录方声明摘要；未声明的记录导出时显式标注，不代为总结 |
| `limitations` | 这条观察没覆盖什么 |

**unknown 也要入账**：hook 失败、环境未达、工具不可用——沉默不是证据。`failure_meaning=unknown` 的步骤结果同样是一条 observation。

## 5. 红线（违反任一条的观察不得入账）

1. 仅限用户拥有或获得书面授权的工件；
2. 演练全程只读：不修改、不回写、不重新打包目标产物；
3. 动态插桩仅限用户自有的沙盒设备/模拟器；禁止生产设备；
4. 工具失败/崩溃/不可用 = unknown，绝不解释为防护成功；
5. PEA 不分发、不安装、不执行任何攻击工具；
6. 结论绑定产物 digest 与时间预算，不可外推。

## 6. 常见失败模式

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| `pea brief` 报 deferred_steps 非空 | 测试台可达层低于步骤要求（如 hook 步骤要 T2） | 准备环境后重跑 `pea testbench` + `pea brief`；或将该步骤结果显式记 unknown 入账 |
| `ledger record` 拒收 `environment` 缺失 | 观察没带环境分层 | 环境分层是观察的一部分；补 `environment_tier` 字段 |
| `ledger gate` 返回 blocked | 有 blocking unknown 未消解 | `pea ledger resolve` 需两侧证据 + observation 权威；只报喜的消解会被拒 |
| REA 报 `capability_unavailable` | 用户环境缺 adb/设备/引擎 | REA 的命名不可用；这不是 PEA 的拒绝，也不是演练失败——是环境 unknown |

## 7. FAQ

**Q：能让 PEA 直接驱动 REA 吗？**
不能，也不打算。驱动 REA 的是你的 agent；PEA 的产出是简报与账本。把攻击执行内置进 PEA 意味着分发攻击工具链——许可、供应链与证据合同三方面都与项目纪律冲突。

**Q：演练一次要多久？**
简报自带时间预算（默认 180 分钟，按步骤权重分配）。预算耗尽后未完成的步骤一律记 unknown——不延长、不升级工具、不追加能力族。

**Q：破解包到了怎么用这套流程？**
破解包 intake 与响应计划见《第三环设计》§4（战场反馈回路）；破解包就是一个工件，七个域直接扫，与原版 manifest digest 逐字节 diff 定位失效防护层。
