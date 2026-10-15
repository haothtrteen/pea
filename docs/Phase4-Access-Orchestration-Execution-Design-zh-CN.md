# Phase 4 设计：可接入、可编排、可执行

> 状态：冻结（2026-10-15）。本文是第三环（`Attack-Verification-and-Field-Feedback-Design-zh-CN.md`）之后的下一程设计——把"分析原型"推进为"可被标准客户端接入、可接受任务、可在受控边界内执行保护并验证效果"的保护工程助手。
>
> 版本目标号：0.6.0（MCP server + 编排器）与 0.7.0（执行闭环 + 第一条真实保护路径）。

---

## 0. 现状与差距（一句话版）

> **落地状态（2026-10-15，0.7.0）**：本节"已有/缺口"是设计冻结时点（2026-10-13）的快照；下表四个缺口**已全部关闭**——WP1/WP2 与 WP0/WP3–WP6 均已交付，证据见 §6 落地清单与 §9 落地记录。

已有：八个只读分析域、规划器、证据账本、35 工具合同 / 35 接线、CLI 与组合层、任务编排器（WP2）、任务简报与战场反馈回路。

缺口（按外部审查共识排序；均为设计时点状态）：

| # | 缺口（设计时点） | 后果 | 现状（0.7.0） |
| --- | --- | --- | --- |
| 1 | **无标准 MCP 服务进程** | 标准 MCP 客户端无法发现/调用 27 个工具（当时计数），只能走 CLI 或组合层编程接口 | ✅ 已关闭（WP1：`pea mcp-server`，35 工具） |
| 2 | **无任务编排器** | `pea.demo_run` 是写死的演示链路，不能接受"分析这个项目"级别的高层任务，不能恢复中断 | ✅ 已关闭（WP2：`pea.run_assessment` 等四工具 + `pea task`） |
| 3 | **执行器未接线** | `apply_plan` / `verify_output` / `compare_results` / `rollback` 四个工具仅有合同，保护执行闭环不存在 | ✅ 已关闭（WP0/WP3：四执行器接线 + `pea protect`） |
| 4 | **候选研究靠预置种子** | capintel 有连接器框架但无在线通道，"先研究现有方案"的纪律只能靠人工执行 | ✅ 已关闭（WP5：`research.py` + research-record 合同；在线通道仍需注入 transport） |

## 1. 设计原则（继承 + 本期新增四条）

继承（不变）：合同先行且唯一真源；`unknown` 是一等公民；证据权威分级（observation / inference / external_claim / human_assertion）；审批强制与路径检查；默认只读。

新增：

1. **成熟 SDK，不自制协议薄壳**。协议实现（JSON-RPC、握手、传输）交给官方 `mcp` Python SDK；PEA 只写"工具发现 + 调用转发"这一层。长期维护一个自制 stdio 薄壳是负资产。
2. **零依赖纪律不被破坏**。核心 `src/pea/` 保持纯标准库；`mcp` SDK 进入 `[project.optional-dependencies]` 的独立可选组（与 `contracts` 组同模式），server 入口在缺包时给出明确安装指引，不影响 CLI 与组合层。
3. **合同是工具发现的唯一真源**。server 的 tools/list 从 `TOOL_EFFECTS` 注册表生成，**不用** FastMCP 的函数签名/docstring 自动生成 schema——那会制造第二真源，契约门将无法守卫协议面。
4. **执行是受控边界内的最小特权操作**。快照先行、审批令牌绑定、回滚路径在计划期声明；无人值守自动执行不进本期。

## 2. L1：MCP stdio server（第一优先）

**目标**：标准 MCP 客户端（Claude Desktop、MCP Inspector 等）开箱发现并调用全部已接线工具（WP1 落地时 27 个；WP2 后 31 个）。

**架构**：

```
MCP 客户端 ←(JSON-RPC stdio)→ SDK Server（官方 mcp 包，仅协议层）
                                    │
                                    ├─ tools/list ← 从 TOOL_EFFECTS 生成（含 input_schema）
                                    └─ tools/call → 参数校验（validation.py，按 tool-contract
                                                   的 input_schema）→ mcpserver.call_tool（组合层，
                                                   审批/路径/副作用检查原样复用）
```

**关键决策**：

| 决策 | 选择 | 理由 |
| --- | --- | --- |
| SDK 层级 | 低层 `Server`（或 FastMCP 的 `add_tool(fn, name=…, input_schema=…)` 自定义入口） | schema 来自合同注册表，不经函数签名推导——保住"契约门可守卫协议面" |
| 依赖位置 | `[project.optional-dependencies] mcp = ["mcp>=1.28"]` | 核心零依赖纪律；与 contracts 组先例同构 |
| 错误语义 | `ToolRefusal` → MCP error（保留 `code`），命名拒绝不降级为通用失败 | 拒绝码是合同的一部分 |
| 未接线工具 | 仍在 tools/list 暴露，调用返回 `tool_not_wired`（与组合层一致）；**0.7.0 起零未接线工具**，该守卫保留 | 可用性是实现属性不是合同属性 |
| 入口 | `pea mcp-server`（CLI 子命令）+ 独立模块 `src/pea/mcpstdio.py` | 与 CLI 既有分发一致 |

**验收**：MCP Inspector 能列出全部 31 个合同工具；调用一个只读工具（如 `pea.check_testbench`）成功；无授权调用写入类工具被命名拒绝；`pip install pea` 不拉 `mcp` 依赖；最小集成测试（起子进程 → initialize → list_tools → call_tool）在干净环境通过。

## 3. L2：任务编排器（`pea.run_assessment`）

**目标**：接受"分析这个项目、给出保护方案"级别的高层任务，自动串起授权确认 → 侦察 → 并行分析域 → 暴露面汇总 → 候选匹配与门控 → 计划生成 → 证据门禁 → 报告，且**可恢复、可审计**。

**任务是一等持久实体**（不是对话上下文）：

- 任务文件落盘（沿用账本 `--store` 模式）：`task_id`、状态、步骤表。
- 每个步骤记录：输入摘要（digest）、输出引用、状态（pending / running / done / failed / skipped-dep）、产生的 unknowns、依赖关系。
- 恢复语义：步骤输入摘要未变则不重跑；失败步骤修复后从该步续跑，不重跑已成功步骤。
- 失败语义：分析域失败 → 任务记 `blocked` + 该域 unknown（不冒充通过、不中断其他只读域）；审批未通过 → 任务停在审批门，等待令牌。

**调度规则**：只读分析域并行；写入/执行类步骤必须串行且过审批门；跨步骤数据传递全部走磁盘产物（与 demo 现状一致），不引入进程内全局态。

**复用**：`demo.run_demo` 的编排逻辑抽出为可配置工作流（不是删 demo——demo 变成工作流的预置配置）；账本、报告、门禁原样复用。

**新 MCP 工具**（合同先行，进 `TOOL_EFFECTS`，副作用声明按既有纪律）：

- `pea.run_assessment`（创建并启动任务；受审批门约束）
- `pea.get_task`（状态查询，含步骤表与恢复点）
- `pea.list_tasks`（任务清单）
- `pea.resume_task`（从失败/中断处恢复）

**验收**：一条命令完成全链且产出与 `pea demo` 等价的报告与账本；kill 进程后 `resume_task` 续跑成功；任一域失败不产生假绿灯。

## 4. L3：受控执行与验证闭环（执行器四件套 + 第一条真实路径）

**目标**：接线 `apply_plan` / `verify_output` / `compare_results` / `rollback`，并用一条**真实的**保护路径证明闭环成立。

**执行模型**：

```
计划（含每步的输入/副作用/回滚声明）
   │
   ▼
快照目标工作区（digest manifest 钉死）          ←—— rollback 的依据
   │
   ▼
用户批准（复用既有一次性令牌：绑定 plan digest
         + 工件 digest + 参数 digest + 授权根）  ←—— 已实现，只差执行器消费
   │
   ▼
apply_plan：受控工作区内调用外部保护工具
   │         （先只接 javascript-obfuscator；spawn 参数从计划
   │          的结构化 argv 生成，不经过 shell）
   ▼
verify_output：构建产物完整性 + 回归测试结果 → 入账本（observation）
   │
   ├── 回归失败 → rollback（恢复快照）→ 任务记 failed + 证据入账
   ▼
compare_results：保护前后差分
   （manifest diff + 暴露面差分 + 性能声明边界）→ 最终报告
```

**第一条闭环选 JavaScript**：`javascript-obfuscator` 是种子目录中验证状态最完整的候选（license `verified`、maintenance `active`、`candidate_requires_project_tests`——第三态诚实）。选它不是因为 Flutter 不重要，而是**闭环先用最便宜的真实工具打通**，Flutter/真实 SDK 构建路径（blutter 恢复率实测）延后到闭环骨架被验证之后。

**红线**（全部已在既有合同中，此处重申不撤）：外部工具失败 → unknown 不是 pass；工具输出不解析为"成功"除非合同声明了成功判据；执行不越出授权根；回滚失败也要如实报告（回滚是尽力而为的恢复，恢复结果本身入账）。

**验收**：JS canary 样板工程（`demo/canary-js-licensing/`：含真实构建脚本 + 基线测试）全流程——基线构建→测试→批准→混淆→构建→回归→差分→报告→回滚演练（人为制造回归，验证自动恢复）；每个环节的证据可在账本中复核。

## 5. L4：候选研究工作流（capintel 在线通道）

**目标**：对"保护一个 X"类问题，产出**有来源、有版本、有证据、有适用限制**的候选研究记录，而不是一段看似合理的自由文本。

- transport 注入点已留（连接器框架 allowlist + 九种安全失败 + 离线默认 unknown 已实现）；本期补**研究记录合同**（research-record schema：问题 → 检索来源（URL + 访问日期）→ 许可证/维护/平台核对 → 适用性判断 → 限制声明）。
- 研究结论权威级恒为 `external_claim`；搜索结果**不得**直接变成候选——必须经 candidate-review 门（license / maintenance / evidence / trust，block 优先）。
- 无 transport 时照常工作：全部结论 unknown，不空谈。

**验收**：给定一个目标问题，产出结构化研究记录（每条结论带 URL 与访问日期）；离线时全 unknown 且不伪装；在线研究结果经门控后进入或不进入候选目录。

## 6. 落地清单（工作包）

| # | 工作包 | 依赖 | 优先级 | 目标版本 | 状态 |
| --- | --- | --- | --- | --- | --- |
| 0 | 信任边界加固（WP0：执行授权根环境注入 + 审批事件与令牌签发分离）——源自 `Execution-Loop-Implementation-Plan-zh-CN.md` §2 | — | P1 | 0.7.0 | ✅ 已落地（0.7.0） |
| 1 | MCP stdio server：SDK 可选组 + 契约驱动的工具发现 + 参数校验 + 最小集成测试 | 现有组合层 | P0 | 0.6.0（随 0.7.0 发布） | ✅ 已落地（0.7.0） |
| 2 | 任务编排器：任务持久化 + 状态机 + 恢复 + 4 个新 MCP 工具合同 | demo 抽取 | P0 | 0.6.0（随 0.7.0 发布） | ✅ 已落地（0.7.0） |
| 3 | 受控执行器四件套接线（快照 + 令牌消费 + 回滚） | 审批令牌（已实现） | P1 | 0.7.0 | ✅ 已落地（0.7.0） |
| 4 | JS canary 端到端样板（第一条真实保护闭环） | WP3 | P1 | 0.7.0 | ✅ 已落地（0.7.0）——`make verify-loop` 八条判据全绿 |
| 5 | capintel 在线研究通道 + research-record 合同 | 连接器框架（已实现） | P2 | 0.7.0 | ✅ 已落地（0.7.0） |
| 6 | 文档 / 官网 / 打包同步（含接线指南的"过渡薄壳"章节退役） | WP1–5 | P2 | 随版本 | ✅ 已落地（0.7.0）——README/CHANGELOG/Demo 文档/接线指南数字零漂移 |

顺序刻意与审查建议一致：**先可接入（WP1），再可编排（WP2），再可执行（WP3–4）**；研究通道（WP5）不阻塞主线。

## 7. 边界（本设计不做的事）

- **不自研 VMP/IR 后端**——"先研究复用"纪律不变；自研只在研究证明无合适方案后立项。
- **不做多平台并发执行**——第一条闭环只 JS；Flutter/真实 SDK 构建路径明确延后。
- **不撤任何审批门**——编排器的自动化只覆盖只读阶段；写入与执行永远停审批门。
- **不把 L2 合成形态升格为真实构建验证**——真实 Flutter 闭环的既有 unknown 原样保留。
- **server 不新增任何绕过路径**——审批、授权根、路径检查、副作用声明全部在组合层，协议层零豁免。

## 8. 与现有架构的复用关系（零新概念清单）

| 现有资产 | Phase 4 中的角色 |
| --- | --- |
| `mcpserver.call_tool` 组合层 | server 的唯一后端；编排器的工具执行通道 |
| `TOOL_EFFECTS` / `tool-contract.json` | tools/list 的唯一真源；新编排工具的注册处 |
| `approval.py` 一次性令牌 | 执行器直接消费（绑定已含 plan/工件/参数/版本 digest） |
| `validation.py` 校验器 | server 参数校验；research-record 合同校验 |
| `ledger.py` 账本 | 任务步骤证据、执行证据、回滚结果入账 |
| `demo.run_demo` | 编排器的第一个工作流配置（demo 不删，变为预置配置） |
| capintel 连接器框架 | 在线研究通道的 transport 宿主 |
| candidate-review 门 | 研究结论进入候选目录的唯一通道 |

新概念仅四个：任务实体（持久化）、受控工作区快照、研究记录合同、SDK 可选依赖组。其余全部复用。

## 9. 验收标准汇总（每个工作包的通过判据）

1. **WP1**：MCP Inspector 列出 31 工具；只读调用成功；未授权写入被命名拒绝；核心零依赖不受影响。
   **落地记录（0.7.0；验收时点为 WP1 交付时）**：集成测试以官方客户端驱动真实子进程完成同等验收——initialize 握手、list_tools 31 工具（0.7.0 为 35）且 inputSchema 与 `tool-schemas.json` 逐字节一致、check_testbench 只读调用成功、缺字段/未知工具/未授权均命名拒绝；核心包 `import pea` 不含 SDK（mypy 30 源文件（0.7.0 为 36）、ruff 全绿）。另修复 WP1 接入时暴露的四处合同/协议面不一致（`check_testbench` 与三个 ledger 只读工具的审批类别、六个工具的 schema 审批表达字段），并新增"审批可表达性"契约门防复发。
2. **WP2**：高层任务全链产出报告；中断恢复成功；失败域不产生假绿灯。
   **落地记录（0.7.0）**：`src/pea/taskrun.py` 把 demo 编排抽取为 14 步工作流表，任务是一等持久实体（每任务一个目录、每步一个 JSON 产物、原子写）。三条验收各有机械载体：**全链产出报告**——bundle 九个分析字段 + report_markdown 与 `demo.run_demo` 逐字节相等（测试钉死，仅元数据块记录编排器而非 demo）；**中断恢复**——每步记录输入摘要（含软依赖产出摘要），done 且摘要未变的步骤零重跑（调用计数测试），失败步骤从自身续跑（注入崩溃后 resume，已完成域观察次数保持 1）；SIGKILL 现场（进程在两步之间被杀、在飞步停在 `running`）同样只丢在飞的一步——其输入摘要在执行前已落盘，resume 从该步自身续跑；**失败域不假绿灯**——账本=失败汇聚点（未完成域记 blocking unknown，严重度是编排规则、不经域措辞）、报告=成功产物（输入不齐即 skipped-dep）、审批门停车（未授权时 13 步全 skipped-dep 且磁盘只有审批门产物，零项目读取）。四个 MCP 工具（`run_assessment`/`get_task`/`list_tasks`/`resume_task`）+ `pea task` CLI 子命令族 + `PEA_TASK_STORE` 环境注入；resume 双不可变规则（路径不符拒绝、请求不改写）。测试 2359 → 2412 passed。
   **两处有意偏差（对照 §3 明文记录，不装作没有）**：(a) 只读分析域是**确定性顺序执行**（域之间无依赖边即表达"可并行"；证据管线确定性优先，未引入线程池，步骤表允许并行调度器接入）；(b) 步骤表记 `unknown_count` **计数**，unknowns 全文在各域自己的步骤产物与账本里（计数是步骤表的摘要，不是全文替代）。另：§3 要求的"每个步骤记录……依赖关系"已落进任务文件（每步带 `depends`/`soft`，单凭任务文件即可还原其运行时的工作流形状）；`get_task` 的"恢复点"由步骤表机械推导（首个非 done 步骤），无额外字段。
3. **WP3**：四执行器接线且合同可用性字段翻正（`tool_not_wired` 消失）；令牌重放/越界拒绝在执行路径上生效。
   **落地记录（0.7.0）**：`src/pea/protect.py` 是执行闭环的单一实现（CLI、四个 MCP 工具与集成脚本共用）：快照受管工作区 → 结构化 argv 应用 → 独立三态验证 → 只读分析栈差分 → 仅限受管工作区的回滚。四条判据的机械载体：**接线与翻正**——35 工具全部 `WIRED_VERSION`，`tool_not_wired` 不再适用任何合同工具（守卫保留）；**令牌拒绝发生在消费点**——`_enforce_approval` 在 handler 之前消费令牌，重放/过期/范围变化/路径越界都是拒绝（`tests/test_executors.py` 钉死，并断言 handler 一次都没跑）；**伪造成功被抓住**——新增 `transformation_effective` 门：产物与快照逐字节一致即 fail，工具 exit 0 不构成证据；**中断重放等价**——受管工作区在任何 mutating 重放前从快照重建，SIGKILL 现场重放后产物与一次性成功路径逐字节一致（调用计数 = 2）。另：执行授权根由 `PEA_AUTHORIZED_ROOTS` 注入（未配置即 `execution_roots_unconfigured` 整体关闭），store 根由 `PEA_RUN_STORE` 注入；首个适配器 `javascript-obfuscator`@5.9.0 携带八字段机器可读 manifest，并纳入 `schemas/adapter-manifest.schema.json` 契约门。
4. **WP4**：JS canary 全流程含回滚演练；账本中每环节证据可复核。
   **落地记录（0.7.0）**：`demo/canary-js-licensing/`（测量载体；基线测试不含明文秘密，使前后差分隔离生产文件）+ `scripts/verify_loop.py`（`make verify-loop`，单独触发不进默认 CI）走通七步——基线测试 / 计划 / 审批（预览 + 真实审批事件）/ 受管工作区混淆 / 三门 + 变换有效性门 / 独立基线运行差分 / 人为失败演练；八条判据逐条机械核验，真实 `javascript-obfuscator`@5.9.0 全绿。**实测归因入 manifest**：默认保守变换下明文秘密消失，但顶层标识符名默认不重命名（上游 `renameGlobals` 默认关），暴露面计数 1→1 是命名形态残留而非明文泄漏——如实测量，不做"保护有效"的结论。
5. **WP5**：结构化研究记录产出；离线全 unknown；结论经门控才入候选。
   **落地记录（0.7.0）**：`src/pea/research.py` + `schemas/research-record.schema.json`——来源带访问日期与版本锚点、license/maintenance/platform 三项核对、适用性三态、限制声明与决策理由；**权威级恒 `external_claim`（schema `const`，不是默认值）**；机械门：`accepted` 需三项核对非 unknown 且 applicability=applicable（核对全 unknown 却接受 = 构造时即拒绝）；离线无 transport 时产出"来源为空、全 unknown、deferred 且写明原因"的记录；检索结果只作来源字段，进候选队列必须过 candidate-review 门。
6. **WP6**：文档、官网、分发包与实现零漂移（含"解压即测试全绿"回归项）。
   **落地记录（0.7.0）**：一句话保护命令 `pea protect <path>`（分析 → 方案 → 审批预览 → 唯一人工决策 y/N → 隔离执行 → 独立验证 → 前后差分 → 报告落盘）与操作者审批通道 `pea approve --fingerprint`；文档数字四处同步（README / README_zh / CHANGELOG / Demo 文档）与接线指南状态翻正；CI 拆为 core-only（不装可选组，缺 SDK 必须显式 skip）与 full-integration（装 `.[dev,mcp]` 跑真实协议面）双 job。
