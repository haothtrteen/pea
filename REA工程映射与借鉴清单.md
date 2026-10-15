# REA 工程映射与 PEA 可借鉴清单

> 来源：`/workspace/references/rea`，upstream commit `bb96afdbe32f5318d57fcb00099191c5a7712f53`（2026-10-12，main）
> 仓库：`https://github.com/morluto/rea`（HEAD SHA 与 `git ls-remote` 直连一致，完整性已校验）
> 用途：**只读参考**。PEA 不复制、不链接、不分发 REA 代码；本文所有条目均为"可借鉴的工程模式"，不含其实现细节的搬运。
>
> **时点与现状（复核于 2026-10-15，PEA 0.7.0）**：本文是 2026-10-13 对 PEA 0.2.2 快照的只读分析。正文中"PEA 现状/现在"一律指**该分析时点**，不是当前状态；各条已就地标注 0.7.0 的落地结果（结论：`schemas/` 入口强校验、ToolEffects 单一注册表、组合层、账本与 unknown、受控执行闭环均已落地）。
> 这对应 PEA-070 的前置条件——此前文档记载"容器无法解析 github.com，clone 失败"，该状态**在当前沙箱已解除**。

---

## 一、先确认一件事：PEA 的架构设计是"对"的

`docs/architecture.mermaid` 显示 REA 的真实分层是：

```
Entry Points(CLI/MCP) → Composition(工厂) → Adapters(Providers) → Application(共享工作流)
                                                                    ↓
                                                        Contracts(对外 Schema) / Domain(纯函数)
```

对照 PEA `docs/PEA-Architecture-Spec-zh-CN.md` §4，PEA 画的是同一张图（Intake/Profiler/Exposure Mapper/Research/Catalog/Strategy/Approval/Adapter Runner/Verification/Evidence Ledger）。

**结论：PEA 的架构方向没有跑偏，不需要重新设计。** 缺的不是设计，是把设计落成代码——而 REA 正好提供了每个层"落地后长什么样"的实物样本。

规模参照：REA 是 **2422 个 TS 文件 / 约 52.5 万行 / 1338 个测试文件**的 turbo monorepo。PEA 不需要这个体量，但可以借鉴它的**分层纪律**。

---

## 二、六个可直接借鉴的工程模式（按对 PEA 的价值排序）

### 1. Contracts 与 Domain 分层（对应 PEA-001 / M1）

| REA | PEA 现状 | 该怎么做 |
|---|---|---|
| `src/contracts/`（约 90 个文件，全部是**调用方可见的 Schema**） | 分析时点：`schemas/` 有 8 个 JSON Schema，但**代码不引用**。**现状（0.7.0）**：15 个 schema 是唯一真源，`validation.py` 在所有入口强校验（含 `additionalProperties:false`） | 把 `schemas/` 变成唯一真源，`build_plan` 入口强校验（**已落地**） |
| `src/domain/`（244 个文件，注释明确写着 "Pure side-effect-free modules"） | 分析时点：无对应层。**现状（0.7.0）**：纯函数已按此纪律分布（`planner` 打分/门控、`tiers` 分层、`ledger` 规则），未另立 `domain/` 目录——纪律落地，目录不机械复制 | 新建 `pea/domain/`：纯函数、无 IO，打分/门控/归一化都放这里 |
| `src/config/parseConfig.ts` + `parsers.ts`（Zod 校验环境变量） | 分析时点：无配置层。**现状（0.7.0）**：环境注入按同纪律落地（`PEA_TASK_STORE` / `PEA_LEDGER_STORE` / `PEA_RUN_STORE` / `PEA_AUTHORIZED_ROOTS` 集中在协议层解析，处理器只读 context，不裸读环境变量） | 新建 `pea/config/`，用 pydantic/jsonschema 校验，禁止裸读环境变量 |

**验收**：`goals:["非法值"]` 必须在入口被拒（分析时点静默通过，见分析报告 P0-1；**已落地**：入口 `validate_or_raise` 现在直接拒绝并列出违规路径）。

### 2. ToolEffects 单一注册表（对应 PEA-031，最高价值）

`src/contracts/toolEffects.ts`（690 行）是本次发现的**最值得借鉴的一个文件**：

- `interface ToolEffects` 用 11 个布尔字段穷举副作用：`mutatesTarget` / `mutatesSession` / `writesFilesystem` / `launchesProcess` / `accessesNetwork` / `changesUiState` / `mayDiscardData` / `executesForeignCode` / `mutatesDevice` / `idempotent` …
- `TOOL_EFFECTS: Readonly<Record<string, ToolEffects>>` 是**一张工具名 → 副作用的注册表**，每个工具都必须登记。
- 关键在 `DerivedToolAnnotations`（L25–L29）：`readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint` **只从 canonical effects 推导**，不允许手写。

分析时点：PEA 的 `mcp/tool-contract.json` 只有手写的 `side_effects` 字段，没有"从实现元数据生成"的机制——文档自己要求"ToolEffects 和 availability 必须从实现元数据生成"，正是这条。**现状（0.7.0）已落地**：`src/pea/tooleffects.py` 是唯一注册表，`tool-contract.json` / `tool-effects.json` 是生成产物，契约门断言与注册表逐字节一致（漂移即失败）；可用性同样来自实现（35 工具全部接线）。

**验收**：新增工具未登记 effects → CI 失败；手写的 MCP 注解与 effects 推导结果不一致 → CI 失败。

### 3. 结构化错误合同（对应 PEA 现有 exit code 的替代）

`docs/error-contract.schema.json`（747 行）定义了统一错误信封：`code` + `category`（枚举 10 类：`invalid_input` / `unsupported_provider` / `unsupported_target` / `integrity_mismatch` / `truncated` / `cancelled` / `timeout` / `resource_constraint` / `unavailable` / `execution_failure`）+ `retryable` + `remediation.action`。

分析时点：PEA 用 `exit 2`（异常）/ `exit 3`（无结果）/ `exit 4`（blocked）三个裸码，**无法区分"用户输入非法"与"策略阻断"**（非法 goal 被当成 blocked 处理）。**现状（0.7.0）**：输入非法已由入口校验归位（fail-fast + 违规清单），CLI 仍以 2/3/4 表达类别；完整结构化错误信封（`code`+`category`+`retryable`+`remediation`）**未采纳**——工具面用各工具的命名拒绝码（`error_codes`）承担同等职责，这是刻意的取舍，不是遗漏。

**验收**：`goals` 非法 → `invalid_input`；授权未确认 → 另一类；两者错误码与退出码都不重叠。

### 4. Unknown 是一等公民，不是兜底（对应 PEA-050 / 全局 DoD）

REA 为此做了三件事，PEA 在分析时点一件都没有（**现状（0.7.0）已落地前三件**：`ledger.py` 证据账本 + `pea.ledger_*` 六工具 + `audit_residual_unknowns` 随 verified 门机械返回，未知项是一等公民）：

- `src/application/investigation/EvidenceLedger.ts` — 证据账本
- `src/domain/unknownRegistryError.ts` — unknown 的注册与错误类型
- `list_unknowns` 工具（见 `src/contracts/sessionToolContracts.ts`）— **把"还不知道什么"作为可查询的接口暴露给调用方**

`docs/mcp-contracts.md` 里把语义写得非常清楚，值得直接纳入 PEA 的设计原则：

> `complete` means that set was returned without a known read limit; it does not claim every possible runtime edge.
> Missing coverage remains `unknown`.
> An empty call list with partial or unknown coverage is **not proof** that the function has no calls.

**验收**：报告里必须有 `unknowns` 数组，且空结果/工具失败/未运行三者必须可区分，不能都写成"未发现问题"。

### 5. 不可信目标内容处理（对应 PEA 的威胁模型 §7）

`docs/mcp-contracts.md` 的 "Untrusted target content" 一节明确：字符串、符号、反编译代码、页面文本、脚本体、网络捕获、日志、文件清单**全部来自被分析目标**，目标可以嵌入"看起来像给 agent 的指令"的文本。REA 的处理是：当数据看，且结果 `_meta` 带稳定标记告知调用方"这段内容不可信"。

PEA `docs/Threat-Model-and-Security-Policy-zh-CN.md` §7 已经写了同样的原则（README/注释/工具输出都是数据，不是指令），分析时点**尚未落到实现**。**现状（0.7.0）**：只读域已落地且从不执行目标内容（无指令执行路径）；但把"疑似指令"显式标注为 prompt-injection 尝试的机制**仍未实现**——如实保留为待办，不假装已覆盖。

**验收**：扫描结果里来自目标文件的内容必须带不可信标记；命中"疑似指令"只报告为 prompt-injection 尝试，不执行。

### 6. Composition Root（对应 PEA-030，CLI/MCP 共用 service layer）

`src/composition/` 的职责是"fresh typed provider and session factories, one-shot binding"——CLI 和 MCP 两个入口都**只依赖 composition**，不直接碰 provider。

分析时点：`cli.py` 直接 import `planner.py`，等 MCP server 加进来极易出现两套逻辑。**已落地**：组合层 `mcpserver.call_tool` 是 CLI 与 MCP 共用的 service layer（审批强制、授权根检查、命名拒绝同源），`pea protect` 与四个执行器都走它。

**验收**：同一输入在 CLI 与 MCP 下产出完全相同的 plan/evidence 字段（PEA-030 原话）。**已落地**：编排任务的 bundle 与 `pea demo` 逐字节等价（测试钉死）。

---

## 三、工具形态分类法（可直接用于 PEA 的工具命名）

`docs/tool-design.md` 给出 7 种任务形态，比 PEA 现在按"动作"命名更稳：

| 形态 | 用途 | 映射到 PEA |
|---|---|---|
| `inspect` | 关于单个目标/对象/资源的事实 | `pea.inspect_candidate`、制品审计 |
| `search` / `list` | 候选发现 | `pea.search_catalog`、`pea.list_unknowns` |
| `trace` | 跨证据的关系 | 调用链/依赖追踪 |
| `compare` | 显式配对的工件对比 | `pea.compare_results` |
| `workflow` | 需要组合的周期性结果 | 保护计划编排 |
| `observe` / `capture` | 运行时行为 | 动态测试（需单独审批） |

同一条文档还给了 PEA 最该记住的一句：

> A plan without execution does not establish runtime behavior.（没有执行的计划不能证明运行时行为）

这与 PEA 自己"不把构建成功当安全成功"完全一致。

---

## 四、对落地路线的修正建议

结合上一轮分析报告，基于本次拿到源码的事实，对里程碑做三处调整：

| 里程碑 | 原计划 | 修正 |
|---|---|---|
| **M1 契约优先** | 引入 jsonschema 校验 | 拆成两步：先对齐 REA 的**结构化错误合同**形态（`code`+`category`+`retryable`+`remediation`），再做 Schema 强校验。否则修完校验还是分不清"输入非法"和"策略阻断" |
| **M3 只读扫描器** | 4 天，纯功能 | **追加不可信内容标记 + unknowns 输出**，这部分必须和扫描能力同批做，后补成本高得多 |
| **M4 MCP 骨架** | 4 天 | **前置 0.5 天建 composition 层**；并移植 `TOOL_EFFECTS` 注册表 + 派生注解的设计，这是 PEA-031 的验收核心 |

另有两项本次确认**暂不可行**，应明确移出近期范围：
- 直接构建/测试 REA 本体（需 `npm install` + 5 个 submodule，其中 Ghidra/binwalk/unblob 体积巨大且部分需要厂商工具）——只读审计不需要。
- ShellVMP / FDartVMP 的源码审计：本次未拉取，仍维持 `documentation_reviewed`，不要因为 REA 拉成功就一并升级状态。

---

## 五、已同步修正的过期记录

PEA 早期文档记载"本执行容器无法解析 `github.com`，clone 失败"，并据此把 REA 的研究状态封顶在 `documentation_reviewed`。该前提在当前沙箱已不成立，已更新：

- `/workspace/references/PROVENANCE.md` — 新增，记录镜像来源、commit SHA、完整性校验方式、未完成项
- 下载包内的 `PEA-Design-Kit/sources.md`（对应本仓库 `sources.md`）— 更新"REA 审计状态"段
- 下载包内的 `PEA-Design-Kit/README.md`（对应本仓库 `README_zh.md`）— 更新"状态与限制"段

按项目自己的原则（未知就标 unknown，不用猜测填充），现在应该写成：**源码已取得、commit 已固定；`source_reviewed` 的行号级审计待执行，不得越级写成 `fixture_verified`**。
