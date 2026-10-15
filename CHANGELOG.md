## [0.7.0] - 2026-10-15

Phase 4 全链落地：**L1/L2**（WP1 MCP stdio server、WP2 任务编排器；原规划的 0.6.0 目标项，未单独发布）与 **L3/L4**（WP0 信任边界、WP3 执行器四件套、WP4 JS canary 闭环、WP5 研究通道、WP6 一句话保护命令）。

### 新增

#### Phase 4 L1（WP1）：MCP stdio server

- **MCP stdio server**（`src/pea/mcpstdio.py`，`pea mcp-server`）：官方 `mcp` SDK（可选依赖组 `pip install "pea[mcp]"`，`mcp>=2.0`）承载 JSON-RPC 传输与握手；PEA 侧只写协议适配，核心包保持纯标准库、缺 SDK 时入口给出安装指引（exit 2）。低层 `add_request_handler` 注册（SDK v2 API），高层装饰器不支持自定义 input_schema——tools/list 必须是合同面，故选低层。
- **合同驱动的工具发现**（`src/pea/toolschemas.py` + `mcp/tool-schemas.json`）：`tools/list` 从 `TOOL_EFFECTS` 注册表与 `tool-schemas.json` 生成，不从函数签名推导；协议面与合同面同源，契约门逐字段守卫。
- **契约门扩展**（`tests/test_toolschemas.py`，101 测试）：schema 工具集与合同一致、每个 schema 是合法 Draft 2020-12 且 `additionalProperties:false`、`required` 与合同 `input_required` 一致、tools/list 生成面零漂移；**"审批要求必须能被协议面表达"**门——合同要求授权确认但 schema 无字段可传的断裂（调用永远被拒）从此失败。
- **协议层集成测试**（`tests/test_mcpstdio.py`）：真实子进程起 server，官方客户端走 initialize → list_tools（31 工具，inputSchema 与合同逐字节一致）→ call_tool（只读成功 / schema 拒绝 / 未知工具命名拒绝）；无 SDK 时带原因跳过。

#### Phase 4 L2（WP2）：任务编排器

- **任务编排器**（`src/pea/taskrun.py`）：`pea.run_assessment` 把 demo 的编排抽取为 14 步工作流表（授权门 → 侦察 → 七个只读分析域 → 计划 → 攻击自测设计 → 证据账本 → verified 门 → 报告）。任务是一等持久实体：`task-XXXXXXXX/task.json`（状态 + 步骤表）+ 每个完成步骤一个 JSON 产物，全部原子写（临时文件 + 改名）——崩溃最多丢失在飞的一步。步骤记录自描述：`depends`/`soft` 随记录落盘，单凭任务文件即可还原其运行时的工作流形状（对齐设计文档"每个步骤记录……依赖关系"）。
- **恢复语义**：每步记录输入摘要（请求摘要 + 项目路径 + 全部依赖[含软依赖]的产出摘要）。done 且摘要未变的步骤不重跑；失败步骤从自身续跑，不重跑已成功步骤。软依赖产物仍进输入摘要——域重跑会带动其软消费者（账本/报告）重跑。
- **失败语义（不假绿灯的三条机械规则）**：
  - **账本 = 失败汇聚点**：九个分析域全是账本的软依赖——域失败时账本仍汇编，把每个未完成域记为 **blocking** unknown（"未评估，不冒充通过"）。严重度是编排规则（`ledger.record_unknown(severity="blocking")` 显式记录），不经域措辞/marker 匹配——marker 改动不能把"未评估的面"降级为"重要"。
  - **报告 = 成功产物**：不可缺失渲染的输入（侦察/计划/攻击自测/三个核心域）列为硬依赖——缺失即 `skipped-dep`，绝不渲染残缺报告；仅可选域缺失时报告照常渲染，该域区块诚实显示"未运行"而非"跑了没发现"。
  - **审批门停车**：未授权时其后 13 步全部 `skipped-dep`（命名原因）、任务 `blocked`、磁盘上只有审批门自己的产物——授权确认前零项目读取。授权后恢复进入同一道门。
- **四个新 MCP 工具**（进 `TOOL_EFFECTS` + `tool-schemas.json` + 合同再生成，31 → 35 工具）：`pea.run_assessment`（审批 `workspace_scope_confirmation`，分析根取授权根，请求原样入账）、`pea.get_task` / `pea.list_tasks`（只读）、`pea.resume_task`（双不可变规则：记录的项目路径与本次调用授权根不一致 → `path_outside_authorized_root` 拒绝——恢复不得切换分析对象；记录的请求永不被恢复改写——新授权 = 新任务）。
- **CLI task 子命令族**（`pea task run/status/list/resume/report`，`--store` 公共参数）：退出码纪律 0 done / 3 blocked / 4 授权未确认（不建任务，镜像 demo/brief）/ 2 命名边界错误；`run --out` 另导 report.md + bundle.json（store 里始终保留全部）。
- **MCP 存储注入**（`PEA_TASK_STORE` 环境变量，`src/pea/mcpstdio.py`）：store 根来自环境配置、永不来自工具参数——调用方给的路径会让调用写到运营者配置之外的 store。缺 store 时四个任务工具一律命名拒绝 `task_store_missing`。
- **bundle 与 demo 逐字段等价**（测试钉死）：九个分析字段（request / recon / domains / plan / attack_simulation / ledger / ledger_audit / gate_blockers / remediation_groups）+ report_markdown 与 `demo.run_demo` 相等；仅元数据块不同（记录编排器而非 demo）。

#### Phase 4 L3/L4（WP0 / WP3–WP6）：受控执行闭环

- **WP0 信任边界**：执行面授权根由 `PEA_AUTHORIZED_ROOTS` 环境注入（模型参数只能选根、不能建根；未配置时四个执行器以 `execution_roots_unconfigured` 整体关闭，只读面保持向后兼容）；审批事件与令牌签发分离——`ApprovalAuthority.issue` 必须挂可信通道产生的 `ApprovalEvent`（磁盘 store 跨进程共享，消费即焚：one approval, one token），agent 的 Boolean 只是意图；`pea.review_plan` 改为预览门：无事件时停车 `awaiting_approval` 并落盘待审批预览，`pea approve` 是第一个可信审批通道。
- **WP3 执行器四件套接线**：`pea.protect.py` 单一实现（快照受管工作区 → 结构化 argv 应用 → 独立三态验证 → 只读分析栈差分 → 仅限受管工作区的回滚），`apply_plan`/`verify_output`/`compare_results`/`rollback` 全部接线；**变换有效性门**（产物与快照逐字节一致 = fail，exit 0 不代表保护生效）；中断 apply 从快照重建后重放等价于首放；store 根由 `PEA_RUN_STORE` 环境配置。首个适配器 `javascript-obfuscator`@5.9.0（版本钉死 + 八字段机器可读 manifest + manifest schema 契约门）。
- **WP4 JS canary 七步闭环**：`demo/canary-js-licensing/`（测量载体 + 诚实声明：客户端校验混淆后仍是客户端校验；基线测试不含明文秘密以隔离测量）+ `scripts/verify_loop.py`（`make verify-loop`，不进默认 CI）——七步证据入档、八条判据机械核验全绿；实测归因入 manifest：明文秘密消失但顶层标识符名默认不重命名（上游 renameGlobals 默认关），暴露面 1→1 是命名形态残留而非明文泄漏。
- **WP5 研究记录合同**：`src/pea/research.py` + `schemas/research-record.schema.json`——来源带访问日期与版本锚点、license/maintenance/platform 三项核对、适用性三态、限制声明与决策理由；权威级恒 `external_claim`（schema const）；机械门：`accepted` 需三项核对非 unknown 且 applicability=applicable；离线（无 transport）产出全 unknown 的 deferred 记录，不空谈；检索结果只作来源，进候选必须过 candidate-review 门。
- **WP6 一句话保护命令**：`pea protect <path>`——分析 → 方案 → 审批预览 → 交互确认（唯一人工决策 y/N）→ 隔离执行 → 独立验证 → 前后差分 → 报告落盘；`pea approve --fingerprint` 为 MCP 面登记审批事件。

### 变更

#### WP1 / WP2 接入期的合同与协议面修正

- **四处审批类别修正**（WP1 接入时发现合同与协议面不一致，CLI 路径不走审批故此前面未暴露）：
  - `pea.check_testbench`：`workspace_scope_confirmation` → `none`。handler 无参、只跑固定只读探测命令（permissions 已钉死 `process:probe:<fixed_readonly_probes>`）、不碰项目数据；其 schema 无字段可传授权，原类别下每次 MCP 调用都会被拒。契约门 `test_mutating_tools_must_declare_approval` 同步细化：spawn_process 豁免仅当权限把进程范围限定为固定只读探测集。
  - `pea.ledger_query` / `pea.ledger_audit_unknowns` / `pea.ledger_gate`：`workspace_scope_confirmation` → `none`。只读账本查询，handler 读 run 作用域的账本而非项目树，CLI 对等路径亦无审批。
  - `pea.map_exposure` / `pea.ledger_record` / `pea.ledger_resolve` 及三个执行器（`verify_output` / `compare_results` / `rollback`，当时尚未接线）：schema 补齐审批表达字段（`authorization` / `explicit_user_approval` / `preview_confirmed`）——审批语义不变，协议面现在能表达。
- **两处注册表 input_required 漂移修正**：`pea.design_attack_simulation`（`plan_id/target_manifest/authorization` → `baseline/languages/platforms`，以处理器实际读取为准）、`pea.fetch_capability_intel`（`query` → `keywords`）；`tool-contract.json` 重新生成。
- **测试 2214 → 2359 passed**（+145：契约门 101、协议层 13（含缺 SDK 降级 2）、注册表/CLI 覆盖增量）。
- `docs/Dual-MCP-Wiring-Guide-zh-CN.md`：§0 诚实边界表"stdio server ❌ 未落地"退役；§2.3 从过渡薄壳改为真实 server 接法（安装、宿主配置、三条硬事实、令牌进程边界）。
- 测试 2359 → **2412 passed**（+16 契约门对 4 个新工具的参数化展开；+37 `tests/test_taskrun.py`：等价性 / 恢复不重跑 / 失败语义 / 审批门停车 / store 原子写与命名边界 / 组合层九场景 / CLI 退出码）。
- 质量门抓到并修复 WP2 接入期两处静态缺陷：`cli.py` 任务助手签名缺 `Any` 导入（F821 ×2）、`taskrun.py` 导入块排序（I001）。
- 按 Phase4 设计文档逐条核对后补齐（审计闭环，见 `docs/Phase4-Access-Orchestration-Execution-Design-zh-CN.md` §9 落地记录）：补 SIGKILL 现场恢复测试（`KeyboardInterrupt` 还原进程被杀：在飞步停在 `running` 且无产物文件，resume 从该步自身续跑——原测试只覆盖步骤内异常）；步骤记录落盘 `depends`/`soft`（对齐"每个步骤记录……依赖关系"，旧任务文件经 `from_dict` 默认值兼容）；两处有意偏差明文入档——只读域按确定性顺序执行（无依赖边只表达"可并行"，未引入线程池）、步骤表记 `unknown_count` 计数而 unknowns 全文在域产物与账本。

#### WP0 / WP3–WP6

- 版本 0.5.0 → 0.7.0；`pea.plan_protection` 持久化计划到运行 store 并携带 `project_path` + `plan_digest`（`protection-plan.schema.json` 相应扩展可选字段；`plan_digest` 不含自身字段，目标路径进 digest——换目标即换 digest，旧审批不覆盖新目标）。
- 合同再生成：35 工具全部 `WIRED_VERSION`；执行面共享拒绝码入各执行器 `error_codes`（`execution_roots_unconfigured` / `run_store_missing` / 适配器与保护循环命名错误全集）。

### 测试

- 2412 → **2451 passed**：+13 `test_wp0_trust.py`（§2.3 五条：自述授权被拒 / 根外路径 / 未配置整体关闭 / 可信通道单令牌 / 事件-范围逐字节绑定）；+9 `test_executors.py`（§3.5 五条：消费点拒令牌 / 伪造成功被变换有效性门抓住 / 中断重放逐字节等价 / 回滚演练与诚实失败 / 合同面逐字段一致 + manifest schema 门）；+8 `test_canary_js.py`（测量隔离 / 基线恰一命中 / 八判据在案 / 不进默认 check）；+7 `test_research.py`；+3 CLI 保护命令；既有令牌生命周期测试按事件模型扩展（签发必须挂事件、一事件一令牌、事件与范围不符拒绝）。
- `tests/test_mcpstdio.py` SDK 检测收紧：从裸 `importorskip("mcp")` 改为探测 `mcp.types` / `ClientSession` / `stdio_client` 具体符号——namespace 占位包骗不过（外部评审 P1 项）。

### 已知边界

- **stdio server 不含跨进程能力**：一次性令牌只在同一 server 进程内有效（重启失效，重放/过期/范围变更为命名拒绝）；账本跨进程续用需设置 `PEA_LEDGER_STORE`（单工具级持久化），任务级断点恢复由 WP2 编排器落地（见下）。
- 编排器（`pea.run_assessment`）的自动化只覆盖只读阶段；写入与执行类步骤**不在编排器内**，而由执行器四件套（`pea.apply_plan` / `verify_output` / `compare_results` / `rollback`，WP3 已接线）在 PEA 受管工作区内完成——编排器本身从不执行变换。
- `resume_task` 是进程内续跑 + 磁盘产物传递：不切换分析对象、不改写已记录请求；跨进程的"接着上周的任务跑"由 store 持久化支持，但一次性审批令牌仍随进程生死（WP1 边界不变）。
- 能力情报通道不由编排工作流查询——bundle 记录 `not_attempted`（未检索 = unknown，不是空结果）；需要时由调用方另行调用 `pea.fetch_capability_intel` 并合并。

---

## [0.5.0] - 2026-10-14

第三环落地（设计冻结于 `docs/Attack-Verification-and-Field-Feedback-Design-zh-CN.md`）：闭合"沙盘 → 实弹"最小回路，并交付 D7 战场反馈回路。三环框架的"证明"环由 🟡 转 ✅。

### 新增

- **第八域：环境侦察**（`src/pea/testbench.py`，`pea testbench` / `pea.check_testbench`）：只检测不安装、不启动。T0–T4 环境阶梯（T0 纯静态 / T1 桌面全权限 / T2 root 模拟器 / T3 root 真机 / T4 硬件级），探测命令全是固定字符串；frida 探测区分"进程不存在"（False）与"设备拒绝/不可达"（unknown + omission）；`reachable_tier` 附带 `tier_basis` 供事后重审；输出同构 `findings + coverage + unknowns`。**T4 永远不声称可达——架构答案是服务端迁移，不是演练缺口。**
- **任务简报五要素**（`schemas/mission-brief.schema.json`，`attacksim.design_mission_brief()`，`pea brief` / `pea.design_mission_brief`）：目标锚点（域扫描观察，脱敏）/ 工具族（能力映射 + research_date）/ 环境分层（testbench）/ 判据与预算（内嵌 attack-simulation）/ 红线（六条固定文本）。环境未达层的步骤**推迟为 unknown（deferred），不删除、不跳过记为通过**；environment 缺失时照常产出（`reachable_tier=unknown`）。
- **证据回流合同**：`evidence-record` 新增可选 `environment` 块（`environment_tier` 必填，T0–T4/unknown），attack-simulation 步骤新增 `environment_tier` 与 `variant_required` 字段。简报的 `evidence_return` 以 const 约束回流合同：`ledger_tool=pea.ledger_record`、`authority_required=observation`、`environment_required=true`——**缺 environment 块的证据账本拒收**。
- **CLI 账本入口**（`pea ledger record/query/audit/gate/resolve/export`）：`--store` 持久化，跨进程续用；ToolRefusal → exit 2，gate blocked/blocking → exit 3；`_ledger_context` 注入 UTC 时间戳。
- **D7 战场反馈回路**（`src/pea/fieldresponse.py`，`pea field intake/respond`，`pea.intake_cracked_artifact` / `pea.design_field_response`）：破解包 intake 复用 manifest 域 diff（机制零新增——diff 事实 = observation，"哪条防护失效"的层归属 = inference，新增文件 = unknown，三者权威等级分离入账）；响应计划是**服务端球门轮换**（rotate what the cracker stripped——他剥掉的正是他答不上的），灰度 rollout；`offline_required` 姿态**拒绝即交付物**（declined 而非空计划）；负向测试必含 `legitimate_variant_unaffected`（不误杀合法用户）。
- **双 MCP 接线指南**（`docs/Dual-MCP-Wiring-Guide-zh-CN.md`）：PEA 侧三形态（CLI / 组合层 `call_tool` / 过渡薄壳）、REA 侧接线、证据回流合同表、失败模式与 FAQ；§0 诚实边界表明确 stdio server 未落地（Phase 4）。
- **MCP 工具 27 → 31**：`pea.check_testbench`（spawn_process）/ `pea.design_mission_brief` / `pea.intake_cracked_artifact`（bounded_filesystem_read，双根都必须在 authorized_root 内）/ `pea.design_field_response`。

### 变更

- 契约门新增四个负向/语义门：越界 `environment_tier`、缺 tier 的 environment 块、field-response 措施必须服务端动作 + 合法变体负向测试、crack-intake 权威分级分离；`field-response.example.json` 纳入 EXAMPLE_SCHEMAS。
- `examples/attack-simulation.flutter-licensing.example.json`：A1/A2 标注 `environment_tier: "T0"`，A3 标注 `"T2"` 并演示环境未达 → deferred unknown 的完整语义。
- 测试 2127 → **2214 passed**（testbench 18 / mission brief 16 / fieldresponse 19 + CLI 三命令族覆盖）。

### 已知边界（本版不能做什么）

- **PEA MCP stdio server 仍未落地**（Phase 4，Unreleased 已交付 WP1）：当前接入形态为 CLI + 组合层 `call_tool`；接线指南给出过渡薄壳接法，不作为长期形态。
- **testbench 只检测不启动**：不执行 `adb root`（避免重启 adbd），root 状态不可判定时记 unknown；环境分层的可达性结论依赖探测命令的固定输出形态，设备侧异常一律 unknown 不是 FAIL。
- **D7 的 diff 只覆盖 manifest 枚举的 shippable 产物**：未枚举路径的改动不可见（intake unknowns 已声明）；新增文件不得假定为恶意载荷。
- 灰度执行在部署方，PEA 只出计划；`pea.design_field_response` 不连接任何服务器。

---

## [0.4.0] - 2026-10-14

路线图第 6 节长线项全部落地：L2 真实工兵层、M4 MCP 骨架、M5 账本工具化。

### 新增

- **L2 真实工兵层**（`src/pea/l2verify.py` + `scripts/verify_real.py`，`make verify-real`）：把七个保护域放到**真实字节**上验证。合成形态 canary 产物（ELF 头部与埋标字符串为真实字节，非 Flutter 构建——本环境无 Flutter SDK，产物逐字节可重建、摘要钉死在 `demo/canary-artifacts.manifest.json`）经七层三态验证：侦察 / 产物清单 / 秘密扫描 / native 结构 / Dart AOT / 构建集成 / CLI 端到端，55 项检查。
- **三态验证语义**：PASS（钉住的预期在真实字节上成立）/ FAIL（预期不成立或域在暂存树上崩溃）/ UNKNOWN（域自己拒绝评估）。整体状态 fail 支配 unknown 支配 pass，退出码 0/1/2，未评估不得窃取绿灯。
- **L2 抓到的两个真 bug**（证明"真实字节 > 合成 fixture happy path"）：ELF32 程序头 `p_flags` 偏移错误（用了 64 位的 4，正解 24）；buildint ABI 匹配必须匹配路径中任意位置的 `lib/<abi>/` 段对。
- **M4 MCP 组合层**（`src/pea/tooleffects.py` + `src/pea/mcpserver.py`）：单一注册表 `TOOL_EFFECTS` 同时携带合同字段与副作用字段，生成 `mcp/tool-contract.json`（27 工具）与 `mcp/tool-effects.json`（逐条过 `tool-effects.schema.json`），契约门断言两份 JSON 与注册表零漂移。
- **一次性审批令牌**（`src/pea/approval.py`）：绑定工具 / 计划 digest / 工件 digest / 规范化参数 digest / 工具版本 / 授权根 / 目标路径。重放（`token_replayed`）、过期（`token_expired`，时钟可注入）、计划变化、参数变化、版本变化（`scope_mismatch`）、路径越界（签发时即拒绝）全部为命名拒绝。
- **M5 账本工具化**：6 个账本 MCP 工具（`pea.ledger_record` / `ledger_query` / `ledger_audit_unknowns` / `ledger_gate` / `ledger_resolve` / `ledger_export`）接 `ledger.py` 运行时核心。`ToolContext` 增加 per-run 账本注册表与可选持久化存储（`ledger_store`），账本可跨进程续用；`run_id` 按文件名分量校验，路径逃逸即命名拒绝。
- **verified 门显式审计**：`ledger_gate` 的裁决附带产出它的 `audit_residual_unknowns`（blocking 计数、按域/严重度分布），门禁可事后重审，不需要重跑任何东西。
- **导出的脱敏纪律**：`ledger_export` 的 Markdown 只渲染记录自己声明的 `redacted_summary`，未声明的记录显式标注（不代为总结）；JSON 携带完整记录供机器审计——摘要与 digest 因此保持有意义。

### 变更

- 合同 27 工具中 **23 个已接线**（原 13 + 8 个 M3 域工具 + 6 个账本工具 + review 面），仅剩 4 个 Phase 4 执行器（`apply_plan` / `verify_output` / `compare_results` / `rollback`）为仅合同（version `0.0.0`）。可用性是实现属性不是合同属性：未接线工具返回 `tool_not_wired` 且**不消耗批准令牌**。
- **许可证统一为 MIT**（Copyright (c) 2026 haothtrteen）：原 `LICENSE-CODE.txt`（MIT）与 `LICENSE-DOCS.txt`（CC BY 4.0）合并为单一 `LICENSE`，代码与文档同许可；`pyproject.toml` 引用随之更新。
- **GitHub 文档**：新增英文 `README.md`（门面，模仿 REA 的文档结构）与 `DISCLAIMER.md`（负责任使用声明）；中文 README 移为 `README_zh.md` 并保留为维护基线，英文文档标注"进行中"。
- **介绍页（landing-page）更新**：CLI 命令从旧包名 `pea_planner.cli` 更新为当前的 `pea.cli`（含新增的 `demo` 端到端步骤）；FAQ 的能力状态改为 0.4.0 实际形态（七个只读域 + 证据账本 + 27 工具合同/23 接线，执行器与服务进程仍未落地）；下载包由冻结的 v0.2.2 重新生成为 `PEA-Design-Kit-v0.4.0.zip`（含全部当前源码与设计文档）；页面许可信息同步为 MIT © 2026 haothtrteen。
- **第三环设计冻结**：新增 `docs/Attack-Verification-and-Field-Feedback-Design-zh-CN.md`——实测攻击验证（REA 作为自测 oracle、任务简报五要素、环境分层 T0–T4、`testbench` 侦察域、源码作弊码原则）与战场反馈回路（D7：破解包 intake、服务端球门轮换、纠缠而非隐藏、中性失效红线）；Demo 文档"下一步"按设计重排（正式项目化已交付）。
- 错误码与实现对齐：6 个账本工具的 `error_codes` 从占位集改为真实拒绝码（`run_id_invalid` / `run_id_unknown` / `evidence_missing_fields` / `evidence_authority_invalid` / `evidence_id_conflict` / `resolution_needs_two_sided_evidence` / `resolution_requires_observation` / `resolution_text_required` / `unknown_not_found` 等）。
- 测试 2116 → **2127 passed**（账本工具 11 项：全流程流、缺 authority、重复 evidence_id、单侧消解、无观察级消解、未知 run、run_id 逃逸、跨上下文持久化、导出脱敏与覆盖确认、未知 unknown）；契约门 31 项。

### 已知边界（本版不能做什么）

- **不是 MCP server 进程**：组合层可调用（`mcpserver.call_tool`），但无 JSON-RPC stdio 服务进程；线上情报连接器需要运行时配置 transport。
- **合成形态不是构建验证**：L2 产物由 `struct` 逐字节合成（ELF 头部与埋标字符串是真实字节，但非 Flutter 构建）。Dart AOT 恢复率在合成形态下恒为 `unknown`——真实 Flutter SDK 构建 + blutter 恢复率实测仍开放。
- **Phase 4 执行器未落地**：计划里的 `apply_in_workspace` 步骤只有合同与令牌签发路径（`review_plan` 可签发绑定 `apply_plan` 的一次性令牌），没有执行器。
- 账本工具是交互面；demo 编排内的账本组装（`demo._build_ledger`）是另一条已存在的路径，两者共用同一运行时核心与同一套证据纪律。

---

## [0.3.0] - 2026-10-13

原型 1.0 垂直切片：防御工程闭环端到端跑通。

### 新增

- **M0 工程化基座**：src 布局、ruff/mypy/pytest 门、CI（3.10–3.12 矩阵 + CLI 冒烟）。
- **M1 契约与策略引擎**（`validation.py`）：纯标准库 JSON Schema 2020-12 子集校验器，入口强制校验、产出前自检；结构化错误合同（code / category / retryable / remediation）；`jsonschema` 参考实现交叉验证（`tests/test_validation_crosscheck.py`）。候选打分重写（M1 缺陷修复）。
- **部署姿态访谈层**（`intake.py`）：`unknown` 是一等公民，未被回答的问题必然出现在 `intake_unknowns`。
- **原型 1.0 demo**（`demo/`）：授权门 → 只读侦察 → 能力族匹配 → 计划生成 → 攻击自测设计 → 证据账本 → verified 门禁 → 报告，端到端垂直切片；固定时间戳下 bundle 与报告逐字节可复现。
- **证据账本运行时**（`ledger.py`）：双向证据门控（消解 unknown 必须同时声明 supporting 与 contradicting）、observation 级消解、`gate_for_verified` 机械阻塞；`audit_residual_unknowns` 把"没有发现 ≠ 证明安全"变成可执行检查。
- **攻击自测合同**（`attack-simulation.schema.json`）：红线入 schema（产物只读、工具失败只能记 unknown、解释规则枚举无"绝对防护"）；步骤按暴露层由高到低排序。
- **暴露面分层模型**（`tiers.py`）：四层暴露面（T1 工具放大层 → T4 算法逻辑层），修复顺序 = 攻击者边际成本排序；贯穿能力映射标注、步骤排序与报告修复优先级三个出口。
- **M3 七域 + D6 双通道**：project-recon / artifact-manifest / secret-scan / string-symbol-scan / native-check / dart-aot-check / build-integration 七域统一 `findings + coverage + unknowns` 输出；capability-intel 连接器（allowlist + 九种安全失败 + 离线默认 unknown）与 candidate-review 门控（block 优先于一切）。
- **REA 六维对标方案**与两个场景走查（Flutter 授权 / Electron 桌面）文档。

### 已知边界

- 演示场景是模拟不是范本；真实 Flutter 构建与 blutter 恢复率实测未做（0.4.0 起由 L2 合成形态层部分承接，恢复率仍 unknown）。
- 规划器只做目录匹配与计划生成，不扫描运行期行为；不联网、不安装、不执行第三方保护器。

---

## [0.2.2] - 2026-10-13 及更早

见 `docs/Update-Notes-v0.2.0.md`、`docs/Update-Notes-v0.2.1.md`、`docs/Update-Notes-v0.2.2.md`（REA 能力映射修订与公开文档核验阶段）。0.2.x 及更早的命令写作 `python -m pea_planner.cli ...`；包改为 src 布局后更名为 `pea`，`landing-page/` 的 v0.2.2 下载包是独立冻结产物。
