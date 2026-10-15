# WP3–5 落地方案：受控执行闭环与第一条真实保护路径

> 状态：**已落地（0.7.0，2026-10-15）**——六个工作包全部交付，验收证据见 §6 排期表与文末落地记录。本文是 Phase 4 设计（`Phase4-Access-Orchestration-Execution-Design-zh-CN.md` §4 L3 / §5 L4）的**落地方案**——把"执行器四件套接线 + JS canary 闭环 + 在线研究通道"从待办分解为可执行、可验收、可测试先行的工作包。设计原则与红线全部继承 Phase 4 设计，不另起炉灶；本文只做三件事：工作分解、外部评审输入处置、验收判据钉死。
>
> 目标版本：0.7.0。
>
> 前置输入：一份针对 `pea-0.5.0+wp2-snapshot-20261015.zip` 的外部评审，其可核实主张已逐条对照代码验证（见 §1）。本文采纳其中 4 条、修正 1 条、驳回 1 条，处置理由全部明文。

---

## 0. 现状与关键路径（一句话版）

（以下为方案撰写时点（2026-10-15 上午）的现状快照。）

已有：可接入（WP1 stdio server）、可编排（WP2 任务编排器）、八个只读分析域、审批令牌（绑定六元组）、35 工具合同 / 31 接线。

当时缺的就是一件事：**`tool_not_wired` 的四个执行器**。而接线前的真正前置只有一个：**信任边界**——当前 MCP 面的授权根来自调用方参数、`authorization` 是调用方自声明的字符串（`mcpstdio.py` `context_from_args`，代码证实），令牌签发只检查 flags（`_h_review_plan` → `ApprovalAuthority.issue`）。只读阶段这是可容忍的粗糙；`apply_plan` 一旦接线，这层自声明授权就是破坏性执行前的唯一闸门。

```
WP0 信任边界（半天，硬前置）
   ↓
WP3 执行器接线（适配器 → apply → verify → compare → rollback，约 1 天）
   ↓
WP4 JS canary 端到端（七步闭环 + 回滚演练，约半天）
   ∥（并行，不阻塞主线）
WP5 在线研究通道 + research-record 合同（可随时插入）
```

廉价项与 WP0 同车：SDK 检测收紧（`importorskip("mcp")` 无法区分真 SDK 与 namespace 占位——外部评审环境因此 5 failed）+ CI 双 job（core-only / full-integration）。

## 1. 外部评审输入与处置

| # | 评审主张 | 核实结果 | 处置 | 落点 |
| --- | --- | --- | --- | --- |
| 1 | 授权根来自模型参数、`authorization` 自声明、令牌签发无真实审批事件——执行器接线前必须先修 | ✅ 代码证实（`mcpstdio.py` `context_from_args`：`project_path` → root；`approval.py` `issue` 只看 flags） | **采纳，升为 WP0（硬前置）** | §2 |
| 2 | 有副作用步骤的 resume 不能"记录说 running 就盲目重放"，须先检查受管工作区 | ✅ 现有 `taskrun.py` 恢复语义对只读步骤安全（重跑无害），对写入步骤不安全（可能部分写入已完成） | **采纳** | §3.3 |
| 3 | 测试套件应区分真 SDK 与 namespace 占位；发布管道拆 core-only / full-integration 两 job | ✅ 机制成立（`pytest.importorskip("mcp")` 只测可导入性）；但严重度从 P0 **修正为 P1**——真 SDK 环境全量 2412 全绿，失败仅出现在评审方自己的占位 namespace 环境 | **采纳（严重度修正）** | §2.4 |
| 4 | 功能正确 ≠ 保护生效，须独立测量；用定义化、可重复的分析师任务协议测抗性；不折算单一安全分 | ✅ 与既有"缺证据不是成功"纪律同源，任务协议是具体增量 | **采纳** | §4.3 |
| 5 | `ProtectionAdapter` 六方法接口（inspect/preview/apply/verify/compare/rollback） | 部分合理 | **采纳前半，驳回后半**：verify/compare/rollback 是**工具无关**能力（跑测试 + 差分 + 丢弃受管工作区），合同已把它们定为独立工具与编排步骤；塞进 adapter 会让每个适配器重写通用逻辑。adapter 只管 inspect/preview/apply | §3.1 |
| 6 | "停止把 PEA 当分析规划助手"的框架性转向 | 评审自身后文已收敛（不加新工具、复用 35 合同）；分析栈恰是 compare 的差分引擎 | **不采纳为行动项**（与 Phase 4 既有规划收敛，无需转向） | — |

## 2. WP0：信任边界加固（新增前置工作包）

**原则**：模型给的 Boolean 不是授权。执行类操作的授权根与审批事件必须来自模型控制面之外。

### 2.1 授权根从环境注入

- 新增 `PEA_AUTHORIZED_ROOTS` 环境变量（路径列表，与 `PEA_TASK_STORE` / `PEA_LEDGER_STORE` 同纪律：**根来自运营者配置，工具参数只能在根内选择，不得建立根**）。
- `mcpstdio.context_from_args` 改造：授权根从 env 读取；调用参数中的路径必须落在运营者配置的某个根内，否则 `path_outside_authorized_root`（已有拒绝码，语义扩展到"建立根"这一侧）。
- **未配置 env 的回退语义**：四个执行器调用一律命名拒绝，新增拒绝码 `execution_roots_unconfigured`；只读分析面保持现状（参数即根，向后兼容，demo 与既有测试不炸）。执行面整体关闭、不静默回退——这是渐进收紧：先关执行，只读面的根收紧留到下一版本决策。
- **CLI 面不适用本约束**：CLI 是用户自己的 shell，信任锚就是用户本人（与 `ledger` 的既有结论一致："Approval is the user's own shell action here; the MCP face enforces it mechanically for agents"）。

### 2.2 审批事件与令牌签发分离

- `review`（生成预览）与 `approve`（真实审批）拆成两步：
  - **预览**（复用 `_h_review_plan`）：plan digest + 工具精确版本 + 受影响文件 + 输出目的地 + 预期副作用 + 令牌指纹。
  - **审批事件**：由可信通道产生审批记录。第一个可信提供者是 **CLI 交互确认**（`pea approve --fingerprint <令牌指纹>`：打印预览，人工确认后登记审批事件）；宿主确认 UI 属后续版本。
  - `ApprovalAuthority.issue` 增加入参 `approval_event`（可信通道产生），模型 flags 不再构成充分条件。
- **MCP 面上 agent 无法自助产生审批事件**——这正是设计目的。agent 能做的全部是"请求预览"；审批必须落到人。

### 2.3 测试先行（WP0 验收）

1. agent 送 `{"authorization": "owner", "explicit_user_approval": true}` + 合法参数请求执行 → 被拒（缺真实审批事件）。
2. 运营者配置根之外的路径 → `path_outside_authorized_root`。
3. 未配置 `PEA_AUTHORIZED_ROOTS` → 执行器 `execution_roots_unconfigured`；只读工具照常。
4. CLI 交互确认流程 → 审批事件登记 → 令牌签发成功；同指纹二次审批 → 拒绝。
5. 审批事件与令牌六元组任一不符 → 拒绝（既有测试模式扩展）。

### 2.4 廉价项（与 WP0 同车）

- `tests/test_mcpstdio.py` 的 SDK 检测从裸 `importorskip("mcp")` 收紧为探测具体符号（如 `mcp.server.stdio` / `ClientSession`）——namespace 占位包骗不过。
- CI 拆两个 job：**core-only**（不装可选组，验证缺依赖是显式 skip 不是 fail）与 **full-integration**（`pip install ".[dev,mcp]"`，起真实子进程走协议面）。

## 3. WP3：执行器四件套接线

### 3.1 适配器基础设施（新模块 `src/pea/adapters/`）

**接口**（有意只含三个方法，处置 §1-5 的落地）：

```python
class ProtectionAdapter(Protocol):
    def inspect(self, target: Path) -> AdapterInspect: ...
        # 支持的目标判定、工具精确版本、能力清单；工具不可用 → unknown，不是不可用≠不适用
    def preview(self, plan: ProtectionPlan, workspace: Path) -> ApplyPreview: ...
        # 结构化 argv + 受影响文件清单 + 预期输出目的地（供审批预览，逐字节可复现）
    def apply(self, plan: ProtectionPlan, workspace: Path) -> ApplyResult: ...
        # 受控执行：node 子进程、结构化 argv、不经 shell、cwd=受管工作区、
        # 超时与资源上限取合同 _EXEC_LIMITS、无网络；产物 manifest 返回
```

**每个适配器配机器可读 manifest**（schema 进 `schemas/`，契约门守卫）：

| 字段 | 用途 |
| --- | --- |
| 工具标识 + 精确版本 | 可复现性（版本钉死，package-lock 入库） |
| 许可证与出处 | 法律与供应链审查（进 candidate-review 门） |
| 支持的语言与目标 | 防止无效选择（适配器自查，不符 → 命名拒绝） |
| 支持的变换 | 说明工具实际改什么 |
| 输入/输出范围 | 防止越界修改 |
| 配置 schema | 参数先校验再执行 |
| 资源上限 | 有界执行 |
| 已知限制 | 防夸大（如 javascript-obfuscator 官方文档警示部分配置 15–80% 减速——直接写进 manifest 限制字段） |

**第一个适配器：`JSObfuscatorAdapter`**。选型依据继承 Phase 4 §4：种子目录中验证状态最完整的候选（license `verified`、maintenance `active`、`candidate_requires_project_tests` 第三态诚实），闭环先用最便宜的真实工具打通。npm 不可用时 `inspect` 返回 unknown 并如实报告（复用 capintel 九种安全失败先例），不装作工具可用。

### 3.2 四工具接线（顺序 = 依赖序）

1. **`pea.apply_plan`**：校验令牌（重放/过期/范围六元组）→ 校验审批事件 → **快照目标到受管工作区**（digest manifest 钉死，rollback 的依据）→ `adapter.apply` → 产物 manifest 落盘 + 入账本（observation）。
2. **`pea.verify_output`**：独立检查，不信 exit 0——受管工作区内构建 + 回归测试 + 产物完整性；三态门（pass/fail/unknown）入账本。**外部工具退出码 0 至多说明"工具报告执行成功"，不自动产生"保护成功"的 finding。**
3. **`pea.compare_results`**：**复用只读分析栈做差分引擎**——保护前后各跑 secret_scan / string_symbol_scan（等既有域），manifest diff + 暴露面差分 + 包体积变化；运行时开销首期不测，记 unknown + manifest 限制字段的引用（诚实边界：不猜）。
4. **`pea.rollback`**：丢弃或恢复受管工作区（从快照重建）；恢复结果本身入账，**回滚失败也如实报告**（回滚是尽力而为的恢复，不是承诺）。

### 3.3 副作用步骤的恢复语义（`taskrun.py` 升级）

WP2 的恢复语义（"input digest 未变 → 不重跑；在飞步从自身续跑"）对只读步骤安全。对写入步骤追加一条机械规则：

- **受管工作区从快照重建使 apply 天然幂等**：resume 遇到写入类步骤时，先把受管工作区恢复到快照态，再决定重放——重放因此等价于首放，"盲目重放"变得安全（这是对评审 §1-2 主张的实现性回答：不是"先检查再决定"，而是**让重放本身无害**，检查只用于记账）。
- 步骤产物 digest 与记录比对：一致 → 补记 done 不重放；不一致 → 从快照重建后重放。两种路径都留证据。

### 3.4 合同翻正与门禁

- 四工具 `CONTRACT_ONLY_VERSION` → `WIRED_VERSION`；`tool-contract.json` / `tool-schemas.json` 再生成；`tool_not_wired` 从四个执行器上消失。
- 契约门新增：适配器 manifest schema 门、执行器可用性门（四工具必须有 handler 且版本翻正）。

### 3.5 测试先行（WP3 验收）

1. 令牌重放 / 过期 / 范围不符在执行路径上被拒（不是调用前被拒——消费点拒绝才算数）。
2. 伪造"成功"的工具输出（exit 0、产物未变）→ verify 门仍 fail/unknown，账本无"保护成功"。
3. apply 中断（SIGKILL 现场还原，WP2 测试模式复用）→ resume 从快照重建 → 重放等价（调用计数：adapter.apply 恰好 2 次，且最终产物与一次性成功路径逐字节一致）。
4. rollback 演练：人为破坏受管工作区 → 恢复 → 恢复证据入账；恢复失败路径 → 如实报告（不假绿灯）。
5. 四工具在 MCP 面的 schema 与合同逐字节一致（既有协议面门自动覆盖）。

## 4. WP4：JS canary 端到端（第一条真实保护闭环）

### 4.1 样板工程 `demo/canary-js-licensing/`

小型自含 Node 项目：license check 模块 + 明确的基线测试（`node --test`）+ 构建脚本。**文档明写：这是保护管线的测量载体，不是安全授权实现**——客户端检查混淆后仍是客户端检查（Phase 4 §4 红线 + 评审 §8 结论一致：客户端决策不因混淆变权威，服务端执法属架构建议，PEA 报告应能提出"把密钥依赖操作移到可信边界后"这类建议）。

### 4.2 七步闭环（每步证据入账本）

| 步 | 动作 | 证据 |
| --- | --- | --- |
| 1 | 基线：构建 + 跑测试 | 工具链版本、测试结果、包体积、manifest、暴露面 findings |
| 2 | 计划：适配器选择与变换清单 | 选择理由（catalog 证据）、变换项、可能破坏什么 |
| 3 | 审批：预览 + 真实审批事件 | 精确计划与受影响文件（WP0 机制） |
| 4 | 执行：受管工作区内混淆 | 工具版本、执行记录、产物 manifest |
| 5 | 功能验证：构建 + 回归 | 通过/失败/unknown 三态门 |
| 6 | 测量：前后差分 | manifest diff、暴露面差分、体积变化 |
| 7 | 失败演练：人为使测试失败 | PEA 拒收 → 丢弃/恢复受管输出 → 恢复证据 |

最终报告：跑了什么、过了什么、挂了什么、改了什么、**还有什么没验证**。

### 4.3 验收判据（八条，先钉后写）

| 判据 | 必需证据 |
| --- | --- |
| 原工程保持原样 | 原始 manifest 与 digest 复验一致 |
| 工具真实执行过 | 工具版本、执行记录、输出产物 |
| 保护产物存在 | 产物 manifest 核验 |
| 功能未破坏 | 基线与保护后测试都通过 |
| 变换有可测效果 | 前后差分 |
| 开销可接受 | 体积实测；运行时记 unknown + manifest 限制引用 |
| 失败被安全处理 | 强制失败测试与恢复证据 |
| 报告可复现 | 记录的输入、工具链、配置、证据齐全 |

**保护有效性独立报告**（六维，不折算单一分）：功能正确 / 静态暴露变化 / 对定义分析任务的抗性 / 体积与运行时开销 / 兼容与运维影响 / 残留风险与未验证假设。"抗性"测量用定义化任务（如"从产物中恢复 license 算法的字符串/符号可见性对比"），不用"看起来难多了"这类外观判断。

### 4.4 e2e 验证脚本

仿 `scripts/verify_real.py` 先例新增 `scripts/verify_loop.py`：干净目录解包 → 走七步 → 全部判据机械核验 → exit 0。"解压即测试全绿"回归项同步扩展。

## 5. WP5：在线研究通道 + research-record 合同（并行线）

- **research-record schema**（`schemas/research-record.schema.json`）：问题 → 检索来源（URL + 访问日期 + 版本/commit）→ 许可证/维护/平台核对 → 适用性判断 → 限制声明 → 接受/拒绝理由。
- 权威级恒为 `external_claim`；**搜索结果不得直接变成候选**——必须过 candidate-review 门（license / maintenance / evidence / trust，block 优先于一切）。
- 无 transport 时照常工作：全部结论 unknown，不空谈（既有 capintel 离线默认扩展）。
- **不阻塞主线**：WP5 与 WP3/4 无依赖，可随时插入；首条 canary 用种子目录既有候选即可。

## 6. 排期与规模估算

| 工作包 | 依赖 | 估算 | 测试先行纪律 |
| --- | --- | --- | --- |
| WP0 信任边界 + 廉价项 | 无 | 半天 | §2.3 五条先钉 |
| WP3.1 适配器基建 + JSObfuscatorAdapter | WP0 | 半天 | manifest schema 门先钉 |
| WP3.2 四工具接线 | WP3.1 | 半天 | §3.5 五条先钉 |
| WP4 JS canary + verify_loop | WP3 | 半天 | §4.3 八条判据先钉 |
| WP5 研究通道 | 无（并行） | 半天 | 离线全 unknown + 门控测试先钉 |
| WP6 文档/合同/打包同步 | WP0–5 | 收尾 | 文档数字零漂移 sweep + 解压即测试 |

关键路径合计约两个工作日。**每个工作包动工前先把它的验收测试写出来**——WP2 的耗时构成证明：测试保真度调试是最大成本，把它前移到实现之前，比事后补测试便宜。

## 7. 边界（本方案不做的事）

- **不撤任何审批门**；无人值守自动执行不进本期（继承 Phase 4 §1-4）。
- **不自研 VMP/IR 后端**——先证明 PEA 能选择、集成、验证现有工具（继承 §7）。
- **首条闭环只 JS**，Flutter / R8 / native 明确延后；不做多平台并发执行。
- **运行时性能首期不实测**——记 unknown + 引用 manifest 限制字段，不猜数字；benchmark 属后续版本。
- **只读面的授权根收紧延后决策**——本期只关执行面（`execution_roots_unconfigured`），只读面保持现状并向后兼容。
- **回滚不碰用户原工程**——一切恢复动作限定在 PEA 受管工作区内（评审 §3-D 采纳：绝不需要对用户仓库做破坏性 git reset）。

## 8. 未决问题（动工前需要拍板）

| # | 问题 | 本方案默认 |
| --- | --- | --- |
| 1 | `PEA_AUTHORIZED_ROOTS` 未配置时，执行面关闭是否可接受（vs 启动报错拒起） | 关闭 + 命名拒绝（渐进收紧，不炸既有部署） |
| 2 | `javascript-obfuscator` 的 `node_modules` 是否入库 | 不入库；锁文件入库 + 安装脚本；CI full-integration job 装真实依赖 |
| 3 | 首个可信审批提供者形态 | CLI 交互确认（`pea approve`）；宿主确认 UI 留后续版本 |
| 4 | canary 的"抗性"测量任务集首版范围 | 两项：字符串/符号可见性对比 + 选定逻辑恢复尝试（定义化、可重复） |

批准后按 §6 顺序动工；每个工作包完成即按 Phase 4 §9 模式追加落地记录，文档数字同步纪律（README / CHANGELOG / Demo 文档 / 接线指南）全程适用。

---

## 9. 落地记录（0.7.0，2026-10-15）

六个工作包按 §6 顺序交付；测试 2412 → **2451 passed**，lint / mypy / 36 契约门全绿，`make verify-loop` 八条判据全绿。

| 工作包 | 交付物 | 验收载体 |
| --- | --- | --- |
| WP0 信任边界 | `PEA_AUTHORIZED_ROOTS` / `PEA_RUN_STORE` 环境注入；`ApprovalAuthority` 审批事件（磁盘 store、消费即焚）；`review_plan` 预览门（无事件停车 `awaiting_approval` + 待审批预览落盘）；`pea approve` 可信通道 | `tests/test_wp0_trust.py` §2.3 五条：自述授权不能执行 / 根外路径拒绝 / 未配置整体关闭（只读面照常）/ 事件登记后单次签发 / 事件与范围任一不符拒绝；SDK 检测收紧（§2.4） |
| WP3 适配器基建 | `src/pea/adapters/`（三方法协议 + 八字段 manifest + `JSObfuscatorAdapter`@5.9.0，PEA 自有 runner、结构化 argv、无 shell） | `schemas/adapter-manifest.schema.json` 契约门；`tests/test_executors.py` manifest 逐字段校验 |
| WP3 四工具接线 | `src/pea/protect.py` 单一实现 + 四个 handler + 合同翻正（35/35 接线） | §3.5 五条：消费点拒令牌（handler 未被调用）/ 伪造成功被 `transformation_effective` 抓住 / 中断重放逐字节等价（调用计数 2）/ 回滚演练 + 失败如实入账 / 合同与 schema 逐字段一致 |
| WP4 JS canary | `demo/canary-js-licensing/` + `scripts/verify_loop.py`（`make verify-loop`） | §4.3 八条判据机械核验全绿；`tests/test_canary_js.py` 钉住测量隔离（基线测试无明文秘密）与"不进默认 check" |
| WP5 研究通道 | `src/pea/research.py` + `schemas/research-record.schema.json` | `tests/test_research.py`：schema 合规 / 权威级 schema `const` / 离线全 unknown / accepted 需核对非 unknown / 检索结果只作来源 |
| WP6 命令与收尾 | `pea protect <path>`、`pea approve`、文档数字同步、CI 双 job | `tests/test_cli.py` 一次性流程与报告断言；`make check` 全绿；CI core-only / full-integration |

**与方案的四点偏差（如实记录，不装作没有）**：
1. **§2.4 的 CI 双 job 在收尾时才补**——落地时先做了 SDK 检测收紧（探测具体符号），CI 拆分随后补上（core-only 不装可选组、full-integration 装 `.[dev,mcp]`）。
2. **§2.2 的"宿主确认 UI"未做**——首个可信通道按 §8-3 的默认决策落地为 CLI（`pea approve` + `pea protect` 交互确认）；MCP 面 agent 只能请求预览。
3. **§3.2 的 `verify_output` 命令预览**：机械表达为 `preview_confirmed` + 可选 `test_command`（结构化 argv）；CLI 一次性流程会展示检测到的命令，MCP 面由调用方显式传入预览过的命令。
4. **§4.3 的"抗性"测量**首版只做**字符串/符号可见性对比**（暴露面计数差分）；"选定逻辑恢复尝试"留待后续版本——因此 `compare_results` 的语义说明里明确"计数变化是观察，不是保护有效的结论"。

