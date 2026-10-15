# PEA 原型 1.0 Demo —— 防御工程闭环的第一次端到端跑通

**日期：** 2026-10-13（内容维护至 0.7.0，2026-10-15） · **性质：** 工程原型（规划 + 受管工作区内的受控执行） · **对应计划：** `docs/REA-Parity-Plan-zh-CN.md` 排序第 1–3 项的垂直切片

## 1. 这个原型是什么

原型 1.0 是 PEA 防御工程闭环的第一个**可运行垂直切片**：一条命令，把"要保护的资产在哪 → 攻击者会怎么拆 → 堆什么措施 → 如何证明有效"整条链路跑完，并产出一份人可读、机可复现的报告。

其中"资产在哪"由七个只读侦察域共同回答（D2 域包装的同一模式逐个进）：项目画像（recon）、产物清单（artifact-manifest）、秘密扫描（secret-scan）、字符串/符号扫描（string-symbol-scan）、native 结构（native-check）、Dart 快照（dart-aot-check）、构建集成（build-integration）；另有候选门控（candidate-review）与能力情报（capability-intel）两个非项目域。

它刻意**不做**的事和刻意做的事同样重要：

- 不安装、不运行、不分发任何保护工具或逆向工具；
- 不执行任何项目脚本（侦察是纯只读静态枚举）；
- 不产生任何"已验证有效"的结论——原型的账本里**必然**存在 blocking unknown，门禁必然阻塞，报告会说明为什么。

## 2. 跑起来

```bash
PYTHONPATH=src python3 -m pea.cli demo \
  --request examples/protection-request.flutter-licensing.example.json \
  --project demo/canary-flutter-licensing \
  --out /tmp/pea-demo-out
```

输出两件产物：

- `report.md` —— 人读报告（一页结论 + 七个章节，每节标注 [实测]/[设计]；第 2 节含多域侦察明细，第 5 节"修复优先级（由高到低）"按暴露面分层模型排序）；
- `bundle.json` —— 机读全量数据（请求、侦察、七个域结果、计划、攻击自测方案、账本、门禁、修复优先级分组、情报通道状态）。

退出码：`0` 正常完成（含计划 blocked 的有效演示）；`4` 授权未确认——此时 PEA 连项目都不读。

同一条走查也可以作为**可持久、可恢复的任务**运行（Phase 4 WP2 任务编排器，报告与账本和 `pea demo` 逐字节等价——这是测试钉死的，不是承诺）：

```bash
PYTHONPATH=src python3 -m pea.cli task run \
  --request examples/protection-request.flutter-licensing.example.json \
  --project demo/canary-flutter-licensing \
  --store /tmp/pea-tasks --out /tmp/pea-task-out
```

任务落盘在 store（每任务一个目录：`task.json` 步骤表 + 每个完成步骤一个 JSON 产物，原子写）；中断后 `pea task resume <task_id> --store /tmp/pea-tasks` 从失败步续跑，输入摘要未变的 done 步骤不重跑。退出码：`0` done / `3` blocked / `4` 授权未确认（不建任务）/ `2` 命名边界错误。任一域失败不产生假绿灯：账本把未完成域记为 blocking unknown，报告在输入缺失时跳过自己而不是渲染残缺文档；授权未确认时 13 个后续步骤全部 skipped-dep、磁盘上只有审批门产物——零项目读取。

L2 真实工兵层（单独触发，按 REA 纪律不进默认 CI）：

```bash
make verify-real          # 等价于 python3 scripts/verify_real.py
```

把源码 canary 与合成形态产物拼成一棵带构建输出的树，对七个域跑**真实字节**验证（三态 PASS/FAIL/UNKNOWN，55 项钉住的预期）；`--digests-only` 只核对 checked-in 产物与清单的摘要。ELF32 程序头 `p_flags` 偏移错误就是这一层在真实字节上抓到的。

## 3. 一条命令里发生了什么

```
request ──► 授权门 ──► 只读侦察 ──► 多域侦察 ──► 能力族匹配 ──► 计划生成 ──► 攻击自测设计 ──► 证据账本 ──► verified 门禁 ──► 报告
           (不读文件)   recon.py    artifactscan    attacksim.py   planner.py   attacksim.py      ledger.py    gate_for_verified   report.py
                                   secretscan
                                   symbolscan
```

各阶段的实测输出（对 canary 的运行结果）：

| 阶段 | 模块 | 实测结果 |
| --- | --- | --- |
| 授权门 | demo.py | `owner` → 放行；`not_confirmed` → 全链路停摆（四域均不运行），只产 blocked 报告 |
| 只读侦察 | `recon.py` | 识别 dart×3 / kotlin×1、flutter_dart+gradle 构建、android+ios 平台；定位 `lib/auth/license_validator.dart` 与 `lib/auth/license_store.dart` 的授权逻辑（模式名+行号+次数，**内容脱敏**）；未发现构建产物 → 记 unknown |
| 产物清单 | `artifactscan.py` | 枚举 18 种可发布产物形态（.so/.apk/.aab/.jar/.wasm/.dex/.node/.asar 等）；canary 无产物 → unknown finding（T1 标注保留）+ unknown |
| 秘密扫描 | `secretscan.py` | 6 种模式命中 1 个文件 2 种模式：`hardcoded_credential`（行 10）与 `hardcoded_endpoint`（行 9）——埋标的假密钥与 `.invalid` 端点被**仅按模式名**记录，内容脱敏 |
| 字符串/符号 | `symbolscan.py` | 输入为产物清单；清单为空 → `not_run` 降级（拒绝扫描而非假成功）+ unknown |
| 能力族匹配 | `attacksim.select_capability_families` | 语言/平台/授权信号规则式选中 4 族（dart AOT、托管代码、二进制布局、运行期观察）+ 差分对比族 |
| 计划生成 | `planner.build_plan` | 姿态 `platform_native_cleanup_first`；离线约束下 `android-r8` 因许可待审被排除 → `no_safe_match` / blocked（如实呈现，不凑候选） |
| 攻击自测设计 | `attacksim.design_attack_simulation` | 7 步最简方案，按暴露层由高到低排序：A1 是 dart 快照恢复对比（T1 工具放大层，47min），其后才是静态内容、运行期行为层步骤；只读、断网、180min 预算；解释规则锁定 `cost_delta_only` |
| 证据账本 | `ledger.py` | 侦察与三域证据按 observation 权威入库；9 条 unknown（3 blocking：recon/产物清单/字符串符号各自的"未发现产物"；其余为覆盖边界与攻击自测边界） |
| verified 门禁 | `ledger.gate_for_verified` | **阻塞**——"未发现构建产物"未消解前，任何 verified 表述都不允许 |
| 报告 | `report.py` | 八节报告（一页结论 + 七个章节）+ 下一步行动项；一页结论新增"多域侦察"状态行；第 2 节含多域侦察明细；第 5 节按 T1→T4 呈现修复优先级（八个来源：能力映射 / 侦察 / 产物清单 / 秘密扫描 / 字符串符号 / native 结构 / Dart 快照 / 构建集成），每条可溯源 |

### 红线在合同里，不在提示词里

攻击自测方案的三条红线由 `schemas/attack-simulation.schema.json` 机械强制，生成器在结构上就无法产出违反它们的计划：

1. `sandbox.read_only_artifacts` 是 `const true`——自测绝不修改产物；
2. `interpretation_rule` 枚举只有 `cost_delta_only` / `tool_failure_is_not_success`——"绝对防护"不可表达；
3. 预期观察为 `error_or_unavailable` 的步骤，`failure_meaning` 必须为 `unknown`——工具失败永远不等于防护成功。

生成器自身还有一条纪律：**每一步的 method 都原文引用能力映射中的记录观察**（"能力映射记录的事实：…"），攻击方法是检索到的事实，不是模型发挥；映射里没有对应观察的族不生成步骤。

### 修复顺序由暴露层机械决定，不靠编辑偏好

原型 1.0 同时把核心思路"暴露面由高到低修复"变成了工程模型——四层暴露面分层（T1 工具放大层 → T2 静态内容层 → T3 运行期行为层 → T4 算法逻辑层，`src/pea/tiers.py`），排序键是**攻击者抵达该层的边际成本**，成本越低越先修。三个出口同序：

1. 能力映射（`catalog/rea-capability-defense-map.json`）每个能力族声明 `exposure_tier`，契约门强制标注存在且合法；
2. 攻击自测步骤按 tier 由高到低重排重编号——A1 永远是成本最低的暴露面（demo 实测：dart 快照恢复对比排第一，语义是"一键工具就能恢复的话，深层保护免谈"）；
3. 报告第 5 节与 bundle 的 `remediation_groups` 按 T1→T4 汇总修复行动，每条带 `[能力映射·family]` 或 `[侦察]` 溯源。

模型依据与边界（severity 上浮不换层、T1 时效性、unknown 不丢序）见 [`docs/Exposure-Tier-Model-zh-CN.md`](Exposure-Tier-Model-zh-CN.md)。

### 多域侦察：D2 域包装的同一模式逐个进

原型 1.0 把 REA 对标方案的 D2 硬规则落成代码：**每个防御域统一输出 `findings + coverage + unknowns`**，域 provider 不可用时该域全部结论记 `unknown`——拒绝而非假成功。当前落地七个域，共享同一套只读遍历纪律（`src/pea/fswalk.py`：根边界检查、深度/文件数上限、VCS 跳过、跳过即记录）：

| 域 | 模块 | 回答的问题 | canary 实测 |
| --- | --- | --- | --- |
| project-recon | `recon.py` | 资产在哪（语言/构建/平台画像） | dart×3 / kotlin×1；授权逻辑定位（脱敏） |
| artifact-manifest | `artifactscan.py` | 什么产物会发布（路径+大小+SHA-256） | 18 种形态识别；无产物 → unknown（T1 标注不丢） |
| secret-scan | `secretscan.py` | 秘密材料是否躺在静态文件里 | 命中埋标假密钥与 `.invalid` 端点（仅模式名，内容脱敏） |
| string-symbol-scan | `symbolscan.py` | 二进制读作文本时会暴露什么 | 无产物 → `not_run` 降级 + unknown |
| native-check | `nativecheck.py` | 已发布二进制的结构加固（栈/NX/PIE/RELRO/strip） | 无产物 → `not_run` + unknown；全失败 → 拒绝假成功（T3 标注不丢） |
| dart-aot-check | `dartaotcheck.py` | Dart 快照面可观测性（锚点+对象池形态） | 无快照 → `not_run` + unknown；混淆状态恒 unknown（不给判定） |
| build-integration | `buildint.py` | 构建声明 vs 实际产物（防护是否落到该 ABI） | 无可解析声明 → unknown；"无声明 ≠ 构建正确" |
| candidate-review | `candidatereview.py` | 候选工具的许可/维护门控（能否进入计划） | 真实 catalog 门控：pyarmor/fdartvmp 等 blocked |

所有域都遵守与 recon 相同的纪律：摘要/命中超限记 omission 不造数据；`secret_value_redacted` 恒为 true（测试断言埋值不出现在任何输出）；finding 全部通过 `exposure-finding.schema.json` 校验并带 `exposure_tier` 标注，直接进证据账本与修复优先级。域之间通过 `DomainReport`（`src/pea/domains.py`）解耦——报告渲染任何域无需导入它。情报通道（capability-intel）默认离线：未注入传输实现时 bundle 记录 `not_attempted`（未检索 = unknown，不是空结果）。

### L2 真实工兵层：单元测试证明设计，真实字节证明实现

单元测试用合成 fixture 走 happy path，证明"代码按设计运行"；L2 层（`src/pea/l2verify.py` + `scripts/verify_real.py`）把域跑到**真实字节**上，证明"设计本身是对的"——ELF32 程序头 `p_flags` 偏移错误（native-check）与 ABI 目录匹配过窄（build-integration）两个 bug 都是这一层暴露的，合成 fixture 的 happy path 对它们完全沉默。

七层验证，每层三态判定（PASS/FAIL/UNKNOWN），`unknown` 不丢序：

| 层 | 钉住什么 |
| --- | --- |
| recon | 声明范围内完整走查（无遗漏），埋点授权逻辑被定位，范围限制被显式声明 |
| secrets | 埋点按模式名定位，内容在结果中不可见 |
| manifest | 6 个产物全部枚举、分类，逐字节摘要与清单一致 |
| native | libapp.so ×3 必须报可执行栈 + 未剥离符号（含 ELF32 的 armeabi-v7a——回归钉）；libflutter.so 必须干净（RELRO full 对照） |
| dart-aot | 四个快照锚点在每个 libapp.so 全部命中；混淆状态保持 unknown；不出现恢复率数字 |
| build-integration | build.gradle 声明的三个 ABI 与产物中的 `lib/<abi>/` 逐一 matched |
| cli-e2e | `pea demo` 对暂存树跑通，新域从 unknown 翻转为实测，埋点内容不出现在任何输出 |

Honesty 边界同样钉死在层里：域崩溃 = FAIL（真实字节上的崩溃是缺陷，必须响亮）；manifest 依赖失败 = 下游三层 UNKNOWN（依赖失败从来不是通过）；整体退出码 0/1/2 三态，未评估不得窃取绿灯。

## 4. 对照 REA 对标方案：原型 1.0 落地了多少

| 维度 | 内容 | 状态 |
| --- | --- | --- |
| D1 合同密度 | `tool-contract.schema.json` 新立并纳入契约门（R5）；**M4 组合层落地**：`tooleffects.py` 单一注册表生成 `tool-contract.json`（13→27→31→35 工具，0.7.0 现状）与 `tool-effects.json`（逐条过 `tool-effects.schema.json`），35 工具全部接线（WP0/3：执行器四件套接线，`tool_not_wired` 从合同面消失）；`approval.py` 短时一次性令牌绑定 plan/工件/参数/版本 digest，计划变化、过期、重放、路径越界全部拒绝；`mcpserver.call_tool` 调度带审批强制，未接线工具不消耗批准 | ✅ 合同层闭合 + 组合层与审批令牌 |
| D2 域包装 | 七域落地：project-recon / artifact-manifest / secret-scan / string-symbol-scan / native-check / dart-aot-check / build-integration / candidate-review，统一 `findings + coverage + unknowns` 输出、四态覆盖度、跳过即记录、共享只读遍历（`fswalk.py`） | ✅ 七域（其余域按同一模式逐个进） |
| D3 验证金字塔 | L0/L1 全绿（2451 测试 + 36 契约门 + 交叉验证）；L2 真实工兵层启动：合成形态 canary 产物（ELF/zip 真实字节，逐字节可重建、摘要钉死）+ `verify_real.py` 七层三态验证 55 项全绿 | 🟡 L2 已抓真 bug（ELF32 phdr 偏移、ABI 匹配）；真实 Flutter 构建 + blutter 实测仍开放 |
| D4 反向自检 | `design_attack_simulation` 原型落地：机械派生、时间预算、红线入 schema、步骤按暴露层排序 | ✅ 原型（执行器属 M4/M6） |
| D5 证据账本 | `ledger.py` 运行时落地：双向证据门控、observation 级消解、`gate_for_verified` 机械阻塞；**M5 工具化**：6 个账本 MCP 工具（record/query/audit_unknowns/gate/resolve/export）接运行时核心，`audit_residual_unknowns` 随门禁结果显式返回，账本可跨进程持久化（`ToolContext.ledger_store`），导出遵循"只渲染声明的脱敏摘要"纪律 | ✅ 运行时强制 + 工具面 |
| D6 情报检索 | `capintel.py` 连接器（allowlist + 九种安全失败 + 离线默认 unknown）+ `candidatereview.py` 门控（block 优先于一切） | ✅ 连接器与门控（真实检索需运行时配置 transport） |
| 核心思路工程化 | 四层暴露面分层模型：tier 标注（能力映射/finding/步骤）+ 排序重编号 + 报告修复优先级章节 | ✅ 运行时强制 |

## 5. 已知边界（这个原型不是什么）

- **演示场景是模拟，不是范本**：Flutter 授权场景与 canary 埋标用来说明流水线如何运转，不对应任何真实项目。真实应用的判断依据只有两个：域扫描实际观察到的**项目状态**（逐域 coverage + unknowns），以及能力映射地图级 `research_date`（2026-10-13，附“运行时确认”注记）的**社区实时状态**。把 demo 的命中结果当作"典型项目结论"依赖，恰是这套系统要防止的误用。
- **不是构建验证**：demo 走查的源码 canary 没有构建产物——"未发现构建产物"在 demo 里是 feature 不是 bug，它演示了"没有发现 ≠ 证明安全"如何被账本机械执行。L2 层已用**合成形态**产物（ELF 头部与埋标字符串是真实字节，但非 Flutter 构建）把七个域放到真实字节上验证，并抓到了两个真 bug；真实 Flutter 构建 + blutter 恢复率实测仍开放，恢复率在合成形态下恒为 unknown。
- **MCP server 是协议壳不是运行时**：WP1 已落地 `pea mcp-server`（官方 SDK 可选依赖；`tools/list` 合同驱动，`tools/call` 直达组合层、审批与命名拒绝零豁免），但 server 不含跨进程状态——一次性令牌随进程生死，任务级恢复属 WP2；**审批事件**则跨进程（落在运行 store，`pea approve` 在操作员自己的 shell 里登记）。执行器四件套已于 0.7.0 接线。
- **执行只在受管工作区内**：计划里的 `apply_in_workspace` 步骤已由执行器四件套（WP3）在 PEA 受管工作区（目标的一份快照）内完成，用户工程目录只读不写；执行结果以三态门 + 变换有效性门 + 前后差分报告呈现，绝不因工具 exit 0 就声明"已保护"。
- **通用模板仍粗糙**：非 dart 族的通用步骤只有一句目标；族级模板化是后续细化项。

## 6. 下一步（对照对标方案排序）

> Phase 4 方案已冻结：`docs/Phase4-Access-Orchestration-Execution-Design-zh-CN.md`（六个工作包，目标版本 0.6.0 / 0.7.0）。下述四项即该设计的落地主线，按"先可接入 → 再可编排 → 再可执行"排序：

1. ~~**MCP stdio server**（WP1，0.6.0）~~ **已交付（Unreleased）**：官方 `mcp` SDK 作为可选依赖组，工具发现由 `TOOL_EFFECTS` 合同驱动（不用函数签名自动生成 schema，保住契约门对协议面的守卫）；标准 MCP 客户端开箱发现并调用 31 个已接线工具；接入时另修掉四处合同/协议面审批不一致并新增"审批可表达性"契约门；
2. ~~**任务编排器**（WP2，0.6.0）~~ **已交付（Unreleased）**：`pea.run_assessment` 把本 demo 的链路升级为可配置、可恢复的工作流——任务持久化（每任务一个目录、原子写）、步骤摘要对比防重跑（软依赖产物也进摘要，域重跑带动账本/报告重跑）、失败域记 blocking unknown 不中断其他只读域、未授权停在审批门零读取；四个 MCP 工具 + `pea task` CLI 子命令族 + `PEA_TASK_STORE` 环境注入；bundle 九字段与报告与 `pea demo` 逐字节等价（测试钉死）；
3. ~~**受控执行与第一条真实闭环**（WP3–4，0.7.0）~~ **已交付（0.7.0）**：四执行器接线（快照受管工作区 + 一次性令牌消费点拒绝 + 变换有效性门 + 仅限受管工作区的回滚）；`demo/canary-js-licensing/` + `scripts/verify_loop.py` 七步闭环（`make verify-loop`）八条判据全绿（真实 javascript-obfuscator@5.9.0；实测归因：明文秘密消失但顶层标识符名默认不重命名，暴露面 1→1 是命名形态残留）；信任边界先行（WP0）：`PEA_AUTHORIZED_ROOTS` + 审批事件分离 + `pea approve`/`pea protect`；
4. ~~**候选研究工作流**（WP5，0.7.0）~~ **已交付（0.7.0）**：`research.py` + `schemas/research-record.schema.json`——来源带访问日期与版本锚点、三项核对（license/maintenance/platform）、适用性三态、accepted 需核对非 unknown 的机械门；权威级恒 external_claim；离线全 unknown 不空谈；检索结果只作来源，进候选必须过 candidate-review 门；

**已交付：第三环六个工作包（0.5.0）**——环境侦察 `testbench` 域（T0–T4）、任务简报五要素、schema 环境字段与证据回流合同、CLI 账本入口、双 MCP 接线指南、D7 战场反馈回路（破解包 intake + 响应计划 + 对决账本）；"沙盘 → 实弹"最小回路闭合。正式项目化（0.4.0：版本元数据 / CHANGELOG / CONTRIBUTING / MIT 许可 / GitHub 门面）已交付。

## 7. 复现性与测试

- 全量测试 **2451 passed**（累计新增：recon 14 / attacksim 21 / ledger 20 / e2e 20 / tiers 13 / fswalk 经 recon 覆盖 / artifactscan 13 / secretscan 14 / symbolscan 14 / nativecheck 29 / dartaotcheck 16 / buildint 12 / capintel 12 / candidatereview 17 / l2verify 14 / mcp 骨架 42——含令牌生命周期 11 项与账本工具 11 项 / testbench 18 / missionbrief 16 / fieldresponse 19 / mcpstdio 协议层 13 / taskrun 37——含与 demo 的九字段逐字节等价、恢复不重跑（含 SIGKILL 现场：进程被杀后从在飞步续跑）、失败语义、审批门停车、组合层九场景、CLI 退出码）；
- 静态门：ruff、mypy 全绿；契约门 36 项（catalog / examples / attack-simulation 语义门 / tool-contract schema / tool-effects schema 逐条校验 + 注册表漂移门 / capability map tier 标注门；另 tests/test_toolschemas.py 协议面门随全量测试运行）；
- 确定性：注入固定时间戳后，bundle 与报告逐字节可复现（`test_demo_e2e.py` 断言）；
- canary 防漂移：`build_canary.py` 与 checked-in fixture 逐字节一致由测试断言；合成产物同样双漂移守卫——`build_canary_artifacts.py` 重建与 checked-in 产物逐字节一致（`test_canary_artifacts_match_builder`），摘要与 `demo/canary-artifacts.manifest.json` 一致（`verify_real.py --digests-only`）。
