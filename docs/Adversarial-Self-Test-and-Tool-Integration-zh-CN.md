# 对抗性自测与保护工具分层集成

**日期：** 2026-10-13 · **性质：** 设计方案（部分已随本轮落地为合同与工具声明）· **上游：** `docs/REA-Parity-Plan-zh-CN.md` D3/D4

## 问题与结论速览

1. **落地时用户需要自测逆向对抗吗？** 需要。PEA 原则 4 只覆盖了一半：「构建成功 ≠ 语义正确」由 `pea.verify_output`（回归/兼容/性能门）验证；但**语义正确 ≠ 防护有效**——测试全过与"混淆真的提高了分析成本"是两回事。闭环缺一个**强度验证**环节。
2. **能否引导模型设计最简沙盒逆向自测攻击方案？** 能，且已经落地为合同：`schemas/attack-simulation.schema.json` + `pea.design_attack_simulation` 工具声明 + Flutter 场景示例。关键设计决策：**攻击步骤从能力映射派生，不从模型自由发挥**。
3. **REA 的 MCP 工具是实打实的逆向工具，PEA 如何应对？** 分层集成开源**保护**工具（见 §3 四层模型），攻击侧工具则采用 REA 自己的做法——**要求用户环境自备、PEA 不分发不自动安装、provider 不可用显式拒绝**。

---

## 1 · 对抗性自测：闭环的最后一环

```
intake ──> 侦察/暴露面 ──> 情报 ──> 匹配/门控 ──> 计划 ──> [批准] ──> apply ──> verify_output
                                                                                        │
              self_check_release（暴露面自检：攻击者能看到什么）                      │
              design_attack_simulation（强度自测：加防护后还剩多少）  <──────────────┘
```

两个自检概念必须分清，它们的**差值**才是防护有效的证据：

| | self_check_release（D4） | design_attack_simulation（本轮新增） |
| --- | --- | --- |
| 问的问题 | "攻击者第一站能看到什么" | "上了措施之后还剩多少" |
| 输入 | 一份产物 | baseline 与 protected 两份产物 |
| 输出 | 暴露面 findings + coverage + unknowns | 成本差证据 + 预算内结论 + unknowns |
| 结论形态 | 暴露清单 | **成本差**（恢复率/时间/工具失败率的可测量差异） |

**红线（编进 schema，不是写进提示词）**：

- `sandbox.read_only_artifacts` 为 `const true`——自测只读产物，绝不修改；
- `failure_meaning` 枚举只有 `protection_gap / cost_raised / unknown`——**工具失败、崩溃、不可用绝不记为防护成功**（架构 §11.2 机械化）；
- `success_criteria.interpretation_rule` 枚举只有 `cost_delta_only / tool_failure_is_not_success`——schema 层面**不存在** `absolute_prevention` 这个取值，"绝对防护"在合同上不可表达；
- `limitations` 为必填且非空——任何自测结论必须声明没覆盖什么。

**引导规则（如何"最简"）**：每个能力族只取**一条最短攻击路径**，能一步覆盖的能力族不得堆叠成两步；总预算耗尽即记 `unknown` 停止，不延长、不升级工具。模型的自由度被限制在：选择能力族子集、填写预期观察与预算——**攻击方法本身来自 `catalog/rea-capability-defense-map.json` 的 observations，是检索来的事实，不是模型编的**。

## 2 · 已落地工件

| 工件 | 内容 |
| --- | --- |
| `schemas/attack-simulation.schema.json` | 自测方案合同（红线入 schema） |
| `examples/attack-simulation.flutter-licensing.example.json` | Flutter 授权场景的最简自测：blutter 双产物恢复率对比（A1）→ 对象池密钥扫描（A2）→ Frida hook 尝试（A3，失败记 unknown）；180 分钟总预算 |
| `mcp/tool-contract.json` | +`pea.design_attack_simulation`（纯计划生成：side_effects 空、approval none；**执行**攻击步骤仍走 `pea.verify_output` 的 `test_command_preview_required`——命令先给用户看） |
| `tests/test_contracts.py` | 新示例入契约门 + 差分语义门（差分对比必须同时有 baseline 与 protected 两份产物） |

## 3 · REA 工具是实打实的逆向工具：PEA 的分层应对

**先看 REA 自己怎么处理"实打实的工具"**（源码核实）：REA **不分发** Ghidra/IDA/Frida/JADX——`verify:flutter` 要求调用方自带真实 APK 与本地引擎；provider 不可用时显式拒绝并声明缺什么。包装 ≠ 分发。PEA 完全照此办理，且对**保护工具**同样成立。

### 3.1 四层集成模型（按许可状态定层）

| 层 | PEA 做什么 | PEA 绝不做什么 | 许可要求 |
| --- | --- | --- | --- |
| **L1 配置生成**（默认） | 输出精确配置/argv/构建参数（proguard-rules.pro、javascript-obfuscator options、`flutter build --obfuscate --split-debug-info`）+ 验证脚本，用户在自己的工具链执行 | 执行工具、分发工具 | 几乎无（引用不受限） |
| **L2 自装驱动** | 用户环境从官方源自装工具；PEA 按 `plugin-manifest.schema.json`（source_url + artifact_sha256 + test_command + rollback_supported，**schema 已有**）定位、钉版本、驱动；provider 缺失显式拒绝 | 替用户下载/安装/升级 | 任意（进程外驱动） |
| **L3 受控执行** | 在隔离工作区执行钉版本工具，argv 冻结、审批令牌、资源限额、回滚（`apply_plan` 合同已有） | 无许可审计的工具进入此层 | 宽松许可（BSD/MIT/Apache）且 catalog `license=verified` |
| **L4 目录参考** | 目录条目 + 文档评审 + 门控拦截；可生成 L1 配置 | 任何形式的集成 | AGPL / 商业双授权 / 未审计 |

### 3.2 现有目录的落位（许可状态 = catalog 实测）

| 候选 | 许可（实测） | 可达层 | 说明 |
| --- | --- | --- | --- |
| javascript-obfuscator | BSD-2-Clause · **verified** | **L3 可达** | 宽松许可 + 已核实 → 唯一可进受控执行的现役候选 |
| android-r8 | Apache-2.0 · needs_review | L1/L2 | 经 AGP 驱动；R8 本身许可宽松，但发行链需复核，先走配置生成 |
| pyarmor | 商业许可 · needs_review | L1/L4 | 商业条款未审 → 配置生成 + 目录参考 |
| fdartvmp | AGPL-3.0-or-later · needs_review | **L4（审计前）** | AGPL 双授权 + `research_only` → PEA-070 源码审计是进 L2 的前置门 |
| logic-extraction-pattern / pea-restricted-ir-vm | not_applicable（自研/架构） | 自研层 | "先检索后自研"原则：检索记录齐 + 排除理由齐后才进入自研 |
| shellvmp / confuserex-legacy | needs_review / archived | L4 | 维护门与许可门拦截中 |

**AGPL 的处理要点**：进程外驱动（L2）不构成链接与分发，但 FDartVMP 这类**目标即是被保护产物构建链**的工具，其输出物许可影响必须由法律层面复核——这正是它被钉在 L4、且必须走 PEA-070 审计的原因。许可状态不因"开源"自动升级。

### 3.3 攻击侧工具（blutter / reFlutter / Frida）

不集成、不分发、不自动安装；只作为 `attack-simulation` 中 `tool_environment` 字段的**环境要求**声明（示例已示范）。执行发生在 `pea.verify_output` 之下且命令预览给用户。这与 REA 对 Ghidra 的处理完全同构，同时保住了许可边界（攻击工具许可未核验，见 `sources.md`）。

## 4 · 与六维方案的衔接

- **D1 工具清单 +1**：`design_attack_simulation`（11→12 个已声明；目标清单 26→27）。
- **D3 验证金字塔**：L2 的 `verify:dart-aot` 实际上就是本方案 A1 步骤的执行器化——attack-simulation 是**计划合同**，verify-real 脚本是**执行器**，两者共用同一份 schema 与红线。
- **D4**：self_check 与 attack_sim 的概念区分（§1 表）正式并入 M3+R3 的验收定义。
- **新增里程碑项**：`pea design_attack_simulation` 的原型实现（纯函数、零依赖、从 capability map 派生步骤）建议排入 M3 尾声，约 2–3 天；其验收 = 示例中的 A1/A2/A3 步骤能从 `dart_aot_snapshot_analysis` 与 `runtime_process_observation` 两个能力族条目**机械推导**出来。
