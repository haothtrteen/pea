# PEA × REA 六维对标方案

**日期：** 2026-10-13 · **输入：** `docs/Scenario-Walkthrough-Flutter-Licensing-zh-CN.md` 附录 A 的源码实测数据 · **性质：** 工程规划

## 0. 对标原则

**不按数量对标，按闭环与密度对标。** REA 的约 109 个工具覆盖的是"逆向分析闭环"（这是什么二进制 → 怎么拆它）；PEA 需要的是"防御工程闭环"（要保护的资产在哪 → 攻击者会怎么拆 → 堆什么措施有效 → 如何证明有效）的**同密度**覆盖。两个闭环大小天然不同，但对每个维度 PEA 必须达到同一标准：**每件能力都有合同、有副作用声明、有边界声明、有端到端验证**。REA 值钱的不是工具列表（其作者社区也承认），是这层纪律——对标对标的是纪律。

---

## D1 · 工具清单与合同密度

**REA 形态（实测）**：约 109 个 MCP 工具，每个走三件套——typed 输入/输出合同（`src/contracts/`）、副作用注册表（`toolEffects.ts` 约 690 行）、错误合同（`docs/error-contract.schema.json`）。

**PEA 对标物**：目标工具清单约 **26 个**（撰写时点 11 个 + 新增 15 个；**现状（0.7.0）**：35 个合同工具全部接线），按防御闭环分组。每个工具同样三件套，其中两件 PEA 已有机座：

| 三件套 | PEA 现状 | 缺口 |
| --- | --- | --- |
| 输入/输出 Schema | `schemas/` 8 个 + `pea.validation`（运行时强制，已实测） | `mcp/tool-contract.json` 本身无 schema（R5） |
| 副作用注册表 | `tool-effects.schema.json` + `pea.*` 命名空间 + mutating 工具必声明审批（契约门已有） | 待与工具清单同步扩 |
| 错误合同 | `PeaContractError`（code/category/retryable/remediation，已实测） | 升格为 `docs/error-contract.schema.json` 等价物 |

**目标工具清单**（M4 的排期依据）：

| 组 | 工具 | 状态 |
| --- | --- | --- |
| 已有 11 个 | assess_project / map_exposure / search_catalog / inspect_candidate / plan_protection / review_plan / apply_plan / verify_output / compare_results / export_report / rollback | ✅ 已声明 |
| 侦察·暴露面（M3） | scan_artifact_manifest · scan_strings_symbols · scan_secrets_redacted · locate_protected_logic（跨语言定位，R4） | ⬜ 新增 4 |
| 反向自检（R3/D4） | self_check_release | ⬜ 新增 1 |
| 情报（R1/D6） | search_candidates · search_capability_intel · record_intel_finding | ⬜ 新增 3 |
| 源码审计（PEA-070） | audit_candidate_source | ⬜ 新增 1 |
| 证据账本（M5/D5） | 落地形态为 `pea.ledger_record` / `pea.ledger_query` / `pea.ledger_audit_unknowns` / `pea.ledger_gate` / `pea.ledger_resolve` / `pea.ledger_export`（以注册表实现名为准） | ✅ 已落地（M5） |

**验收**：契约门覆盖 `mcp/` 全部数据；每个工具必有 purpose/side_effects/approval；mutating 工具无审批声明即 CI 失败（已有）。**工作量：R5 + M4 骨架约 4–5 天。**

---

## D2 · 域包装与能力边界

**REA 形态（实测）**：18 个引擎/域目录，统一接口但**不假装等价**——provider 不可用时显式拒绝并声明缺什么，绝不降级成假成功。

**PEA 对标物**：PEA 不包装逆向引擎，包装的是约 **9 个防御域**，每个域一个适配器 + 三态能力声明（能做 / 不能做 / 本环境 unknown）：

| 防御域 | 对应 REA 目录的镜像 | 输出合同 |
| --- | --- | --- |
| project-recon（语言/构建/平台识别） | catalogIdentity / application | `coverage` + `unknowns` |
| artifact-manifest（路径 + SHA-256 清单） | artifacts | evidence-record（hash） |
| string-symbol-scan | 借鉴其 strings/xrefs 输出形态 | exposure-finding |
| secret-scan（默认不读凭据、命中脱敏、蜜罐 fixture） | ——（REA 无对应物） | exposure-finding（`secret_value_redacted`） |
| dart-aot-check（D3/D4 的载体） | flutter | exposure-finding + coverage |
| native-check | native | exposure-finding |
| capability-intel（检索连接器） | ——（REA 无对应物） | capability-map 条目 |
| candidate-review（候选审查） | reference | research-candidate-review |
| build-integration（用户工具链接口，PEA 不包办构建） | —— | 产物验证记录 |

**硬规则**：域 provider 不可用 → 该域全部结论记 `unknown`，计划中相应措施不得标 `verified`；域接口统一输出 `findings + coverage + unknowns`（schema 已有）。

**验收**：每个域至少 1 个 provider 实现 + 1 个不可用降级测试（断言"拒绝而非假成功"）。**工作量：约 5–6 天（M3 框架先行，域逐个进）。**

---

## D3 · 端到端验证金字塔

**REA 形态（实测）**：88 个 npm `verify:*` 脚本、25 个 `verify-real-*.mjs`（Ghidra×14 / Hopper×4 / IDA×1 / Browser×1 / Electron×1）；`verify:flutter` 对**真实 APK** 经 stdio MCP 端到端断言 49 项。真实引擎验证不进默认 CI（需要本地引擎），单独触发。

**PEA 对标物**：`pea verify` 验证金字塔，逐层对标——

| 层 | 内容 | PEA 现状 | REA 对应 |
| --- | --- | --- | --- |
| L0 静态 | ruff / mypy | ✅ 每次提交 | lint |
| L1 单测+契约+交叉验证 | 1510 tests / 21 contracts / 1465 crosscheck | ✅ 每次提交 | vitest |
| **L2 真实工件** | canary fixtures + `verify-real-*` 脚本 | ✅ 已落地（0.4.0；R3/R6 的 L2 层缺口关闭） | `scripts/verify_real.py` / `build_canary_artifacts.py` / `verify_loop.py` |
| L3 发布前 | `verify:published`（安装包完整性） | ⬜ | verify:published |

**L2 目标脚本集**（每个推荐措施类型至少 1 个，没有 L2 的措施类型不得标 `verified`）：

```text
verify:recon        canary 多语言项目（Kotlin 主体 + Lua 桥接授权）——侦察必须报对语言分布与桥接边界
verify:manifest     对已知 fixture 的路径/SHA-256 清单必须逐字节精确
verify:secrets      canary 蜜罐密钥全命中 + 无秘钥误报 + 命中一律脱敏
verify:dart-aot     自建 canary Flutter release，blutter 实测 --obfuscate 前后恢复率对比（可测量的成本差）
verify:cli-e2e      请求 → 计划 → 审批 → 隔离执行 → 验证 → 报告全链道走通
```

canary fixtures 全部**自建、有意埋标、可重建**（构建脚本进仓库），不使用任何第三方逆向工具的分发物。**工作量：约 4–5 天（canary 构建是大头）。**

---

## D4 · Flutter 专项的镜像：反向自检

**REA 形态（实测）**：`identify_flutter_build`（各 ABI 的 libapp.so + 快照哈希）+ `inspect_dart_aot`——攻击者视角的侦察工具，`verify:flutter` 用它对自己做端到端验证。

**PEA 对标物**：同一能力的**防御性用法**——`pea self_check_release`：把"分析师会先跑到什么"变成自检器。对用户授权的自家 release 产物执行 libapp.so 清单、对象池扫描、字符串/端点检查，输出"攻击者同款工具能看到什么"的报告 + coverage + unknowns。

**边界红线**：仅用于用户自有/获授权产物；用公开工具（blutter 类）只读分析、不修改产物；结果只进证据账本；输出受 `secret_value_redacted` 约束。这条红线同时回答了"PEA 会不会变成攻击工具"——它只看自家东西，且每一步有审批令牌。

**验收**：`verify:dart-aot`（D3）即本维度的验收；输出合同复用 exposure-finding schema。**工作量：约 3–4 天（依赖 D3 的 canary 构建能力）。**

---

## D5 · 证据契约与 unknown 生命周期

**REA 形态（实测）**：`record_unknown`（question / severity / domain / required_authority / required_confidence / recommended_probes）→ `update_unknown`（**supporting + contradicting 双向 evidence IDs** / status / resolution）→ `verify_unknown_resolution`；另有 `audit_residual_unknowns` 总审计。静态证据不得冒充运行时观察。

**PEA 对标物**：合同已备、运行时未建。`schemas/evidence-record.schema.json` 已含 `authority: observation | inference | external_claim | human_assertion` 与 `coverage_state`，`exposure-finding` 已含 confidence/coverage/limitations——**缺的是把它们变成运行时账本**（M5 的准确定义）：

> **状态更新（M5 已落地）**：`src/pea/ledger.py` 与 6 个 `pea.ledger_*` MCP 工具均已实现并测试（见 Demo 文档 D5 行）；`audit_residual_unknowns` 经 `pea.ledger_audit_unknowns` / `pea.ledger_gate` 对工具面暴露，`gate_for_verified` 机械阻塞。下文为原始规划，保留作对照。

1. `src/pea/ledger.py`：`UnknownRecord` + `EvidenceLedger`，unknown 消解必须引用双向证据（支持 + 反驳），resolution 只认 `observation` 级证据；
2. D1 清单中的 6 个账本工具（list/record/update/verify/audit/export）；
3. `audit_residual_unknowns` 对等物：计划 `status=verified` 前强制审计——关键类 unknown 残留即阻塞，且"没有发现 ≠ 证明安全"由账本机械执行（今天的 `intake_unknowns ⊇ blocking` 不变量是它的第一块，已实测）。

**验收**：verified 结论至少引用一条 observation 级证据；消解 unknown 而无反向证据考虑的，CI 拒绝。**工作量：约 4–5 天（M5）。**

---

## D6 · 双通道情报检索（REA 为零，PEA 独有）

**REA 形态（实测）**：**零**。109 个工具中无任何 web/论坛/GitHub 检索（唯一 search 工具是本地代码搜索）。这块没有参考实现，是 PEA 相对 REA 的独有需求——因为 PEA 的输入是"我该怎么防"，答案依赖时效性情报（当前主流破解路径是什么）。

**PEA 对标物**（R1，把 PEA-020 拆成两类）：

| | search_candidates（候选工具检索） | search_capability_intel（能力情报检索） |
| --- | --- | --- |
| 检索对象 | 防御侧：保护工具/方案 | 攻击侧：破解方法/分析工具 |
| 固定来源 | 官方仓库、官方文档、包元数据 | 看雪 / 52PJ / GitHub / 权威技术站，域名 allowlist |
| 产出 | catalog 条目 → 许可/维护门控 | capability-map 条目 → 证据合同 |
| 证据等级 | 检索结果 = `external_claim`，源码审计后升 `verified` | 同左（本轮 `dart_aot_snapshot_analysis` 条目即首例：web 核实 = documentation_reviewed） |

**硬约束（两条通道共享）**：结果只进队列、不能直接执行；每条带 source + date + confidence；域名 allowlist 外、重定向越界、断网、失效链接、巨大响应、未知 MIME 全部安全失败（PEA-020 已有验收）；**断网 = 显式 `unknown`，不是降级更不是假成功**。

**验收**：对 canary 情报源跑通"检索 → 条目草稿 → 证据分级 → 入库契约门"全链道。**工作量：约 3–4 天（连接器骨架 + allowlist 配置，复用 evidence-record 合同）。**

---

## 排序与汇总

| 维度 | 缺口 | 里程碑 | 工作量 |
| --- | --- | --- | --- |
| D1 合同密度 | tool-contract schema（R5）+ 15 个新工具 | M4 | 4–5 天 |
| D2 域包装 | 9 个防御域适配器 | M3 | 5–6 天 |
| D3 验证金字塔 | L2 真实工件层（R3/R6） | M3 附带 | 4–5 天 |
| D4 反向自检 | self_check_release | R3 内含 | 3–4 天 |
| D5 证据账本 | ledger.py + 6 工具 + 强制审计 | M5 | 4–5 天 |
| D6 情报检索 | 双通道连接器（R1） | 新 Epic | 3–4 天 |
| **合计** | | | **约 23–29 天** |

**建议排序**（杠杆从高到低）：

1. **R5 + M4 骨架**——最低成本闭合 D1 的合同层，后续一切工具都长在这层上；
2. **M3 + R3/R4**——D2/D3/D4 一次推进：扫描器域框架 + canary fixtures + 自检器，场景走查已给出全部验收标准；
3. **M5（D5）**——把证据合同从 schema 变成运行时强制，"验证 > 声称"落地；
4. **R1（D6）**——检索双通道，让能力映射条目的更新从手工变成流水线；
5. **M6 落地执行**——apply_plan / verify_output 已有合同，最后接通。

**对标底线**：本方案不引入对 REA 代码的复制或链接（`references/PROVENANCE.md` 许可边界不变）；攻击者工具只出现在自检（D4）与情报条目（D6）中，且仅限自家产物与只读分析。
