# 场景走查：保护一个 Flutter 项目的授权逻辑（端到端模拟）

**日期：** 2026-10-13 · **原型版本：** 0.3.0 · **性质：** 模拟场景，用于验证能力链、暴露缺口、反哺路线

本文模拟一个完整形态的用户请求，逐步走查 PEA 应有的行为。标注为 **[实测]** 的输出均由当前原型（commit `f63f8b8`）真实运行产生，可复现；标注为 **[设计]** 的环节尚未实现，本文同时给出其验收标准。场景中引用的外部工具事实见附录 B 的核查记录。

## 0. 用户请求原话

> 帮我保护这个项目的授权逻辑。

不加更多信息。此时模型**不知道**：项目用什么语言、授权逻辑在哪、分发给谁、跑在什么设备上。PEA 的第一反应不是搜工具，而是**先问明白**（intake），再**看清楚**（项目侦察），再**查攻击面**（情报检索），最后才谈方案。

---

## 阶段 1 · intake：先问明白 [实测]

`pea intake` 对本场景的示例请求（`examples/protection-request.flutter-licensing.example.json`）推导出：

```text
posture : platform_native_cleanup_first
理由    : 先清理发布产物里无意交付的材料，再评估是否需要更强的客户端措施。
置信度  : medium
建议目标: resource_protection, obfuscation

已作的假设（需你确认）：
  - 使用对象为 partners；环境校验类措施需评估对合法使用的误伤。

硬门槛：
  - 明确攻击假设与剩余风险，不得把"没有发现"写成"证明安全"
  - 保护前后语义、兼容性与性能预算有实测结果
  - 声明测试覆盖范围与未覆盖部分；未覆盖项记为 unknown

警告：
  - 客户端校验（反调试、环境门控、完整性探测）只能提高分析成本，不构成绝对保证；拥有设备完全控制权的对手面前没有可信的本地信号。
  - 必须离线且秘密不能移出客户端：此时不存在可信的客户端秘密边界，需明确接受该残余风险。

客户端加固: allowed=False requires_explicit_approval=True
```

**场景设定回顾**：应用以离线授权形式**有限分发给合作方**（`external_limited` + `unknown_devices` + 离线 + 秘密不可移出客户端）。

**判读**：

1. PEA 没有顺着"保护"二字直接堆加固。姿态是 `platform_native_cleanup_first`——先清理发布产物，客户端加固**暂时不允许**（`allowed=False`），语义是"现在不谈，先做清理，之后重新评估"。这是设计使然：在设备不受控的外部分发下，PEA 拒绝在产物未清理前就推销混淆类措施。
2. 两条护栏警告必然随行，且**不随用户意愿消失**：成本非保证、离线+不可移出的残余风险。用户若说"我要绝对安全"，这两条警告仍然原样输出。
3. **[实测发现的开放问题 R2]**：把同样的回答改成 `mass_offline` 会得到 `cost_raising_only` 且客户端加固 allowed=True——分发面**更广**反而约束更松，而"有限分发给合作方"却落入最严格的兜底分支。直觉上存在严格度倒挂，已记录为待复核项（见优化项）。

---

## 阶段 2 · 项目侦察：快速但不出错 [设计 → M3]

用户说"这个项目"。PEA 需要在几分钟内回答：什么语言、什么结构、什么分发平台、**要保护的逻辑到底在哪**。对应已规划的 `pea.assess_project`（只读、workspace 范围确认后执行）。

**[设计] 预期输出（产物侧）**：

```text
语言构成      : kotlin 62% / dart 27% / lua 8% / js 3%
构建系统      : Flutter (Gradle host + Dart AOT)
关键产物      : lib/arm64-v8a/libapp.so  ← Dart AOT 快照（业务逻辑在此）
              lib/arm64-v8a/libflutter.so ← Flutter 引擎
分发形态      : Android arm64 APK，签名更新通道
```

**跨语言陷阱与轻引导**：这正是用户提示的场景——"代码整体大部分为 Java/Kotlin，结果授权逻辑在 Lua/Web/其它语言里，导致一开始保护方向就错"。侦察规则草案（R4）：

- 语言占比**不能**推出保护对象位置；占比回答"项目是什么"，不回答"资产在哪"。
- 模型应向用户给**证据链**而非结论："我在 `lib/license/` 下发现 Lua 桥接层与 `LicenseValidator` 的 JNI 绑定，授权校验发生在 Lua 侧——要保护的到底是 Java 入口还是 Lua 实现？请确认。"
- 判读必须**轻引导**：给出定位与证据，把最终确认留给用户，因为真实项目的判读依赖项目自身约定。

**本场景的判读结果**：授权逻辑以 Dart 实现，编译进 `libapp.so` 的 Dart AOT 快照；`libflutter.so` 内置 BoringSSL（不经过平台 TLS 栈）。用户初始直觉"用 R8 混淆"在此被轻引导纠正：**R8/ProGuard 只作用于 Android Java/Kotlin 宿主层，完全不触及 Dart 快照**——若按直觉执行，保护会落在错误的语言层上，而真正的攻击面原样暴露。

---

## 阶段 3 · 攻击面研究：像攻击者一样思考 [设计 → PEA-020b；研究成果已入库]

用户场景原文："通过检索工具从看雪、52PJ、GitHub 或权威论坛获取 Flutter 目前的主要破解方法。" 检索结论（2026-10-13 web 核实，来源见附录 B）：

**主要公开分析路径（攻击面）**：

| 工具 | 做什么 | 关键事实 |
| --- | --- | --- |
| blutter | 解析 `libapp.so` Dart AOT 快照 | 从 `libflutter.so` 自动识别 Dart 版本并编译匹配的 Dart 运行时；恢复类层级/方法清单/带注释的 ARM64 汇编；整体倾倒对象池（`pp.txt`）；**自动生成 Frida 钩子模板**（`blutter_frida.js`）；目前仅 Android arm64 |
| reFlutter | 替换 Flutter 引擎 | 用打过补丁的引擎重打包 APK：转储运行时快照、**中和 BoringSSL 证书校验**以截获流量；需要版本匹配的预编译引擎 |
| Doldrums | 纯 Python 解析 Dart 2.x 快照 | Dart 3.x 已失效，仅历史参考 |
| Frida + 模式扫描 | 运行时 hook | 定位 `libflutter.so` 中的证书校验函数并使返回值恒真，绕过 reFlutter 无匹配版本时的缺口 |

**关键事实（影响防御设计）**：

- 授权逻辑在 `libapp.so` 内意味着攻击者的第一站是 Dart 快照分析，**不是** Java 层反编译。
- Flutter 自带 BoringSSL，Java 层的 TLS hook（TrustManager 等）全部无效。
- blutter 的自述 TODO 明确写着 "Obfuscated app (still missing many functions)"——`--obfuscate` **降低**自动化还原质量但**不阻止**快照结构解析。混淆是成本手段，不是秘密边界。

**[本次落地]** 以上研究成果已固化为结构化工件：`catalog/rea-capability-defense-map.json` 新增第 11 个能力族 `dart_aot_snapshot_analysis`（observations / potential_exposures / defense_options / verification / limitations），并通过契约门。情报不再是一次性对话记忆，而是可复核、可引用、可更新的目录数据。

**[设计] PEA-020b 情报检索连接器**：REA 的完整工具清单里**没有任何**联网/社区检索工具（见附录 A），所以这块没有现成参考，PEA 需要自建，且与 PEA-020 的候选工具检索是**两类不同检索**（优化项 R1）：

| | PEA-020 候选工具检索 | PEA-020b 分析能力情报检索 |
| --- | --- | --- |
| 检索对象 | 保护工具/方案（防御侧） | 破解方法/分析工具（攻击侧） |
| 产出 | 候选目录条目（走许可/维护门控） | 能力映射条目（走证据合同） |
| 固定来源 | 官方仓库、官方文档 | 看雪/52PJ/GitHub/权威技术站，域名 allowlist |
| 硬约束 | 结果只能进队列，不能直接执行 | 每条发现带来源+日期+置信度；`unknown` 不得写成 pass |

**[设计] 反向自检（R3）**：研究攻击面后，PEA 应把**攻击者同款工具**用于自家 release 产物——这正是 REA `verify:flutter` 的模式（对真实 APK 走 stdio MCP 端到端断言 49 项）。PEA 的对等验收标准："在 canary Flutter 产物上运行 blutter，记录恢复出什么；对象池倾倒里不得含需要保护的秘密"。

---

## 阶段 4 · 防御匹配：门控说了算 [实测]

`pea plan --request examples/protection-request.flutter-licensing.example.json` 的真实输出：

```text
status   : blocked
strategy : no_safe_match
posture  : platform_native_cleanup_first
selected : []
excluded : android-r8 -> license needs review; production recommendation blocked
unknowns : []

steps:
  S1 manual_review - 请求维护者提供可信仓库、许可证和可复现测试样例
  S2 reassess      - 更新目录后重新运行匹配；在此之前不自动保护或执行未知工件
```

**这个"失败"正是设计在工作**。场景里最像答案的两个候选，都被 PEA 自己的门控拦住了：

1. **android-r8**（能力匹配：obfuscation + android 目标命中）——被许可门拦下：`needs_review`，生产推荐阻塞。R8 对本场景本来也只保护 Java 宿主层（阶段 2 已判读）。
2. **fdartvmp**（目录中唯一的 Dart 层虚拟化候选）——**两层**被拦：`verification_status = research_only`（默认搜索直接排除）；且其能力族（`dart_function_to_private_ir` 等）对应 `function_virtualization` 目标，与请求的 `licensing_hardening / obfuscation / logic_extraction` 不匹配。用户直觉里的"用 FDartVMP 保护授权逻辑"在当前证据状态（`documentation_reviewed`，见 `sources.md`）下**不能**进入生产推荐——必须先过 PEA-070 源码审计门。

**PEA 的回答因此是诚实的**：不编造一个"看起来很配"的方案，而是给出两条路径——(a) 提供 FDartVMP 的源码级审计证据后重新评估；(b) 走不受许可门阻塞的架构路径：授权**决策**移服务端（本场景 posture 下受"离线+不可移出"残余风险约束，须用户明示接受）、或把关键纯函数经 FFI 移入原生保护库（改变攻击者所需工具链）。

---

## 阶段 5/6 · 报告与落地 [设计 → M5/M6]

- **报告（M5）**：证据账本汇总每一步的 observation / inference / unknown 与证据 ID；保护前后差分（产物 manifest + SHA-256、恢复对比、测试结果）；残余风险明示。
- **落地（M6 / `pea.apply_plan`）**：需要 `valid_scoped_one_time_token`（一次性审批令牌），仅在隔离工作区对用户确认的文件范围执行；`pea.verify_output` 要求 `test_command_preview_required`——测试命令先给用户看，再跑。
- PEA **不**替用户构建编译环境：构建集成在用户自己的工具链上执行（`--obfuscate` 是 Flutter 构建参数、R8 由 AGP 接管），PEA 的角色是校验产物与证据，不是包办构建。

---

## 场景 → 路线映射

| # | 场景步骤 | 承载工具/Skill | 里程碑 | 状态 |
| --- | --- | --- | --- | --- |
| 1 | 先问明白（分发/受众/设备/离线/威胁模型） | `pea intake`（CLI 已实测） | 已交付 | ✅ 0.3.0 |
| 2 | 请求合法性（非法 goal/空 targets 拒绝） | `pea.validation`（已实测） | M1 | ✅ 0.3.0 |
| 3 | 项目侦察（语言/结构/产物/平台） | `pea.assess_project` + M3 扫描器 | M3 | ⬜ 设计中 |
| 4 | 跨语言陷阱轻引导 | 侦察规则 R4（随 M3） | M3 | ⬜ 本文明文化 |
| 5 | 暴露面映射（libapp.so、对象池、TLS 栈） | `pea.map_exposure` | M3 | ⬜ 设计中 |
| 6 | 攻击面情报检索（看雪/52PJ/GitHub） | PEA-020b 连接器（R1） | 新增 Epic | ⬜ 本文提案 |
| 7 | 情报固化为能力映射 | `catalog/rea-capability-defense-map.json` | 已交付 | ✅ 本文 +1 族 |
| 8 | 候选匹配与硬门控 | `pea.search_catalog` / `pea plan`（已实测） | 已交付 | ✅ 0.3.0 |
| 9 | 候选工具源码审计 | PEA-070 审计门 + `docs/REA-Source-Audit-Template` | 已规划 | ⬜ FDartVMP 待审 |
| 10 | 报告与证据账本 | `pea.export_report` | M5 | ⬜ 设计中 |
| 11 | 用户批准后落地构建 | `pea.apply_plan` + 一次性令牌 | M6/M4 | ⬜ 设计中 |
| 12 | 反向自检（blutter 打自家产物） | verify:real-* 式脚本（R3） | 新增 Epic | ⬜ 本文提案 |

---

## 优化项（本场景暴露，建议并入路线）

**R1 · 把 PEA-020 拆成两类检索。** 候选工具检索（防御侧，产出目录条目）与分析能力情报检索（攻击侧，产出能力映射条目）走不同的 allowlist 与证据合同，共享"结果只能进队列、每条带来源与置信度"的硬约束。工作量：连接器骨架 + 来源 allowlist 配置 + 证据合同复用，约 3-4 天。

**R2 · 复核 posture 兜底分支的严格度倒挂。** `external_limited + unknown_devices` 落入 `platform_native_cleanup_first`（加固 allowed=False），`mass_offline` 反而得到 `cost_raising_only`（allowed=True）。需要一次设计评审：要么为外部有限分发增设独立姿态，要么在 cleanup 完成并验证后允许"复查升级"。这是**行为问题**不是 bug（语义是"先清理再评估"），但倒挂值得显式裁决并补测试固化。

**R3 · M3 扫描器必须内建"反向自检模式"。** 对标 REA 的 `verify:real-*`（88 个 npm verify 脚本、25 个 verify-real 引擎脚本、`verify:flutter` 对真实 APK 49 项断言）。PEA 的等价物：`pea verify --against-real-artifact`，对每类推荐措施至少一个真实产物级验证脚本（canary Flutter 产物用 blutter 跑、混淆后对比恢复率）。**没有这一步，"保护成功"就只是声称。**

**R4 · 项目侦察的跨语言陷阱规则。** 语言占比 ≠ 保护对象位置；模型给证据链与候选定位，用户做最终确认（轻引导）。规则写成 M3 扫描器输出合同的一部分（`coverage` + `unknowns` 字段），不写成自由文本提示。

**R5 · 补 `mcp/tool-contract.json` 的 JSON Schema。** 它目前只有结构性断言（工具名/审批声明），没有 schema，是契约门覆盖范围的缺口（M4 一并补）。

**R6 · 对齐 REA 的"验证 > 声称"基线。** REA 以 25 个真实引擎端到端脚本支撑其能力声称；PEA 每接入一类新能力（扫描器、连接器、apply_plan），CI 都应有对应的真实工件验证，而非仅单测。

---

## 附录 A · REA 实际提供了哪些能力（源码核实，2026-10-13）

以下数据直接来自 `references/rea`（commit `bb96afdb`）源码统计，非文档转述：

| 维度 | 实测数据 |
| --- | --- |
| MCP 工具声明 | contracts 目录声明约 **109 个**工具名（114 个 name 字面量去除 5 个非工具匹配） |
| 引擎/域包装 | **18 个**模块目录：ghidra / hopper / ida / jeb / frida / adb / flutter / browser / wasm / evm / go / dotnet / firmware / apktool / pcap / sqlite / native / windows |
| 端到端验证 | npm `verify:*` 脚本 **88 个**；其中 `verify-real-*.mjs` 脚本文件 **25 个**（Ghidra 14 / Hopper 4 / IDA 1 / Browser 1 / Electron 1 等） |
| Flutter 专项 | `identify_flutter_build`（识别 APK 内各 ABI 的 libapp.so 与快照哈希）+ `inspect_dart_aot`；`verify:flutter` 用**真实 APK** 经 stdio MCP 端到端跑通并断言 **49 项** |
| 证据契约 | unknown 生命周期：`record_unknown` / `update_unknown`（含 supporting/contradicting evidence IDs、required_authority/required_confidence、recommended_probes）/ `verify_unknown_resolution`；`audit_residual_unknowns`；toolEffects 副作用注册表约 690 行 |
| 引导式工作流 | `.agents/skills/reverse-engineer-anything`（SKILL.md v41）：按目标类型路由首个工具，声明"技能只提供说明，不注册服务器、不安装引擎" |
| **联网/社区检索** | **零。** 全部 109 个工具中没有任何 web search / 论坛检索 / GitHub 检索能力；唯一带 search 的工具是本地代码搜索 `search_android_classes`。`discover_webmcp_tools` 是 WebMCP 协议发现，不是知识检索 |

**对标结论**：用户引用的社区评论方向正确，但有两个数字需要修正——"verify:real-* 超过 50 个"实际是 **88 个 npm verify 脚本 / 25 个 verify-real 脚本文件**；"六步引导工作流"实际是 skill 文档形式的**软约束**路由（REA 作者自己也承认这点）。PEA 对标 REA 需要补的不是工具数量，而是三件事：**证据契约的机械化**（已随 0.3.0 部分落地）、**真实工件端到端验证**（R3）、**REA 明确没有的情报检索连接器**（R1——这反而是 PEA 相对 REA 的独有需求，因为 PEA 的输入是"我该怎么防"，而 REA 的输入是"这是什么二进制"）。

## 附录 B · 外部事实核查记录

| 事实 | 核查方式 | 日期 |
| --- | --- | --- |
| blutter：从 libflutter.so 自动识别 Dart 版本、编译匹配运行时、解析 libapp.so、输出 asm/pp.txt/objs.txt/blutter_frida.js；仅 Android arm64；TODO 自述"Obfuscated app (still missing many functions)" | blutter 官方 README（worawit/blutter） | 2026-10-13 |
| reFlutter：替换引擎重打包、转储快照、中和 BoringSSL `ssl_crypto_x509_session_verify_cert_chain`；需版本匹配 | reFlutter 项目页 + 公开技术资料交叉 | 2026-10-13 |
| Flutter 自带 BoringSSL 于 libflutter.so，不走平台 TLS 栈，Java 层 TLS hook 无效 | 公开逆向资料交叉 | 2026-10-13 |
| R8/ProGuard 仅作用于 Java/Kotlin 宿主层，不触及 Dart AOT 快照 | Android 官方文档语义 + 公开资料交叉 | 2026-10-13 |
| Doldrums 仅支持 Dart 2.x，Dart 3.x 失效 | 公开资料交叉 | 2026-10-13 |

以上均为 **web 检索核实**，未做本地源码审计；据此新增的能力映射条目若要升级为 `verified`，须按 `docs/REA-Source-Audit-Template-zh-CN.md` 执行源码级审计。外部工具的许可状态未审查，本仓库不引入、不分发、不自动执行它们。
