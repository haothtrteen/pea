# 暴露面分层模型 —— “由高到低修复”的工程化

**日期：** 2026-10-13 · **性质：** 核心设计（落地件：`src/pea/tiers.py` + capability map `exposure_tier` + 报告“修复优先级”章节）· **对应：** 架构文档执行摘要第 2 条（分析能力—暴露面—防护方案映射器）与设计原则 2（按风险路径防护，而非堆叠术语）

## 1. 一句话

**暴露面的修复顺序不是偏好，是攻击者抵达该暴露面的边际成本排序；成本越低越先修。** 这个排序由 `src/pea/tiers.py` 机械执行，贯穿能力映射标注、攻击自测步骤排序与报告修复优先级三个出口。

## 2. 四层模型

| 层 | 名称 | 定义 | 攻击者边际成本 | 修复杠杆 |
| --- | --- | --- | --- | --- |
| **T1** | 工具放大层 | 开源一键逆向工具直接命中的暴露面 | ≈0：工具现成、分钟级恢复 | 让工具失效/降效/被迫换工具链 |
| **T2** | 静态内容层 | 不运行即可观察的产物内容 | 低：扫描即得 | 清除、外移、裁剪 |
| **T3** | 运行期行为层 | 需运行目标才可见的行为 | 中：需运行环境与插桩 | 收窄运行期暴露 |
| **T4** | 算法逻辑层 | 需理解逻辑才能利用的结构 | 高：需人工阅读理解 | 混淆、虚拟化、逻辑重构、服务端化 |

**T1 是横跨 T2–T4 的放大器**：同一份产物内容，在存在一键工具时暴露程度高几个数量级——blutter 一次解析全量恢复 Dart 快照的类/方法结构，jadx 一键反编译 dex，Frida 用自动生成的模板 hook 校验函数。工具把内层暴露的获取成本压到接近零。

## 3. 为什么先修 T1——“针对工具”为什么不偏离初心

“针对暴露面做保护”的初心，追问到底是**针对暴露面的哪个属性**。暴露面有两个正交属性：

- **内容属性**：产物里有什么（T2–T4 的领域）；
- **可达性属性**：拿到它有多便宜（T1 的领域）。

一键工具不改变产物内容，但把可达性成本压到零——**此时“暴露面”实际上等于“工具效率”**。所以：

> 修复 T1 正是针对暴露面中**最便宜抵达、因而最先被利用**的部分；把工具层纳入修复范围不是偏离“针对暴露面”，而是把“针对暴露面”执行到底。

对防御方还有一层结构性含义：攻击工具链按产物形态特化且互不通用（Dart 快照要 blutter、.NET 要 JEB、native 要 Ghidra/IDA，每条链还有平台与版本锁定）。每做一层产物形态转换，攻击者就要换工具链——**工具切换成本是 T1 修复的主要实践形态**，capability map 中“relocate critical pure functions behind an FFI boundary so a different toolchain is required”记录的正是这一杠杆。

## 4. 三个出口：模型如何贯穿流水线

```
capability map (exposure_tier 标注)
        │
        ▼
attacksim 步骤按 tier 由高到低排序 ──► 报告「修复优先级（由高到低）」章节
        │                                （T1→T4，每条行动可溯源）
        ▼
recon findings 带 exposure_tier ────────► bundle.remediation_groups（机读）
```

1. **能力映射标注**（`catalog/rea-capability-defense-map.json`）：每个能力族声明它主要放大的暴露层。契约门强制：无标注或非法值即 CI 失败——没有 tier 的族会从“由高到低”排序中静默掉队。
2. **攻击自测排序**（`attacksim.design_attack_simulation`）：生成的步骤按 tier 由高到低重排并重编号，A1 永远是成本最低的暴露面。语义：如果一键工具就能恢复，深层保护免谈——先测放大器。
3. **报告修复优先级**（`report._section_remediation`）：按 tier 汇总修复行动，两个来源都带溯源——能力映射记录的 `defense_options`（按族标注）与侦察发现的 `recommended_actions`（按 finding 的 tier 标注）。章节头部明示排序依据，读者不会把它误读为编辑偏好。

## 5. 当前能力族的 tier 归属

| 能力族 | tier | 归属理由 |
| --- | --- | --- |
| dart_aot_snapshot_analysis | T1 | blutter/reFlutter/Doldrums 均为一键/半自动工具 |
| native_binary_inspection | T1 | Ghidra/IDA/Hopper 反编译 + strings 一键 |
| javascript_electron_static_analysis | T1 | ASAR 解包 / source map 恢复工具现成 |
| managed_code_and_mobile_analysis | T1 | JEB/jadx 反编译 |
| dotnet_android_flutter_jeb_and_managed_artifacts | T1 | JEB 反编译 |
| artifact_and_function_comparison | T1 | 差分对比工具（bindiff 类） |
| binary_layout_and_build_metadata | T2 | 静态布局/元数据，readelf 类即得 |
| wasm_evm_sqlite_and_related_static_artifacts | T2 | 静态解析 |
| browser_and_network_observation | T3 | 浏览器/网络运行期观察 |
| runtime_process_observation | T3 | 运行期进程/文件观察 |
| network_capture_firmware_logic_signal_and_recorded_crash_artifacts | T3 | 抓包/固件/崩溃记录 |

11 族中 6 族落在 T1——这不是模型失衡，而是**现实快照**：今天绝大多数“分析能力”已经工具化，这正是“工具攻击更快更恐怖”的量化表达，也是 T1 必须最先修的论据。

## 6. 边界与注意事项

- **排序键是边际成本，不是严重度**。若某运行期暴露涉及秘密材料（内存明文密钥），其 severity 可在 T3 内上浮，但不因此越过 T1——成本排序保证“先拆放大器”不被个别严重案例带偏。
- **时效性是 T1 的固有属性**。工具在进化（blutter 从不能解析混淆快照到部分支持），能力映射地图级 `research_date`（2026-10-13）与“运行时确认实际工具与可用性”注记；D6 情报检索（R1）的独立维度正为此存在——工具变强直接改变 T1 暴露面评级。
- **T4 的保护不消除其他层**。虚拟化提高静态阅读成本，但运行期输入/输出/内存暴露仍在（架构文档 2.4 节已声明）；层级之间是叠加关系不是替代关系。
- **unknown 不丢序**。recon 未发现构建产物时，产物类发现仍带 T1 标注（status=unknown）——“先修工具层”的顺序在证据缺失时依然成立。

## 7. 落地清单

| 件 | 位置 | 门 |
| --- | --- | --- |
| tier 定义/排序/映射 | `src/pea/tiers.py` | `tests/test_tiers.py`（13 例） |
| 能力族标注 | `catalog/rea-capability-defense-map.json` | 契约门 `test_capability_map_declares_exposure_tiers` |
| finding tier 字段 | `schemas/exposure-finding.schema.json` | 契约门 + `tests/test_recon.py` |
| 步骤 tier 排序 | `schemas/attack-simulation.schema.json` + `attacksim.py` | `tests/test_attacksim.py` |
| 报告修复优先级章节 | `report.py` + `demo.py` | `tests/test_demo_e2e.py`（顺序断言） |
