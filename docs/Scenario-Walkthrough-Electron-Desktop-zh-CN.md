# 场景走查：保护一个 Electron 桌面客户端（目标形态端到端模拟）

**日期：** 2026-10-13 · **性质：** 目标形态模拟（系统按对标方案全部建成后的理想使用样子）· **对应：** `docs/REA-Parity-Plan-zh-CN.md` 全里程碑 · **对照：** [`Scenario-Walkthrough-Flutter-Licensing-zh-CN.md`](Scenario-Walkthrough-Flutter-Licensing-zh-CN.md)（原型现状走查）

> **读前须知**：本文每个阶段标注 **[现已落地]**（当前代码可运行）或 **[目标形态]**（对应里程碑建成后的样子）。场景本身是虚构的——它是"这套系统理想中如何被使用"的演示，**不是任何真实项目的描述，也不预设真实项目的形态**。真实判断依据只有域扫描观察到的项目状态与带日期的能力情报（地图级 `research_date` + “运行时确认”注记）。

## 0. 场景设定：CanvasSync

**CanvasSync** —— 一个设计资产同步桌面客户端：Electron + TypeScript，外部分发给付费设计团队，连接 CanvasSync 云服务。用户（项目 owner）的原话：

> "帮我保护这个 Electron 应用。授权逻辑在渲染进程里，云服务的 token 也打在包里——别让人白嫖，也别让人把我们的 token 挖走。"

与 Flutter 授权场景的差异（这套系统要证明的正是通用性）：

| 维度 | Flutter 授权场景 | 本场景（Electron） |
| --- | --- | --- |
| 语言/构建 | dart / flutter + gradle | typescript / node_npm + electron-builder |
| 主要产物 | libapp.so 快照、APK | **app.asar**、.node 原生插件、安装包 |
| T1 一键工具 | blutter 类快照恢复 | ASAR 解包 + source map 恢复 + 反打包 |
| 主要暴露 | 快照内授权逻辑 | 渲染进程源码、长效 token、IPC 特权面 |
| 能力族 | dart_aot_snapshot_analysis | **javascript_electron_static_analysis** + binary_layout + runtime_process |

## 1. intake：先问明白 [现已落地 · M1]

PEA 不先搜方案，先问清楚。MCP 会话形态（目标形态 M4 提供工具；现阶段为 CLI/库调用）：

```
pea.intake → 分发方式？        → external_limited（外部分发，付费团队）
             使用者？          → others_devices（他人可控设备）
             设备控制权？      → none
             秘密可离开客户端？ → partial（授权决策可移出；离线缓存密钥不可）
             是否要求离线？    → no（联网同步是核心功能）
```

推导姿态：**`no_trustworthy_client_signal`**（外部有限分发 + 他人设备）叠加 `server_side_first` 成分（秘密可部分移出）。三条护栏随行：本地校验只提高成本不构成保证；能移出的秘密优先移出；残余风险必须明示。`intake_unknowns` 为空——问题答全了才继续。

## 2. 四域侦察：资产在哪 [现已落地 · M3]

授权确认后，四个只读域并联运行（统一 `findings + coverage + unknowns`，共享遍历纪律）：

| 域 | 实测发现（模拟输出） | tier |
| --- | --- | --- |
| recon | typescript×214 / javascript×36；node_npm + electron-builder 构建；定位 `src/main/license/*.ts` 与 `src/renderer/license-gate.ts`（模式名+行号，内容脱敏） | T2 |
| artifact-manifest | `release/win-unpacked/resources/app.asar`（18.4 MB，SHA-256 已记录）、`resources/native/sync-addon.node`、安装包 `CanvasSync-Setup-1.4.2.exe`；指纹入账本 | **T1** |
| secret-scan | `.env.production` 命中 `hardcoded_credential`（`CLOUD_API_TOKEN=…`，行 7）；`renderer` bundle 命中 `api_key_literal`（`sk-…` 形态，行 1 压缩产物中）；**内容脱敏，只回模式名与行号** | T2 |
| string-symbol-scan | app.asar 字符串：`/Users/ci/builds/1.4.2/…` 构建路径 ×37、`license`/`signature` 关键字 ×12、`sourcesContent` 声明 ×1；.node 含 JNI 无关符号与构建路径 | T2 |

关键交叉验证：secret-scan 在 bundle 里命中 `sk-` 形态，symbol-scan 同时看到 `sourcesContent` 声明——两个独立域指向同一结论：**生产包里带着可恢复的源码与长效密钥**。这不是某一个扫描器的噪声，是互相印证的观察。

unknowns（如实入账，不得当作已确认）：安装包内部未展开（.exe 形态无清单条目）；运行期 IPC 实际配对情况静态不可见；asar 内 UTF-16 字符串未覆盖。

## 3. 能力情报：社区现在到什么程度 [目标形态 · D6/R1]

intel 连接器（allowlist + 安全失败）返回带日期的声明，与侦察发现交叉：

- `javascript_electron_static_analysis` 族维持 **T1**：ASAR 提取与 source map 恢复工具现成、分钟级；`sourcesContent` 一旦随包发布等于发布源码（2026-10-13 地图快照，运行时再确认）；
- 新观察入库：electron 新版本 `contextIsolation` 默认值变化影响 preload 特权面评级；
- 一条外部声明与本地发现矛盾时（情报称"该构建通常剥离 source map"，侦察称发现 `sourcesContent`）——**本地观察优先，矛盾本身记为 unknown 并两条都留档**。

若连接器不可用：安全失败——该次情报记为 `unavailable`，T1 评级退回地图静态快照并明示时效缺口，绝不静默使用旧数据装作最新。

## 4. 计划生成：门控说了算 [现已落地 M1 + 候选研究]

姿态 `no_trustworthy_client_signal` 的直接后果：**不承诺"让白嫖变困难"之外的任何强度**。计划（`plan_only`，无自动执行）：

| 步骤 | 内容 | 依据 |
| --- | --- | --- |
| 1 | `CLOUD_API_TOKEN` 移出客户端：同步流程改为短期令牌，由服务端签发 | intake 姿态 + secret-scan 命中 |
| 2 | 生产构建排除 source map（`sourcesContent` 不发布） | symbol-scan 命中 + 能力族 defense_options |
| 3 | 授权校验从渲染进程移入主进程，最终决策移服务端 | 姿态护栏 2 |
| 4 | preload IPC 面最小化 + schema 校验（sender/origin 校验） | 能力族 defense_options |
| 5 | 残留成本提升：sync-addon.node 的关键函数考虑原生保护候选（VMP 类） | 候选研究；**许可待审 → 不自动纳入** |

候选打分如实呈现：performance 轴永不计分（无数据）；某 AGPL 混淆器因许可证门槛被排除并记录理由——**门槛不以综合评分抵消**。

## 5. 攻击自测：先测放大器 [设计现已落地 R3；执行目标形态 M6]

生成的方案按暴露层由高到低排序，A1 永远是成本最低的暴露面：

| 步 | 内容 | 层 | 预算 |
| --- | --- | --- | --- |
| A1 | 对自家 1.4.2 安装包跑 ASAR 解包 + source map 恢复，记录恢复了什么 | T1 | 30min |
| A2 | 解包产物内复扫 secret 模式（修复前基线） | T1/T2 | 15min |
| A3 | 修复后构建同法重跑，与 A1/A2 差分对比 | T1 | 30min |
| A4 | IPC 正负向契约测试（设计用例，用户执行） | T3 | 45min |
| A5 | 运行期进程观察：内存/临时文件中的令牌形态 | T3 | 30min |
| A6 | pre/post 产物函数级对比（bindiff 类） | T1 | 30min |

红线由 schema 机械强制：`read_only_artifacts: const true`；`interpretation_rule: cost_delta_only`（“绝对防护”不可表达）；工具失败 → `failure_meaning: unknown`。每一步 method 原文引用能力映射观察。

执行在用户沙盒（工具用户自备，PEA 不分发不自动装），观察证据回填账本。

## 6. 证据账本与门禁：逐项消解，不一次性宣布胜利 [核心现已落地 M5；工具化目标形态]

三个 unknown 的 lifecycle（模拟）：

1. **“renderer bundle 是否含长效 secret”** → 消解为 resolved：supporting = A3 复扫无命中；contradicting = A2 修复前有命中（证明扫描器真的能看见，不是漏报）。双边界证据齐备 → 该项可标 verified，**绑定版本 1.4.3、方法与覆盖范围**。
2. **“IPC 校验是否健壮”** → 仍 open：A4 契约测试未执行（用户侧工程）。 blocking → 总门禁保持阻塞。
3. **“运行期内存无令牌明文”** → 仍 open：A5 未跑。且其 limitation 明示：即便跑通，也只覆盖观测窗口。

一页结论因此是**混合状态**——部分 verified、部分阻塞、每项绑定证据。这比“修复完成 ✅”诚实，也正是 `gate_for_verified` 的设计意图：没有发现 ≠ 证明安全；部分证据 ≠ 整体通过。

## 7. 这个模拟暴露的系统缺口（反哺路线）

- **`.asar` 形态是这轮补进产物清单的**——真实场景调研直接推动了代码演化（18 种形态）；域的形状正确时，新场景的接入成本就是一个表项加一个测试；
- **D6 缺失时 T1 评级只能静态**：情报双通道不是锦上添花，是 T1 时效性的机械化保障；
- **IPC 契约测试属用户侧工程**：PEA 设计用例、门禁等待证据，但执行器边界（M6）必须保持“用户沙盒 + 工具自备”；
- **.exe 安装包内部未展开**：目录形态（.app/.framework）与嵌套包是 manifest 的已知边界，记 limitation 不假装覆盖。

## 8. 一页结论（目标形态报告样例，模拟）

| 检查项 | 结果 |
| --- | --- |
| 计划状态 | needs_user_review（5 步，2 步涉许可待审候选） |
| 多域侦察 | 产物清单:complete_for_scope, 秘密扫描:complete_for_scope, 字符串/符号:partial |
| 攻击自测 | 6 步设计；A1–A3 已执行回填，A4–A6 待用户执行 |
| 证据账本 | 11 open / 2 blocking（IPC 健壮性、运行期内存） |
| verified 门禁 | **阻塞**——2 项 blocking unknown 未消解 |
| 成本变化（实测） | A1→A3 差分：源码恢复率 100%→0%，secret 命中 2→0；IPC 面未测，无数据 |

最后一行是这套系统的诚实底线：**改变了什么、没改变什么，都写在报告里；没测的，就没有数字。**
