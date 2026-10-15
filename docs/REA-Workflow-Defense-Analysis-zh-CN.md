# REA 工作流研究与 PEA 防护映射（更新版）

**整理日期：** 2026-10-13  
**版本：** 0.2.2  
**研究状态：** 已核对当前公开上游文档及 ShellVMP/FDartVMP 的官方公开仓库页面；本执行环境 `git clone` 因无法解析 `github.com` 失败，因此未完成本地源码级审计。本文把在线文档结论与源码审计结论分开。

## 1. 研究范围与源码身份

优先参考的上游仓库为 [morluto/rea](https://github.com/morluto/rea)。此前被提到的 [Opiuz/REA](https://github.com/Opiuz/REA) 是另一个公开仓库/fork，不能不加区分地把 fork 的状态当作上游主线的状态。

当前在线文档描述 REA 是一个面向 Agent 的本地分析编排工具，通过 CLI 与 MCP 提供共用工作流和 Evidence 契约。其公开调查模型为 Decompile → Understand → Recreate：收集工件事实与代码线索，沿引用/调用关系建立解释，再由 Agent 根据证据编写自己项目中的兼容实现。REA 说明它不声称恢复出原始源代码，也不自动克隆整个应用。

截至本次研究日期，官方仓库页面和文档提到多种分析能力与 provider。此前研究笔记里出现过 `rea-agents` 4.1.0/125 个 MCP 工具的数字，但未能在当前 `morluto/rea` 上游 README 中确认其适用的仓库与发行版本，因此本版本不将其归属为上游事实。真实集成必须查询实际服务端 `tools/list`、工具输入 schema、能力状态与 provider 身份，并保存实际版本和 commit。

## 1.1 公开 README 可确认的能力分组（不是逐文件源码结论）

当前上游 README 将能力描述为一组按目标/Provider 划分的操作。对 PEA 来说，重要的是记录“工具族—目标工件—是否执行目标—证据类型—副作用”，而不是静态写死某个工具总数。

| 公开文档中的能力组 | README 中举例/描述 | PEA 审计关注点 |
|---|---|---|
| 原生二进制分析 | `open_binary`、`binary_overview`、字符串/过程/名称搜索、交叉引用、调用者/被调用者、调用图、伪代码、汇编、批量反编译 | 输入工件如何复制/绑定、地址和范围校验、Provider 选择、临时项目、取消与清理 |
| 深度分析 Provider（Hopper / Ghidra / IDA，具体依版本与平台） | 原生目标的伪代码、汇编、函数/字符串/符号与调用/引用线索；并非每个 Provider 支持完全相同的能力 | 每项 operation 的 schema、真实支持状态、工具/运行时版本、Mock 与真实 Provider 测试的差别 |
| JS/Electron 静态工件分析 | 目录/ASAR、模块/imports、source maps、路由、IPC、存储和 native add-ons 的静态映射；文档称该路径不执行应用模块 | 路径穿越/符号链接、资源限额、缺失资源状态、source map/秘密在证据包中的脱敏 |
| 浏览器与进程观察 | 浏览器 CDP 和受控场景下的 process capture/compare | 必须与静态分析分开标注；确认实际执行的二进制、cwd、env、场景、网络/文件副作用和清理 |
| Evidence、快照与比较 | Evidence 导入/导出、工件或函数比较、快照缓存和未解决问题跟踪 | 证据是否绑定工件摘要、操作参数、Provider/工具版本；未知、矛盾、不可用是否保留 |
| CLI/MCP 与工作流提示 | CLI/MCP 共用工作流；公开文档描述有序调查工作流和工具能力查询 | 运行时 `tools/list`、schema 与文档是否漂移；权限/副作用声明是否真实；旧提示是否引用失效工具 |

这些细节取自当前公开 README 的自述，应在本地固定 commit 后逐一核验源文件、测试和真实 Provider 行为。不同历史版本或 fork 的工具数量不能外推到上游主线；目录不应把“22 项”或“39 个原生工具”之类的固定数量当作长期 API 合同。


### 1.2 上游 README 所列目标类型：用于覆盖规划，不代表逐项运行时已验证

公开 README 涉及的目标/证据面不止原生二进制和 JS/Electron。它还列举了 ELF 布局、Go 构建元数据、WASM/EVM 字节码、SQLite、记录式 Linux 崩溃信息、网站/浏览器行为、网络捕获、.NET、Android APK/设备与资源、JEB、Flutter、固件、逻辑信号、软件包/资源以及进程行为等方向。此清单是研究日期时的公开文档归纳；可用性取决于当前发布版本、宿主平台、输入格式、可选 Provider 和权限，不能据此推断每类都在当前运行环境中具备完整或可执行能力。

PEA 的能力注册表应至少区分：

- **Target family**：输入是可执行二进制、源代码包、移动端安装包、捕获文件还是运行时会话。
- **Observation mode**：纯静态解析、沙箱内执行、连接设备/服务，或调用外部分析器。
- **Authority and side effects**：是否启动目标、访问网络、写文件、附加进程或触发设备状态变化。
- **Evidence and unknowns**：声明实际解析范围、未覆盖区域、输入摘要、Provider/版本与错误，不将失败、空结果或不支持解释为“保护有效”。

对应的补充映射已落入 `catalog/rea-capability-defense-map.json`，覆盖平台/构建元数据、字节码/数据库工件、移动端/托管运行时和捕获/嵌入式类工件。它们仍是“候选审计面”，不是针对每个格式均已执行的保护规则。

## 2. REA 架构中值得 PEA 学习的设计点

### 2.1 统一应用工作流

REA 的公开文档说明 CLI 与 MCP 使用相同的 application workflows 和 Evidence contracts。PEA 应采用相同架构原则：CLI、MCP、CI 不应分别实现策略逻辑；它们只应适配同一个服务层。

### 2.2 Provider 和能力不是一回事

REA 公开设计包含目标绑定、provider registry、确定性选择及显式能力声明。其 Ghidra provider 文档特别强调：provider 并非 Hopper 的完全替代品，每项能力都要单独声明为 supported、unavailable、unknown 或 degraded，不能因为“已安装 provider”就断言“操作一定支持”。

PEA 应照此实践：保护器可安装，不等于它支持用户的语言/版本/架构；保护命令成功退出，不等于变换后的语义正确；分析工具启动成功，也不等于其所有能力都已通过真实集成验证。

### 2.3 Evidence 必须绑定来源与限制

REA 文档强调 Evidence 中应保留工件身份、provider、位置、置信/限制等上下文；静态推断和动态观察要分离，未观测区域保持 unknown。PEA 的报告应采用相同精神：finding 除了结论，还要有文件位置/工件摘要/扫描器版本/证据等级/覆盖范围/误报可能性。

### 2.4 工具副作用要声明

REA 的公开 issue/文档讨论了将目标、provider、policy 和实际副作用映射到工具可用性及 MCP annotation。PEA 应建立一份唯一的 ToolEffects/Capability registry，由它生成 MCP 工具清单和文档，避免在 prompt 中硬编码与实际服务端不同步的工具名称。

### 2.5 安全的工件读取和运行生命周期

REA 的 JavaScript 工件重建文档描述了在静态分析路径中解析 ASAR/源码图，而不执行应用启动代码；也写明了符号链接、路径规范化、哈希、资源限额、取消和 unknown 语义。Ghidra provider 文档则强调私有临时项目、有限子进程生命周期、超时、清理与真实 provider 验证。PEA 可以吸收这些工程原则，但不能默认每个公开工具或 provider 已在所有平台具备相同实现质量。

## 3. 能力类别 → 暴露面 → 防护建议

| 分析能力类别 | 常见可观察事实 | PEA 应检查的暴露面 | 推荐防护（非万能对应） | 验证方式 |
|---|---|---|---|---|
| 工件识别/布局 | 文件类型、节区、包结构、哈希、依赖 | 发布物包含不必要文件、符号或资源 | 清理 release manifest；确保签名/摘要与构建记录一致 | 对发布物生成清单并与 allowlist 比对 |
| 字符串与符号 | 硬编码字符串、导出符号、函数名称 | 秘密、内部路径、调试文本、模块职责 | 移除调试数据；避免客户端长期秘密；适度符号裁剪 | 字符串/符号扫描、人工复核、误报记录 |
| 函数与调用关系 | 函数边界、引用、调用者/被调用者、控制流 | 核心算法容易定位，授权判断完全由客户端控制 | 优先迁移高价值决策；仅针对可测试模块采用混淆/VMP | 静态对比 + 功能等价测试 + 成本报告 |
| 反编译与汇编 | 伪代码、汇编、变量/类型推断（因 provider 而异） | 关键函数语义可读 | 评估成熟保护器，不自创不验证的指令变换 | 固定版本/provider/样本并报告工具限制 |
| JS/Electron 工件图 | imports、bundle 模块、source-map 声明、preload、IPC | source map 泄露、暴露内部 API、过宽 IPC | 限制 source map 发布；最小化 preload 权限；校验 sender/origin/schema；敏感决策留在可信边界 | 打包检查、IPC 契约测试、Electron E2E |
| 浏览器/网络观察 | 页面行为、请求与响应、端点和存储调用 | 客户端持有长效 token、接口返回过多数据 | 服务端鉴权与速率限制、短期凭据、最小响应 | 未授权请求、令牌过期、重放和权限负向测试 |
| 进程/运行时观察 | 生命周期、文件/网络活动、控制台输出（取决于 provider） | 秘密出现在 argv、日志、临时文件或转储 | 将凭据从命令参数移除；日志去敏；最小权限；限制 core dump 的策略需平台验证 | 沙箱活动记录和日志测试 |
| .NET/Android/托管代码 | 元数据、DEX/CIL、映射文件、反射/JNI 线索 | 过度暴露的符号/元数据/映射文件，客户端授权状态可 patch | 平台原生 R8/裁剪或成熟混淆；映射文件受控保存；服务端授权 | 反射/序列化/JNI 回归测试；映射访问控制检查 |
| Snapshot/比较/Evidence | 不同工件/函数的差异、证据引用 | 发布版本意外回归，报告包含敏感源码或凭据 | 建立发布基线，报告仅保留必要摘要；限制本地证据权限 | 可重复比较、报告去敏测试、哈希验证 |

### 重要限制

表中每项是候选映射，不意味着目标一定受到该类分析。必须先用当前 REA 版本或其他扫描器确认支持范围与 Evidence；不可把“工具不可用/结果为空/分析失败”算作“保护有效”。对于可能破坏可调试性、误伤合法监控软件或影响 CI 的反分析控制，PEA 默认不启用。

## 4. 保护器研究流程

1. 用户给出目标资产、语言/版本、运行环境、离线要求、可接受成本与授权声明。
2. Research Agent 从官方仓库、官方文档、发行物和许可文件检索候选；社区讨论仅作为发现源。
3. 生成候选清单，每项保存 `source_url`、`release/tag/commit`、许可文本摘要、平台矩阵、安装副作用、网络行为、依赖和已知限制。
4. 不执行 `curl | sh`、npm postinstall、构建脚本或下载后的二进制。下载、验证、执行是三项独立行为。
5. 通过硬约束后，使用用户拥有的 fixture 在隔离环境验证候选的最小功能与故障模式。
6. 由 Strategy Engine 对其余候选评分，并给出候选选择理由；模型不能把未经验证的项目升级为 `production_eligible`。
7. 需要执行时，生成冻结计划并等待审批；审批令牌绑定计划摘要、工件哈希、命令、版本与文件范围。
8. 保护完成后，运行语义、兼容性、性能和产物检查；失败立即停止发布。

## 5. 对 `lang-vmp-guide` Skill 的引入建议

推荐创建 `pea-vmp-research` 子技能，职责是分析“解释型语言保护是否适用、需要改变哪些层、如何验证”，而不是直接将 Skill 中所有机制无条件执行。

### 适合迁移为通用方法论的内容

- 先建立威胁模型和攻击路径，再判断每一个措施解决什么问题。
- 结构暴露与词法暴露必须分别检查，不能只做字符串替换就声称代码不可理解。
- 将关键函数清单作为单一事实来源，构建前断言保护目标真实存在。
- 先保护单个目标，跑回归和差分，再扩大范围。
- 在构建记录中保留版本、配置、工件摘要和验证结果。
- 对保护产物执行正向和反向验证，验证失败必须阻止发布。

### 需要纠正的绝对化说法

- `seccomp`、`TracerPid`、`DONTDUMP`、`mlock` 等是特定 OS/内核/权限条件下的控制，不是任意平台上绝对或唯一的保证。
- 对 root/管理员或设备完全控制者的抵抗能力必须按具体威胁模型评估，不能将“信噪比稀释”描述为不可被算力解决的普遍结论。
- `free`、删除变量或加密磁盘载荷不代表所有缓存、日志、core dump 和运行时明文都消失；需要逐类验证。
- “检测入侵后毒化密钥”不应成为默认行为，容易引起数据破坏和不可诊断故障。推荐有限重试、明确错误、fail-closed 与可审计的服务端吊销流程。
- Bash 的分派点、解释器内部 hook、GPR/NEON 限制和 ELF 尾载荷不是可直接推广到 Python、JavaScript、Lua、Windows 或 Android 的通用施工步骤。

技能应将结论分为：`transferable_methodology`、`platform_specific_hypothesis`、`unverified_claim`。只有第一类可直接用于规划；第二类需目标环境实验；第三类不得成为自动化执行依据或对外承诺。

## 6. 与 ShellVMP / FDartVMP 研究的交叉价值

REA 与两个 VMP 项目解决的是不同问题：REA 把分析工具组织成可供 Agent 调用的观察/推理工作流；ShellVMP 与 FDartVMP 则在特定语言层面尝试增加对程序逻辑的静态恢复成本。PEA 应连接它们的“验证和证据”层，而不是把 VMP 当成能关闭逆向分析的开关。

- **REA 可以作为授权环境中的观察器**：固定版本与 provider，对同一个自有 fixture 的保护前/后工件做可复核比较。分析器失效、崩溃或 unavailable 必须记为 `unknown`，不得记为保护成功。
- **ShellVMP 的研究重点**：shell 语义兼容、预检/lint、真实插桩命中、ELF/解释器版本矩阵、异常和退出码差分、构建与许可可复现性。其公开文档声明包括反调试与环境门控；PEA 默认不启用这些选项，先用纯功能性测试，避免误伤 CI/运维环境。
- **FDartVMP 的研究重点**：源函数到私有 IR/字节码的映射、字节码容器验证、Dart stub/FFI 边界、APK 工件检查、差分测试覆盖率、解释器及运行时暴露。该仓库公开的限制说明承认解释器可被分析、Dart 调试器能观察堆/返回值，且离线部署材料本身不能作为真正的秘密边界。
- **许可证与依赖独立审查**：两个项目公开说明均涉及 AGPL 与商业双授权；FDartVMP 文档还指出 VMPacker 为单独工具和单独许可。PEA 仅能把 URL/许可状态记为候选元数据，不能因此自动认定可把代码纳入自身仓库或将其用于闭源发行。
- **证据状态**：当前对两个仓库的结论基于其公开 README/许可证说明；尚未固定 commit 或克隆源码。记录状态为 `documentation_reviewed`，禁止标记 `source_reviewed`、`fixture_verified` 或 `production_eligible`。

## 7. 当前源代码审计状态

本次工具环境执行：

```bash
git clone --depth 1 https://github.com/morluto/rea.git REA
```

本文撰写时执行容器无法解析 `github.com`，克隆失败，因此本文是**在线公开文档研究**（该网络限制后来已解除：REA 源码已按 commit `bb96afdbe32f5318d57fcb00099191c5a7712f53` 取得，见 `sources.md`；但本文的行号级审计未因此重做，结论仍按在线文档口径）。后续行号级审计应固定 commit SHA，再逐一追踪：

`MCP tool registration → schema/handler → shared workflow/service → provider/adapter → external process/API → Evidence projection → cleanup/error path`

每个结论至少记录源码文件与行号、关联测试、真实 provider 验证状态和平台边界。Mock 测试不能证明真实工具有效。

## 8. 后续 clone 与只读审计步骤

在可访问 GitHub 的开发环境中执行：

```bash
git clone https://github.com/morluto/rea.git
cd rea
git rev-parse HEAD
git status --short
git log -1 --format='%H%n%ad%n%s' --date=iso-strict
```

然后保存 commit SHA，读取 `package.json`、`AGENTS.md`、`docs/architecture.mermaid`、`docs/mcp-contracts.md`、`docs/provider-evaluation.md`、`docs/javascript-artifact-reconstruction.md`、生成的 product catalog、MCP tool 注册入口、provider registry 和对应测试。先静态读代码，使用 REA 自带 demo / 自建 toy fixtures 验证，不对未经授权的第三方目标执行动态分析。

审计表建议列：工具名、输入 schema、权限/副作用、handler 文件/行、service 层、provider、外部命令/网络、Evidence 契约、超时/取消、清理路径、测试类型（mock/fixture/真实 provider）、平台状态、PEA 对应检测项。

## 9. 参考链接

- 上游仓库：<https://github.com/morluto/rea>
- README：<https://github.com/morluto/rea/blob/main/README.md>
- MCP 合同：<https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md>
- Provider 评估：<https://github.com/morluto/rea/blob/main/docs/provider-evaluation.md>
- JavaScript/Electron 工件重建：<https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md>
- 安装/发行版本状态：<https://github.com/morluto/rea/blob/main/docs/installation.md>
- MCP 调查 prompts：<https://github.com/morluto/rea/blob/main/docs/mcp-prompts.md>
- REA roadmap：<https://github.com/morluto/rea/blob/main/docs/roadmap.md>
- ShellVMP 官方仓库：<https://github.com/haothtrteen/ShellVMP>
- FDartVMP 官方仓库：<https://github.com/haothtrteen/FDartVMP>
- FDartVMP 授权说明：<https://github.com/haothtrteen/FDartVMP/blob/main/LICENSING.md>
- OWASP MASVS Resilience：<https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/>

**总结：PEA 应针对“分析能力暴露的资产”做工程防护和测试，而不是对某一款逆向工具进行定点对抗。**
