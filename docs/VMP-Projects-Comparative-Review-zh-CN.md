# ShellVMP / FDartVMP：PEA 研究与集成评估备忘录

**评审时点 PEA 版本：** 0.2.2  
**核对日期：** 2026-10-13  
**核验等级：** documentation_reviewed（官方公开页面与许可说明）；不是源码审计或复现测试报告。

## 1. 目的

把用户提出的两个 VMP 项目作为 PEA 的研究样本，理解其公开描述的工程结构与测试闭环，提炼可独立实现的方法论，并列出在 PEA 做自动化集成前必须补齐的证据。本文不复制第三方源代码，也不把仓库自述能力当成独立验证的事实。

## 2. 项目现状对比

| 维度 | ShellVMP | FDartVMP |
|---|---|---|
| 官方仓库 | <https://github.com/haothtrteen/ShellVMP> | <https://github.com/haothtrteen/FDartVMP> |
| 目标范围 | Shell 脚本；公开文档描述 Bash 主线及独立 mksh 打包路线，生成纯脚本或 ELF | Flutter/Dart 中被选定的敏感函数 |
| 公开架构 | V6 脚本混淆；V7 ELF 包装和流式处理；V7-ISA 令牌化/解释器 PoC | Dart 函数转换为私有指令/字节码，封装到 native library，由私有解释器执行；Dart 侧保留 FFI stub |
| 公开测试/辅助工具 | 预检 lint、ISA 集成测试、目标函数定位、argv 泄露扫描等（按 README 的项目结构说明） | 仓库声明编译器测试、Dart 差分测试、APK 保护检查和真机运行工作流 |
| 许可证线索 | 页面显示 AGPL-3.0，并有商业许可文件；具体组件和适用条款需要复核 | `LICENSING.md` 明确声明 AGPL-3.0-or-later / 商业双授权；VMPacker 是单独工具且独立许可 |
| 目前 PEA 状态 | `documentation_reviewed` | `documentation_reviewed` |
| 禁止推断 | 未源码审计、未复现，不等于生产可用或“磁盘/内存绝不泄露明文” | 未复现，不等于所有 Dart 函数可保护或所有 APK/设备均兼容 |

## 3. ShellVMP 公开资料所提示的设计模式

### 可迁移到 PEA 的工程原则

1. **前置 lint**：在变换前检查语法/运行模式兼容性，把不支持的脚本尽早拒绝，而非产出后再猜原因。
2. **目标清单为单一真源**：需要保护的函数/符号/脚本入口应在 manifest 中明确列出，目标丢失或插桩锚点不匹配必须让构建失败。
3. **版本绑定**：解释器钩子与特定 Bash/mksh 版本绑定，PEA 需要生成精确版本/ABI 矩阵，并通过真实 fixture 验证每个 hook 命中。
4. **完整差分**：比较退出码、stdout/stderr、文件副作用、环境变量读取、信号与异常行为，而不仅是“样例能输出预期字符串”。
5. **问题可诊断**：静默退出和时间门槛误伤慢机器会使保护失败与业务失败难以区分。PEA 应优先提供可诊断错误，默认不开启分析环境门控。

### 需要独立验证的主张

项目公开说明了分块加密、状态链、ELF 包装、流式处理、反调试、反内存读取等机制。PEA 不能仅通过 README 判断这些机制覆盖了哪些内核、root/管理员权限、swap/core dump、管道缓存、调试器和特定 shell 组合。必须为每个主张定义 threat model、可复现 fixture、观测手段和反例；没有测试时标记 `unknown`。

## 4. FDartVMP 公开资料所提示的设计模式

### 可迁移到 PEA 的工程原则

1. **函数级 scope**：仅把用户确认的目标函数纳入保护，而不把整个应用一刀切；生成前检查目标在当前源码/编译中真实存在。
2. **显式编译边界**：记录源函数、私有 IR/字节码、运行时入口和 FFI stub 的映射关系；类型/异常/调用语义的未支持部分必须拒绝转换。
3. **差分与产物检查**：把解释器测试、与参考实现差分、APK 静态检查和设备运行视为不同门槛，分别记证据。
4. **验证器与构建器分离**：对字节码容器格式、长度、偏移、认证标签等做独立校验，并用故意篡改的测试样本证明检查确实会失败。
5. **公开限制**：仓库文档单独说明了 native interpreter、Dart heap/返回值和离线 seed/派生信息的分析边界。这种对失败面和剩余风险的明确说明应成为 PEA 报告的规范。

### 不应泛化的结论

- Flutter/Dart AOT、`libapp.so`、FFI 与 Android APK 属于特定执行栈，不能由此推出同一转换可直接支持 Python、JavaScript、.NET 或 C++。
- 自定义字节码和加密容器提高静态分析成本，但解释器和运行时输出本身仍可能可观察；若需要真正保密的决策，应优先放入可信服务端。
- 项目文档说明 VMPacker 为独立工具并单独许可。若集成该工具，不能把 FDartVMP 的许可结论直接套用到 VMPacker。

## 5. 给 PEA 的参考实现/防护验证矩阵

| 研究点 | PEA 应实现/检测什么 | 验收条件 |
|---|---|---|
| 目标函数 manifest | 为每个目标保存源码位置、名称/签名、输入工件摘要与构建期探针 | 目标缺失/重命名/优化移除时阻断构建或显式人工确认 |
| 变换前 lint | 对运行时版本、语法子集、依赖及已知不兼容模式静态检查 | 正向/负向 fixture；每条拒绝都有可理解原因 |
| 插桩命中 | 测试构建中记录 hook/转换是否真实执行 | 只要目标没命中，构建失败；不允许静默生成“受保护”产物 |
| 容器独立校验 | 长度、偏移、版本、摘要/认证校验、拒绝异常输入 | 截断、偏移越界、随机字节、旧版本文件全部安全拒绝 |
| 语义差分 | 输入/返回值/异常/副作用/退出码测试 | 故意引入错误变换后必须失败；覆盖范围被记录 |
| 运行时暴露评估 | 在授权 fixture 上记录临时文件、日志、argv、崩溃工件和运行时可观察数据 | 每种数据源单独报告；不能用“未发现”推断所有数据都不可获取 |
| 工具供应链 | 锁定 commit/release，核验依赖、构建脚本和 LICENSE | 未审查许可/依赖的候选不能进入 production 阶段 |
| 性能预算 | 延迟、内存、包体、构建时间和启动失败率 | 超预算时计划阻断或经用户批准记录例外 |

## 6. 对开源和许可的处理规则

- ShellVMP、FDartVMP 的仓库代码和文档由各自权利人控制。PEA 目录应链接官方来源、记录访问日期和许可证状态，不应把第三方源代码复制到 PEA 的 MIT/CC BY 文件范围内。
- 对 ShellVMP：公开页面列出 AGPL-3.0 LICENSE 与商业授权文件；应读取固定 commit 中的 `LICENSE`、商业授权文件及第三方目录/子模块声明。
- 对 FDartVMP：官方 `LICENSING.md` 声明 AGPL-3.0-or-later 和商业双授权；闭源应用的链接/分发问题需要由项目维护者做法律审核。仓库还指出 VMPacker 为独立第三方工具，需单独检查其源代码、来源、版本和许可证。
- 在没有许可证兼容结论前，只能在目录中作为候选研究项目，不可自动下载、执行、链接、打包或再分发。
- 技术方法的概念总结可以独立编写，但避免复制大量原始实现细节；归属、许可证和引用按原项目要求处理。

## 7. 后续只读源码审计计划

本次整理时本地执行环境无法解析 `github.com`，`git clone` 失败（该网络限制后来已解除——REA 源码现已取得；ShellVMP / FDartVMP 仍未拉取，故核验等级不放行）；因此此节是计划而非完成状态。网络可用的开发环境应：

1. `git clone` 后立即记录 `git rev-parse HEAD`、tag、工作树状态、提交时间和 `LICENSE` 摘要。
2. 阅读顶层贡献指南、威胁模型、架构文档、构建入口、测试入口和第三方许可声明。
3. 对照真实构建路径逐层追踪“解析/编译 → 转换 → 打包 → 运行时解码/解释 → 验证器 → 报告/清理”。记录源码路径与行号。
4. 只使用仓库自带测试和专门构造的自有 fixture；所有外部程序在隔离工作区运行，不对未授权的第三方目标做分析。
5. 将每项结论标为 `claim_from_docs`、`observed_in_source`、`reproduced_in_fixture` 或 `unknown`。源码中存在一段代码不等于运行时执行过它。
6. 为发布出具审计报告：commit SHA、依赖清单、测试命令/结果、未覆盖边界、许可证状态和后续建议。

## 8. 参考来源

- ShellVMP README：<https://github.com/haothtrteen/ShellVMP>
- ShellVMP LICENSE：<https://github.com/haothtrteen/ShellVMP/blob/main/LICENSE>
- ShellVMP 商业许可（仓库文件）：<https://github.com/haothtrteen/ShellVMP/blob/main/LICENSE.COMMERCIAL>
- FDartVMP README：<https://github.com/haothtrteen/FDartVMP>
- FDartVMP LICENSING：<https://github.com/haothtrteen/FDartVMP/blob/main/LICENSING.md>
- FDartVMP LICENSE：<https://github.com/haothtrteen/FDartVMP/blob/main/LICENSE>
- REA 上游：<https://github.com/morluto/rea>

---

**结论：** PEA 先将两个项目当作“可供研究的方法样本”，把可迁移的构建与验证经验沉淀进自身实现；在完成固定版本、许可复核、源代码审计和 fixture 复现前，不将任何项目描述为 PEA 已验证保护器。
