# PEA MVP 工程 Backlog 与 Definition of Done

本 Backlog 将架构规格拆成适合 issue/PR 的小任务。每项都包含可测试验收条件；MVP 不以自研 VMP 后端作为第一交付目标。

## Epic A：统一模型与离线规划器

### PEA-001：统一请求和结果类型

- 定义 `ProtectionRequest`、`ProjectProfile`、`ExposureFinding`、`CatalogCandidate`、`ProtectionPlan`、`VerificationResult`、`EvidenceRecord`。
- 所有枚举可扩展；未知值必须保留并标记，不静默转换。
- 验收：JSON Schema 正/负样例覆盖必填字段、边界值、未知版本和非法路径。

### PEA-002：计划输出包含完整审查信息

- 输出策略、候选、评分维度、候选排除原因、执行副作用、命令预览、批准要求、测试门槛、回滚。
- 验收：相同输入与目录快照生成相同 plan digest；任何工具版本变化都会改变 digest。

### PEA-003：目录状态门控

- 状态区分 discovered/reviewed/fixture_verified/project_verified/production_eligible/blocked。
- 验收：discovered、unknown-license、archived 或 source-unverified 候选不能被默认选为 production 执行候选。

## Epic B：只读画像和暴露面清单

### PEA-010：项目 Profiler

- 读取清单和配置，不执行项目生命周期脚本。
- 建立 ignore/allowlist；默认不读取 `.env`、私钥、凭据文件和浏览器配置。
- 验收：路径穿越、符号链接跳出、超大文件和异常编码测试均有明确结果。

### PEA-011：产物 Manifest

- 对用户指定发布物生成相对路径、大小、SHA-256、文件类型和解析状态。
- 验收：重跑结果稳定；读取失败标记 unknown；不把失败条目从报告中删除。

### PEA-012：暴露面扫描 v1

- 字符串/符号、调试符号、source map、环境配置、疑似秘密模式和非预期资源。
- 所有匹配只作为 finding；疑似秘密不得被报告回显，应输出类型、位置和脱敏摘要。
- 验收：canary fixtures 命中率、误报样例、排除规则、覆盖声明和报告脱敏测试。

## Epic C：研究与目录

### PEA-020：官方源检索接口

- 支持配置固定来源和域名 allowlist；网络访问显式打开。
- 在线搜索结果进入候选队列，不能直接执行。
- 验收：超范围域名、重定向越界、断网、失效链接、巨大响应和未知 MIME 均安全失败。

### PEA-021：候选审查器

- 读取 release/tag/commit、LICENSE、平台文档、依赖和安装副作用。
- 验收：候选页面提到 MIT 但仓库 LICENSE 缺失时不自动判定许可已核实；fork 许可不继承上游许可结论。

### PEA-022：REA 能力目录导入

- 将当前公开文档和运行中 `tools/list` 作为不同来源；记录版本/时间和能力状态。
- 验收：工具数量或名称变化可检测；旧记录无法覆盖当前运行时能力；provider unavailable 不能被当作保护通过。

## Epic D：MCP 工具与权限

### PEA-030：共享 Service Layer

- CLI/MCP 共用同一业务逻辑与策略检查。
- 验收：同一输入在 CLI 和 MCP 返回相同核心 plan/evidence 字段。

### PEA-031：ToolEffects/Catalog 生成

- 所有工具声明目标、文件/网络/进程/UI 副作用、幂等性、批准要求、权限和错误码。
- 验收：缺字段、未登记 handler 或文档 schema drift 时 CI 失败。

### PEA-032：审批令牌

- 令牌绑定计划 digest、工件 digest、adapter 版本、参数和路径范围；短期且一次性。
- 验收：过期、重放、计划变化、输入工件变化和跨目录复用均拒绝。

## Epic E：受控执行与适配器

### PEA-040：隔离工作区

- 复制/工作树隔离、默认断网、低权限账号、清理子进程树。
- 验收：源工作树在成功、失败、取消和崩溃后保持不变。

### PEA-041：结构化 Adapter Contract

- adapter 只返回 executable + argv + cwd + env allowlist + resource budget。
- 验收：注入 shell metacharacter 不会改变 argv 语义；拒绝 shell 字符串接口。

### PEA-042：首个成熟保护器 Adapter

- 由维护者依当前目标选择一个候选；精确固定版本，录入许可、下载来源和 fixture。
- 验收：正/负 fixture、版本漂移检测、回滚与语义验证全部通过。

## Epic F：验证和报告

### PEA-050：差分验证器

- 比较返回值、退出码、stdout/stderr、异常、输出文件和已声明副作用。
- 验收：故意引入语义偏差时必须 fail；缺失测试时显示 unknown/coverage gap。

### PEA-051：性能/兼容性预算

- 支持用户设定 latency、memory、binary-size、startup budgets。
- 验收：超预算不自动生成 release candidate；例外需要记录批准理由。

### PEA-052：报告与证据保留

- Markdown/JSON 报告、工件 manifest、候选来源、工具版本、日志脱敏、回滚。
- 验收：可以用 plan/run ID 重建该次运行；报告不会含有测试 canary 的秘密原文。

## Epic G：VMP 专业技能与 IR PoC

### PEA-060：合并 `pea-vmp-research` Skill

- 包含触发条件、适用性筛选、来源检查、假设等级、测试和退出规则。
- 验收：适合/不适合/信息不足的 fixture 均能给出对应结论，不将平台机制泛化。

### PEA-061：IR 可行性审查器

- 初期只判断函数是否满足纯函数、类型和测试要求，不生成代码。
- 验收：有 IO、线程、反射、动态代码、异常复杂控制流或无测试覆盖时会提出阻断/人工审查。

### PEA-062：独立 IR PoC（后续）

- 单独 repo/实验分支，仅有限 opcode；实现 IR verifier 与资源限制。
- 验收：随机差分、fuzz、异常/边界用例和安全审查；未通过不整合为生产 adapter。

## 全局 Definition of Done

- 行为由测试证明，而不是由注释或 README 声称。
- 失败、取消、超时和未知都能显式呈现。
- 默认最小权限，所有副作用可追踪和回滚。
- 文档、schema、示例、测试、风险和版本锁同时更新。
- 所有外部研究信息包含来源与核验日期。


## Epic H：分析能力与 VMP 候选审计

### PEA-070：REA 工具调用链只读审计

- 固定 REA 上游 commit，确认工具注册、输入 schema、共享 workflow、provider、外部进程/API、Evidence 记录与清理路径。
- 逐个结论记录源码路径/行号、测试类型、平台和证据状态；不把 README 和 mock 结果写成运行时事实。
- 验收：生成带 commit SHA 的工具/副作用矩阵；至少抽查一个原生分析 provider 与一个 JS/Electron 静态路径；网络不可用时状态为 `unknown`，不伪造报告。

### PEA-071：ShellVMP / FDartVMP 候选验证

- 分别固定仓库 commit，读取 LICENSE、商业授权、第三方依赖、构建和测试入口。
- 使用自有最小 fixture 复现基础功能、差分测试、故障用例和产物检查；不默认打开反调试/环境门控。
- 验收：许可证与依赖清单完成；记录工具链/设备/架构；明确未支持语法/函数、性能预算与剩余风险；任何关键测试未复现时不能高于 `source_reviewed`/`test_reviewed` 对应证据状态。

### PEA-072：Research Evidence / Candidate Review schema

- 为每个候选分别记录 README 声明、源码发现、测试复核和 fixture 实测，不能合并为一个模糊“已验证”。
- 验收：schema 校验、示例解析、未知状态负向测试通过；候选只有在许可、供应链、平台与功能测试全部过门后才能进入生产状态。

### PEA-073：分析能力审计 Skill

- 使用 `skills/pea-analysis-capability-audit/SKILL.md` 标准化只读审计，输出调用链、副作用、Evidence 与 PEA 防护映射。
- 验收：对文档-only、源码可读但未实测、fixture 已复现三种样例返回不同状态；工具不可用不会被记成防护通过。
