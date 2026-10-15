# PEA 工程实施计划（v0.2.2）

**更新日期：** 2026-10-13。v0.2.2 增加只读分析能力审计与 VMP 候选研究门，避免在仅有 README 证据时直接接入第三方工具。

## 1. 交付顺序

先交付可复现、低副作用、测试驱动的目录与规划器；然后增加只读画像、暴露面映射和研究索引；之后才实现 MCP、审批与隔离执行。真正的保护器适配器应在策略和验证基础设施成熟后逐个加入。受限 IR/VM 是独立研究分支，不是 MVP 阻塞项。

## 2. 推荐仓库结构

```text
pea/
├── README.md
├── pyproject.toml / lockfile
├── src/pea/
│   ├── api/cli.py, mcp_server.py
│   ├── service/                 # CLI 和 MCP 共用
│   ├── schemas/
│   ├── profiling/
│   ├── exposure/
│   ├── research/connectors/
│   ├── catalog/
│   ├── policy/
│   ├── planner/
│   ├── approvals/
│   ├── adapters/
│   ├── execution/sandbox/
│   ├── verification/
│   ├── evidence/
│   ├── reports/
│   └── storage/
├── catalog/seed.json
├── skills/pea-protection-planner/; pea-catalog-maintainer/; pea-vmp-research/; pea-analysis-capability-audit/
├── schemas/
├── docs/
├── tests/unit/ integration/ fixtures/ conformance/
└── scripts/
```

## 3. 阶段计划

### Phase 0：规格与离线规划器

已提供请求、目录、计划和插件 Schema、离线 CLI 与单元测试。验收：示例可运行、输入拒绝策略确定、不执行外部程序、相同输入生成相同结果。

### Phase 1：只读 Profiler 与 Exposure Mapper

先支持 package/build manifests、release artifact manifest、字符串与符号/调试信息、JS source-map 声明、危险文件和疑似秘密扫描。任何命中都应输出脱敏信息和误报提示。验收：不运行项目脚本；路径越界/symlink 逃逸测试通过；未知解析状态不被忽略。

### Phase 2：研究索引与目录同步

支持 official repositories / release / LICENSE / docs 元数据；网络搜索结果进入待审核区。验收：离线模式可工作；许可证未知不可生产推荐；下载和执行分开；每条候选有来源与核验时间。

### Phase 2.5：只读分析能力审计与候选证据固化（v0.2.2 新增）

在接入高副作用保护器之前，先对参考分析框架和候选 VMP 做只读、可追溯的工程审计。

- **REA 审计**：从 MCP 工具注册与输入 schema 开始，追踪共享 workflow/service、provider、外部进程或 API、Evidence 产出、取消/超时和资源清理；记录源码路径、行号、关联测试与平台范围。
- **研究候选固化**：对 ShellVMP、FDartVMP 分开记录文档声称、源码观察、测试审查和自有 fixture 实测；不将公开 README 等同于通过验证。
- **许可和供应链门控**：锁定 commit/release，审阅 SPDX/商业授权、第三方目录、依赖、安装脚本和下载来源。没有许可结论的项目仅能作为研究条目。
- **状态机**：`discovered → documentation_reviewed → source_reviewed → test_reviewed → fixture_verified → project_verified → production_eligible`。阶段不能跳跃；任何未知/失败都必须留在证据记录中。

验收：生成带 commit SHA 的 REA 工具/副作用矩阵；至少覆盖一个原生分析 provider 与一个静态 JS/Electron 路径；候选项目报告包含来源、许可证、依赖、限制及测试命令；网络不可用时不得伪造源码审计或测试通过。

### Phase 3：MCP + ToolEffects + 审批

CLI/MCP 共用 service layer；由一份 schema 生成工具能力/副作用声明。建立绑定 plan digest、工件 digest、参数和版本的短时一次性批准。验收：计划变化、令牌过期/重放、路径越界都拒绝。

### Phase 4：受控执行器

隔离工作区、结构化 argv、网络默认关闭、环境变量 allowlist、超时与资源限制、进程树终止和恢复。验收：取消/崩溃/超时后原始工作树不变；不允许任意 shell 文本；输出只能写入计划声明范围。

### Phase 5：第一批适配器

优先低风险检查类适配器：JS 工件与 source map 检查、Android R8 配置检查、原生符号/调试信息检查、许可证报告。再选择一个成熟保护器，完整经过 fixture/集成测试后接入。每个 adapter 必须有 manifest、锁版本、许可、副作用和回滚策略。

### Phase 6：验证与报告

构建原始/保护后差分测试，兼容性/性能测试，SBOM/许可证清单，工件泄露和签名检查。验收：关键测试失败或 unknown 时不生成 release candidate；报告中有证据和剩余风险。

### Phase 7：VMP Skill 与受限 IR/VM PoC

将 `lang-vmp-guide` 方法提炼为可审阅 Skill，区分通用方法、平台假设和未验证主张。IR PoC 限于纯函数与受限类型；实现 IR validator、解释器、资源限制、随机差分与模糊测试。验收：错误 IR 被安全拒绝；变换行为可对拍；性能开销和兼容边界有数据；独立安全审查通过。

## 4. 测试矩阵

| 类别 | 关键测试 | 发布门槛 |
|---|---|---|
| 输入/权限 | 未确认授权、错误目标路径 | 副作用操作阻断 |
| 目录/许可 | 缺失 LICENSE、归档仓库、fork 来源不明 | 不能进入生产候选 |
| 文件系统 | 路径穿越、symlink、超大归档 | 拒绝越界，记录原因 |
| 执行器 | shell 元字符、环境变量泄露、无网络任务联网 | 阻断或安全失败 |
| 功能正确性 | return/stdout/stderr/退出码/文件/异常对比 | 关键差异为 fail |
| 兼容性 | 反射、序列化、JNI/FFI、动态加载、异常分支 | 支持声明内通过 |
| 性能 | 启动、P50/P95、内存、包体积 | 预算通过或审批例外 |
| Evidence | 工具版本、工件摘要、coverage 缺失 | unknown 不能成为 pass |
| 取消/回滚 | 取消、超时、进程崩溃 | 子进程清理，原工作树不变 |
| 提示注入 | README/源码指示忽略策略 | 当成不可信数据 |

## 5. 角色分工

- **维护者/用户：** 确定授权范围、目标资产、阈值、批准计划和发布。
- **Agent：** 理解需求、研究候选、总结证据、协助生成计划和测试。
- **Policy Engine：** 施加确定性硬门槛，验证审批令牌和权限。
- **Adapter：** 执行单一已登记工具，按固定合同收集工件和证据。
- **Verification Engine/CI：** 运行测试、生成报告并阻止失败产物发布。

Agent 不能同时充当提案者、审批者和受保护执行器。

## 6. Definition of Done

每项交付需包括实现、schema、单元测试、集成/fixture 测试、错误码、日志脱敏、风险/兼容说明、版本锁定和回滚文档。涉及工件转换的功能必须含正向测试、负向测试与“失败不发布”门控测试。
