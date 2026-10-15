# REA 源码级审计模板（只读与授权范围）

本模板用于网络与仓库访问可用时，对固定版本的 REA 进行可复核的只读架构/安全审计。不要将文档推断冒充源码事实；不要在未经授权的第三方目标上运行工具。

## A. 仓库身份

| 字段 | 值 |
|---|---|
| 上游 URL | `https://github.com/morluto/rea` |
| 审计 commit SHA | 待填 |
| 检查时间（UTC） | 待填 |
| 本地工作树干净 | 待填 |
| LICENSE / 第三方声明 | 待填 |
| Node / package manager / MCP SDK 版本 | 待填 |
| 对照发行包与 source SHA 是否一致 | 待填 / unknown |

## B. 工具调用追踪矩阵

每一个被纳入 PEA 设计的工具都应单独一行；不要用“工具总体安全”替代逐项审查。

| 字段 | 要记录的内容 |
|---|---|
| MCP tool 名称 | 真实 `tools/list` 名称与 schema digest |
| 工具注解/效果 | 目标、session、filesystem、process、network、UI、discard、idempotence 等实际效果 |
| 入口位置 | 文件路径、符号/函数、行号 |
| 参数校验 | 类型、范围、规范化、拒绝理由/错误码 |
| 服务层调用 | workflow/service 函数及责任 |
| provider/adapter | 注册处、能力声明、选择规则、版本 |
| 外部进程/API | 可执行文件、argv 构造、cwd、env、网络、文件访问 |
| 资源控制 | 超时、输出大小、内存/CPU、取消、子进程树清理 |
| Evidence 合同 | 输出字段、来源、artifact digest、coverage、limitations、unknown |
| 文件/缓存副作用 | 临时文件、快照、Evidence bundle、覆盖规则、访问权限 |
| 测试证据 | 测试文件、fixture、mock/真实 provider 分类、运行结果 |
| 平台矩阵 | supported/unavailable/degraded/unknown 及来源 |
| PEA 映射 | 暴露风险、防护建议、可验证检查、局限 |

## C. 安全检查清单

- [ ] 工具能力与 provider 实际状态一致，不从“已安装”推断“可用”。
- [ ] 路径规范化和 symlink 行为已检查。
- [ ] 外部命令采用参数数组，不存在非预期 shell 拼接。
- [ ] 网络 host、跳转、认证和超时策略明确。
- [ ] 不继承不必要的 ambient environment/credentials。
- [ ] 取消/超时/失败路径清理临时资源并保持一致状态。
- [ ] Evidence 明确区分 observation / inference / unknown。
- [ ] 大型输出、超大文件、格式畸形输入、路径穿越都有资源边界。
- [ ] 快照与缓存按 artifact digest、操作、参数、provider 和配置绑定。
- [ ] 敏感字段脱敏有明确语义，不靠变量名启发式盲目删改。
- [ ] MCP tool 标注与真实副作用有合同测试。
- [ ] mock 测试和真实 provider conformance 测试已区分。

## D. 审计结论标签

- `source_confirmed`：已读到具体实现，路径/行号已保存。
- `test_confirmed`：有相关测试；必须说明 mock 还是真实 provider。
- `runtime_confirmed`：在固定测试环境实测成功，并留有环境摘要。
- `document_only`：只能从公开文档得知。
- `unknown`：没有足够证据。

每项结论必须引用至少一种证据。一个 `source_confirmed` 的功能实现，不等于相关 provider 在每个平台都 `runtime_confirmed`。

## E. 建议审计顺序

1. 记录 package.json、license/third-party notices、版本和 commit。
2. 查找 CLI 路由、MCP server、工具注册与生成 catalog。
3. 追踪一个工具从 schema/handler 到共享 service，再到 provider/外部工具。
4. 检查 Evidence 结构、缓存、临时文件、错误处理和清理。
5. 阅读 unit/contract/fixture/provider 测试，标记 mock 边界。
6. 在自建 toy fixtures 上运行最小真实分析流程，并记录 host/provider/版本。
7. 将观察映射进 `catalog/rea-capability-defense-map.json`，每项映射需附适用条件与验证方法。
8. 生成变更建议时仅引用来源和证据，不把 REA 内部实现信息作为对抗/规避分析工具的代码方案。
