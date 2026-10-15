# PEA Catalog Maintainer Skill

## 目标
给 PEA 目录增加或更新一个保护器项目，确保条目可以审计、可复现且许可证和维护状态透明。

## 添加前检查
1. 提供官方仓库或作者控制的下载/文档 URL；不得把搜索引擎摘要当作唯一来源。
2. 记录仓库/包版本、发布日期、commit/tag、维护状态及检查时间。
3. 检查 LICENSE 文件、SPDX 标识、商业/再分发约束和所有第三方依赖；不确定则设为 `needs_review`。
4. 确认项目的真实输入、输出、目标语言/平台和构建链。
5. 检查已知安全公告、归档状态、二进制来源、签名/校验摘要和是否需要不合理权限。
6. 在隔离环境用无害自有样例运行，不使用真实私钥、生产许可证或第三方商业软件样本。
7. 添加至少一个成功样例、一个失败样例、兼容性范围、性能影响和回滚说明。
8. 让 Schema 校验与目录测试通过；以 PR 形式提交人工审查。

## 状态约定
- `active`：仍在维护且有近期可信证据；
- `slow`：维护不频繁，但通过项目自身验证矩阵；
- `archived`：上游归档或明确停止维护；生产默认排除；
- `unknown`：证据不足；生产排除。

许可状态：
- `verified`：按指定版本核验 SPDX 与适用方式；
- `needs_review`：证据不足或条款复杂；生产排除；
- `incompatible`：已确认不满足项目分发需求；硬性排除；
- `not_applicable`：条目是内部设计模式，不是第三方代码。

## 更新规则
- 不能因新版本发布自动替换生产锁定版本。
- 许可证、下载地址、签名、插件权限或供应链变化视为需要重新审批的变化。
- ShellVMP / FDartVMP 官方公开 URL 已确认，可登记为 `documentation_reviewed`；必须将源码审计、commit、复现测试和许可兼容性单独标记。未完成前不得声称已验证或 production-eligible。

## 证据与能力模型
- 分开保存 `repository_claims`、`package_release_claims`、`local_runtime_capabilities` 与 `fixture_results`。一个层面的事实不得自动证明其他层面。
- 记录工具输入 schema、目标/主机约束、副作用、网络和进程权限、超时、取消、清理及 Evidence 结构。
- 维护状态需要具体时间和证据 URL；不能仅凭 GitHub stars、README 自述或一次成功启动判定为 production-eligible。
- 如果上游提供 capability catalog 或 `tools/list`，保存快照 digest；实际运行时能力应优先于过期文档。
- 对 REA 的防护映射使用 `catalog/rea-capability-defense-map.json`，但映射只是研究线索；必须在实际使用版本中确认每项能力可用。
