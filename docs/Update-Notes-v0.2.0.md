# PEA Design Kit 更新说明：v0.1.0 → v0.2.0

日期：2026-10-13

## 重要改进

1. 将 REA 参考从早期 fork 视角调整为上游 `morluto/rea` 的公开文档，明确区分上游、fork、当前主线和发行包快照。
2. 根据当前公开 REA 文档补充 provider/capability 分离、Evidence provenance、工具副作用、JS/Electron 工件图、安全读取和 unknown 语义。
3. 新增 `rea-capability-defense-map.json`，把分析能力映射到可观察暴露面、防护选项、验证方法和局限。
4. 新增用户 `lang-vmp-guide` Skill 的接入评审与 `pea-vmp-research` Skill，保留有效工程原则，同时降低平台特定/过强声明的置信等级。
5. 将 `seccomp`、root/dump、信噪比稀释、反调试与主动密钥毒化等说法明确视为平台特定或待验证内容；默认采用可审计、可诊断、可恢复的失败关闭策略。
6. 增加 Research Agent 信任层级、项目候选状态机、评分硬约束、短期一次性批准令牌、结构化 argv、隔离工作区和完整验证门槛。
7. 增加 Evidence/Exposure Finding/ToolEffects Schema、源码审计模板和可以拆分为 issue 的 MVP Backlog。
8. 明确 REA clone 在当前执行环境因 DNS 失败，没有完成本地源码级审计。公开文档研究与源码确认状态分开，不将文档描述伪装为逐行审计。
9. 保留用户上传的原始 Skill ZIP，不推断缺失的许可证；新增衍生内容应由维护者单独确定开源许可。

## 仍未实现的产品能力

本版本没有实现 MCP server、在线项目检索 connector、保护器安装/执行 sandbox、REA 源码级审计结果采集器或 IR/VM 后端。现有 Python 规划器仍为离线计划原型，不会修改用户代码。
