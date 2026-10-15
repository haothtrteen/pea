# PEA Design Kit 更新说明：v0.2.0 → v0.2.1

日期：2026-10-13

## 本次改进

1. 将 ShellVMP 与 FDartVMP 从占位研究名称更新为各自官方仓库候选，并分别登记到目录种子中。
2. 新增 `VMP-Projects-Comparative-Review-zh-CN.md`，比较公开架构、可迁移工程经验、限制、许可线索和 PEA 需补齐的验证步骤。
3. 补充两项目 `documentation_reviewed` 的证据状态；明确它们尚未在本地 clone、固定 commit 或复现测试，不把 README 声明当成 PEA 自身验证结论。
4. 主架构文档加入 ShellVMP/FDartVMP 的集成评估矩阵、许可门控与不可泛化的结论。
5. REA 工作流分析加入与 VMP 项目交叉的防护/验证价值，同时保留 clone 失败和未完成源码审计的事实。
6. 更新 Planner / VMP Research Skills，不再把项目当作完全未知名称，但将它们限制在研究候选阶段。
7. 更新 README、来源清单和目录记录，明确 AGPL/商业双授权及 FDartVMP 提及的独立 VMPacker 许可风险。
8. 版本增至 0.2.1；未改变规划器不执行第三方工具、不修改源项目的安全边界。

## 已实现 / 验证状态

- `pea_planner` 仍是离线目录和计划原型，并非保护执行器。
- REA、ShellVMP、FDartVMP 的本地源码审计：未完成，原因是容器无法解析 `github.com`。
- ShellVMP / FDartVMP 的精确 commit、完整依赖、生产兼容性及可复现测试：`unknown`。
- 第三方代码未复制进 PEA；原始用户 Skill 仍以附件保存，但 ZIP 中未发现独立 LICENSE。

9. 增强 REA 能力盘点：将公开 README 中的原生分析、Ghidra、JS/Electron 静态分析、浏览器/进程观察、Evidence 与 CLI/MCP 分组映射到下一步源码审计问题；继续明确这些是文档层核验，不是源码审计。
10. 更新实施计划，新增 Phase 2.5：只读分析能力审计、REA 工具/副作用矩阵、VMP 候选状态机与固定版本/许可门控。
11. 修正 Word 导出器的表格分页策略，为每个表格行设置 `cantSplit`，避免分页时单个表格行被拆开；重新生成 Word 并进行分页图像检查。
