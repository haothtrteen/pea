# PEA 参考资料与核验记录

**整理日期：2026-10-13。** 链接作为架构和候选发现依据，不表示项目背书。具体集成前需要按精确版本再次核验。

## REA 与 Agent / MCP 架构及目标类型

1. REA 上游 README：<https://github.com/morluto/rea>。了解其 CLI/MCP、provider 与公开调查模型。
2. REA MCP 运行时合同：<https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md>。参考统一工具合同、能力和 Evidence 语义。
3. REA Provider 评估：<https://github.com/morluto/rea/blob/main/docs/provider-evaluation.md>。参考支持/不可用/降级状态、provider 验证与生命周期。
4. REA JavaScript/Electron 工件重建：<https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md>。参考静态解析、不执行应用代码、artifact graph、范围限制和 unknown。
5. REA 安装和版本状态：<https://github.com/morluto/rea/blob/main/docs/installation.md>。用于区分当前主线与带日期的发行快照。
6. REA MCP prompts：<https://github.com/morluto/rea/blob/main/docs/mcp-prompts.md>。参考分阶段工作流与观察/推断/未知区分。
7. REA Roadmap：<https://github.com/morluto/rea/blob/main/docs/roadmap.md>。用于理解功能准入和验证标准。
8. REA AGENTS.md：<https://github.com/morluto/rea/blob/main/AGENTS.md>。参考配置变更需审批、环境变量最小化和架构分层。

## 保护技术与安全工程

10. OWASP MASVS Resilience：<https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/>。将混淆、反调试、反篡改定位为纵深防御的一部分。
11. Android R8：<https://developer.android.com/build/shrink-code>。平台原生代码缩减和混淆。
12. javascript-obfuscator：<https://github.com/javascript-obfuscator/javascript-obfuscator>。候选工具；生产执行前核验精确版本、LICENSE、配置与性能。
13. PyArmor 文档：<https://pyarmor.readthedocs.io/en/stable/>。候选工具；当前许可、版本计划和平台适配需单独核验。
14. ConfuserEx 原始仓库：<https://github.com/yck1509/ConfuserEx>。用于展示历史项目需要维护状态和 fork 来源门控。
15. VMProtect：<https://vmpsoft.com/vmprotect>。商业工具能力参考，不构成复制/集成许可。

## 分析能力情报（攻击侧参考，2026-10-13 web 核实）

以下条目来自场景走查（`docs/Scenario-Walkthrough-Flutter-Licensing-zh-CN.md`）阶段 3 的检索研究，为 `catalog/rea-capability-defense-map.json` 新增能力族 `dart_aot_snapshot_analysis` 的证据来源。**均为 `documentation_reviewed`（web 检索核实），未做本地源码审计；PEA 不引入、不分发、不自动执行这些工具。** 对应 REA 自身的工具清单中**不存在**任何联网/社区检索能力，此节为 PEA 独有的情报维度。

20. blutter（worawit/blutter）：<https://github.com/worawit/blutter>。Flutter 逆向工具：从 `libflutter.so` 自动识别 Dart 版本并编译匹配运行时，解析 `libapp.so` Dart AOT 快照，输出带注释的 ARM64 汇编、类/方法清单、对象池倾倒（`pp.txt`）与自动生成的 Frida 钩子模板（`blutter_frida.js`）；当前仅支持 Android arm64。其 README TODO 自述 "Obfuscated app (still missing many functions)"——混淆降低其自动化还原质量但不阻止快照结构解析。
21. reFlutter（Impact-I/reFlutter）：<https://github.com/Impact-I/reFlutter>。用打过补丁的 Flutter 引擎重打包 APK：转储运行时快照、中和 BoringSSL `ssl_crypto_x509_session_verify_cert_chain` 以截获流量；依赖版本匹配的预编译引擎。
22. Doldrums（rscloura/Doldrums）：<https://github.com/rscloura/Doldrums>。纯 Python 的 Dart 2.x 快照解析器，Dart 3.x 已失效，仅历史参考。
23. Flutter 自带 BoringSSL（`libflutter.so`）而不经平台 TLS 栈——Java 层 TLS hook 对 Flutter 应用无效；此事实由多份公开逆向资料交叉确认。
24. blutter 类工具链方法论（Phrack 71 "Reversing Dart AOT snapshots"、公开 pentest 知识库）：快照格式内部结构、对象池寄存器约定（ARM64 x27）与分析流程。

## 用户 Skill 与 VMP 项目参考

16. `docs/skill-lang-vmp-guide-original.zip`。用户上传的原始 Skill 包，作为本次设计参考材料保留；ZIP 中未发现独立 LICENSE 文件，公开发布原包或其衍生内容前需要权利人确认许可范围。
17. ShellVMP 官方仓库：<https://github.com/haothtrteen/ShellVMP>。公开页面描述 shell 混淆、ELF 封装、流式处理与解释器令牌化；页面列出 AGPL-3.0 LICENSE 与商业许可文件。当前只核对公开文档与许可入口，未 clone/固定 commit/复现。
18. FDartVMP 官方仓库：<https://github.com/haothtrteen/FDartVMP>。公开页面描述 Flutter/Dart 函数级私有字节码与 native interpreter；`LICENSING.md` 声明 AGPL-3.0-or-later / 商业双授权，并指出 VMPacker 是独立工具。当前只核对公开文档与许可说明，未 clone/固定 commit/复现。
19. GitHub 许可证说明：<https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository>。用于提醒“仓库公开”不等于可任意复制、修改或再分发；正式集成以适用许可证及法律审查为准。

## REA 审计状态

**2026-10-13 更新（第二次记录）：REA 源码已在本地取得。**

- 拉取方式：从官方仓库 `https://github.com/morluto/rea` 浅克隆至 `/workspace/references/rea`。
- **固定 commit：`bb96afdbe32f5318d57fcb00099191c5a7712f53`**（main，2026-10-12 22:29:09 -0700，`fix(pcap): name the host tool to configure in capability refusals (#2507)`）。
- 完整性校验：HEAD 与 `git ls-remote https://github.com/morluto/rea.git` 直连返回值一致，内容未被篡改。
- 规模：3270 个跟踪文件，2422 个 TS/TSX 文件、约 52.5 万行、1338 个测试文件；turbo monorepo + vitest。
- **证据状态：`documentation_reviewed` → 源码已就位，`source_reviewed` 的前置条件已满足，但行号级源码审计（PEA-070）尚未执行，不得越级记为 `fixture_verified`。**
- 未完成项：5 个 submodule 未初始化（`third_party/jadx-headless-mcp`、`binwalk`、`unblob`、`ghidra-nativeaot`、`wakaru`）；浅克隆无历史，需追溯时执行 `git fetch --unshallow`。
- 许可边界：REA 只作只读参考，PEA 不复制、链接或分发其代码；详见其 `LICENSE` 与 `THIRD_PARTY_NOTICES.md`。
- 已从源码确认的可借鉴工程模式见 `/workspace/REA工程映射与借鉴清单.md`（Contracts/Domain 分层、`src/contracts/toolEffects.ts` 副作用注册表、`docs/error-contract.schema.json` 错误合同、EvidenceLedger 与 `list_unknowns`、不可信目标内容标记、composition root）。

**2026-10-13 初次记录（历史留档）：** 此前执行容器因 DNS 无法解析 `github.com`，`git clone` 失败，故 REA/ShellVMP/FDartVMP 均停留在 `documentation_reviewed`。该环境限制在当前沙箱已不成立，上述状态据实更新。ShellVMP 与 FDartVMP **未**随本次一并拉取，仍维持 `documentation_reviewed`，不得因 REA 拉取成功而升级其状态。
