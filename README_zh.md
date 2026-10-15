<div align="center">

[English](README.md) · **简体中文**

</div>

# PEA：保护工程助手（Protective Engineering Assistant）

**版本：0.7.0 · 文档基线：2026-10-15 · 许可：[MIT](LICENSE) © 2026 haothtrteen**

PEA 是面向自有或获授权软件项目的软件保护研究、方案选择、受控集成与验证编排设计。它遵循：**分析能力 → 暴露面 → 防护措施 → 可复核证据**。目标不是让某一款逆向工具“失效”，而是识别软件实际暴露的资产，选择合适保护措施，并用测试说明它改变了什么、没有改变什么。

## 主要内容

- `docs/PEA-Architecture-Spec-zh-CN.md`：核心架构、MCP 合同、威胁模型、执行审批和验证门槛。
- `docs/PEA-Architecture-Spec-zh-CN.docx`：核心架构 Word 版。
- `docs/PEA-Architecture-Spec-zh-CN.pdf`：便于快速阅读和审阅的 PDF 版。
- `docs/REA-Workflow-Defense-Analysis-zh-CN.md`：REA 工作流、扩展目标类型、能力暴露面和防护映射；明确区分在线文档研究与源码审计。
- `docs/Scenario-Walkthrough-Flutter-Licensing-zh-CN.md`：端到端场景走查——"帮我保护这个 Flutter 项目的授权逻辑"从 intake 到落地的全链路模拟，含 [实测] 输出、攻击面情报（blutter / reFlutter / Doldrums）、场景到路线的映射与优化项 R1–R6、REA 实际能力源码核实（附录 A）。
- `docs/Scenario-Walkthrough-Electron-Desktop-zh-CN.md`：第二个场景的目标形态模拟——Electron 桌面客户端（CanvasSync）在系统全部建成后的理想使用样子；每阶段标注 [现已落地]/[目标形态]，与 Flutter 场景对照证明域模型的通用性。
- `docs/REA-Parity-Plan-zh-CN.md`：六维对标方案——工具合同密度 / 域包装边界 / 验证金字塔 / 反向自检 / 证据账本 / 双通道情报检索，逐维给出落地件、验收标准与工作量（约 23–29 天）。
- `docs/Exposure-Tier-Model-zh-CN.md`：暴露面分层模型——"由高到低修复"的工程化。四层暴露面（T1 工具放大层 → T4 算法逻辑层），修复顺序 = 攻击者边际成本排序；`src/pea/tiers.py` 为唯一真源，贯穿能力映射标注、攻击自测步骤排序与报告修复优先级三个出口。
- `docs/Adversarial-Self-Test-and-Tool-Integration-zh-CN.md`：对抗性自测与保护工具分层集成——`attack-simulation.schema.json` 合同（红线入 schema）、四层集成模型（L1 配置生成 / L2 自装驱动 / L3 受控执行 / L4 目录参考，按许可定层）、攻击侧工具"不分发不自动装"边界。
- `docs/Attack-Verification-and-Field-Feedback-Design-zh-CN.md`：第三环设计冻结——实测攻击验证（REA 作为自测 oracle、任务简报五要素、环境分层 T0–T4 与 `testbench` 侦察域、源码作弊码原则）与战场反馈回路（D7：破解包 intake、服务端球门轮换、纠缠而非隐藏、中性失效红线），含六个工作包的落地清单。
- `docs/Phase4-Access-Orchestration-Execution-Design-zh-CN.md`：Phase 4 设计冻结——官方 SDK 的 MCP stdio server（合同驱动的工具发现，核心零依赖不破）、`pea.run_assessment` 任务编排器（任务持久化 + 中断恢复）、受控执行器四件套（apply/verify/compare/rollback，快照 + 令牌 + 回滚）与第一条真实保护闭环（JS canary 端到端样板），含六个工作包的落地清单。
- `docs/Execution-Loop-Implementation-Plan-zh-CN.md` — WP0–WP6 落地方案：外部评审处置 + 交付验收记录
- `docs/Dual-MCP-Wiring-Guide-zh-CN.md`：双 MCP 接线指南——同一 agent 挂 PEA + REA 的实弹演练工作流（PEA 出简报 → 你的 agent 驱动你自己的 REA → 证据回流账本），含 CLI/组合层/MCP server 三种接入形态、证据回流合同与常见失败模式。
- `schemas/attack-simulation.schema.json` + `examples/attack-simulation.flutter-licensing.example.json`：最简沙盒逆向自测方案合同与 Flutter 场景示例；红线机械执行——产物只读 `const true`、工具失败只能记 `unknown`、解释规则枚举里不存在"绝对防护"。
- `catalog/rea-capability-defense-map.json`：结构化的分析能力族—暴露面—防护措施—验证证据映射；含场景研究新增的 `dart_aot_snapshot_analysis` 能力族。
- `docs/REA-Source-Audit-Template-zh-CN.md`：未来对 REA 做只读源码审计的证据模板。
- `docs/VMP-Projects-Comparative-Review-zh-CN.md`：ShellVMP / FDartVMP 的公开文档比较、集成风险和验证矩阵。
- `docs/Skill-Lang-VMP-Guide-Review-zh-CN.md`：用户上传 Skill 的方法论评审和许可证边界说明。
- `docs/MVP-Backlog-zh-CN.md` 与 `docs/PEA-Implementation-Plan-zh-CN.md`：可拆成 issue 的开发任务和阶段路线。
- `docs/Threat-Model-and-Security-Policy-zh-CN.md`：安全策略和威胁模型。
- `docs/skill-lang-vmp-guide-original.zip`：用户上传的原始 Skill 附件，原样保存。**该包内无独立 LICENSE 文件，已列入 `.gitignore` 不随仓库分发**；公开发布原包或其衍生内容前，须由权利人确认许可范围（详见 `sources.md`）。
- `skills/`：保护规划、目录维护、VMP 研究、分析能力只读审计等 Agent Skill 草案。
- `schemas/`、`catalog/`、`mcp/tool-contract.json`：数据合同、候选项目种子和 MCP 工具定义。
- `schemas/protection-request.schema.json` / `schemas/protection-plan.schema.json`：保护请求与保护计划的合同；请求侧含 `distribution` / `audience` / `device_control` / `platforms` / `offline_required` / `secret_can_leave_client` 等部署姿态字段，计划侧含 `deployment_posture` / `intake_unknowns` / `client_side_hardening` 等推导结论。
- `src/pea/intake.py`：部署姿态访谈层——先问清语言、平台、分发方式、使用者与威胁模型，再推导 posture；`unknown` 是一等公民，未被回答的问题必然出现在 `intake_unknowns` 里。
- `src/pea/validation.py` + `src/pea/paths.py`：**纯标准库**的 JSON Schema 2020-12 子集校验器（运行时仍零第三方依赖）。入口强制校验请求与目录，产出计划前自检计划合同；不支持的关键字会**响亮报错**而不是被跳过。
- `tests/test_validation_crosscheck.py`：用 dev 依赖里的 `jsonschema` 做参考实现，对全语料 + 系统变异语料交叉验证自研校验器的每一项判定与 `(path, keyword)` 完全一致。
- `examples/protection-request.internal-android.example.json`：内部受控安卓场景示例，展示"要绝对安全"的诉求如何被推导为 `controlled_environment_hardening` 而非无限加固。
- `examples/protection-request.flutter-licensing.example.json`：Flutter 授权逻辑保护场景示例（有限外部分发 + 离线 + 秘密不可移出），实测推导为 `platform_native_cleanup_first` 且候选被许可/证据门控如实拦截。
- `schemas/research-candidate-review.schema.json` + `examples/fdartvmp-research-review.example.json`：研究候选的来源、源码、许可证、fixture 与决策状态示例。
- `src/pea/`、`tests/`：离线规划器原型与单元测试（src 布局，可 `pip install -e .`）。
- `docs/Update-Notes-v0.2.2.md`：本次修订范围和验证状态。
- `CHANGELOG.md`：版本变更日志与版本策略（0.x：MINOR = 里程碑闭合，PATCH = 缺陷修复；契约与文档漂移即发布阻塞）。
- `CONTRIBUTING.md`：开发纪律（Schema 唯一真源 / 无静默成功 / unknown 不是 pass / 证据权威显式化）、质量门与提交约定。
- `sources.md`：参考来源与核验状态。
- `references/PROVENANCE.md`：REA 上游源码的拉取记录、固定 commit 与未完成项。
- `landing-page/`：自包含单页官网原型。

## 快速开始

需要 Python 3.10+。**运行时零第三方依赖**（仅标准库）；测试与契约门需要 `pip install -e ".[dev]"`。

```bash
pip install -e ".[dev]"        # 开发安装（含 pytest / jsonschema / ruff / mypy）
pip install -e ".[mcp]"        # 可选：MCP stdio server（官方 SDK，核心包保持纯标准库）

pea catalog                    # 列出本地候选目录
pea search --target javascript --goal obfuscation
pea intake                     # 先访谈：问清平台、分发、使用者，推导部署姿态
pea plan --request examples/protection-request.example.json --out /tmp/pea-plan.json
pea demo --request examples/protection-request.flutter-licensing.example.json --project demo/canary-flutter-licensing --out build/demo-out
                                # 原型 1.0：端到端走通防御工程闭环（侦察→计划→攻击自测→账本→报告）
pea task run --request examples/protection-request.flutter-licensing.example.json --project demo/canary-flutter-licensing --store .pea/tasks --out build/task-out
                                # 同一走查作为可持久、可恢复的任务实体：审批门→域→计划→账本→门→报告

pea protect demo/canary-js-licensing
                                # 一句话保护：分析 → 方案 → 审批预览 → 一个 y/N → 受管工作区内执行 → 验证 → 差分 → 报告

make check                     # lint + typecheck + test + 契约门
make verify-real               # L2 真实工兵层（对合成形态产物跑真实域；单独触发，不在 check 内）
make verify-loop               # WP4 执行闭环七步 + 八条判据（真实工具；单独触发，不在 check 内）
```

不安装也可直接运行（源码方式）：

```bash
PYTHONPATH=src python -m pea.cli catalog
```

> 注：v0.2.2 及更早的文档里的命令写作 `python -m pea_planner.cli ...`；包在改为标准 src 布局后更名为 `pea`，上述命令为当前形式。`landing-page/` 的下载包为 `PEA-Design-Kit-v0.5.0.zip`（页面命令与当时代码一致；0.7.0 的受控执行闭环尚未重打包进下载包）。

## 仓库结构

```text
src/pea/          规划器与 CLI（domain 逻辑应保持纯函数、无 IO）
  intake.py       部署姿态访谈与 posture 推导
  planner.py      目录搜索、候选打分与计划生成（入口/出口双 schema 校验）
  tiers.py        暴露面分层模型：T1 工具放大→T4 算法逻辑，按攻击者边际成本由高到低排序
  fswalk.py       共享只读遍历纪律（根边界/深度/文件数上限/VCS 跳过，跳过即记录）
  domains.py      D2 统一域输出形态：findings + coverage + unknowns
  recon.py        只读项目侦察（语言/构建/平台画像 + 授权逻辑定位，四态覆盖度）
  artifactscan.py 产物清单域：可发布产物枚举 + SHA-256 指纹（超限记 omission 不造 hash）
  secretscan.py   秘密扫描域：秘密材料模式命中，仅记模式名与行号（内容脱敏）
  symbolscan.py   字符串/符号扫描域：二进制产物 strings 式提取 + 泄漏模式计数
  nativecheck.py   native 结构域：ELF/PE/Mach-O 只读头解析（栈/NX/PIE/RELRO/strip）
  dartaotcheck.py  Dart 快照域：libapp.so 锚点与对象池形态探测（混淆状态恒 unknown）
  buildint.py      构建集成域：构建声明 vs 实际产物比对（无声明 ≠ 构建正确）
  capintel.py      能力情报连接器：域名 allowlist + 安全失败 + 离线默认 unknown
  candidatereview.py 候选门控域：许可/维护/证据/信任四门控，block 优先于一切
  attacksim.py    能力映射 → 最简沙盒攻击自测方案（机械派生，红线入 schema）
  ledger.py       证据账本与 unknown 生命周期（双向证据门控 + verified 门禁）
  demo.py         原型 1.0 端到端编排（pea demo）
  l2verify.py     L2 真实工兵层：对合成形态 canary 产物跑真实域，三态 PASS/FAIL/UNKNOWN
  tooleffects.py  MCP 工具注册表：单一实现元数据，生成 tool-contract.json 与 tool-effects.json
  taskrun.py      任务编排器（WP2）：14 步工作流 + 任务持久化 + 输入摘要恢复 + 失败语义
  mcpstdio.py     MCP stdio server（WP1）：官方 SDK 之上只做协议适配，tools/list 合同驱动
  testbench.py    环境侦察域（T0–T4）：固定只读探测，缺环境记 unknown 不冒充通过
  fieldresponse.py 战场反馈回路（D7）：破解包 intake diff + 服务端球门轮换设计
  protect.py      执行闭环（WP3）：快照受管工作区 → 应用 → 三态验证（含变换有效性门）→ 差分 → 回滚
  research.py     研究记录（WP5）：external_claim 恒定 + 离线全 unknown + accepted 机械门
  approval.py     短时一次性批准令牌 + 审批事件（WP0）：绑定六元组，重放/过期/越界/无事件全部拒绝
  mcpserver.py    MCP 组合层：call_tool 调度 + 审批强制；可用性来自处理器表而非合同
  report.py       Markdown 报告渲染
  validation.py   纯标准库 Schema 校验器与结构化错误合同
  paths.py        仓库根 / schemas 目录定位
  adapters/       保护工具适配器（WP3）：三方法协议（inspect/preview/apply）+ 机器可读 manifest
schemas/          JSON Schema 2020-12 —— 数据合同的唯一真源（含 adapter-manifest / research-record）
catalog/          候选种子与「分析能力 → 暴露面 → 防护 → 验证证据」映射
mcp/              MCP 工具合同与副作用声明（tool-contract.json 35 工具 + tool-effects.json，由 src/pea/tooleffects.py 注册表生成，漂移即失败）
demo/             原型 1.0 演示材料：Flutter canary（只读侦察用）+ JS canary（执行闭环测量载体）+ 合成形态产物 fixture
examples/         请求 / 计划 / 暴露发现 / 研究评审示例
skills/           Agent Skill 草案
docs/             架构规格、实施计划、MVP backlog、威胁模型等
scripts/          L2 真实工兵层与 canary 构建脚本（verify_real.py / build_canary_artifacts.py）+ 执行闭环七步验证（verify_loop.py）
tests/            单元测试 + 契约一致性门（test_contracts.py）+ 校验器交叉验证（test_validation_crosscheck.py）
references/       上游只读参考的来源记录（REA 源码本身不入库）
landing-page/     单页官网原型
```

**契约门**：`tests/test_contracts.py` 会把 `catalog/`、`examples/`、`mcp/` 的全部数据按 `schemas/` 逐条校验。数据与合同漂移时 CI 直接失败——这是"Schema 是唯一真源"这条原则的机械化执行。

**入口校验与结构化错误**：`build_plan` 在动手前按 `protection-request.schema.json` 校验请求，产出前按 `protection-plan.schema.json` 自检计划。非法输入不再被静默接受——未知 goal、空 `targets`、缺 `project_path`、多余字段都会抛出 `PeaContractError`，其中携带全部违规项（`code` / `category` / `retryable` / `remediation` / `path` / `keyword` / `message`），CLI 以退出码 2 呈现。候选分数只在**有真实信号的轴**上加权归一化，`basis` 字段随分数一起输出，说明这个数字由什么构成；`performance` 恒不在内，因为目录里没有性能数据。

## 运行规划器原型

需要 Python 3.10+，无需第三方 Python 包。在项目根目录运行：

```bash
python -m pea.cli catalog
python -m pea.cli search --target javascript --goal obfuscation
python -m pea.cli plan --request examples/protection-request.example.json --out /tmp/pea-plan.json
python -m pea.cli testbench             # 环境侦察（T0–T4，只检测不安装）
python -m pea.cli brief --request examples/protection-request.flutter-licensing.example.json \
    --project demo/canary-flutter-licensing --no-testbench --out /tmp/pea-brief.json
python -m pea.cli ledger record --run <run-id> --store /tmp/pea-ledger --evidence evidence.json
python -m pytest tests -q
python3 scripts/verify_real.py       # L2 真实工兵层（可选，单独触发）
```

分析域只做本地只读扫描与计划生成，不联网、不启动目标程序、不执行你的项目代码。受控执行（0.7.0）只在 PEA 受管工作区（目标的一份快照）内运行已审阅的保护工具：工具按固定版本装进 PEA 自己的缓存（不进你的工程），执行需可信通道的审批事件 + 一次性令牌，用户工程目录只读不写——这条边界由测试与集成脚本各自钉死。M4 组合层（`mcpserver.call_tool`，35 工具合同、35 全接线、审批强制与一次性令牌）已落地；MCP stdio server（`pea mcp-server`，官方 SDK 可选依赖，`tools/list` 合同驱动、tools/call 直达组合层零豁免）已落地——**跨进程能力不在 server 内**：一次性令牌随进程生死；**任务编排器（WP2）已落地**（`pea task run/status/list/resume/report` 与 `pea.run_assessment` 等四个 MCP 工具：任务落盘、输入摘要恢复、失败域记 blocking unknown 不冒充通过、未授权停在审批门零读取；store 根由 `PEA_TASK_STORE` 环境配置）；**受控执行闭环（WP0/3，0.7.0）已落地**：执行面授权根由 `PEA_AUTHORIZED_ROOTS` 环境注入（模型参数只能选根、不能建根，未配置即 `execution_roots_unconfigured` 整体关闭），审批事件与令牌签发分离（agent 的 Boolean 只是意图，`pea approve` / `pea protect` 交互确认才是审批）；`apply_plan` / `verify_output` / `compare_results` / `rollback` 四执行器全部接线（快照受管工作区 + 变换有效性门 + 独立三态验证 + 只读分析栈差分 + 仅限受管工作区的回滚），store 根由 `PEA_RUN_STORE` 环境配置；一句话保护命令 `pea protect <path>`（唯一人工决策 = 最终 y/N）与 `pea approve` 已交付；**JS canary 七步闭环**（`make verify-loop`，八条判据机械核验）与**研究记录合同**（`research.py` + schema：external_claim 恒定、离线全 unknown、accepted 需三项核对非 unknown）已落地。真正的 VMP/IR 后端与宿主确认 UI 尚未实现。

## 原型 1.0 demo（pea demo）

一条命令跑通防御工程闭环的垂直切片——**纯规划，零执行**：

```bash
PYTHONPATH=src python -m pea.cli demo \
  --request examples/protection-request.flutter-licensing.example.json \
  --project demo/canary-flutter-licensing \
  --out /tmp/pea-demo-out
```

流水线：授权门 → 只读侦察（`recon.py`）→ 能力族匹配（`attacksim.py`）→ 计划生成（`planner.py`）→ 攻击自测设计（`attacksim.py`）→ 证据账本（`ledger.py`）→ verified 门禁 → 报告（`report.py`）。

设计要点：

- **授权未确认 = 不读文件**：`authorization: not_confirmed` 时侦察、暴露面、自测全部不执行，退出码 4；
- **红线在合同里**：攻击自测方案的"产物只读 / 无绝对防护结论 / 工具失败≠成功"由 `attack-simulation.schema.json` 机械强制，生成器结构上无法违反；
- **攻击方法只引用不发挥**：每一步的 method 原文引用 `catalog/rea-capability-defense-map.json` 中的记录观察；
- **多域侦察同一模式**：产物清单 / 秘密扫描 / 字符串符号 / native 结构 / Dart 快照 / 构建集成五个域与 recon 共享只读遍历纪律，统一输出 `findings + coverage + unknowns`；不可用时记 unknown——拒绝而非假成功；秘密扫描只记模式名不记内容（`secret_value_redacted` 恒真）；候选门控把"许可待审不自动纳入计划"变成机械规则；
- **修复顺序按暴露层由高到低**：T1 一键工具放大层 → T4 算法逻辑层（`src/pea/tiers.py`），排序键是攻击者边际成本；攻击自测步骤与报告修复优先级同序，A1 永远是成本最低的暴露面；
- **verified 必然阻塞**：原型的账本里必有 blocking unknown（如"未发现构建产物"），`gate_for_verified` 机械执行"没有发现 ≠ 证明安全"；
- **确定性**：注入固定时间戳后 bundle 与报告逐字节可复现。

完整说明见 [`docs/Prototype-1.0-Demo-zh-CN.md`](docs/Prototype-1.0-Demo-zh-CN.md)。

## 部署姿态访谈（pea intake）

规划器的第一步不是搜候选，而是**先问清楚再给方案**。`pea intake` 会依次询问：分发方式、使用者、设备控制权、语言与架构、平台、是否离线、威胁模型、能否把秘密移出客户端、更新通道与兼容矩阵。据此推导部署姿态（`deployment_posture`）：

| posture | 触发条件（摘要） | 含义 |
| --- | --- | --- |
| `insufficient_information` | 必答项未答全 | 停在访谈门，不产出候选建议 |
| `controlled_environment_hardening` | 授权 + 仅自己/团队 + 掌握设备控制权 | 允许环境校验与密钥授权，但需显式批准，且三条护栏警告随行 |
| `no_trustworthy_client_signal` | 授权 + 他人可控设备（外部有限分发） | 本地信号不可信，不因检测命中而宣称安全 |
| `server_side_first` | 秘密可移出客户端（SaaS 或可联网） | 秘密与最终授权决策优先移到服务端 |
| `cost_raising_only` | 大规模离线分发 + 秘密不可移出 | 只能提高分析成本，须明示残余风险 |
| `platform_native_cleanup_first` | 解释型语言且未启用跨平台需求 | 先做平台原生清理，再考虑加固 |

三条不随 posture 变化的护栏（`src/pea/intake.py`）：

> 1. 客户端校验（反调试、环境门控、完整性探测）只能提高分析成本，不构成绝对保证；拥有设备完全控制权的对手面前没有可信的本地信号。
> 2. 能移出客户端的秘密和最终授权决策，应优先移到服务端或可信边界；混淆不是秘密存储。
> 3. 离线分发且秘密不可移出时，任何客户端内的授权material都可被提取，须明示残余风险。

非交互用法（CI / 脚本）：`pea intake --from request.json --format json`。必答项未答全时退出码非零，`intake_unknowns` 列出全部缺口；`blocking_questions` 必为 `intake_unknowns` 的子集（由测试强制）。

## 状态与限制

- 当前交付物是**只读侦察、保护规划、受控执行、验证与证据**（落地细节见下一行），不是可自动保护任意程序的生产级工具：**保护执行已落地（0.7.0）**——但只在 PEA 受管工作区内（目标项目的一份快照）执行已审阅的变换，用户工程目录只读不写；执行结果一律以三态门与前后差分报告，绝不因工具 exit 0 就声明"已保护"。
- 只读侦察已落地八个域（项目画像 / 产物清单 / 秘密扫描 / 字符串符号 / native 结构 / Dart 快照 / 构建集成，M3/D2 + 环境侦察 testbench，第三环）+ 候选门控与能力情报连接器；**L2 真实工兵层已启动**（合成形态产物 + `make verify-real` 七层三态验证，抓到 ELF32 phdr 偏移等真 bug；真实 Flutter 构建与 blutter 恢复率实测仍开放）；**M4 MCP 骨架已落地**（`tooleffects.py` 注册表生成 35 工具合同与副作用声明，31 工具经 `mcpserver.call_tool` 接线，短时一次性批准令牌绑定 plan/工件/参数/版本 digest——计划变化、过期、重放、路径越界全部拒绝）；**M5 账本工具化已落地**（6 个账本工具接 `ledger.py` 运行时：record/query/audit/gate/resolve/export，`audit_residual_unknowns` 随 verified 门显式返回，账本可跨进程持久化；WP0/3 执行器四件套已全部接线，`tool_not_wired` 从合同面消失）；**第三环已落地**（0.5.0：任务简报五要素 + 环境分层 T0–T4 + CLI 账本入口 + D7 战场反馈回路——破解包 intake 的 diff 事实 / 层归属 / 新增文件按 observation / inference / unknown 三级权威分离，响应计划仅服务端球门轮换）；**Phase 4 L1 已落地**（WP1：`pea mcp-server` 以官方 SDK 跑标准 MCP stdio 协议——`tools/list` 由 `TOOL_EFFECTS` 注册表与 `mcp/tool-schemas.json` 生成（不从函数签名推导），`tools/call` 先过 schema 校验再直达 `mcpserver.call_tool`（审批强制、授权根检查、命名拒绝原样复用，协议层零豁免）；契约门新增"审批要求必须能被协议面表达"门，并修掉 0.5.0 遗留的 `check_testbench` 等四处审批类别与协议面不一致）；**Phase 4 L2 已落地**（WP2 任务编排器：`taskrun.py` 14 步工作流 + 每任务一个目录的原子落盘 + 输入摘要恢复——done 且摘要未变的步骤不重跑，失败步骤从自身续跑；失败语义三条机械规则：账本=失败汇聚点（未完成域记 blocking unknown，严重度是编排规则不经域措辞）、报告=成功产物（输入不齐即 skipped-dep 不渲染残缺报告）、审批门停车（未授权零项目读取）；`pea.run_assessment` / `get_task` / `list_tasks` / `resume_task` 四个 MCP 工具 + `pea task` CLI 子命令族，store 根由 `PEA_TASK_STORE` 环境配置；bundle 九字段与 report_markdown 与 `pea demo` 逐字节等价（测试钉死））；规划器目前只做目录匹配与计划生成，不扫描真实产物之外的运行期行为。
- **演示场景（Flutter 授权 canary）是模拟而非范本**：它说明流水线如何运转，不对应真实项目。真实应用的判断依据是域扫描观察到的项目状态与能力映射地图级 `research_date`（2026-10-13，附“运行时确认”注记）的社区实时状态——详见 `demo/README.md` 的说明。
- 已通过网页核对 REA 上游、ShellVMP 和 FDartVMP 的部分官方公开 README/许可说明。**2026-10-13 已成功克隆 REA 上游源码**（`https://github.com/morluto/rea`，固定 commit `bb96afdbe32f5318d57fcb00099191c5a7712f53`，置于 `references/rea`，详见 `sources.md` 与 `/workspace/references/PROVENANCE.md`）；REA 的源码已就位但**行号级源码审计尚未执行**，故状态仍为源码已取得、审计待完成。ShellVMP 与 FDartVMP **未拉取**，仍停留在 `documentation_reviewed`，均未完成本地源码审计或测试复现。
- ShellVMP 与 FDartVMP 公开页面有 AGPL 与商业双授权线索。闭源集成、分发、第三方依赖或商业使用前，必须固定版本并审查完整许可证；当前目录不把它们作为自动执行依赖。
- 用户上传的原始 Skill ZIP 未发现独立 LICENSE 文件。它仅作为本次内部设计参考附件保留；公开发布原包或其衍生代码/文档前，须由权利人确认许可范围。
- PEA 不承诺绝对不可逆向，也不会将“工具崩溃/不可用/输出为空”解释为保护成功。任何防护强度声明都必须绑定版本、样本、测试方法、覆盖范围和限制。

## 项目原则

1. 先检索成熟方案，再决定是否自研。
2. 许可证、来源、平台和威胁模型为硬门槛，不以综合评分抵消。
3. 默认只读；执行前必须有显式授权、冻结计划、结构化 argv 和回滚路径。
4. 构建成功不等于语义正确；保护前后必须进行差分、兼容性、性能和产物检查。
5. 未验证内容标记 `unknown`，而不是猜测为 pass。

## 许可证

PEA 代码与 PEA 自行编写的设计文档统一适用单一 [`LICENSE`](LICENSE)（MIT，© 2026 haothtrteen）。第三方项目、第三方文档和用户上传的原始 Skill 不因被收录进 ZIP 而获得新的许可授权。
