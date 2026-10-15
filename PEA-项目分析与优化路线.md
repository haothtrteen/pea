# PEA 项目分析与可落地优化路线

> 分析对象：`PEA-Landing-Page.zip`（落地页 + 内嵌 `PEA-Design-Kit-v0.2.2.zip`）
> 分析日期：2026-10-13 ｜ 分析环境：Ubuntu 22.04 / Python 3.11.1
> 结论一句话（**2026-10-13 时点**；其后版本已逐项回填，见下"历史分析"块）：**这是一个"设计规格 + 数据合同 + 离线规划器原型"的早期仓库，文档质量远高于工程实现质量；短板集中在"契约未被代码强制""打分引擎形同虚设""零工程化底座"三点上，且这三点都可以在当前沙箱内直接补齐。**


> **历史分析（针对 v0.2.2 快照）—— 请勿按本文判断项目现状**：本文写于 2026-10-13，分析对象是 0.2.2 期的仓库快照（当时只有 `pea_planner/{cli.py,planner.py}` 两个实现文件、8 个单元测试）。文中“实际代码只有……”“完全没引用”“恒为 1.0”等一切“现状”叙述都指**该时点**，且**均已被后续版本取代**：
> - P0（契约未被代码强制、打分维度为假）→ 0.3.0 起入口 `validate_or_raise` 强校验 + 真实打分轴（`planner.SCORE_WEIGHTS`）；
> - P1（工程化底座 / 测试 / 匹配逻辑）→ 0.4.0 起 `make check` 全量门禁（现 **2451 passed + 36 契约门**）、CI 双 job；
> - 只读画像与暴露面扫描 → M3 八个只读域；
> - MCP 骨架与审批令牌 → M4/M5 + WP1/WP2（35 工具全接线）；
> - 受控执行与第一条真实闭环 → **0.7.0**（`pea protect`、执行器四件套、JS canary 八条判据）；
> - 仍未实现（如实保留）：在线研究连接器、真正的 IR/VMP 后端、宿主确认 UI、多平台执行。
>
> 本文保留为**历史记录**，用于追溯优化路线的来龙去脉；当前状态请看 `README_zh.md`、`CHANGELOG.md` 与 `docs/Prototype-1.0-Demo-zh-CN.md`。

---

## 一、项目概览

外层是一个自包含单页官网，内层 `downloads/` 里装的是真正的工程主体（PEA Design Kit）。

| 层 | 内容 | 规模 |
|---|---|---|
| 官网 | `index.html`（自包含：内联 CSS/JS，无 CDN/无网络请求） | 353 行 / 44 KB |
| 说明 | `README.md`、`DESIGN-MAPPING.md`、`NOTICE.md`、`LICENSE.txt` | — |
| Design Kit | 43 个文件，含 `pea_planner/`（原型）、`schemas/`（8 个）、`catalog/`、`mcp/`、`skills/`（4 个）、`docs/`（13 篇）、`examples/`、`tests/` | 1.3 MB |

**PEA 的定位**：一个"保护工程编排"的 Agent 工具设计——检索成熟保护方案 → 识别自身软件暴露面 → 生成可审阅计划 → 经审批受控执行 → 用测试证据验证。它明确拒绝第三方授权绕过、密钥窃取等非法用途，并把"未验证"强制标为 `unknown`，不以构建成功冒充安全成功。这套**安全与合规理念在文档层面做得相当扎实**，是本项目最值得保留的资产。

### 目录结构对照（文档承诺 vs 实际）

`docs/PEA-Implementation-Plan-zh-CN.md` 里画的目标结构是 `src/pea/{api,service,schemas,planner,adapters,execution,...}`，但**实际代码只有 `pea_planner/{cli.py,planner.py}` 两个文件**。这本身不是错（原型阶段），但意味着任何新开发者按文档找代码会扑空——需要在 README 里显式标注"当前为 PoC 布局，目标布局见 X"。

---

## 二、实际验证结果（我在沙箱里跑过的）

| 验证项 | 命令/方法 | 结果 |
|---|---|---|
| 单元测试 | `python -m unittest discover -s tests -v` | ✅ 8/8 通过 |
| CLI 冒烟 | `catalog` / `search` / `plan` | ✅ 均正常，`plan` 输出 `strategy=existing_tool status=needs_user_review` |
| Schema 一致性 | jsonschema 校验 8 条目录条目 | ✅ 8/8 合规 |
| 示例与 Schema 匹配 | 校验 `protection-request/plan.example.json` | ✅ 0 错误 |
| 文档产物 | `pdfinfo` | ✅ PDF 11 页，与更新说明一致 |
| **非法 goal 输入** | `goals:["totally_invalid_goal"]` | ❌ **被静默接受**（分析时点）——**已修复**：入口校验直接拒绝并列出违规路径 |
| **缺字段/空 targets** | 去掉 `project_path`、`targets:[]` | ❌ **被静默接受**（分析时点）——**已修复**：同上 |
| **打分是否区分候选** | 构造功能匹配度截然不同的两条候选 | ❌ **两者得分完全相同（均 90.0）**（分析时点）——**已修复**：打分按 `SCORE_WEIGHTS` 的真实轴计算，`basis` 逐项可查 |

后三条是本次分析发现的**真实缺陷**，也是优化价值最高的地方；三条均已修复（见文首历史分析说明）。

---

## 三、优化点（按优先级）

### P0 — 契约没有被代码强制（数据合同形同虚设）

项目花了大量精力写 JSON Schema，但 `planner.py` **完全没引用 `schemas/`**，只做了最低限度的手工键检查（`load_catalog` 里核对 8 个必填键）。后果：

- `goals` 里塞非法值、`targets` 为空、`project_path` 缺失，全都被当合法输入处理；
- Schema 与实现会随时间静默漂移，而"Schema 是单一真源"正是该项目自己宣称的原则；
- `additionalProperties:false` 之类的严格性在运行时完全没有生效。

**建议**：引入 `jsonschema`（或 `fastjsonschema`），在 `build_plan` / `load_catalog` 入口做 fail-fast 校验，错误码区分"输入非法(2)"与"策略阻断(4)"（当前两者都混在 exit=2/4 里）。工作量：**0.5 天**。

### P0 — 策略引擎的打分维度是假的

`candidate_score()` 里 `fit`、`platform_fit` 恒为 `1.0`，`build_integration`、`performance_fit` 恒为 `0.5`——也就是说架构文档第 8 节承诺的"功能匹配 25% + 平台适配 20%"两个最大权重维度**根本没有计算**。得分实际只由 `maintenance / license / trust_level` 三项（合计 40 分权重）决定，且被硬编码常数推高到固定值。

实测证据：两条功能匹配度完全不同的候选，得分都是 90.0，排序无意义。

**建议**：让评分真正读取 `request.goals ∩ entry.capabilities` 的重合度、`request.targets` 与 `entry.targets` 的覆盖度、以及 `performance_budget_percent` 约束；并在计划输出里附**逐维度得分 + 证据缺口**（文档已如此要求，只是没实现）。工作量：**1 天**。

### P1 — `search_catalog` 的目标匹配逻辑有歧义

```python
target_match = "all" in entry_targets or "unknown" not in entry_targets and bool(normalized.intersection(entry_targets))
```

混合了 `or/and` 且没有括号，实际语义是 `A or (B and C)`。从注释和上下文看，作者想表达的是"目标含 `unknown` 的条目应谨慎匹配"，但现写法会让含 `unknown` 的条目**只能靠 `all` 命中**，行为难以预期。建议显式拆成命名函数 + 加注释 + 补测试。工作量：**0.5 天**。

### P1 — 零工程化底座

仓库**没有** `pyproject.toml` / `requirements.txt` / `.github/workflows` / lint / type check / 打包配置。README 要求用户"在项目根目录手动跑 `python -m pea_planner.cli`"，无法 `pip install`，也无法 CI。

**建议**：补齐 `pyproject.toml`（`src/` 布局 + `[project.scripts] pea = ...`）、`pytest`、`ruff`、`mypy`、GitHub Actions（跑测试 + Schema 一致性校验 + 文档链接检查）。工作量：**1 天**。

### P1 — 测试覆盖偏薄

现有 8 个测试只覆盖"正常路径 + 2 个阻断分支"，缺失：CLI 端到端测试、Schema 负例、路径越界/symlink 逃逸（文档第 15 节列为核心验收项却无测试）、打分排序正确性、`search --include-research` 语义。工作量：**1 天**。

### P2 — 文档信息架构与版本散落

文档总量 1386 行、质量很高，但存在可维护性隐患：版本号（0.2.2 / 0.2.1 / 0.2.0）散落在多个文件；`Threat-Model` 标题写的是 v0.2.0 而项目已到 0.2.2；用户上传的 `skill-lang-vmp-guide-original.zip` **无独立 LICENSE**，目前"原样保留"，需要在 NOTICE 里更醒目地标注"未经权利人确认不得公开再分发"。工作量：**0.5 天**。

### P2 — 落地页的 SEO 与前端工程

页面本身做得不错（响应式、深浅色、`prefers-reduced-motion`、ARIA、无外部请求）。可优化点：

- 缺 `og:image` / `twitter:card` / `<link rel="canonical">` / favicon / JSON-LD 结构化数据；
- 纯内联 44KB，无缓存策略与构建流程，后续维护靠手改大文件；
- 下载包与页面是"手工对齐"版本号，容易漂移，建议由构建脚本注入版本。

工作量：**1 天**。

---

## 四、可在当前环境落地的开发路线

> 判定标准：**只要 Python 3.11 + Node + 联网 pip 就能在沙箱内完成**的算"当前可落地"；需要真实保护器二进制、真机、特定网络资源的算"需外部条件"，本期只做脚手架 + fixture/mock。

### 里程碑 M0 — 工程化基座（当前可落地，约 2 天）

| 交付物 | 验收条件 |
|---|---|
| `pyproject.toml` + `src/pea/` 布局 + `pea` 命令入口 | `pip install -e .` 后 `pea catalog` 可跑 |
| `pytest` 迁移 + `ruff` + `mypy` | CI 全绿，类型检查通过 |
| GitHub Actions：测试 / Schema 一致性 / 文档链接存活 | PR 触发即跑，失败阻断合并 |

### 里程碑 M1 — 契约优先（当前可落地，约 2 天）

把 `schemas/*.json` 变成**唯一真源**：入口强校验 `protection-request`、`catalog-entry`；非法输入 fail-fast 并返回结构化错误码；用 Schema 自动生成 CLI `--help` 与示例骨架；加一组"正例通过 / 负例被拒"的契约测试。**验收：本次发现的 3 个静默接受缺陷全部变成显式拒绝。**

### 里程碑 M2 — 可解释的决策引擎（当前可落地，约 3 天）

重写 `planner.py`：真实计算功能匹配度、平台覆盖度、性能预算约束；输出**逐维度得分 + 证据缺口 + 排除原因**（对齐架构文档第 8 节）；把 `locals()` 反模式改成显式变量；补排序/门控单元测试。**验收：两条功能匹配度不同的候选必须得到不同得分与不同排序。**

### 里程碑 M3 — 只读画像与暴露面扫描（当前可落地，约 4 天）

实现文档 Phase 1 承诺的只读能力：目录/构建清单解析、产物 manifest（相对路径 + SHA-256 + 类型）、符号/字符串/source-map/疑似密钥检测。硬性要求：**默认不读 `.env`/私钥/凭据**；秘密命中只回显类型+位置+脱敏摘要；路径穿越、symlink 逃逸、超大文件、异常编码全部有测试；用 canary fixture 验证命中率与误报。**这是本项目最有实际价值、且完全无高副作用风险的一块。**

### 里程碑 M4 — MCP 服务与审批门（当前可落地，约 4 天）

按 `mcp/tool-contract.json` 落一个 MCP server 骨架，与 CLI **共用同一 service layer**（文档明确要求，当前两者尚未拆分）；实现一次性审批令牌：绑定 `plan_digest` + 工件摘要 + 工具版本 + 路径范围，支持过期/重放/跨目录复用拒绝；`apply_plan` 未获批准必须失败。沙箱内可用 mock adapter 验证门控逻辑，无需真实保护器。

### 里程碑 M5 — 报告与证据账本（当前可落地，约 2 天）

SQLite/JSON 证据账本 + 脱敏 Markdown/JSON 报告，实现"用 plan/run ID 可重建该次运行"；确保报告不含 canary 秘密原文。对齐架构文档附录 A 的报告字段。

### 里程碑 M6 — 落地页现代化（当前可落地，约 1 天）

补 `og:image`、canonical、favicon、JSON-LD；把内联 CSS/JS 拆成源文件 + 构建脚本注入版本号，使下载包与页面版本自动对齐。

### 需外部条件（本期只留接口与 fixture，不做实作）

- 真实保护器 adapter（需固定版本二进制、许可审查、真机/真构建环境）；
- 线上研究连接器（需受控网络策略与域名 allowlist）；
- 受限 IR/VM 后端（文档自己也把它列为 Phase 7 独立分支，**不应作为近期目标**）。

---

## 五、优先级总表

| 优先级 | 事项 | 影响 | 成本 | 当前可落地 |
|---|---|---|---|---|
| P0 | 入口强制 JSON Schema 校验 | 高（正确性/安全前提） | 0.5 天 | ✅ |
| P0 | 重写打分引擎，真实计算维度 | 高（核心输出可信度） | 1 天 | ✅ |
| P1 | 工程化底座 + CI | 高（可维护性） | 2 天 | ✅ |
| P1 | 补齐测试（含路径/symlink/负例） | 高 | 1 天 | ✅ |
| P1 | 修正 `search_catalog` 匹配逻辑 | 中 | 0.5 天 | ✅ |
| P2 | 文档版本统一 + 许可风险标注 | 中 | 0.5 天 | ✅ |
| P2 | 落地页 SEO/构建流程 | 中 | 1 天 | ✅ |
| — | 只读 Profiler/Exposure Scanner | 很高（真实价值） | 4 天 | ✅ |
| — | MCP 骨架 + 审批令牌 | 高 | 4 天 | ✅ |
| — | 真实保护器 adapter / IR-VM 后端 | 高 | 大 | ⚠️ 半落地：真实保护器 adapter 已落地（`javascript-obfuscator`@5.9.0，0.7.0）；IR/VMP 后端仍待外部条件 |

---

## 六、风险与边界提醒

1. **合规优先于功能**：`ShellVMP` / `FDartVMP` 为 AGPL-3.0 + 商业双授权，闭源集成前必须做项目级许可审查；用户上传的 Skill 原始包**无 LICENSE**，公开再分发前须由权利人确认。这些应在 NOTICE 中前置警示，而不是埋在文档中段。
2. **保持"默认只读 + 显式审批"的架构红线**：M3/M4 落地时最容易走偏的就是"顺手把执行也做了"，务必让 `apply_plan` 严格依赖一次性令牌。
3. **不要把 `unknown` 转成 `pass`**：这是本项目自己定的第 5 条原则，也是打分/报告改动时最容易被无意破坏的语义。

---

## 附：本次分析产出

- 已在沙箱内完整解压、运行测试、跑通 CLI、做 Schema 一致性校验与边界探测；
- 发现的 3 个可复现缺陷（静默接受非法输入 ×2、打分不区分候选 ×1）均附实测证据，可直接转成 M0/M1/M2 的验收用例。
