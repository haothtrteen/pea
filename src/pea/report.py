"""Markdown report rendering for the prototype-1.0 demo.

The report's job is to make the *state of knowledge* legible: what was
observed, what was designed, what is still unknown, and what blocks calling
anything verified. It follows the walkthrough document's convention of
tagging every section as [实测] (measured from this run) or [设计] (design
output, not yet executed) so no reader can confuse a plan with a result.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pea.domains import DomainReport
from pea.recon import ReconResult
from pea.tiers import TIER_ATTACK_COST, TIER_LABELS, TIER_LEVERS


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    if not rows:
        return "（无）\n"
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def _section_request(request: Mapping[str, Any]) -> str:
    rows = [
        ("授权状态", str(request.get("authorization", "unknown"))),
        ("目标平台", ", ".join(request.get("targets", [])) or "unknown"),
        ("语言", ", ".join(request.get("languages", [])) or "unknown"),
        ("保护目标", ", ".join(request.get("goals", [])) or "unknown"),
        ("威胁模型", str(request.get("threat_model", "unknown"))),
        ("分发形态", f"{request.get('distribution', 'unknown')} / {request.get('audience', 'unknown')}"),
        ("设备受控性", str(request.get("device_control", "unknown"))),
        ("秘密可离开客户端", str(request.get("secret_can_leave_client", "unknown"))),
        ("执行模式", str(request.get("execution_mode", "plan_only"))),
    ]
    return _table(["项", "值"], rows)


def _section_domains(domains: Sequence[DomainReport]) -> str:
    """Render the multi-domain recon block: coverage, findings, unknowns.

    Findings are exposure-finding-shaped, so the rendering is generic; the
    detail table (redacted hits, artifact digests) is supplied by the
    orchestrator and stays as redacted as the domain produced it.
    """
    if not domains:
        return "（授权未确认，未运行多域侦察。）\n"
    parts: list[str] = []
    for domain in domains:
        parts.append(f"\n### {domain.label}（`{domain.key}`）\n\n")
        coverage = domain.coverage
        parts.append(f"- 覆盖度: **{coverage['state']}** — {coverage['scope']}\n")
        for omission in coverage.get("omissions", []):
            parts.append(f"- 未覆盖: {omission}\n")
        for finding in domain.findings:
            parts.append(
                f"- [{finding['status']}/{finding['severity']}] **{finding.get('title', finding['id'])}**"
                f" — {finding.get('summary', '')}\n"
            )
        if domain.detail_rows:
            parts.append(f"\n{domain.detail_title}\n\n")
            parts.append(_table(list(domain.detail_headers), [list(row) for row in domain.detail_rows]))
        if domain.unknowns:
            parts.append("\n仍未观察到的（不得当作已确认）：\n\n")
            for unknown in domain.unknowns:
                parts.append(f"- {unknown}\n")
    return "".join(parts)


def _section_recon(recon: ReconResult) -> str:
    parts: list[str] = []
    language_rows = [(obs.language, str(obs.file_count), ", ".join(obs.extensions)) for obs in recon.languages]
    parts.append(_table(["语言", "文件数", "扩展名"], language_rows))
    parts.append(f"- 构建系统: {', '.join(recon.build_systems) or 'unknown'}\n")
    parts.append(f"- 平台: {', '.join(recon.platforms) or 'unknown'}\n")
    parts.append(f"- 扫描文件数: {recon.files_scanned}\n")
    if recon.pattern_hits:
        hit_rows = [
            (h.path, h.pattern, str(h.line), str(h.count))
            for h in sorted(recon.pattern_hits, key=lambda h: (h.path, h.pattern))
        ]
        parts.append("\n授权相关模式命中（仅模式名、首行与次数，内容脱敏）：\n\n")
        parts.append(_table(["文件", "模式", "首行", "次数"], hit_rows))
    if recon.key_artifacts:
        artifact_rows = [
            (a.path, a.kind, str(a.size_bytes), (a.sha256[:12] + "…") if a.sha256 else "未计算")
            for a in recon.key_artifacts
        ]
        parts.append("\n关键资产：\n\n")
        parts.append(_table(["路径", "类型", "字节", "SHA-256"], artifact_rows))
    coverage = recon.coverage
    parts.append(f"\n覆盖度: **{coverage['state']}** — {coverage['scope']}\n")
    for omission in coverage.get("omissions", []):
        parts.append(f"- 未覆盖: {omission}\n")
    if recon.unknowns:
        parts.append("\n仍未观察到的（不得当作已确认）：\n\n")
        for unknown in recon.unknowns:
            parts.append(f"- {unknown}\n")
    return "".join(parts)


def _section_plan(plan: Mapping[str, Any]) -> str:
    parts: list[str] = []
    parts.append(f"- 策略: **{plan.get('strategy')}** · 状态: **{plan.get('status')}** · plan_id: `{plan.get('plan_id')}`\n")
    parts.append(f"- 部署姿态: {plan.get('deployment_posture')}（置信度 {plan.get('posture_confidence')}）\n")
    parts.append(f"- 姿态理由: {plan.get('posture_rationale')}\n")
    scores = plan.get("candidate_scores", [])
    if scores:
        score_rows = [(s["id"], str(s["score"]), ", ".join(s.get("basis", []))) for s in scores]
        parts.append("\n候选打分（performance 永不在列——无数据即不评分）：\n\n")
        parts.append(_table(["候选", "分数", "计分轴"], score_rows))
    excluded = plan.get("excluded_candidates", [])
    if excluded:
        excluded_rows = [(e["id"], e["reason"]) for e in excluded]
        parts.append("\n被硬门槛排除的候选：\n\n")
        parts.append(_table(["候选", "原因"], excluded_rows))
    if plan.get("risks"):
        parts.append("\n风险：\n\n")
        for risk in plan["risks"]:
            parts.append(f"- {risk}\n")
    if plan.get("verification_gates"):
        parts.append("\n验证门：\n\n")
        for gate in plan["verification_gates"]:
            parts.append(f"- {gate}\n")
    return "".join(parts)


def _section_attack(simulation: Mapping[str, Any]) -> str:
    parts: list[str] = []
    sandbox = simulation["sandbox"]
    parts.append(
        f"- 隔离: {sandbox['isolation']} · 只读产物: {sandbox['read_only_artifacts']} · "
        f"网络: {sandbox['network']} · 时间预算: {sandbox['time_budget_minutes']} 分钟\n"
    )
    if sandbox.get("device"):
        parts.append(f"- 设备: {sandbox['device']}\n")
    artifact_rows = [
        (a["path"], a["role"], (a["sha256"][:12] + "…") if a.get("sha256") else "未计算（产物未构建）")
        for a in simulation["target_artifacts"]
    ]
    parts.append("\n参与对比的产物：\n\n")
    parts.append(_table(["路径", "角色", "SHA-256"], artifact_rows))
    step_rows = [
        (
            s["step_id"],
            s["capability_family"],
            s["objective"],
            s["expected_observation"],
            s["failure_meaning"],
            s["applies_to"],
            str(s.get("time_budget_minutes", "-")),
        )
        for s in simulation["capability_steps"]
    ]
    parts.append("\n攻击步骤（每步溯源到能力映射的记录观察，非模型发挥）：\n\n")
    parts.append(
        _table(
            ["步骤", "能力族", "目标", "预期观察", "失败语义", "适用范围", "预算(分)"],
            step_rows,
        )
    )
    criteria = simulation["success_criteria"]
    parts.append(
        f"\n成功判据: 比较={criteria['comparison']} · 解释规则=**{criteria['interpretation_rule']}**\n\n"
        f"> {criteria.get('budget_rule', '')}\n"
    )
    if simulation.get("limitations"):
        parts.append("\n局限：\n\n")
        for limitation in simulation["limitations"]:
            parts.append(f"- {limitation}\n")
    return "".join(parts)


def _section_ledger(audit: Mapping[str, Any], gate_blockers: Sequence[str]) -> str:
    parts: list[str] = []
    parts.append(
        _table(
            ["总数", "open", "resolved", "wont_resolve", "blocking"],
            [
                (
                    str(audit["total"]),
                    str(audit["open"]),
                    str(audit["resolved"]),
                    str(audit["wont_resolve"]),
                    str(len(audit["blocking"])),
                )
            ],
        )
    )
    if audit["blocking"]:
        parts.append("\n阻塞中的 unknown（verified 门前必须消解）：\n\n")
        for record in audit["blocking"]:
            parts.append(f"- `{record['unknown_id']}` [{record['domain']}] {record['question']}\n")
    if gate_blockers:
        parts.append("\n门禁结论: **不得标 verified**\n\n")
        for blocker in gate_blockers:
            parts.append(f"- {blocker}\n")
    else:
        parts.append("\n门禁结论: 无阻塞项（本原型中不会出现——侦察与自测未执行前，账本必有 blocking 项）\n")
    return "".join(parts)


def _section_remediation(remediation_groups: Sequence[tuple[str, Sequence[str]]]) -> str:
    """Repair order, highest exposure first - the founding principle, rendered.

    Each group is ``(tier, actions)``; the caller has already ordered the
    groups by tier. The ordering key is stated in the section itself so no
    reader mistakes it for an editorial preference: it is the attacker's
    marginal cost of reaching that layer.
    """
    if not remediation_groups:
        return "（授权未确认，未生成修复优先级。）\n"
    parts: list[str] = [
        "> 排序依据：攻击者到达该层暴露面的**边际成本**——成本越低越先修。"
        "T1 是一键逆向工具放大的暴露面（成本≈0），所以永远排第一；"
        "针对工具的修复没有偏离“针对暴露面”的初心——工具层正是暴露面中最便宜抵达的部分。\n\n"
    ]
    for tier, actions in remediation_groups:
        parts.append(f"### {TIER_LABELS[tier]}\n\n")
        parts.append(f"- 攻击成本: {TIER_ATTACK_COST[tier]}\n")
        parts.append(f"- 修复杠杆: {TIER_LEVERS[tier]}\n\n")
        for action in actions:
            parts.append(f"- {action}\n")
        parts.append("\n")
    return "".join(parts)


def render_markdown(
    *,
    request: Mapping[str, Any],
    plan: Mapping[str, Any],
    recon: ReconResult | None,
    attack_simulation: Mapping[str, Any] | None,
    ledger_audit: Mapping[str, Any],
    gate_blockers: Sequence[str],
    generated_at: str,
    demo_version: str,
    remediation_groups: Sequence[tuple[str, Sequence[str]]] = (),
    domains: Sequence[DomainReport] = (),
) -> str:
    """Render the full demo report. All inputs are already-computed results."""
    authorized = recon is not None
    parts: list[str] = [
        f"# PEA 原型 {demo_version} Demo 报告\n",
        f"生成时间: {generated_at} · 模式: **plan_only（纯规划，未执行任何保护变换）**\n",
        "\n> 性质声明：本报告由纯函数流水线生成——只读侦察 + 目录匹配 + 计划生成 + 攻击自测设计 + 证据账本。",
        "没有任何保护工具被安装或运行；攻击自测方案是*设计*，不是执行结果。",
        "章节标注：[实测] = 本次运行的观察；[设计] = 尚未执行的设计输出。\n",
        "\n## 0. 一页结论\n",
    ]
    plan_status = plan.get("status", "unknown")
    steps = len(attack_simulation.get("capability_steps", [])) if attack_simulation else 0
    conclusion_rows = [
        ("授权状态", "已确认" if authorized else "**未确认——未执行任何侦察**"),
        ("计划状态", f"**{plan_status}**"),
        ("攻击自测步骤（设计）", str(steps) if authorized else "未生成"),
        ("多域侦察", ", ".join(f"{d.label}:{d.coverage['state']}" for d in domains) if authorized else "未运行"),
        ("证据账本 unknown", f"{ledger_audit['open']} open / {len(ledger_audit['blocking'])} blocking"),
        ("verified 门禁", "**阻塞**" if gate_blockers else "通过"),
    ]
    parts.append(_table(["检查项", "结果"], conclusion_rows))
    parts.append("\n## 1. 请求与部署姿态 [实测]\n\n")
    parts.append(_section_request(request))
    parts.append("\n## 2. 项目画像与多域侦察 [实测]\n\n")
    if authorized and recon is not None:
        parts.append(_section_recon(recon))
        parts.append("\n### 多域侦察（产物清单 / 秘密扫描 / 字符串符号 / native 结构 / Dart 快照 / 构建集成 / 候选门控 / 能力情报）\n")
        parts.append(_section_domains(domains))
    else:
        parts.append("授权未确认，未执行侦察。PEA 在所有权确认前不读取项目文件。\n")
        parts.append(_section_domains(()))
    parts.append("\n## 3. 保护计划 [设计]\n\n")
    parts.append(_section_plan(plan))
    parts.append("\n## 4. 攻击自测方案 [设计]\n\n")
    if authorized and attack_simulation is not None:
        parts.append(_section_attack(attack_simulation))
    else:
        parts.append("授权未确认，未设计攻击自测方案。\n")
    parts.append("\n## 5. 修复优先级（由高到低）[设计]\n\n")
    parts.append(_section_remediation(remediation_groups))
    parts.append("\n## 6. 证据账本与 unknown 门禁 [实测]\n\n")
    parts.append(_section_ledger(ledger_audit, gate_blockers))
    parts.append("\n## 7. 下一步\n\n")
    if not authorized:
        parts.append("1. 确认项目所有权或获取书面授权；\n2. 重新运行 demo。\n")
    else:
        next_steps = [
            "消解账本中的 blocking unknown（补答 intake、补齐侦察覆盖或构建 release 产物）",
            "人工审阅第 3 节计划中的候选与排除理由，确认函数/模块范围",
            "按第 4 节方案在一次性沙盒中执行攻击自测（工具用户自备），把观察证据回填账本",
            "证据齐备且门禁通过后，才谈得上执行保护变换与 verified 结论",
        ]
        parts.extend(f"{i}. {step}\n" for i, step in enumerate(next_steps, start=1))
    parts.append(
        f"\n---\n\nPEA 原型 {demo_version} · 防御工程闭环 demo · "
        "所有结论可随输入复现（确定性输出，注入时间戳后逐字节一致）\n"
    )
    return "".join(parts)
