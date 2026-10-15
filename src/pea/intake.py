"""Structured intake for PEA protection planning.

Before any catalog matching happens, PEA must establish *who will run the
software, where, under whose control, and what is actually worth protecting*.
The architecture spec puts this first (workflow steps 1-5) and the
``pea-protection-planner`` skill lists it as required input, but the original
prototype jumped straight to catalog search. This module closes that gap.

Design rules encoded here, taken from the project's own security policy:

* Client-side checks (anti-debug, environment gating, integrity probes) **raise
  analysis cost; they never guarantee secrecy**. They are never auto-enabled.
* A fully attacker-controlled device has no trustworthy client-side signal.
* Secrets that can leave the client should leave the client.
* Anything not answered stays ``unknown`` and is reported as such - it is never
  silently filled in.

Everything here is a pure function: no IO, no network, no execution.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Question set
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Question:
    """One intake question.

    ``required_when`` decides whether the question is *currently relevant*; it
    is evaluated against the answers collected so far. Questions that are not
    yet relevant are not asked - asking everything up front is how intake
    questionnaires become noise.
    """

    id: str
    prompt: str
    why: str
    choices: tuple[str, ...] = ()
    free_text: bool = False
    required_when: Callable[[Mapping[str, Any]], bool] = lambda a: True
    multi: bool = False
    optional: bool = False
    """When True, "no answer" is itself a valid answer and does not block intake."""


def _always(_: Mapping[str, Any]) -> bool:
    return True


def _authorized(answers: Mapping[str, Any]) -> bool:
    return answers.get("authorization") in {"owner", "written_authorization"}


def _distributed_to_others(answers: Mapping[str, Any]) -> bool:
    return answers.get("distribution") in {
        "internal_uncontrolled",
        "external_limited",
        "mass_offline",
        "saas",
    }


def _mass_or_multi_platform(answers: Mapping[str, Any]) -> bool:
    platforms = answers.get("platforms") or []
    return answers.get("distribution") == "mass_offline" or len(platforms) > 1


def _needs_client_secret_decision(answers: Mapping[str, Any]) -> bool:
    """Only worth asking about moving logic out when it could actually move."""
    if not _authorized(answers):
        return False
    return answers.get("distribution") != "mass_offline" or answers.get("offline_required") is False


def _offline_distribution(answers: Mapping[str, Any]) -> bool:
    return answers.get("distribution") == "mass_offline"


QUESTIONS: tuple[Question, ...] = (
    Question(
        id="authorization",
        prompt="你对这个项目有什么权利？（owner / written_authorization / not_confirmed）",
        why="授权未确认时，PEA 只能做一般性设计，不能进入任何保护操作。",
        choices=("owner", "written_authorization", "not_confirmed"),
    ),
    Question(
        id="assets",
        prompt="要保护的具体是什么？（算法 / 授权决策 / 密钥材料 / 客户端资源 / 构建发布链路）",
        why="资产决定威胁模型；不能仅凭函数名自动决定“该保护它”。",
        free_text=True,
        required_when=_authorized,
    ),
    Question(
        id="distribution",
        prompt="软件怎么分发、给谁用？（internal_controlled / internal_uncontrolled / external_limited / mass_offline / saas）",
        why=(
            "分发方式决定可信边界的强度。内部受控环境里“设备大概率可信”可以作为一种假设；"
            "大规模离线分发时，客户端完全在攻击者手里。"
        ),
        choices=(
            "internal_controlled",
            "internal_uncontrolled",
            "external_limited",
            "mass_offline",
            "saas",
        ),
        required_when=_authorized,
    ),
    Question(
        id="audience",
        prompt="最终使用对象是谁？（self / team / partners / public）",
        why="使用对象影响误报成本：给同事用的工具被环境校验挡住，代价是真实的生产力损失。",
        choices=("self", "team", "partners", "public"),
        required_when=_authorized,
    ),
    Question(
        id="device_control",
        prompt="运行设备的受控程度？（managed_devices / known_devices / unknown_devices / attacker_controlled）",
        why=(
            "设备是否受控决定客户端信号有多少可信度。attacker_controlled 下任何本地检测都只是成本信号，"
            "不能作为信任根。"
        ),
        choices=("managed_devices", "known_devices", "unknown_devices", "attacker_controlled"),
        required_when=_distributed_to_others,
    ),
    Question(
        id="platforms",
        prompt="目标平台与架构？（可多选，如 android-arm64、windows-x64、linux-x64、macos-arm64）",
        why="平台差异必须显式化；同一措施在不同 ABI / 运行时 / 授权模式下不可互推。",
        free_text=True,
        multi=True,
        required_when=_authorized,
    ),
    Question(
        id="languages",
        prompt="语言与运行时精确版本？（如 dart 3.5 / python 3.11 / c++17）",
        why="保护措施与解释器 / 编译器版本强相关，跨版本结论不能迁移。",
        free_text=True,
        multi=True,
        required_when=_authorized,
    ),
    Question(
        id="offline_required",
        prompt="是否必须完全离线运行？（true / false）",
        why="离线约束直接决定“把秘密移到服务端”这条路是否走得通。",
        choices=("true", "false"),
        required_when=_authorized,
    ),
    Question(
        id="update_channel",
        prompt="有没有可信更新通道？（none / signed_updates / app_store / server_controlled）",
        why="签名与可信更新是防篡改的首选手段，优先级高于本地完整性检测。",
        choices=("none", "signed_updates", "app_store", "server_controlled"),
        required_when=_authorized,
    ),
    Question(
        id="cross_platform_requirements",
        prompt="多平台各自的行为一致性要求是什么？",
        why=(
            "大规模离线分发 + 多平台时，兼容矩阵本身就是主要风险；"
            "必须先确定每个平台的可接受差异，再选保护措施。"
        ),
        free_text=True,
        required_when=_mass_or_multi_platform,
    ),
    Question(
        id="secret_can_leave_client",
        prompt="高价值逻辑能否移出客户端（服务端 / 可信进程 / 硬件安全模块）？（yes / no / unknown）",
        why="能移出的秘密不应留在客户端；混淆不是秘密存储。",
        choices=("yes", "no", "unknown"),
        required_when=_needs_client_secret_decision,
    ),
    Question(
        id="threat_model",
        prompt="假想的对手是谁？（casual_static_analysis / competent_reverse_engineer / runtime_control / mixed / unspecified）",
        why="没有明确攻击假设时，无法说明任何保护措施的实际影响。",
        choices=(
            "casual_static_analysis",
            "competent_reverse_engineer",
            "runtime_control",
            "mixed",
            "unspecified",
        ),
        required_when=_authorized,
    ),
    Question(
        id="performance_budget_percent",
        prompt="性能与体积预算（百分比，可空）？",
        why="预算超支不是可以靠综合评分抵消的软性指标。",
        free_text=True,
        required_when=_authorized,
        optional=True,
    ),
    Question(
        id="test_baseline",
        prompt="现有回归测试覆盖情况？（full / partial / none）",
        why="没有测试基线就无法验证保护前后语义一致，PEA 不会保护无法验证的关键逻辑。",
        choices=("full", "partial", "none"),
        required_when=_authorized,
    ),
    Question(
        id="allowed_spdx_licenses",
        prompt="可接受的 SPDX 许可证（可空表示未限制，但未知许可仍会被门控）？",
        why="许可证是硬门槛，不能因为候选评分高而进入生产执行。",
        free_text=True,
        multi=True,
        required_when=_authorized,
        optional=True,
    ),
    Question(
        id="allow_network",
        prompt="是否允许 PEA 联网检索官方源？（true / false）",
        why="联网检索与下载执行是两个独立权限，默认关闭。",
        choices=("true", "false"),
        required_when=_authorized,
        optional=True,
    ),
)


# ---------------------------------------------------------------------------
# Derived profile
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeploymentProfile:
    """What the intake answers imply about the trust boundary."""

    answers: Mapping[str, Any]
    unknowns: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    posture: str = "insufficient_information"
    posture_rationale: str = ""
    recommended_goals: tuple[str, ...] = ()
    hard_gate_checks: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    client_side_hardening_allowed: bool = False
    client_side_hardening_requires_approval: bool = True
    confidence: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "posture": self.posture,
            "posture_rationale": self.posture_rationale,
            "recommended_goals": list(self.recommended_goals),
            "hard_gate_checks": list(self.hard_gate_checks),
            "warnings": list(self.warnings),
            "client_side_hardening_allowed": self.client_side_hardening_allowed,
            "client_side_hardening_requires_approval": self.client_side_hardening_requires_approval,
            "confidence": self.confidence,
            "unknowns": list(self.unknowns),
            "assumptions": list(self.assumptions),
        }


# The one sentence that must survive every refactor of this module.
_CLIENT_SIDE_LIMIT = (
    "客户端校验（反调试、环境门控、完整性探测）只能提高分析成本，"
    "不构成绝对保证；拥有设备完全控制权的对手面前没有可信的本地信号。"
)

_SECRET_FIRST = "能移出客户端的秘密和最终授权决策，应优先移到服务端或可信边界；混淆不是秘密存储。"


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence):
        return [str(v) for v in value]
    return [str(value)]


def pending_questions(answers: Mapping[str, Any], *, include_optional: bool = True) -> list[Question]:
    """Questions that are still unanswered *and* currently relevant, in order.

    ``include_optional=False`` drops questions where "no answer" is itself a
    valid answer (budget, licence list, network policy), which is what a caller
    uses to decide whether intake can proceed.
    """
    out: list[Question] = []
    for question in QUESTIONS:
        if not include_optional and question.optional:
            continue
        if question.id in answers and answers[question.id] not in (None, "", []):
            continue
        try:
            relevant = question.required_when(answers)
        except Exception:  # a malformed partial answer must not crash intake
            relevant = False
        if relevant:
            out.append(question)
    return out


def blocking_questions(answers: Mapping[str, Any]) -> list[Question]:
    """Questions that must be answered before a plan can leave intake."""
    return [q for q in pending_questions(answers, include_optional=False)]


def derive_profile(answers: Mapping[str, Any]) -> DeploymentProfile:
    """Turn intake answers into a deployment profile and a protection posture.

    The posture is a *starting recommendation*, never an automatic action. Every
    posture carries its own warnings and hard gates so that a caller cannot
    quietly drop them.
    """
    unknowns: list[str] = []
    assumptions: list[str] = []
    warnings: list[str] = []

    authorization = answers.get("authorization")
    if authorization not in {"owner", "written_authorization"}:
        return DeploymentProfile(
            answers=answers,
            unknowns=tuple(q.id for q in QUESTIONS if q.id != "authorization"),
            posture="insufficient_information",
            posture_rationale="所有权/授权未确认；只能继续一般性设计。",
            hard_gate_checks=("确认项目所有权或书面授权",),
            # The limit sentence is attached to *every* profile, including this one:
            # a caller must never be able to obtain a posture without it.
            warnings=(_CLIENT_SIDE_LIMIT, "授权未确认前不得执行任何有副作用的保护操作。"),
            confidence="unknown",
        )

    distribution = answers.get("distribution")
    device_control = answers.get("device_control")
    offline = _as_bool(answers.get("offline_required"))
    secret_can_leave = answers.get("secret_can_leave_client")
    threat_model = answers.get("threat_model")
    test_baseline = answers.get("test_baseline")
    update_channel = answers.get("update_channel")
    platforms = _as_list(answers.get("platforms"))
    audience = answers.get("audience")

    # ---- what is still missing -------------------------------------------
    # These mirror the relevance rules on the questions themselves, so "PEA
    # insists on asking" and "PEA reports it unknown" can never drift apart.
    # (Enforced by tests/test_intake.py::test_blocking_questions_are_always_reported_as_unknowns.)
    if not answers.get("assets"):
        unknowns.append("assets")
    if not platforms:
        unknowns.append("platforms")
    if not _as_list(answers.get("languages")):
        unknowns.append("languages")
    if not distribution:
        unknowns.append("distribution")
    if not audience:
        unknowns.append("audience")
    if not update_channel:
        unknowns.append("update_channel")
    if distribution in {"internal_uncontrolled", "external_limited", "mass_offline", "saas"} and not device_control:
        unknowns.append("device_control")
    if offline is None:
        unknowns.append("offline_required")
    if not threat_model or threat_model == "unspecified":
        unknowns.append("threat_model")
    if not test_baseline:
        unknowns.append("test_baseline")
    if _needs_client_secret_decision(answers) and secret_can_leave in (None, "unknown"):
        unknowns.append("secret_can_leave_client")
    if _mass_or_multi_platform(answers) and not answers.get("cross_platform_requirements"):
        unknowns.append("cross_platform_requirements")

    # ---- assumptions we are forced to make -------------------------------
    if distribution and not device_control and distribution in {
        "internal_uncontrolled",
        "external_limited",
        "mass_offline",
        "saas",
    }:
        assumptions.append("未说明设备受控程度；暂按 unknown_devices 处理，客户端信号按不可信计算。")
    if offline is None:
        assumptions.append("未说明离线要求；暂按允许服务端迁移处理，若实际必须离线需重新评估。")
    if audience:
        assumptions.append(f"使用对象为 {audience}；环境校验类措施需评估对合法使用的误伤。")

    # ---- posture ----------------------------------------------------------
    attacker_controlled = device_control == "attacker_controlled"
    internal_controlled = distribution == "internal_controlled" and device_control in {
        "managed_devices",
        "known_devices",
    }

    if unknowns:
        posture = "insufficient_information"
        rationale = "关键 intake 信息缺失；先补齐问题再进入候选匹配。"
        goals: tuple[str, ...] = ()
        confidence = "unknown"
    elif attacker_controlled:
        posture = "no_trustworthy_client_signal"
        rationale = (
            "运行环境被攻击者完全控制时，任何本地检测都可被绕过；"
            "客户端措施只能作为成本信号，不能作为信任根。"
        )
        goals = ("logic_extraction", "tamper_detection")
        confidence = "medium"
    elif secret_can_leave == "yes" and offline is False:
        posture = "server_side_first"
        rationale = "高价值逻辑可以移出客户端且不要求完全离线；优先服务端化。"
        goals = ("logic_extraction", "licensing_hardening")
        confidence = "high"
    elif distribution == "mass_offline":
        posture = "cost_raising_only"
        rationale = (
            "大规模离线分发下客户端完全在对方手里；可选手段只剩提高分析成本，"
            "且必须明确说明这提高了谁的成本、剩什么风险。"
        )
        goals = ("obfuscation", "tamper_detection", "resource_protection")
        confidence = "medium"
    elif internal_controlled:
        posture = "controlled_environment_hardening"
        rationale = (
            "内部受控环境 + 设备受控，可以把环境校验作为一种成本手段；"
            "但默认不开启，需显式批准并保证不影响调试/CI/可访问性。"
        )
        goals = ("tamper_detection", "obfuscation", "licensing_hardening")
        confidence = "medium"
    else:
        posture = "platform_native_cleanup_first"
        rationale = "先清理发布产物里无意交付的材料，再评估是否需要更强的客户端措施。"
        goals = ("resource_protection", "obfuscation")
        confidence = "medium"

    # ---- gates & warnings that must travel with the posture ---------------
    gates: list[str] = [
        "明确攻击假设与剩余风险，不得把“没有发现”写成“证明安全”",
        "保护前后语义、兼容性与性能预算有实测结果",
    ]
    if test_baseline == "none":
        gates.append("先补齐目标函数/模块的回归测试基线，再进入任何变换")
        warnings.append("没有测试基线时 PEA 不会保护无法验证的关键逻辑。")
    if test_baseline == "partial":
        gates.append("声明测试覆盖范围与未覆盖部分；未覆盖项记为 unknown")
    if posture == "cost_raising_only":
        gates.append("逐条说明每项措施提高的是谁的成本、剩余什么风险")
    if posture == "no_trustworthy_client_signal":
        gates.append("关键授权决策必须落在服务端或可信边界")
    if update_channel in (None, "none"):
        warnings.append("没有可信更新通道时，防篡改只能依赖本地检测，回滚与吊销路径需单独设计。")
    if offline is True and secret_can_leave == "no":
        warnings.append("必须离线且秘密不能移出客户端：此时不存在可信的客户端秘密边界，需明确接受该残余风险。")

    # The limit sentence is attached to *every* posture, without exception.
    warnings.insert(0, _CLIENT_SIDE_LIMIT)
    if posture in {"cost_raising_only", "controlled_environment_hardening", "no_trustworthy_client_signal"}:
        warnings.insert(1, _SECRET_FIRST)

    hardening_allowed = posture in {
        "cost_raising_only",
        "controlled_environment_hardening",
        "no_trustworthy_client_signal",
    }

    return DeploymentProfile(
        answers=dict(answers),
        unknowns=tuple(unknowns),
        assumptions=tuple(assumptions),
        posture=posture,
        posture_rationale=rationale,
        recommended_goals=goals,
        hard_gate_checks=tuple(gates),
        warnings=tuple(warnings),
        client_side_hardening_allowed=hardening_allowed,
        client_side_hardening_requires_approval=True,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Answer coercion helpers (for reading a protection request as partial intake)
# ---------------------------------------------------------------------------

_REQUEST_FIELD_TO_QUESTION = {
    "authorization": "authorization",
    "targets": "platforms",
    "languages": "languages",
    "offline_required": "offline_required",
    "threat_model": "threat_model",
    "performance_budget_percent": "performance_budget_percent",
    "allowed_spdx_licenses": "allowed_spdx_licenses",
    "allow_network": "allow_network",
    "distribution": "distribution",
    "audience": "audience",
    "device_control": "device_control",
    "update_channel": "update_channel",
    "secret_can_leave_client": "secret_can_leave_client",
    "cross_platform_requirements": "cross_platform_requirements",
    "assets": "assets",
    "test_baseline": "test_baseline",
}


def answers_from_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Lift whatever intake information a protection request already carries."""
    answers: dict[str, Any] = {}
    for request_key, question_id in _REQUEST_FIELD_TO_QUESTION.items():
        if request_key in request and request[request_key] not in (None, "", []):
            answers[question_id] = request[request_key]
    return answers


def apply_profile_to_request(request: dict[str, Any], profile: DeploymentProfile) -> dict[str, Any]:
    """Write the intake-derived goals back into a request (non-destructive)."""
    updated = dict(request)
    if profile.recommended_goals:
        existing = list(updated.get("goals") or [])
        for goal in profile.recommended_goals:
            if goal not in existing:
                existing.append(goal)
        updated["goals"] = existing
    return updated
