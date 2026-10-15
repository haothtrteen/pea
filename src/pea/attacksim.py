"""Minimal sandboxed attack-simulation design (D4 / R3).

This module turns the capability map (``catalog/rea-capability-defense-map.json``)
into a *minimal* adversarial self-test plan: for each capability family that
applies to the project under review, it emits the shortest attack path an
analyst would take, derived mechanically from the map's recorded observations.

Design rules, all enforced here or by ``attack-simulation.schema.json``:

* **Retrieved facts, not improvisation.** Every step's ``method`` quotes a
  recorded observation from the capability map verbatim. The generator cannot
  invent an attack technique; if the map has no observation for a family, that
  family produces no step.
* **Red lines live in the contract.** ``interpretation_rule`` can only be
  ``cost_delta_only`` or ``tool_failure_is_not_success`` - "absolute
  prevention" is not expressible. A step whose expected observation is
  ``error_or_unavailable`` must carry ``failure_meaning = unknown``: tool
  failure is never evidence of protection.
* **Minimal by construction.** One step per capability family unless the
  family's recorded observations genuinely split into distinct paths (the Dart
  family splits into recovery comparison / object-pool scan / runtime hook
  because those are three separately recorded observation chains). No step is
  emitted to pad the plan.
* **Bounded and read-only.** The emitted sandbox declares ``read_only_artifacts``
  (schema ``const true``), no network, and a time budget; budget exhaustion
  means ``unknown``, never success.

The output is validated against the attack-simulation schema on the way out,
so a generator bug fails loudly instead of emitting an unenforceable plan.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pea.paths import find_repo_root
from pea.tiers import sort_by_priority
from pea.validation import validate_or_raise

ATTACK_SIMULATION_SCHEMA = "attack-simulation"
CAPABILITY_MAP_PATH = find_repo_root() / "catalog" / "rea-capability-defense-map.json"

# ---------------------------------------------------------------------------
# Capability-family selection
# ---------------------------------------------------------------------------

#: Language observed by recon -> capability families an analyst would reach for.
#: Every value must exist in the capability map; the contract gate asserts it.
FAMILY_BY_LANGUAGE: dict[str, tuple[str, ...]] = {
    "dart": ("dart_aot_snapshot_analysis",),
    "javascript": ("javascript_electron_static_analysis",),
    "typescript": ("javascript_electron_static_analysis",),
    "kotlin": ("managed_code_and_mobile_analysis",),
    "java": ("managed_code_and_mobile_analysis", "dotnet_android_flutter_jeb_and_managed_artifacts"),
    "csharp": ("dotnet_android_flutter_jeb_and_managed_artifacts",),
    "c": ("native_binary_inspection",),
    "cpp": ("native_binary_inspection",),
    "objective-c": ("native_binary_inspection",),
    "objective-cpp": ("native_binary_inspection",),
    "swift": ("native_binary_inspection",),
    "lua": ("wasm_evm_sqlite_and_related_static_artifacts",),
    "python": ("wasm_evm_sqlite_and_related_static_artifacts",),
    "go": ("native_binary_inspection",),
    "rust": ("native_binary_inspection",),
}

#: Platform observed by recon -> additional capability families.
FAMILY_BY_PLATFORM: dict[str, tuple[str, ...]] = {
    "android": ("binary_layout_and_build_metadata",),
    "ios": ("binary_layout_and_build_metadata",),
    "web": ("browser_and_network_observation",),
    "linux_desktop": ("binary_layout_and_build_metadata",),
    "windows_desktop": ("binary_layout_and_build_metadata",),
    "macos_desktop": ("binary_layout_and_build_metadata",),
}

#: Runtime observation applies to every distributed client, but it is only
#: *relevant* when there is something to observe at runtime - i.e. the request
#: is about licensing/authorization or recon located authorization logic.
RUNTIME_FAMILY = "runtime_process_observation"

#: Differential comparison is the default whenever two artifacts are in play;
#: this family is about comparing artifacts, so it joins whenever a baseline
#: and a protected candidate are both declared.
COMPARISON_FAMILY = "artifact_and_function_comparison"

# ---------------------------------------------------------------------------
# Step templates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StepTemplate:
    """One attack path, mechanically tied to a recorded observation.

    ``observation_index`` points into the mapping's ``observations`` list; the
    emitted ``method`` quotes that observation so every step traces back to a
    retrieved fact. ``objective_prefix`` is fixed template text - the *goal* of
    the step, never a claimed technique. ``environment_tier`` is the lowest
    rung of the T0-T4 ladder (``pea.testbench``) the step needs; a step whose
    tier the testbench cannot reach is deferred to unknown, never silently
    dropped or counted as passed.
    """

    key: str
    objective_prefix: str
    method_prefix: str
    observation_index: int
    expected_observation: str
    failure_meaning: str
    applies_to: str
    weight: float
    tool_environment: str
    environment_tier: str = "T0"
    requires_device: bool = False
    note: str = ""


#: The Dart AOT family splits into three steps because the capability map
#: records three distinct observation chains (snapshot parsing, object-pool
#: dump, runtime hooking). Splitting is derived from the map, not preference.
DART_TEMPLATES: tuple[StepTemplate, ...] = (
    StepTemplate(
        key="dart_recovery_comparison",
        objective_prefix="量化保护前后从 Dart AOT 快照恢复业务类/方法结构的差异",
        method_prefix="分别解析 baseline 与 protected 产物的快照，比对恢复出的类与方法数量及符号质量；能力映射记录的事实：",
        observation_index=1,
        expected_observation="partial_recovery",
        failure_meaning="cost_raised",
        applies_to="both",
        weight=0.5,
        tool_environment="blutter（用户环境自装，需匹配 Dart SDK 版本；PEA 不分发、不自动安装）",
        note="恢复率下降须量化为成本差记录，不得解释为不可逆或不可攻破。",
    ),
    StepTemplate(
        key="dart_object_pool_secret_scan",
        objective_prefix="在对象池倾倒中查找授权端点与密钥材料",
        method_prefix="检查快照解析输出的对象池倾倒内容中的 URL、密钥样串与授权相关常量；能力映射记录的事实：",
        observation_index=2,
        expected_observation="recovers_target",
        failure_meaning="protection_gap",
        applies_to="both",
        weight=0.2,
        tool_environment="blutter 输出 + 文本检索",
        note="baseline 命中属预期；protected 若仍命中即为防护缺口，须在报告中按 severity 标注。",
    ),
    StepTemplate(
        key="dart_runtime_hook_probe",
        objective_prefix="运行期定位并 hook 授权校验函数，观察返回值篡改",
        method_prefix="以静态恢复的地址为锚，用自动生成的 Frida hook 模板尝试 hook 授权校验函数；能力映射记录的事实：",
        observation_index=3,
        expected_observation="error_or_unavailable",
        failure_meaning="unknown",
        applies_to="protected_only",
        weight=0.3,
        tool_environment="Frida（用户环境自装，许可由用户核验）+ 用户提供的测试设备",
        environment_tier="T2",
        requires_device=True,
        note="hook 失败可能是地址失效、时序或环境问题，不能直接解释为防护成功——只能记 unknown 或记录为成本上升的具体原因。",
    ),
)

#: Default one-step template for every other family: quote the family's first
#: recorded observation as the method. Minimal by construction. Its weight is
#: deliberately a quarter of a dedicated path: generic checks are ride-along
#: steps and must not dilute the budget of a family-specific attack chain.
GENERIC_TEMPLATE = StepTemplate(
    key="generic_exposure_check",
    objective_prefix="验证该能力族记录的暴露声明在当前产物上的实际表现",
    method_prefix="按能力映射记录的方法观察产物；能力映射记录的事实：",
    observation_index=0,
    expected_observation="partial_recovery",
    failure_meaning="cost_raised",
    applies_to="both",
    weight=0.25,
    tool_environment="对应能力族的公开分析工具（用户环境自备；PEA 不分发、不自动安装）",
)

#: Per-family template overrides; families not listed use GENERIC_TEMPLATE.
FAMILY_TEMPLATES: dict[str, tuple[StepTemplate, ...]] = {
    "dart_aot_snapshot_analysis": DART_TEMPLATES,
}

#: Shipped with every generated plan regardless of family selection.
BASE_LIMITATIONS: tuple[str, ...] = (
    "结论绑定到声明的产物指纹与时间预算，不可外推到其它构建、ABI 或更高预算的攻击者",
    "未覆盖 IL2CPP、自研壳、更高预算的人工分析与动态插桩组合路径",
    "攻击工具由用户环境自备；PEA 不分发、不自动安装、不执行",
)

_BUDGET_RULE = "预算耗尽后未完成的步骤一律记 unknown；不延长预算、不临时升级工具、不追加能力族。"


@dataclass(frozen=True)
class ArtifactRef:
    """One artifact participating in the simulation."""

    path: str
    sha256: str | None = None


def load_capability_map(path: str | Path | None = None) -> dict[str, Any]:
    """Load the capability map; structure is guarded by the contract gate."""
    map_path = Path(path) if path else CAPABILITY_MAP_PATH
    return json.loads(map_path.read_text(encoding="utf-8"))


def capability_families(capability_map: Mapping[str, Any] | None = None) -> set[str]:
    """All capability family ids the map declares."""
    data = capability_map if capability_map is not None else load_capability_map()
    return {m["capability_family"] for m in data["mappings"]}


def family_tier(family: str, capability_map: Mapping[str, Any] | None = None) -> str | None:
    """The exposure tier a capability family amplifies, per the capability map.

    ``None`` means the map does not declare a tier for this family; callers
    must treat that as "unknown ordering", never as a default tier.
    """
    data = capability_map if capability_map is not None else load_capability_map()
    for mapping in data["mappings"]:
        if mapping["capability_family"] == family:
            tier = mapping.get("exposure_tier")
            return tier if isinstance(tier, str) else None
    return None


def select_capability_families(
    languages: Sequence[str],
    platforms: Sequence[str],
    goals: Sequence[str] = (),
    *,
    has_authorization_logic: bool = False,
    with_baseline_and_protected: bool = False,
    capability_map: Mapping[str, Any] | None = None,
) -> list[str]:
    """Pick the capability families that apply, in a stable order.

    Selection is rule-based (language/platform/goals/signal), never a free-form
    judgement: the same inputs always select the same families, and every
    selected family is guaranteed to exist in the capability map.
    """
    known = capability_families(capability_map)
    selected: list[str] = []

    def add(family: str) -> None:
        if family in known and family not in selected:
            selected.append(family)

    for language in languages:
        for family in FAMILY_BY_LANGUAGE.get(language, ()):
            add(family)
    for platform in platforms:
        for family in FAMILY_BY_PLATFORM.get(platform, ()):
            add(family)
    if has_authorization_logic or "licensing_hardening" in goals:
        add(RUNTIME_FAMILY)
    if with_baseline_and_protected:
        add(COMPARISON_FAMILY)
    return selected


def _templates_for(family: str, mapping: Mapping[str, Any]) -> list[StepTemplate]:
    """Templates that survive contact with the mapping's actual data.

    A template whose ``observation_index`` is out of range for this mapping is
    dropped - the generator refuses to quote an observation that does not exist
    rather than inventing one.
    """
    observations = mapping.get("observations", [])
    templates = FAMILY_TEMPLATES.get(family, (GENERIC_TEMPLATE,))
    return [t for t in templates if t.observation_index < len(observations)]


def _allocate_budget(templates: Sequence[StepTemplate], total_minutes: int) -> list[int]:
    """Split the budget by template weight; every step keeps at least 1 minute."""
    if not templates:
        return []
    weight_sum = sum(t.weight for t in templates)
    raw = [total_minutes * t.weight / weight_sum for t in templates]
    minutes = [max(1, int(value)) for value in raw]
    # Hand the rounding remainder to the heaviest step so the parts sum to the
    # declared total whenever the budget allows it.
    remainder = total_minutes - sum(minutes)
    if remainder > 0:
        heaviest = max(range(len(templates)), key=lambda i: templates[i].weight)
        minutes[heaviest] += remainder
    return minutes


def design_attack_simulation(
    *,
    baseline: ArtifactRef,
    protected: ArtifactRef | None,
    languages: Sequence[str],
    platforms: Sequence[str],
    goals: Sequence[str] = (),
    has_authorization_logic: bool = False,
    recon_unknowns: Sequence[str] = (),
    time_budget_minutes: int = 180,
    plan_id: str | None = None,
    simulation_id: str | None = None,
    capability_map: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Design a minimal, read-only, time-budgeted attack self-test plan.

    ``baseline`` is the unprotected artifact; ``protected`` the candidate. When
    ``protected`` is ``None`` the plan degrades to an absolute-only self-check
    (``self_check_release`` shape): the schema then forbids claiming a cost
    delta, and the limitations say so explicitly.
    """
    if time_budget_minutes < 1:
        raise ValueError("time_budget_minutes must be >= 1")
    data = capability_map if capability_map is not None else load_capability_map()
    mappings = {m["capability_family"]: m for m in data["mappings"]}

    differential = protected is not None
    families = select_capability_families(
        languages,
        platforms,
        goals,
        has_authorization_logic=has_authorization_logic,
        with_baseline_and_protected=differential,
        capability_map=data,
    )

    artifacts: list[dict[str, Any]] = [{"path": baseline.path, "role": "unprotected_baseline"}]
    if baseline.sha256:
        artifacts[0]["sha256"] = baseline.sha256
    if differential:
        assert protected is not None
        candidate: dict[str, Any] = {"path": protected.path, "role": "protected_candidate"}
        if protected.sha256:
            candidate["sha256"] = protected.sha256
        artifacts.append(candidate)

    steps: list[dict[str, Any]] = []
    skipped_families: list[str] = []
    all_templates: list[StepTemplate] = []
    for family in families:
        mapping = mappings.get(family)
        if mapping is None:
            skipped_families.append(family)
            continue
        templates = _templates_for(family, mapping)
        if not templates:
            skipped_families.append(family)
            continue
        all_templates.extend(templates)
    budgets = _allocate_budget(all_templates, time_budget_minutes)

    step_no = 0
    for family in families:
        mapping = mappings.get(family)
        if mapping is None:
            continue
        templates = _templates_for(family, mapping)
        if not templates:
            continue
        observations = mapping.get("observations", [])
        tier = family_tier(family, data)
        for template in templates:
            step_no += 1
            observation = observations[template.observation_index]
            step: dict[str, Any] = {
                "step_id": f"A{step_no}",
                "capability_family": family,
                "objective": template.objective_prefix,
                "method": f"{template.method_prefix}{observation}",
                "tool_environment": template.tool_environment,
                "time_budget_minutes": budgets[step_no - 1],
                "expected_observation": template.expected_observation,
                "failure_meaning": template.failure_meaning,
                "applies_to": template.applies_to,
                "environment_tier": template.environment_tier,
            }
            if tier:
                step["exposure_tier"] = tier
            if template.note:
                step["notes"] = template.note
            steps.append(step)

    # Repair order is exposure order: reorder steps by tier (tool efficiency
    # first) and renumber, so A1 is always the cheapest-to-reach exposure.
    steps = [dict(step) for step in sort_by_priority(steps)]
    for index, step in enumerate(steps, start=1):
        step["step_id"] = f"A{index}"

    if not steps:
        raise ValueError(
            "no capability family produced a step; attack simulation requires at least one "
            "family whose recorded observations support a step (refusing to emit an empty plan)"
        )

    requires_device = any(
        t.requires_device
        for family in families
        for t in _templates_for(family, mappings.get(family, {}))
        if family in mappings
    )

    limitations: list[str] = list(BASE_LIMITATIONS)
    for family in families:
        for limitation in mappings.get(family, {}).get("limitations", []):
            if limitation not in limitations:
                limitations.append(limitation)
    if not differential:
        limitations.insert(0, "缺少 unprotected baseline：本方案只能给出绝对观察，不构成保护前后的成本差证据")
    for family in skipped_families:
        limitations.append(f"能力族 {family} 无可用观察记录，未生成步骤（不得以模型知识替代）")

    unknown_set: list[str] = list(recon_unknowns)
    unknown_set.append("更高预算攻击者（数天级）下成本差是否仍然成立，未知")

    digest_source = {
        "families": families,
        "artifacts": artifacts,
        "budget": time_budget_minutes,
        "plan_id": plan_id,
    }
    if simulation_id is None:
        simulation_id = "atk-" + hashlib.sha256(
            json.dumps(digest_source, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:12]

    simulation: dict[str, Any] = {
        "schema_version": "1.0",
        "simulation_id": simulation_id,
        "target_artifacts": artifacts,
        "sandbox": {
            "isolation": "disposable_container",
            "read_only_artifacts": True,
            "time_budget_minutes": time_budget_minutes,
            "network": False,
        },
        "capability_steps": steps,
        "success_criteria": {
            "comparison": "differential_baseline_vs_protected" if differential else "absolute_only",
            "interpretation_rule": "cost_delta_only" if differential else "tool_failure_is_not_success",
            "budget_rule": _BUDGET_RULE,
        },
        "limitations": limitations,
        "unknowns": unknown_set,
    }
    if plan_id:
        simulation["plan_id"] = plan_id
    if requires_device:
        simulation["sandbox"]["device"] = "用户提供的测试设备；禁止使用生产设备"

    # Self-check against our own contract: an unenforceable plan must never
    # leave this function.
    validate_or_raise(simulation, _schema(ATTACK_SIMULATION_SCHEMA), subject="generated attack simulation")
    return simulation


def _schema(name: str) -> Mapping[str, Any]:
    from pea.validation import default_registry

    return default_registry().get(name)


# ---------------------------------------------------------------------------
# Mission brief (third ring §2): the deliverable for a live-fire exercise
# ---------------------------------------------------------------------------

MISSION_BRIEF_SCHEMA = "mission-brief"

#: Environment ladder order; a step is deferred when the testbench's reachable
#: tier ranks below the step's required tier.
_TIER_RANK: dict[str, int] = {"T0": 0, "T1": 1, "T2": 2, "T3": 3, "T4": 4}

#: Red lines that travel with every brief (third ring §2 and the adversarial
#: self-test contract). They are fixed text, not parameters: a brief that
#: could be configured without them would not be a brief.
MISSION_RED_LINES: tuple[str, ...] = (
    "仅限用户拥有或获得书面授权的工件；不得对第三方产物发起演练",
    "演练全程只读：不修改、不回写、不重新打包目标产物（源码作弊码变体由用户自行构建后作为新工件入场）",
    "动态插桩（frida 类）仅限用户自有的沙盒设备或模拟器；禁止使用生产设备",
    "工具失败、崩溃或不可用一律记 unknown，绝不可解释为防护成功",
    "PEA 不分发、不安装、不执行任何攻击工具；工具由用户环境自备，用户与 REA 之间自行适用其许可",
    "演练结论绑定产物指纹（sha256）与时间预算，不可外推到其它构建、ABI 或更高预算的攻击者",
)

#: Evidence回流要求：第三方工具观察入账的合同字段。
EVIDENCE_RETURN_REQUIRED_FIELDS: tuple[str, ...] = (
    "evidence_id",
    "kind",
    "source",
    "observed_at",
    "authority",
    "limitations",
    "tool_name",
    "tool_version",
    "artifact_digest",
    "content_digest",
    "redacted_summary",
    "environment",
)

EVIDENCE_RETURN_NOTES: tuple[str, ...] = (
    "演练前用 artifact-manifest 钉死目标工件 digest，保证'打的就是这个版本'",
    "每个能力步骤的结果各入账一条；结果为 unknown 的也要入账，沉默不是证据",
    "environment 块缺失的记录会被 pea.ledger_record 拒收——环境分层是观察的一部分",
    "脱敏是声明式的：redacted_summary 由记录方声明，未声明的记录在导出时显式标注",
)


def _tier_rank(tier: str) -> int | None:
    return _TIER_RANK.get(tier)


def _defer_reason(required: str, reachable: str) -> str | None:
    """Why a step cannot run now, or ``None`` when the environment suffices.

    ``T4`` is never reachable by construction: it is the architectural answer
    (move the surface server-side), so a T4 step is always deferred with that
    reason rather than treated as a test gap.
    """
    if required == "T4":
        return "T4 硬件级暴露面无法在任何测试台模拟；该步骤的答案是服务端迁移（架构答案），不是演练缺口"
    if reachable == "unknown":
        if required == "T0":
            return None  # static analysis needs no environment reconnaissance
        return f"测试台环境未侦察或不可判定（reachable_tier=unknown）；本步骤需要 {required}"
    required_rank = _tier_rank(required)
    reachable_rank = _tier_rank(reachable)
    if required_rank is None or reachable_rank is None:
        return f"环境层无法判定（required={required}, reachable={reachable}）"
    if reachable_rank < required_rank:
        return f"测试台最高可达 {reachable}，本步骤需要 {required}"
    return None


def design_mission_brief(
    *,
    baseline: ArtifactRef,
    protected: ArtifactRef | None,
    languages: Sequence[str],
    platforms: Sequence[str],
    goals: Sequence[str] = (),
    has_authorization_logic: bool = False,
    objective_anchors: Sequence[str] = (),
    environment: Mapping[str, Any] | None = None,
    recon_unknowns: Sequence[str] = (),
    time_budget_minutes: int = 180,
    plan_id: str | None = None,
    brief_id: str | None = None,
    capability_map: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Design the mission brief for one live-fire exercise (third ring §2).

    The brief is the hand-off artifact: PEA's planner hands it to the user's
    agent, which drives the user's own REA installation; every observation
    comes back through the evidence contract (``pea.ledger_record``).

    Five elements, all derived rather than improvised:

    * **objective anchors** - observations of the owner's own artifact
      (``objective_anchors``, e.g. the snapshot anchors dart-aot-check found);
    * **tool families** - the capability map (never a fresh tool list);
    * **environment tier** - the testbench reconnaissance result
      (``environment``, ``pea.testbench`` output); steps the environment
      cannot reach are *deferred to unknown*, never dropped or passed;
    * **criteria and budget** - the embedded attack-simulation plan;
    * **red lines** - fixed text, carried with every brief.

    ``environment=None`` means the testbench was not reconnoitered: the brief
    still emits, with ``reachable_tier=unknown`` and every non-static step
    deferred - a missing environment is a named unknown, not a failure.
    """
    simulation = design_attack_simulation(
        baseline=baseline,
        protected=protected,
        languages=languages,
        platforms=platforms,
        goals=goals,
        has_authorization_logic=has_authorization_logic,
        recon_unknowns=recon_unknowns,
        time_budget_minutes=time_budget_minutes,
        plan_id=plan_id,
        capability_map=capability_map,
    )

    data = capability_map if capability_map is not None else load_capability_map()
    research_date = data.get("research_date")
    mappings = {m["capability_family"]: m for m in data["mappings"]}
    families = [step["capability_family"] for step in simulation["capability_steps"]]
    ordered_families: list[str] = []
    for family in families:
        if family not in ordered_families:
            ordered_families.append(family)
    tool_families: list[dict[str, Any]] = []
    for family in ordered_families:
        entry: dict[str, Any] = {"capability_family": family}
        tier = mappings.get(family, {}).get("exposure_tier")
        if isinstance(tier, str):
            entry["exposure_tier"] = tier
        if isinstance(research_date, str):
            entry["research_date"] = research_date
        tool_families.append(entry)

    reachable_tier = "unknown"
    tier_basis: list[str] = []
    if environment is not None:
        raw_tier = environment.get("reachable_tier")
        if isinstance(raw_tier, str) and raw_tier in {*ENVIRONMENT_TIER_VALUES, "unknown"}:
            reachable_tier = raw_tier
        basis = environment.get("tier_basis")
        if isinstance(basis, list):
            tier_basis = [str(item) for item in basis]
    if reachable_tier == "unknown" and not tier_basis:
        tier_basis = ["未侦察测试台（environment 未提供或不可判定）；环境可达层记 unknown，动态步骤全部推迟"]

    deferred_steps: list[dict[str, Any]] = []
    for step in simulation["capability_steps"]:
        required = str(step.get("environment_tier", "T0"))
        reason = _defer_reason(required, reachable_tier)
        if reason is not None:
            deferred: dict[str, Any] = {
                "step_id": step["step_id"],
                "required_tier": required,
                "note": reason,
            }
            deferred_steps.append(deferred)

    unknown_set: list[str] = list(simulation.get("unknowns", []))
    if not objective_anchors:
        unknown_set.append("未提供目标锚点（域扫描观察）；简报的目标锚点要素为空，执行前应补齐")
    for deferred in deferred_steps:
        unknown_set.append(
            f"步骤 {deferred['step_id']} 需要环境层 {deferred['required_tier']}，本次不可达（{deferred['note']}）；结果记 unknown"
        )
    if environment is None:
        unknown_set.append("测试台未侦察（未调用 pea.check_testbench）；环境可达层 unknown")

    digest_source = {
        "simulation_id": simulation["simulation_id"],
        "anchors": list(objective_anchors),
        "environment": reachable_tier,
        "plan_id": plan_id,
    }
    if brief_id is None:
        brief_id = "mb-" + hashlib.sha256(
            json.dumps(digest_source, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:12]

    brief: dict[str, Any] = {
        "schema_version": "1.0",
        "brief_id": brief_id,
        "generated_at": _utc_now_iso(),
        "simulation_id": simulation["simulation_id"],
        "simulation": simulation,
        "objective_anchors": list(objective_anchors),
        "environment": {
            "reachable_tier": reachable_tier,
            "tier_basis": tier_basis,
            "deferred_steps": deferred_steps,
        },
        "tool_families": tool_families,
        "red_lines": list(MISSION_RED_LINES),
        "evidence_return": {
            "ledger_tool": "pea.ledger_record",
            "authority_required": "observation",
            "environment_required": True,
            "required_fields": list(EVIDENCE_RETURN_REQUIRED_FIELDS),
            "notes": list(EVIDENCE_RETURN_NOTES),
        },
        "limitations": list(simulation.get("limitations", [])),
        "unknowns": unknown_set,
    }
    if plan_id:
        brief["plan_id"] = plan_id

    # Self-check against our own contract: an unenforceable brief must never
    # leave this function.
    validate_or_raise(brief, _schema(MISSION_BRIEF_SCHEMA), subject="generated mission brief")
    return brief


#: Tier values accepted in the brief's environment block (mirrors the schema).
ENVIRONMENT_TIER_VALUES: tuple[str, ...] = ("T0", "T1", "T2", "T3", "T4")


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")
