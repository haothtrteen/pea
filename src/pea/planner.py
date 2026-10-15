"""Deterministic, offline-only planning helpers for the PEA design prototype."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pea.paths import find_repo_root
from pea.validation import PeaContractError, validate, validate_or_raise

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from pea.intake import DeploymentProfile


ROOT = find_repo_root()
DEFAULT_CATALOG = ROOT / "catalog" / "catalog.seed.json"
REQUEST_SCHEMA = "protection-request"
CATALOG_ENTRY_SCHEMA = "catalog-entry"
PLAN_SCHEMA = "protection-plan"
GOAL_CAPABILITIES: dict[str, set[str]] = {
    "obfuscation": {"identifier_mangling", "string_transformation", "control_flow_options", "python_obfuscation", "obfuscation"},
    "tamper_detection": {"tamper_detection", "integrity", "code_signing"},
    "logic_extraction": {"server_side_logic", "api_contract_generation", "client_stub_generation", "secret_boundary_review"},
    "licensing_hardening": {"licensing", "authorization", "license_validation"},
    "resource_protection": {"resource_encryption", "resource_protection"},
    "function_virtualization": {"pure_function_lowering", "restricted_ir", "bytecode_interpreter"},
}
TARGET_ALIASES = {
    "js": "javascript",
    "ts": "typescript",
    "node": "nodejs",
    "dotnet": "dotnet-framework",
    "csharp": "dotnet-framework",
    "c#": "dotnet-framework",
    "kotlin": "android",
    "java": "java",
    "cpp": "cpp",
    "c++": "cpp",
}


def normalize_target(target: str) -> str:
    value = target.strip().lower()
    return TARGET_ALIASES.get(value, value)


def load_catalog(path: str | Path = DEFAULT_CATALOG) -> list[dict[str, Any]]:
    """Load the seed catalog and enforce its schema on every entry.

    The hand-rolled "required keys" check this replaces let anything else
    through - wrong types, out-of-enum values, unexpected properties. The
    catalog is now validated against ``catalog-entry.schema.json`` so data
    drift fails loudly at load time instead of surfacing as a bad plan later.
    """
    catalog_path = Path(path).expanduser().resolve()
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Catalog root must be a JSON array")
    for index, entry in enumerate(data):
        violations = validate(entry, _schema(CATALOG_ENTRY_SCHEMA))
        if violations:
            raise PeaContractError(violations, subject=f"catalog entry #{index} ({entry.get('id', '?')})")
    return data


def _schema(name: str) -> Mapping[str, Any]:
    """Fetch a contract schema from the repository's ``schemas/`` directory."""
    from pea.validation import default_registry

    return default_registry().get(name)


def _goal_matches(entry: dict[str, Any], goal: str) -> bool:
    """Does this entry serve one specific goal?

    Split out of :func:`_goal_match` so the scorer can measure *how many*
    requested goals an entry covers instead of collapsing everything to a
    boolean. The capability lookup and the category fallbacks are kept as one
    expression on purpose: a goal listed in ``GOAL_CAPABILITIES`` still falls
    through to its category fallback when the capability set does not hit.
    """
    caps = set(entry.get("capabilities", []))
    category = entry.get("category", "")
    capability_hit = goal in GOAL_CAPABILITIES and bool(caps.intersection(GOAL_CAPABILITIES[goal]))
    return (
        capability_hit
        or (goal == "obfuscation" and category in {"source_obfuscator", "binary_protector", "platform_native"})
        or (goal == "tamper_detection" and category in {"integrity", "platform_native"})
        or (goal == "licensing_hardening" and category == "licensing")
        or (goal == "resource_protection" and "resource_protection" in caps)
        or (goal == "function_virtualization" and category == "restricted_vm")
    )


def _goal_match(entry: dict[str, Any], goals: list[str]) -> bool:
    if not goals:
        return True
    return any(_goal_matches(entry, goal) for goal in goals)


def _target_matches(entry_targets: set[str], requested: set[str]) -> bool:
    """Decide whether a catalog entry's declared targets cover the request.

    Precedence is written out explicitly rather than relying on ``and`` binding
    tighter than ``or``:

    * an entry declaring ``all`` covers every target;
    * otherwise the entry must declare at least one requested target, **and**
      must not have declared ``unknown`` as a target — an entry that does not
      know its own platform support is never a match for a concrete request.

    An empty request set matches nothing here; callers that want "any target"
    must ask for it deliberately.
    """
    if "all" in entry_targets:
        return True
    if "unknown" in entry_targets:
        return False
    return bool(requested & entry_targets)


def search_catalog(
    targets: list[str],
    goals: list[str],
    catalog: list[dict[str, Any]] | None = None,
    include_research: bool = False,
) -> list[dict[str, Any]]:
    """Return matching entries. This function never fetches or executes anything."""
    entries = catalog if catalog is not None else load_catalog()
    normalized = {normalize_target(t) for t in targets}
    results: list[dict[str, Any]] = []
    for entry in entries:
        entry_targets = {normalize_target(t) for t in entry.get("targets", [])}
        if not _target_matches(entry_targets, normalized) or not _goal_match(entry, goals):
            continue
        if not include_research and entry.get("verification_status") in {"research_only", "blocked"}:
            continue
        results.append(entry)
    return sorted(results, key=lambda e: (e.get("name", "").lower(), e.get("id", "")))


def _canonical_digest(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# Candidate scoring
# ---------------------------------------------------------------------------
# Weights mirror the evaluation axes in the architecture spec and sum to 100.
# The original prototype hardcoded ``fit = 1.0`` and ``platform_fit = 1.0``,
# which made the two heaviest axes constants: every candidate that survived
# the gates scored exactly 90.0 regardless of whether it served the request.
# Both axes are now measured from the request.

SCORE_WEIGHTS: dict[str, int] = {
    "capability_fit": 25,
    "platform_fit": 20,
    "maintenance": 15,
    "license": 15,
    "build_integration": 10,
    "performance": 10,
    "provenance": 5,
}

_MAINTENANCE_SCORES = {"active": 1.0, "slow": 0.5}
_LICENSE_SCORES = {"verified": 1.0, "not_applicable": 0.8}
_BUILD_INTEGRATION_SCORES = {"exact_pin": 1.0, "semver_minor": 0.85, "user_managed": 0.5, "not_applicable": 0.5}
_PROVENANCE_SCORES = {"high": 1.0, "medium": 0.7, "low": 0.3}


def score_axes(
    entry: dict[str, Any],
    goals: list[str] | None = None,
    requested_targets: set[str] | None = None,
) -> dict[str, float | None]:
    """Per-axis scores in ``[0, 1]``; ``None`` means the catalog has no signal.

    ``performance`` is always ``None``: the catalog carries no performance
    data, and inventing a value for it would be exactly the fake precision the
    architecture spec forbids. Performance has to be measured on the project
    before anyone claims a budget.
    """
    goals = goals or []
    requested = requested_targets or set()

    if goals:
        covered = sum(1 for goal in goals if _goal_matches(entry, goal))
        capability_fit: float | None = covered / len(goals)
    else:
        capability_fit = None

    entry_targets = {normalize_target(t) for t in entry.get("targets", [])}
    if not requested:
        platform_fit: float | None = None
    elif "all" in entry_targets:
        platform_fit = 1.0
    else:
        platform_fit = len(requested & entry_targets) / len(requested)

    return {
        "capability_fit": capability_fit,
        "platform_fit": platform_fit,
        "maintenance": _MAINTENANCE_SCORES.get(entry.get("maintenance", {}).get("state", "")),
        "license": _LICENSE_SCORES.get(entry.get("license", {}).get("status", "")),
        "build_integration": _BUILD_INTEGRATION_SCORES.get(entry.get("version_policy", "")),
        "performance": None,
        "provenance": _PROVENANCE_SCORES.get(entry.get("trust_level", "")),
    }


def candidate_score(
    entry: dict[str, Any],
    goals: list[str] | None = None,
    requested_targets: set[str] | None = None,
) -> float:
    """Score a candidate on a 0-100 scale, renormalized over known axes.

    Only axes with a real signal contribute to numerator and denominator, so
    an axis PEA knows nothing about neither rewards nor punishes the entry.
    With every axis known this is the plain weighted sum.
    """
    axes = score_axes(entry, goals, requested_targets)
    known = {name: value for name, value in axes.items() if value is not None}
    if not known:
        return 0.0
    weight = sum(SCORE_WEIGHTS[name] for name in known)
    total = sum(SCORE_WEIGHTS[name] * value for name, value in known.items())
    return round(100.0 * total / weight, 2)


def score_basis(
    entry: dict[str, Any],
    goals: list[str] | None = None,
    requested_targets: set[str] | None = None,
) -> list[str]:
    """Names of the axes that actually contributed to :func:`candidate_score`.

    Emitted next to the score in the plan so a reader can see what the number
    is made of - and that ``performance`` is never part of it.
    """
    axes = score_axes(entry, goals, requested_targets)
    return sorted(name for name, value in axes.items() if value is not None)


def build_plan(
    request: dict[str, Any],
    catalog: list[dict[str, Any]] | None = None,
    profile: DeploymentProfile | None = None,
) -> dict[str, Any]:
    """Build a safe, non-executing plan from a request and the local seed catalog.

    ``profile`` is the deployment profile derived from intake. When it is given,
    its posture, assumptions, unknowns and hard gates are carried into the plan
    so that a caller cannot silently drop them. When it is omitted, PEA derives
    one from whatever intake fields the request already carries - which usually
    means the plan will report missing information rather than guess.

    The request is validated against ``protection-request.schema.json`` before
    anything else happens. Previously an unknown goal, an empty ``targets``
    array or a missing ``project_path`` were all silently accepted and simply
    produced an empty or misleading plan; now they fail loudly with the full
    violation list. The emitted plan is checked against
    ``protection-plan.schema.json`` on the way out for the same reason.
    """
    validate_or_raise(request, _schema(REQUEST_SCHEMA), subject="protection request")
    if profile is None:
        from pea.intake import answers_from_request, derive_profile

        profile = derive_profile(answers_from_request(request))
    intake_unknowns = list(profile.unknowns)
    # Declared up front so the unauthorized branch and the authorized branch
    # report the same fields; this replaces three `locals().get(...)` reads.
    selected: list[dict[str, Any]] = []
    compatible: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    goals = list(request.get("goals", []))
    normalized_targets = {normalize_target(t) for t in request.get("targets", [])}
    if request.get("authorization") == "not_confirmed":
        strategy = "no_safe_match"
        status = "blocked"
        risks = ["项目所有权/授权尚未确认；只能继续一般性设计，不能执行保护操作。"]
    else:
        targets = request.get("targets", [])
        candidates = search_catalog(targets, goals, catalog=catalog)
        allowed = set(request.get("allowed_spdx_licenses", []))
        offline_required = bool(request.get("offline_required", False))
        for entry in candidates:
            lic = entry.get("license", {})
            lic_status = lic.get("status", "needs_review")
            spdx = lic.get("spdx")
            maint_state = entry.get("maintenance", {}).get("state", "unknown")
            if lic_status == "incompatible":
                excluded.append({"id": entry["id"], "reason": "license marked incompatible"})
                continue
            if lic_status == "needs_review":
                excluded.append({"id": entry["id"], "reason": "license needs review; production recommendation blocked"})
                continue
            if allowed and spdx and spdx not in allowed and lic_status != "not_applicable":
                excluded.append({"id": entry["id"], "reason": f"license {spdx} not in allowed_spdx_licenses"})
                continue
            if maint_state in {"archived", "unknown"}:
                excluded.append({"id": entry["id"], "reason": f"maintenance state is {maint_state}"})
                continue
            if entry.get("verification_status") in {"research_only", "blocked"}:
                excluded.append({"id": entry["id"], "reason": "research-only or blocked entry"})
                continue
            compatible.append(entry)

        compatible.sort(key=lambda e: (-candidate_score(e, goals, normalized_targets), e.get("id", "")))
        if compatible:
            selected = [compatible[0]]
            strategy = "platform_native" if selected[0]["category"] == "platform_native" else "existing_tool"
            status = "needs_user_review"
            risks = ["候选尚未在此项目上验证；需固定工具版本并运行回归与性能测试。"]
            if any(goal in {"logic_extraction", "function_virtualization"} for goal in goals):
                risks.append("目录候选不代表可以保护所有指定逻辑；需人工审阅函数边界与能力差距。")
        else:
            selected = []
            if "logic_extraction" in goals and not offline_required:
                strategy = "logic_extraction"
                status = "needs_user_review"
                risks = ["这是架构脚手架建议，不会自动部署服务或迁移业务数据。", "服务端接口必须实现认证、授权、速率限制、日志和密钥管理。"]
            elif "function_virtualization" in goals and offline_required:
                strategy = "restricted_ir_vm"
                status = "needs_user_review"
                risks = ["自研 VM 仅适用于用户拥有的、可测试的纯函数受限子集。", "原型尚未实现 VM 后端；必须先做可行性评审和独立差分测试。"]
            elif not offline_required:
                strategy = "logic_extraction"
                status = "needs_user_review"
                risks = ["未找到满足硬约束的目录候选；建议先评估将秘密逻辑移出客户端。", "需要用户确认网络边界、服务端成本和可用性要求。"]
            else:
                strategy = "no_safe_match"
                status = "blocked"
                risks = ["离线约束下未找到经过许可/维护门控的候选；不应自动生成不可验证的保护变换。", "可以由维护者提供候选工具 URL、许可证与目标平台测试样例后重新评估。"]

    request_id = "req-" + _canonical_digest(request)[:12]
    # Annotated explicitly: without it mypy joins the str and list values in this
    # literal to Collection[Any] and every later mutation becomes an error.
    plan_core: dict[str, Any] = {
        "schema_version": "1.0",
        "request_id": request_id,
        "status": status,
        "strategy": strategy,
        "selected_catalog_ids": [e["id"] for e in selected],
        "candidate_scores": [
            {
                "id": entry["id"],
                "score": candidate_score(entry, goals, normalized_targets),
                "basis": score_basis(entry, goals, normalized_targets),
            }
            for entry in compatible
        ],
        "steps": [],
        "risks": risks,
        "verification_gates": [
            "用户审阅并确认函数/模块范围",
            "工具来源、版本与许可证通过审查",
            "原始测试与保护后测试全部通过",
            "兼容性与性能预算通过或明确记录例外",
            "产物摘要、变更 diff 和回滚指引已保存"
        ],
        "side_effects": [],
        "excluded_candidates": excluded,
        "deployment_posture": profile.posture,
        "posture_rationale": profile.posture_rationale,
        "posture_confidence": profile.confidence,
        "intake_assumptions": list(profile.assumptions),
        "intake_unknowns": intake_unknowns,
        "client_side_hardening": {
            "allowed": profile.client_side_hardening_allowed,
            "requires_explicit_approval": profile.client_side_hardening_requires_approval,
        },
    }
    if intake_unknowns:
        plan_core["verification_gates"].insert(
            0, f"补齐 intake 未知项后才能进入执行：{', '.join(intake_unknowns)}"
        )
        plan_core["risks"].append(
            "intake 信息不完整；以上结论建立在已声明假设之上，未知项不得当作已确认。"
        )
    for warning in profile.warnings:
        if warning not in plan_core["risks"]:
            plan_core["risks"].append(warning)
    for gate in profile.hard_gate_checks:
        if gate not in plan_core["verification_gates"]:
            plan_core["verification_gates"].append(gate)
    if strategy == "existing_tool":
        plan_core["steps"] = [
            {"id": "S1", "kind": "review", "description": "审阅候选来源、版本、许可证和项目适配限制", "side_effect": False},
            {"id": "S2", "kind": "apply_in_workspace", "description": "固定工具版本，仅在隔离临时工作区对用户确认的文件范围运行", "requires_approval": True},
            {"id": "S3", "kind": "verify", "description": "运行单元测试、兼容性测试、性能基准和产物检查", "requires_approval": True},
            {"id": "S4", "kind": "report", "description": "导出 diff、工件哈希、测试证据与回滚说明", "side_effect": False}
        ]
        plan_core["side_effects"] = ["未来执行时会在临时工作区运行外部工具；本原型不会执行"]
    elif strategy == "logic_extraction":
        plan_core["steps"] = [
            {"id": "S1", "kind": "boundary", "description": "确定哪些数据/决策可以安全移出客户端", "side_effect": False},
            {"id": "S2", "kind": "contract", "description": "生成请求/响应 Schema、错误模型和鉴权需求", "side_effect": False},
            {"id": "S3", "kind": "scaffold", "description": "生成客户端 Stub 与服务端骨架供开发者审阅；不部署、不创建凭据", "requires_approval": True},
            {"id": "S4", "kind": "verify", "description": "用模拟服务端执行契约测试和原函数差分测试", "requires_approval": True}
        ]
        plan_core["side_effects"] = ["正式实现会涉及 API 边界和服务端代码变更；需单独审批"]
    elif strategy == "restricted_ir_vm":
        plan_core["steps"] = [
            {"id": "S1", "kind": "feasibility", "description": "检查函数是否纯函数、类型受限且有回归测试", "side_effect": False},
            {"id": "S2", "kind": "ir_prototype", "description": "在独立实验分支实现 IR 解析、类型验证和解释器，不处理任意二进制", "requires_approval": True},
            {"id": "S3", "kind": "differential_test", "description": "对原函数与 VM 结果运行固定与随机测试，限制指令数和内存", "requires_approval": True},
            {"id": "S4", "kind": "decision_gate", "description": "正确性、性能或安全门槛不通过则停止，不进入发布", "side_effect": False}
        ]
        plan_core["side_effects"] = ["需要新编译器/解释器研究实现；目前没有实际转换代码"]
    else:
        plan_core["steps"] = [
            {"id": "S1", "kind": "manual_review", "description": "请求维护者提供可信仓库、许可证和可复现测试样例", "side_effect": False},
            {"id": "S2", "kind": "reassess", "description": "更新目录后重新运行匹配；在此之前不自动保护或执行未知工件", "side_effect": False}
        ]

    plan_core["plan_id"] = "plan-" + _canonical_digest(plan_core)[:12]
    plan_core["approval_token"] = None
    plan_core["rollback"] = ["删除 PEA 管理的临时工作区", "只撤销 PEA 本次生成的补丁，不执行全仓库重置"]
    # Self-check: the plan PEA hands out must satisfy PEA's own published plan
    # contract. Emitting a plan that violates our own schema is exactly the
    # silent drift the "Schema 是唯一真源" rule exists to prevent.
    validate_or_raise(plan_core, _schema(PLAN_SCHEMA), subject="generated protection plan")
    return plan_core
