"""Exposure tier model - the engineering form of PEA's founding principle.

The architecture spec's first research order is "build the analysis-capability
-> exposure-surface -> protection mapping" and its second design principle is
"protect along the risk path, not by stacking terminology". This module turns
that into a *mechanical repair order*.

The model has four tiers. The repair order is **highest exposure first**,
where "highest" is measured by the attacker's marginal cost of reaching the
exposure - the same quantity the attack simulation budgets measure:

* **T1 tool_efficiency** - one-click open-source tooling turns the artifact
  into structure in minutes (blutter recovers a Dart snapshot in one pass;
  jadx decompiles dex; Frida hooks a check with a generated template).
  Marginal cost ~ 0, so it is repaired first: the lever is making the tool
  fail, degrade, or force a toolchain switch - not hiding content.
* **T2 static_content** - visible without running anything: hard-coded
  secrets and endpoints, symbols and debug data, source maps, strings.
  Marginal cost low (a scan). Lever: remove / relocate / strip.
* **T3 runtime_behavior** - only visible when the target runs: credentials
  in argv or environment, plaintext temp files, log leakage, traffic.
  Marginal cost medium (needs an environment and instrumentation). Lever:
  narrow what the running process exposes.
* **T4 algorithm_logic** - requires understanding, not just running: the
  authorization algorithm can be read and re-implemented, control flow
  followed. Marginal cost high (human analysis). Lever: obfuscation, VMP,
  logic restructuring, server-side relocation.

T1 is an *amplifier* across T2-T4: the same artifact content is orders of
magnitude more exposed when a one-click tool exists for it. That is why the
tool layer is repaired first even though the content it exposes belongs to
the inner layers - and why "targeting the tools" never departs from
"targeting the exposure": the tool layer is where the exposure is cheapest
to reach.

Severity note: when a runtime exposure involves secret *material* (a
plaintext key in memory), its severity floats up within its tier - ordering
is by marginal cost, not by how bad the worst case is.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

# ---------------------------------------------------------------------------
# Tier definitions - the single source of repair order
# ---------------------------------------------------------------------------

TIER_TOOL_EFFICIENCY = "tool_efficiency"
TIER_STATIC_CONTENT = "static_content"
TIER_RUNTIME_BEHAVIOR = "runtime_behavior"
TIER_ALGORITHM_LOGIC = "algorithm_logic"

#: Repair order: index 0 is repaired first. Do not reorder casually - the
#: order is the attacker's marginal cost of reaching each layer, which is
#: what makes "highest exposure first" mechanical rather than editorial.
TIER_ORDER: tuple[str, ...] = (
    TIER_TOOL_EFFICIENCY,
    TIER_STATIC_CONTENT,
    TIER_RUNTIME_BEHAVIOR,
    TIER_ALGORITHM_LOGIC,
)

TIER_LABELS: dict[str, str] = {
    TIER_TOOL_EFFICIENCY: "T1 工具放大层（开源一键逆向工具直接命中的暴露面）",
    TIER_STATIC_CONTENT: "T2 静态内容层（不运行即可观察的产物内容）",
    TIER_RUNTIME_BEHAVIOR: "T3 运行期行为层（需运行目标才可见的行为）",
    TIER_ALGORITHM_LOGIC: "T4 算法逻辑层（需理解逻辑才能利用的结构）",
}

TIER_ATTACK_COST: dict[str, str] = {
    TIER_TOOL_EFFICIENCY: "边际成本≈0：一键工具现成、分钟级恢复",
    TIER_STATIC_CONTENT: "边际成本低：扫描即得，无需运行",
    TIER_RUNTIME_BEHAVIOR: "边际成本中：需运行环境与插桩/抓包",
    TIER_ALGORITHM_LOGIC: "边际成本高：需人工阅读理解与重实现",
}

TIER_LEVERS: dict[str, str] = {
    TIER_TOOL_EFFICIENCY: "让工具失效/降效/被迫换工具链（提高工具切换成本）",
    TIER_STATIC_CONTENT: "清除、外移、裁剪（秘密离开客户端、符号与映射不发布）",
    TIER_RUNTIME_BEHAVIOR: "收窄运行期暴露（凭据不入 argv/环境、临时文件与日志脱敏）",
    TIER_ALGORITHM_LOGIC: "混淆、函数虚拟化、逻辑重构或服务端化",
}

#: Exposure-finding categories (produced by recon and the mappers) -> tier.
#: ``project_profile`` is context, not an exposure, so it has no tier.
CATEGORY_TIERS: dict[str, str] = {
    "authorization_logic_surface": TIER_STATIC_CONTENT,
    "release_artifact_surface": TIER_TOOL_EFFICIENCY,
    "static_secret_surface": TIER_STATIC_CONTENT,
    "symbol_debug_surface": TIER_STATIC_CONTENT,
    "source_map_surface": TIER_STATIC_CONTENT,
    "runtime_credential_surface": TIER_RUNTIME_BEHAVIOR,
    "process_filesystem_surface": TIER_RUNTIME_BEHAVIOR,
    "network_surface": TIER_RUNTIME_BEHAVIOR,
    "algorithm_logic_surface": TIER_ALGORITHM_LOGIC,
    "control_flow_surface": TIER_ALGORITHM_LOGIC,
}

#: Categories that are informational context rather than an exposure tier.
UNTIERED_CATEGORIES = frozenset({"project_profile"})


class UnknownTierError(ValueError):
    """A tier string outside the model was used where a tier is required."""


def tier_rank(tier: str) -> int:
    """Repair priority: lower rank is repaired first."""
    try:
        return TIER_ORDER.index(tier)
    except ValueError as exc:
        raise UnknownTierError(f"unknown exposure tier {tier!r}; expected one of {TIER_ORDER}") from exc


def is_tier(value: str) -> bool:
    return value in TIER_ORDER


def tier_label(tier: str) -> str:
    if not is_tier(tier):
        raise UnknownTierError(f"unknown exposure tier {tier!r}")
    return TIER_LABELS[tier]


def tier_of_category(category: str) -> str | None:
    """Map an exposure-finding category to its tier; ``None`` when untiered."""
    return CATEGORY_TIERS.get(category)


def sort_by_priority(items: Sequence[Mapping[str, Any]], *, tier_key: str = "exposure_tier") -> list[Mapping[str, Any]]:
    """Sort tier-carrying mappings by repair priority, highest exposure first.

    Items without a tier (or with an unrecognized one) sort last, preserving
    their relative order - a missing tier must never silently jump the queue.
    """
    def rank(item: Mapping[str, Any]) -> tuple[int, int]:
        tier = item.get(tier_key)
        if isinstance(tier, str) and is_tier(tier):
            return (0, tier_rank(tier))
        return (1, 0)

    return sorted(items, key=rank)


def remediation_order(
    actions: Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Order ``(tier, action)`` pairs by repair priority, stable within a tier."""
    indexed = list(actions)
    return [indexed[i] for i in sorted(range(len(indexed)), key=lambda i: (tier_rank(indexed[i][0]), i))]


def tier_summary(tiers: Iterable[str]) -> dict[str, int]:
    """Count items per tier, including zero counts - a zero is information."""
    counts = {tier: 0 for tier in TIER_ORDER}
    for tier in tiers:
        if not is_tier(tier):
            raise UnknownTierError(f"unknown exposure tier {tier!r}")
        counts[tier] += 1
    return counts
