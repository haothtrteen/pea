"""Exposure tier model tests: the repair order is mechanical, not editorial."""
from __future__ import annotations

import pytest

from pea.tiers import (
    TIER_ALGORITHM_LOGIC,
    TIER_ORDER,
    TIER_RUNTIME_BEHAVIOR,
    TIER_STATIC_CONTENT,
    TIER_TOOL_EFFICIENCY,
    UnknownTierError,
    is_tier,
    remediation_order,
    sort_by_priority,
    tier_label,
    tier_of_category,
    tier_rank,
    tier_summary,
)


class TestOrder:
    def test_tool_layer_is_repaired_first(self) -> None:
        """The founding principle: one-click tooling is the cheapest exposure
        to reach, so it is the first thing repaired."""
        assert TIER_ORDER[0] == TIER_TOOL_EFFICIENCY
        assert tier_rank(TIER_TOOL_EFFICIENCY) < tier_rank(TIER_STATIC_CONTENT)
        assert tier_rank(TIER_STATIC_CONTENT) < tier_rank(TIER_RUNTIME_BEHAVIOR)
        assert tier_rank(TIER_RUNTIME_BEHAVIOR) < tier_rank(TIER_ALGORITHM_LOGIC)

    def test_unknown_tier_fails_loudly(self) -> None:
        with pytest.raises(UnknownTierError):
            tier_rank("tier_zero_trust_me")
        with pytest.raises(UnknownTierError):
            tier_label("nope")
        assert not is_tier("nope")

    def test_every_tier_has_label_cost_and_lever(self) -> None:
        from pea.tiers import TIER_ATTACK_COST, TIER_LABELS, TIER_LEVERS

        for tier in TIER_ORDER:
            assert tier in TIER_LABELS and tier in TIER_ATTACK_COST and tier in TIER_LEVERS


class TestSorting:
    def test_sort_puts_highest_exposure_first(self) -> None:
        items = [
            {"id": "algo", "exposure_tier": TIER_ALGORITHM_LOGIC},
            {"id": "tool", "exposure_tier": TIER_TOOL_EFFICIENCY},
            {"id": "runtime", "exposure_tier": TIER_RUNTIME_BEHAVIOR},
            {"id": "static", "exposure_tier": TIER_STATIC_CONTENT},
        ]
        assert [i["id"] for i in sort_by_priority(items)] == ["tool", "static", "runtime", "algo"]

    def test_untiered_items_sort_last_without_jumping_queue(self) -> None:
        items = [
            {"id": "context"},
            {"id": "tool", "exposure_tier": TIER_TOOL_EFFICIENCY},
            {"id": "bogus", "exposure_tier": "not_a_tier"},
        ]
        ordered = [i["id"] for i in sort_by_priority(items)]
        assert ordered[0] == "tool"
        assert set(ordered[1:]) == {"context", "bogus"}

    def test_stable_within_tier(self) -> None:
        items = [
            {"id": "a", "exposure_tier": TIER_STATIC_CONTENT},
            {"id": "b", "exposure_tier": TIER_STATIC_CONTENT},
        ]
        assert [i["id"] for i in sort_by_priority(items)] == ["a", "b"]

    def test_remediation_order(self) -> None:
        actions = [
            (TIER_ALGORITHM_LOGIC, "加深混淆"),
            (TIER_TOOL_EFFICIENCY, "让一键工具降效"),
            (TIER_STATIC_CONTENT, "清除硬编码端点"),
            (TIER_TOOL_EFFICIENCY, "切换产物形态提高工具链成本"),
        ]
        ordered = remediation_order(actions)
        assert ordered[0][1] == "让一键工具降效"
        assert ordered[1][1] == "切换产物形态提高工具链成本"
        assert ordered[2][1] == "清除硬编码端点"
        assert ordered[3][1] == "加深混淆"


class TestCategoryMapping:
    def test_release_artifacts_are_tool_layer(self) -> None:
        """An artifact is where one-click tooling bites, so finding one is a
        T1 exposure regardless of what is inside it."""
        assert tier_of_category("release_artifact_surface") == TIER_TOOL_EFFICIENCY

    def test_secret_and_symbol_categories_are_static_layer(self) -> None:
        assert tier_of_category("authorization_logic_surface") == TIER_STATIC_CONTENT
        assert tier_of_category("static_secret_surface") == TIER_STATIC_CONTENT
        assert tier_of_category("symbol_debug_surface") == TIER_STATIC_CONTENT
        assert tier_of_category("source_map_surface") == TIER_STATIC_CONTENT

    def test_runtime_and_algorithm_categories(self) -> None:
        assert tier_of_category("runtime_credential_surface") == TIER_RUNTIME_BEHAVIOR
        assert tier_of_category("process_filesystem_surface") == TIER_RUNTIME_BEHAVIOR
        assert tier_of_category("network_surface") == TIER_RUNTIME_BEHAVIOR
        assert tier_of_category("algorithm_logic_surface") == TIER_ALGORITHM_LOGIC
        assert tier_of_category("control_flow_surface") == TIER_ALGORITHM_LOGIC

    def test_context_has_no_tier(self) -> None:
        assert tier_of_category("project_profile") is None
        assert tier_of_category("never_heard_of_it") is None


class TestSummary:
    def test_zero_counts_are_information(self) -> None:
        summary = tier_summary([TIER_TOOL_EFFICIENCY, TIER_TOOL_EFFICIENCY])
        assert summary[TIER_TOOL_EFFICIENCY] == 2
        assert summary[TIER_ALGORITHM_LOGIC] == 0
        assert set(summary) == set(TIER_ORDER)

    def test_unknown_tier_in_summary_fails(self) -> None:
        with pytest.raises(UnknownTierError):
            tier_summary(["made_up"])
