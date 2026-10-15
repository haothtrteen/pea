"""Candidate-review gate tests: blocks block, and nothing gets upgraded.

The gate's job is to stop candidates that look technically attractive but
are not usable - AGPL in a closed distribution, archived upstream, README
claims nobody compiled. The assertions therefore focus on the refusals:
a catalog that says ``needs_review`` must never yield an eligible decision.
"""
from __future__ import annotations

import json
from pathlib import Path

from pea.candidatereview import (
    DEFAULT_CATALOG_PATH,
    CandidateReviewError,
    load_catalog,
    review_catalog,
    review_entry,
    to_review_document,
)
from pea.tiers import TIER_TOOL_EFFICIENCY


def _entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "test-candidate",
        "name": "Test Candidate",
        "category": "restricted_vm",
        "targets": ["dart"],
        "capabilities": ["dart_function_to_private_ir"],
        "repository_url": "https://github.com/example/test",
        "documentation_url": "https://github.com/example/test#readme",
        "license": {"spdx": "MIT", "status": "verified", "checked_at": "2026-10-13", "notes": "ok"},
        "maintenance": {"state": "active", "checked_at": "2026-10-13", "last_release": None, "notes": "ok"},
        "verification_status": "candidate_requires_project_tests",
        "trust_level": "medium",
        "version_policy": "exact_pin",
        "limits": ["test limitation"],
        "notes": "",
    }
    base.update(overrides)
    return base


def _by_id(reviews, candidate_id: str):
    return next(r for r in reviews if r.candidate_id == candidate_id)


# --------------------------------------------------------------------------
# gate outcomes
# --------------------------------------------------------------------------


def test_license_needs_review_blocks_the_candidate():
    review = review_entry(_entry(license={"spdx": None, "status": "needs_review", "notes": "AGPL 双授权待审"}))

    assert review.decision == "blocked"
    assert next(g for g in review.gates if g.name == "license").status == "block"


def test_archived_upstream_blocks_the_candidate():
    review = review_entry(_entry(maintenance={"state": "archived", "notes": "上游已归档"}))

    assert review.decision == "blocked"
    assert next(g for g in review.gates if g.name == "maintenance").status == "block"


def test_research_only_entry_is_never_eligible():
    review = review_entry(_entry(verification_status="research_only"))

    assert review.decision == "research_only"
    assert any("不得作为 verified" in item for item in review.limitations)


def test_verified_license_and_active_maintenance_become_eligible():
    review = review_entry(_entry())

    assert review.decision == "eligible_for_project_review"


def test_verified_everything_is_production_eligible():
    review = review_entry(_entry(verification_status="verified"))

    assert review.decision == "production_eligible"


def test_low_trust_requires_a_fixture_first():
    review = review_entry(_entry(trust_level="low"))

    assert review.decision == "candidate_for_fixture"


def test_not_applicable_license_does_not_block():
    review = review_entry(_entry(license={"spdx": "NOASSERTION", "status": "not_applicable", "notes": "PEA 自有模式"}))

    assert review.decision != "blocked"
    assert next(g for g in review.gates if g.name == "license").status == "not_applicable"


def test_block_outranks_every_other_signal():
    # archived + research_only + great license: still blocked.
    review = review_entry(
        _entry(verification_status="research_only", maintenance={"state": "archived", "notes": ""})
    )

    assert review.decision == "blocked"


def test_unknown_statuses_are_never_treated_as_pass():
    review = review_entry(_entry(license={"spdx": None, "status": "whatever"}, maintenance={"state": "whatever"}))

    assert review.decision == "blocked" or any(g.status != "pass" for g in review.gates)
    assert any(g.status == "needs_verification" for g in review.gates)


# --------------------------------------------------------------------------
# catalog-level behaviour
# --------------------------------------------------------------------------


def test_real_catalog_gates_known_entries_as_documented():
    entries = load_catalog()
    reviews = review_catalog(entries).reviews

    assert _by_id(reviews, "pyarmor").decision == "blocked"  # license needs_review
    assert _by_id(reviews, "confuserex-legacy").decision == "blocked"  # archived
    assert _by_id(reviews, "shellvmp").decision == "blocked"  # license needs_review
    assert _by_id(reviews, "fdartvmp").decision == "blocked"  # license needs_review
    assert _by_id(reviews, "javascript-obfuscator").decision == "eligible_for_project_review"
    assert _by_id(reviews, "logic-extraction-pattern").decision == "production_eligible"


def test_gate_finding_is_observed_and_carries_tier():
    result = review_catalog()

    finding = result.findings[0]
    assert finding["status"] == "observed"
    assert finding["exposure_tier"] == TIER_TOOL_EFFICIENCY
    assert "blocked" in finding["summary"]


def test_unreadable_catalog_is_unknown_not_empty(tmp_path):
    result = review_catalog(catalog_path=tmp_path / "missing.json")

    assert result.reviews == ()
    finding = result.findings[0]
    assert finding["id"] == "candidate-review-unavailable"
    assert finding["status"] == "unknown"
    assert result.coverage["state"] == "unavailable"


def test_malformed_catalog_raises_rather_than_gating_nothing(tmp_path):
    bad = tmp_path / "catalog.json"
    bad.write_text("{not json", encoding="utf-8")

    try:
        load_catalog(bad)
    except CandidateReviewError:
        return
    raise AssertionError("malformed catalog must raise, not yield an empty gate")


def test_default_catalog_path_exists():
    assert Path(DEFAULT_CATALOG_PATH).is_file()


# --------------------------------------------------------------------------
# review document export (schema-conformant, claims stay external)
# --------------------------------------------------------------------------


def test_review_document_matches_the_schema_and_keeps_claims_external():
    from pea.paths import schema_dir
    from pea.validation import validate

    entry = _entry(capabilities=["a", "b"])
    review = review_entry(entry)
    document = to_review_document(entry, review)

    schema = json.loads((schema_dir() / "research-candidate-review.schema.json").read_text(encoding="utf-8"))
    errors = validate(document, schema)
    assert errors == [], errors

    assert {c["claim_status"] for c in document["claims"]} == {"external_claim"}
    assert document["decision"] == review.decision
    assert document["source_audit"]["status"] == "not_attempted"
    assert document["fixture_test"]["status"] == "not_run"
    assert document["commit_sha"] is None


def test_review_document_without_capabilities_records_the_gap():
    entry = _entry(capabilities=[])
    review = review_entry(entry)

    document = to_review_document(entry, review)

    assert document["claims"][0]["claim_status"] == "unknown"
