"""Cross-check the offline validator against the real ``jsonschema`` library.

``pea.validation`` exists because the runtime must stay dependency-free, but a
hand-rolled validator is only trustworthy if something pins it to a reference
implementation. ``jsonschema`` is a dev-only dependency, so these tests run it
over the whole contract corpus plus a systematic mutation corpus and require the
two implementations to agree on every verdict and every ``(path, keyword)``
pair.

If this file fails, the offline validator has drifted. Fix
``src/pea/validation.py`` - never adjust this file's expectations to match.
"""
from __future__ import annotations

import json
import sys
import unittest
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pea.validation import (  # noqa: E402
    PeaContractError,
    SchemaRegistry,
    UnsupportedSchemaKeyword,
    default_registry,
    validate,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
CATALOG_DIR = ROOT / "catalog"
EXAMPLES_DIR = ROOT / "examples"

# ---------------------------------------------------------------------------
# Reference implementation
# ---------------------------------------------------------------------------


def _reference_registry() -> Registry:
    """Same ``$id``-keyed registry the contract gate uses."""
    resources = [
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in (
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        )
        if "$id" in schema
    ]
    return Registry().with_resources(resources)


REFERENCE_REGISTRY = _reference_registry()
INTERNAL_REGISTRY = SchemaRegistry(SCHEMA_DIR)


def _reference_errors(schema: Mapping[str, Any], instance: Any) -> set[tuple[tuple[Any, ...], str]]:
    validator = Draft202012Validator(dict(schema), registry=REFERENCE_REGISTRY)
    return {(tuple(error.path), error.validator) for error in validator.iter_errors(instance)}


def _internal_errors(schema: Mapping[str, Any], instance: Any) -> set[tuple[tuple[Any, ...], str]]:
    return {(violation.path, violation.keyword) for violation in validate(instance, schema, registry=INTERNAL_REGISTRY)}


def _assert_agreement(schema: Mapping[str, Any], instance: Any, label: str) -> None:
    reference = _reference_errors(schema, instance)
    internal = _internal_errors(schema, instance)
    assert reference == internal, (
        f"{label}: offline validator disagrees with jsonschema\n"
        f"  only jsonschema: {sorted(reference - internal)}\n"
        f"  only offline   : {sorted(internal - reference)}"
    )


def _corpus() -> Iterator[tuple[str, Mapping[str, Any], Any]]:
    """(label, schema, document) for every schema-bearing file."""
    catalog = json.loads((CATALOG_DIR / "catalog.seed.json").read_text(encoding="utf-8"))
    for entry in catalog:
        yield f"catalog:{entry['id']}", INTERNAL_REGISTRY.get("catalog-entry"), entry

    pairs = {
        "protection-request.example.json": "protection-request",
        "protection-request.internal-android.example.json": "protection-request",
        "protection-request.flutter-licensing.example.json": "protection-request",
        "protection-plan.example.json": "protection-plan",
        "fdartvmp-research-review.example.json": "research-candidate-review",
        "attack-simulation.flutter-licensing.example.json": "attack-simulation",
    }
    for filename, schema_name in pairs.items():
        yield f"example:{filename}", INTERNAL_REGISTRY.get(schema_name), json.loads(
            (EXAMPLES_DIR / filename).read_text(encoding="utf-8")
        )

    envelope = json.loads((EXAMPLES_DIR / "exposure-findings.example.json").read_text(encoding="utf-8"))
    finding_schema = INTERNAL_REGISTRY.get("exposure-finding")
    for index, finding in enumerate(envelope["findings"]):
        yield f"finding[{index}]", finding_schema, finding


CORPUS = list(_corpus())


@pytest.mark.parametrize("label,schema,document", CORPUS, ids=[c[0] for c in CORPUS])
def test_offline_validator_matches_jsonschema_on_the_corpus(label: str, schema: Mapping[str, Any], document: Any) -> None:
    _assert_agreement(schema, document, label)


# ---------------------------------------------------------------------------
# Mutation corpus: systematically break one thing at a time
# ---------------------------------------------------------------------------


def _mutations(node: Any) -> list[tuple[str, Any]]:
    """Every single-edit mutation of ``node``, as ``(label, mutated)`` pairs."""
    out: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for key in list(node):
            out.append((f"drop:{key}", {k: v for k, v in node.items() if k != key}))
            extra = dict(node)
            extra["__unexpected_property__"] = 1
            out.append((f"extra-at:{key}", extra))
            for label, mutated in _mutations(node[key]):
                out.append((f"{key}/{label}", {**node, key: mutated}))
    elif isinstance(node, list):
        if node:
            out.append(("empty", []))
            out.append(("duplicate-first", [*node, node[0]]))
            for index, item in enumerate(node[:3]):
                for label, mutated in _mutations(item):
                    out.append((f"[{index}]/{label}", [*node[:index], mutated, *node[index + 1 :]]))
    elif isinstance(node, bool):
        out.append(("wrong-type", "not-a-boolean"))
    elif isinstance(node, str):
        out.append(("wrong-type", 12345))
        out.append(("emptied", ""))
    elif isinstance(node, (int, float)):
        out.append(("negative", -999999))
        out.append(("too-large", 999999))
    return out


def _mutation_corpus() -> Iterator[tuple[str, Mapping[str, Any], Any]]:
    for label, schema, document in CORPUS:
        for mutation_label, mutated in _mutations(document):
            yield f"{label} :: {mutation_label}", schema, mutated


MUTATIONS = list(_mutation_corpus())


@pytest.mark.parametrize("label,schema,document", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_offline_validator_matches_jsonschema_on_mutations(label: str, schema: Mapping[str, Any], document: Any) -> None:
    """The interesting half: both implementations must reject, and reject at the
    same locations, for the same reason."""
    _assert_agreement(schema, document, label)


def test_mutation_corpus_is_not_vacuous() -> None:
    """Guard against the corpus degenerating into all-valid documents."""
    rejected = 0
    for _, schema, document in MUTATIONS:
        if _internal_errors(schema, document):
            rejected += 1
    assert rejected > len(MUTATIONS) // 2, f"only {rejected}/{len(MUTATIONS)} mutations were rejected"


# ---------------------------------------------------------------------------
# Keyword subset: every keyword the offline validator claims to support
# ---------------------------------------------------------------------------

SUBSET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["always"],
    "properties": {
        "always": {"type": "string", "minLength": 2, "maxLength": 5, "pattern": "^[a-z]+$"},
        "nullable_string": {"type": ["string", "null"]},
        "nullable_int": {"type": ["integer", "null"], "minimum": 0, "maximum": 10},
        "nullable_object": {"type": ["object", "null"]},
        "plain_int": {"type": "integer", "exclusiveMinimum": 0, "exclusiveMaximum": 100},
        "plain_number": {"type": "number"},
        "flag": {"type": "boolean"},
        "choice": {"enum": ["a", "b", None]},
        "fixed": {"const": 42},
        "bounded_list": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 3, "uniqueItems": True},
        "typed_list": {"type": "array", "items": {"type": "integer", "minimum": 1}},
    },
}

SUBSET_INSTANCES: list[tuple[str, Any]] = [
    ("valid-minimal", {"always": "ab"}),
    ("valid-full", {"always": "abc", "nullable_string": None, "nullable_int": 5, "nullable_object": None,
                    "plain_int": 50, "plain_number": 1.5, "flag": True, "choice": "a", "fixed": 42,
                    "bounded_list": ["x", "y"], "typed_list": [1, 2]}),
    ("integer-accepts-1.0", {"always": "ab", "plain_int": 1.0}),
    ("null-in-nullable-string", {"always": "ab", "nullable_string": None}),
    ("string-in-nullable-int", {"always": "ab", "nullable_int": "5"}),
    ("bool-is-not-integer", {"always": "ab", "plain_int": True}),
    ("bool-is-not-number", {"always": "ab", "plain_number": False}),
    ("too-short", {"always": "a"}),
    ("too-long", {"always": "abcdef"}),
    ("pattern-violated", {"always": "AB1"}),
    ("below-minimum", {"always": "ab", "nullable_int": -1}),
    ("above-maximum", {"always": "ab", "nullable_int": 11}),
    ("exclusive-minimum", {"always": "ab", "plain_int": 0}),
    ("exclusive-maximum", {"always": "ab", "plain_int": 100}),
    ("enum-violated", {"always": "ab", "choice": "c"}),
    ("enum-null-allowed", {"always": "ab", "choice": None}),
    ("const-violated", {"always": "ab", "fixed": 43}),
    ("empty-array", {"always": "ab", "bounded_list": []}),
    ("too-many-items", {"always": "ab", "bounded_list": ["a", "b", "c", "d"]}),
    ("duplicate-items", {"always": "ab", "bounded_list": ["a", "a"]}),
    ("numeric-strings-are-duplicates", {"always": "ab", "bounded_list": ["a", "a"]}),
    ("wrong-item-type", {"always": "ab", "typed_list": ["1"]}),
    ("item-below-minimum", {"always": "ab", "typed_list": [0]}),
    ("missing-required", {}),
    ("unexpected-property", {"always": "ab", "surprise": 1}),
    ("wrong-root-type", ["not", "an", "object"]),
]


@pytest.mark.parametrize("label,instance", SUBSET_INSTANCES, ids=[s[0] for s in SUBSET_INSTANCES])
def test_offline_validator_matches_jsonschema_on_keyword_subset(label: str, instance: Any) -> None:
    _assert_agreement(SUBSET_SCHEMA, instance, label)


def test_unique_items_treats_numbers_and_booleans_differently() -> None:
    """JSON Schema value equality: 1 == 1.0, but True != 1."""
    schema = {"uniqueItems": True}
    for instance, expected_valid in ([1, 1.0], False), ([1, True], True), (["a", "a"], False):
        assert (not _internal_errors(schema, instance)) is expected_valid, instance
        assert (not _reference_errors(schema, instance)) is expected_valid, instance


def test_format_is_annotation_only() -> None:
    """Both implementations skip ``format`` unless format-assertion is enabled."""
    schema = {"type": "string", "format": "uri"}
    assert not _internal_errors(schema, "definitely not a uri")
    assert not _reference_errors(schema, "definitely not a uri")


# ---------------------------------------------------------------------------
# Behaviours that must NOT silently pass
# ---------------------------------------------------------------------------


def test_unsupported_keyword_fails_loudly() -> None:
    """A keyword outside the subset must raise, not be skipped."""
    with pytest.raises(UnsupportedSchemaKeyword):
        validate({}, {"anyOf": [{"type": "string"}, {"type": "integer"}]})


def test_boolean_schemas_are_honoured() -> None:
    assert _internal_errors(False, {"anything": 1})
    assert not _internal_errors(True, {"anything": 1})


def test_registry_resolves_the_cross_file_ref() -> None:
    """exposure-finding.schema.json $refs evidence-record.schema.json."""
    schema = INTERNAL_REGISTRY.get("exposure-finding")
    assert "$ref" in json.dumps(schema)
    finding = json.loads((EXAMPLES_DIR / "exposure-findings.example.json").read_text(encoding="utf-8"))["findings"][0]
    assert not _internal_errors(schema, finding)


def test_unknown_schema_name_is_an_error() -> None:
    with pytest.raises(KeyError):
        INTERNAL_REGISTRY.get("no-such-schema")


def test_default_registry_is_cached() -> None:
    assert default_registry() is default_registry()


def test_violation_contract_shape() -> None:
    """Every violation carries the structured fields PEA promises callers."""
    violations = validate({"always": "a"}, SUBSET_SCHEMA)
    assert violations
    for violation in violations:
        assert violation.code and violation.category == "input" and violation.retryable is True
        assert violation.remediation and violation.keyword and violation.message
        assert violation.json_path.startswith("$")
        assert set(violation.to_dict()) == {"code", "category", "retryable", "remediation", "path", "keyword", "message"}


def test_contract_error_reports_every_violation() -> None:
    """One pass, all violations - not just the first failure."""
    error = PeaContractError(
        validate({"always": "a", "surprise": 1, "choice": "z"}, SUBSET_SCHEMA), subject="unit"
    )
    assert len(error.violations) >= 3
    assert "unit" in str(error)


def test_load_catalog_rejects_drift() -> None:
    """End-to-end: a broken catalog entry fails at load, not at planning time."""
    from pea.planner import load_catalog

    broken = [{"schema_version": "1.0", "id": "ok-entry"}]  # missing most required fields
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "broken.json"
        path.write_text(json.dumps(broken), encoding="utf-8")
        with pytest.raises(PeaContractError):
            load_catalog(path)


def test_build_plan_rejects_malformed_request() -> None:
    """The three silent-acceptance defects, pinned as regressions."""
    from pea.planner import build_plan, load_catalog

    catalog = load_catalog(CATALOG_DIR / "catalog.seed.json")
    base = {
        "schema_version": "1.0",
        "project_path": "./x",
        "authorization": "owner",
        "targets": ["javascript"],
        "goals": ["obfuscation"],
        "offline_required": True,
        "execution_mode": "plan_only",
    }
    cases = {
        "unknown goal": (dict(base, goals=["make_it_unhackable"]), "enum"),
        "empty targets": (dict(base, targets=[]), "minItems"),
        "missing project_path": ({k: v for k, v in base.items() if k != "project_path"}, "required"),
        "wrong schema_version": (dict(base, schema_version="2.0"), "const"),
        "unexpected field": (dict(base, surprise=True), "additionalProperties"),
    }
    for label, (request, expected_keyword) in cases.items():
        with pytest.raises(PeaContractError) as caught:
            build_plan(request, catalog)
        keywords = {violation.keyword for violation in caught.value.violations}
        assert expected_keyword in keywords, f"{label}: expected {expected_keyword}, got {keywords}"


def test_build_plan_output_conforms_to_plan_schema() -> None:
    """PEA's own plans must satisfy PEA's own plan contract."""
    from pea.planner import build_plan, load_catalog

    request = json.loads((EXAMPLES_DIR / "protection-request.example.json").read_text(encoding="utf-8"))
    plan = build_plan(request, load_catalog(CATALOG_DIR / "catalog.seed.json"))
    plan_schema = INTERNAL_REGISTRY.get("protection-plan")
    assert not _internal_errors(plan_schema, plan)
    assert not _reference_errors(plan_schema, plan)


def test_candidate_score_reflects_fit_and_platform() -> None:
    """The two heaviest axes must move the number; performance never does."""
    from pea.planner import SCORE_WEIGHTS, candidate_score, load_catalog, score_axes, score_basis

    catalog = load_catalog(CATALOG_DIR / "catalog.seed.json")
    entry = next(e for e in catalog if e["id"] == "javascript-obfuscator")

    both = candidate_score(entry, ["obfuscation"], {"javascript", "nodejs"})
    one_goal = candidate_score(entry, ["obfuscation", "licensing_hardening"], {"javascript", "nodejs"})
    other_platform = candidate_score(entry, ["obfuscation"], {"rust"})
    assert both > one_goal > other_platform, (both, one_goal, other_platform)
    assert "performance" not in score_basis(entry, ["obfuscation"], {"javascript"})
    assert score_axes(entry)["performance"] is None
    assert sum(SCORE_WEIGHTS.values()) == 100


if __name__ == "__main__":
    unittest.main()
