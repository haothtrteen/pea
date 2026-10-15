"""Offline JSON Schema validation for PEA's own contract files.

Runtime dependencies are intentionally empty - PEA must stay usable with the
standard library only - so this module implements the fixed subset of JSON
Schema 2020-12 that ``schemas/`` actually uses. It is deliberately **not** a
general-purpose validator: reaching a keyword outside the supported subset
raises :class:`UnsupportedSchemaKeyword` instead of skipping the constraint,
because a validator that quietly ignores half a schema is worse than none.

The subset is pinned against the real ``jsonschema`` library (a dev-only
dependency) in ``tests/test_validation_crosscheck.py`` over the whole corpus
plus a mutation corpus, so this implementation cannot drift from what CI
already enforces.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pea.paths import SCHEMA_SUFFIX, schema_dir

__all__ = [
    "ContractViolation",
    "PeaContractError",
    "SchemaRegistry",
    "UnsupportedSchemaKeyword",
    "default_registry",
    "validate",
    "validate_or_raise",
]


# ---------------------------------------------------------------------------
# Structured error contract
# ---------------------------------------------------------------------------
# Mirrors the shape PEA promises callers (see docs/error-contract.schema.json):
# a stable machine-readable code, a category, whether retrying after a fix can
# succeed, and a remediation hint. "Invalid input" is a normal outcome, not a
# crash - callers get the full violation list, not just the first failure.

_INPUT_CATEGORY = "input"


@dataclass(frozen=True)
class ContractViolation:
    """One schema violation with everything a caller needs to fix it."""

    code: str
    category: str
    retryable: bool
    remediation: str
    path: tuple[Any, ...]
    keyword: str
    message: str

    @property
    def json_path(self) -> str:
        """Render the instance path as ``$.a[0].b`` for humans and logs."""
        rendered = "$"
        for element in self.path:
            if isinstance(element, int):
                rendered += f"[{element}]"
            else:
                rendered += f".{element}"
        return rendered

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "retryable": self.retryable,
            "remediation": self.remediation,
            "path": self.json_path,
            "keyword": self.keyword,
            "message": self.message,
        }


class PeaContractError(ValueError):
    """Raised when data does not satisfy its declared contract."""

    def __init__(self, violations: Sequence[ContractViolation], *, subject: str) -> None:
        self.violations: tuple[ContractViolation, ...] = tuple(violations)
        self.subject = subject
        shown = "; ".join(f"{v.json_path}: {v.message}" for v in self.violations[:5])
        hidden = len(self.violations) - min(5, len(self.violations))
        if hidden > 0:
            shown += f"; (+{hidden} more)"
        super().__init__(f"{subject} violates its schema ({len(self.violations)} violation(s)): {shown}")

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "violations": [v.to_dict() for v in self.violations]}


class UnsupportedSchemaKeyword(NotImplementedError):
    """A schema uses a keyword this offline validator deliberately does not implement."""

    def __init__(self, keyword: str) -> None:
        self.keyword = keyword
        super().__init__(
            f"schema keyword {keyword!r} is outside the offline validator's supported subset; "
            "extend pea.validation deliberately instead of letting the constraint pass silently"
        )


# ---------------------------------------------------------------------------
# Supported keyword subset
# ---------------------------------------------------------------------------

#: Keywords that carry no assertion. ``format`` is annotation-only in JSON
#: Schema 2020-12 unless the format-assertion vocabulary is switched on, and
#: ``jsonschema.Draft202012Validator`` does not assert it by default either -
#: so skipping it here matches the behaviour the contract gate already enforces.
_ANNOTATION_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "$anchor",
        "$comment",
        "title",
        "description",
        "default",
        "examples",
        "deprecated",
        "readOnly",
        "writeOnly",
        "notes",
        "format",
    }
)

_SUPPORTED_KEYWORDS = frozenset(
    {
        "type",
        "enum",
        "const",
        "required",
        "properties",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "uniqueItems",
        "pattern",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "$ref",
    }
)

# Subschema-valued positions that :func:`_preflight` must descend into.
_SUBSCHEMA_KEYS = ("items", "additionalProperties")

# (code, remediation) per failing keyword. Every one of these is caller-fixable
# data, hence category=input and retryable=True throughout.
_VIOLATION_CONTRACT: dict[str, tuple[str, str]] = {
    "type": ("type_mismatch", "把该字段改成 schema 声明的类型"),
    "enum": ("value_not_allowed", "把该值改成 enum 列出的取值之一"),
    "const": ("value_not_allowed", "把该值改成 schema 固定的取值"),
    "required": ("missing_required_property", "补齐 required 列出的字段"),
    "additionalProperties": ("unexpected_property", "删除 schema 未声明的字段，或先在 schemas/ 中声明它"),
    "items": ("item_violation", "修正数组中不满足 items 约束的元素"),
    "minItems": ("array_too_short", "至少提供 minItems 个元素"),
    "maxItems": ("array_too_long", "删减到 maxItems 个元素以内"),
    "minLength": ("string_too_short", "把字符串补到 minLength 个字符以上"),
    "maxLength": ("string_too_long", "把字符串截短到 maxLength 个字符以内"),
    "uniqueItems": ("duplicate_items", "移除数组中的重复元素"),
    "pattern": ("pattern_mismatch", "使字符串匹配 schema 的 pattern"),
    "minimum": ("below_minimum", "把数值提高到 minimum 或以上"),
    "maximum": ("above_maximum", "把数值降到 maximum 或以下"),
    "exclusiveMinimum": ("below_minimum", "把数值提高到 exclusiveMinimum 以上"),
    "exclusiveMaximum": ("above_maximum", "把数值降到 exclusiveMaximum 以下"),
    "false_schema": ("value_not_allowed", "该位置不允许出现任何值（schema 为 false）"),
}


def _violation(keyword: str, path: tuple[Any, ...], message: str) -> ContractViolation:
    code, remediation = _VIOLATION_CONTRACT.get(keyword, ("schema_violation", "按 schemas/ 修正该值"))
    return ContractViolation(
        code=code,
        category=_INPUT_CATEGORY,
        retryable=True,
        remediation=remediation,
        path=path,
        keyword=keyword,
        message=message,
    )


# ---------------------------------------------------------------------------
# JSON value semantics
# ---------------------------------------------------------------------------


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    if expected == "integer":
        # JSON Schema counts 1.0 as an integer; booleans are never numbers.
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, float) and value.is_integer()
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise ValueError(f"unknown JSON Schema type name: {expected!r}")


def _canonical(value: Any) -> Any:
    """A hashable key that is equal iff the JSON values are equal.

    JSON Schema value equality treats ``1`` and ``1.0`` as the same number but
    keeps booleans distinct from numbers (``True != 1``), which Python's own
    ``==`` does not.
    """
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, (int, float)):
        return ("number", value)
    if isinstance(value, str):
        return ("string", value)
    if value is None:
        return ("null",)
    if isinstance(value, list):
        return ("array", tuple(_canonical(item) for item in value))
    if isinstance(value, dict):
        return ("object", tuple(sorted((key, _canonical(item)) for key, item in value.items())))
    raise TypeError(f"not a JSON value: {value!r}")


# ---------------------------------------------------------------------------
# Schema loading and $ref resolution
# ---------------------------------------------------------------------------


def _preflight(schema: Any) -> None:
    """Walk the schema's subschema positions and reject unsupported keywords.

    Only real subschema positions are descended into; ``enum`` / ``const`` /
    ``default`` payloads are data and may legitimately contain keys that look
    like schema keywords.
    """
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise TypeError(f"schema must be an object or a boolean, got {type(schema).__name__}")
    for keyword in schema:
        if keyword not in _ANNOTATION_KEYWORDS and keyword not in _SUPPORTED_KEYWORDS:
            raise UnsupportedSchemaKeyword(keyword)
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for subschema in properties.values():
            _preflight(subschema)
    for key in _SUBSCHEMA_KEYS:
        subschema = schema.get(key)
        if isinstance(subschema, dict):
            _preflight(subschema)


class SchemaRegistry:
    """Load the contract schemas from one directory and resolve their ``$ref``s.

    Names are accepted in every form that appears in the repository: the bare
    stem (``protection-request``), the filename with or without the
    ``.schema`` infix (``protection-request.schema``,
    ``protection-request.schema.json``) and the declared ``$id``.
    """

    def __init__(self, directory: str | Path | None = None) -> None:
        self._dir = Path(directory) if directory is not None else schema_dir()
        if not self._dir.is_dir():
            raise FileNotFoundError(f"schema directory not found: {self._dir}")
        self._by_name: dict[str, Mapping[str, Any]] = {}
        self._by_id: dict[str, Mapping[str, Any]] = {}
        for path in sorted(self._dir.glob(f"*{SCHEMA_SUFFIX}")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(schema, dict):
                raise TypeError(f"{path.name}: schema root must be an object")
            stem = path.name[: -len(SCHEMA_SUFFIX)]
            self._by_name[stem] = schema
            self._by_name[f"{stem}.schema"] = schema
            self._by_name[path.name] = schema
            declared_id = schema.get("$id")
            if isinstance(declared_id, str):
                self._by_id[declared_id] = schema
        for schema in self._by_name.values():
            _preflight(schema)
        self._by_name = {name: self._by_name[name] for name in sorted(self._by_name)}

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._by_name)

    def get(self, name: str) -> Mapping[str, Any]:
        try:
            return self._by_name[name]
        except KeyError:
            pass
        if name in self._by_id:
            return self._by_id[name]
        raise KeyError(f"unknown schema {name!r}; available: {', '.join(self.names)}")

    def resolve_ref(self, ref: str) -> Mapping[str, Any]:
        """Resolve a ``$ref`` against this registry.

        Refs inside ``schemas/`` are bare filenames (``evidence-record.schema.json``),
        which :meth:`get` already understands. Anything unresolvable raises
        instead of silently validating nothing.
        """
        if ref.startswith("#"):
            raise UnsupportedSchemaKeyword("$ref with a JSON pointer fragment")
        for candidate in (ref, ref.rsplit("/", 1)[-1]):
            if candidate in self._by_name:
                return self._by_name[candidate]
            if candidate in self._by_id:
                return self._by_id[candidate]
        stem = ref[: -len(SCHEMA_SUFFIX)] if ref.endswith(SCHEMA_SUFFIX) else ref
        if stem in self._by_name:
            return self._by_name[stem]
        raise KeyError(f"unresolvable $ref {ref!r}; available: {', '.join(self.names)}")


_DEFAULT_REGISTRY: SchemaRegistry | None = None


def default_registry() -> SchemaRegistry:
    """Process-wide registry over ``<repo>/schemas`` (built once)."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = SchemaRegistry()
    return _DEFAULT_REGISTRY


# ---------------------------------------------------------------------------
# The validator itself
# ---------------------------------------------------------------------------


def validate(
    instance: Any,
    schema: Mapping[str, Any] | bool,
    *,
    registry: SchemaRegistry | None = None,
) -> list[ContractViolation]:
    """Validate ``instance`` against ``schema`` and return every violation.

    An empty list means the instance conforms. Unlike raising on the first
    problem, this reports all of them so a caller can fix a whole request in
    one pass.
    """
    registry = registry if registry is not None else default_registry()
    # Preflight here too, not just at registry construction: a schema built
    # inline (or mutated by a caller) must hit the same loud failure as one
    # loaded from schemas/.
    _preflight(schema)
    violations: list[ContractViolation] = []
    _validate(instance, schema, (), frozenset(), violations, registry)
    return violations


def validate_or_raise(
    instance: Any,
    schema: Mapping[str, Any] | bool,
    *,
    subject: str,
    registry: SchemaRegistry | None = None,
) -> None:
    """Validate and raise :class:`PeaContractError` carrying every violation."""
    violations = validate(instance, schema, registry=registry)
    if violations:
        raise PeaContractError(violations, subject=subject)


def _validate(
    instance: Any,
    schema: Mapping[str, Any] | bool,
    path: tuple[Any, ...],
    ref_stack: frozenset[str],
    violations: list[ContractViolation],
    registry: SchemaRegistry,
) -> None:
    if schema is True:
        return
    if schema is False:
        violations.append(_violation("false_schema", path, "no value is allowed here (schema is false)"))
        return
    if not isinstance(schema, dict):
        raise TypeError(f"schema must be an object or a boolean, got {type(schema).__name__}")

    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str):
            raise TypeError("$ref must be a string")
        if ref in ref_stack:
            raise ValueError(f"cyclic $ref chain: {' -> '.join([*ref_stack, ref])}")
        target = registry.resolve_ref(ref)
        # The $ref target validates the *same* instance at the *same* path.
        _validate(instance, target, path, ref_stack | {ref}, violations, registry)

    if "type" in schema:
        expected = schema["type"]
        names = expected if isinstance(expected, list) else [expected]
        if not any(_matches_type(instance, name) for name in names):
            joined = ", ".join(repr(name) for name in names)
            violations.append(_violation("type", path, f"{instance!r} is not of type {joined}"))

    if "enum" in schema:
        allowed = {_canonical(option) for option in schema["enum"]}
        if _canonical(instance) not in allowed:
            rendered = ", ".join(repr(option) for option in schema["enum"])
            violations.append(_violation("enum", path, f"{instance!r} is not one of {rendered}"))

    if "const" in schema and _canonical(instance) != _canonical(schema["const"]):
        violations.append(_violation("const", path, f"{instance!r} was expected to be {schema['const']!r}"))

    if isinstance(instance, str):
        _validate_string(instance, schema, path, violations)
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        _validate_number(instance, schema, path, violations)
    if isinstance(instance, list):
        _validate_array(instance, schema, path, violations, registry)
    if isinstance(instance, dict):
        _validate_object(instance, schema, path, violations, registry)


def _validate_string(
    instance: str,
    schema: Mapping[str, Any],
    path: tuple[Any, ...],
    violations: list[ContractViolation],
) -> None:
    if "minLength" in schema and len(instance) < schema["minLength"]:
        violations.append(_violation("minLength", path, f"{instance!r} is shorter than {schema['minLength']}"))
    if "maxLength" in schema and len(instance) > schema["maxLength"]:
        violations.append(_violation("maxLength", path, f"{instance!r} is longer than {schema['maxLength']}"))
    if "pattern" in schema:
        pattern = schema["pattern"]
        # JSON Schema patterns are unanchored (search, not fullmatch).
        if re.search(pattern, instance) is None:
            violations.append(_violation("pattern", path, f"{instance!r} does not match {pattern!r}"))


def _validate_number(
    instance: float,
    schema: Mapping[str, Any],
    path: tuple[Any, ...],
    violations: list[ContractViolation],
) -> None:
    if "minimum" in schema and instance < schema["minimum"]:
        violations.append(_violation("minimum", path, f"{instance!r} is less than the minimum of {schema['minimum']}"))
    if "maximum" in schema and instance > schema["maximum"]:
        violations.append(_violation("maximum", path, f"{instance!r} is greater than the maximum of {schema['maximum']}"))
    if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
        violations.append(
            _violation("exclusiveMinimum", path, f"{instance!r} is not greater than {schema['exclusiveMinimum']}")
        )
    if "exclusiveMaximum" in schema and instance >= schema["exclusiveMaximum"]:
        violations.append(_violation("exclusiveMaximum", path, f"{instance!r} is not less than {schema['exclusiveMaximum']}"))


def _validate_array(
    instance: list[Any],
    schema: Mapping[str, Any],
    path: tuple[Any, ...],
    violations: list[ContractViolation],
    registry: SchemaRegistry,
) -> None:
    if "minItems" in schema and len(instance) < schema["minItems"]:
        violations.append(_violation("minItems", path, f"array is too short: {len(instance)} < {schema['minItems']}"))
    if "maxItems" in schema and len(instance) > schema["maxItems"]:
        violations.append(_violation("maxItems", path, f"array is too long: {len(instance)} > {schema['maxItems']}"))
    if schema.get("uniqueItems") is True:
        seen: set[Any] = set()
        for index, item in enumerate(instance):
            key = _canonical(item)
            if key in seen:
                # The constraint belongs to the array, so the violation is
                # reported at the array's path - matching jsonschema.
                violations.append(_violation("uniqueItems", path, f"item at index {index} is a duplicate: {item!r}"))
            seen.add(key)
    if "items" in schema:
        item_schema = schema["items"]
        for index, item in enumerate(instance):
            _validate(item, item_schema, (*path, index), frozenset(), violations, registry)


def _validate_object(
    instance: dict[str, Any],
    schema: Mapping[str, Any],
    path: tuple[Any, ...],
    violations: list[ContractViolation],
    registry: SchemaRegistry,
) -> None:
    for required in schema.get("required", []):
        if required not in instance:
            violations.append(_violation("required", path, f"{required!r} is a required property"))
    properties = schema.get("properties", {})
    for key, value in instance.items():
        if key in properties:
            _validate(value, properties[key], (*path, key), frozenset(), violations, registry)
    additional = schema.get("additionalProperties", True)
    if additional is not True:
        for key in instance:
            if key not in properties:
                if additional is False:
                    violations.append(
                        _violation("additionalProperties", path, f"additional property {key!r} is not allowed")
                    )
                else:
                    _validate(instance[key], additional, (*path, key), frozenset(), violations, registry)


def load_and_validate(
    path: str | Path,
    schema_name: str,
    *,
    registry: SchemaRegistry | None = None,
) -> Any:
    """Read a JSON file and validate it against a named schema.

    Returns the parsed document; raises :class:`PeaContractError` on drift and
    the usual ``OSError`` / ``json.JSONDecodeError`` on unreadable input.
    """
    registry = registry if registry is not None else default_registry()
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    violations = validate(document, registry.get(schema_name), registry=registry)
    if violations:
        raise PeaContractError(violations, subject=f"{Path(path).name} ({schema_name})")
    return document


def iter_violations(
    documents: Iterable[tuple[Any, Mapping[str, Any] | bool]],
    *,
    registry: SchemaRegistry | None = None,
) -> Iterable[ContractViolation]:
    """Validate several (instance, schema) pairs, yielding every violation."""
    registry = registry if registry is not None else default_registry()
    for instance, schema in documents:
        yield from validate(instance, schema, registry=registry)
