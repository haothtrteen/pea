"""Field feedback loop (D7) tests: cracked intake and the response plan.

The diff is the observation; the layer attribution is an inference; added
files are unknowns. The response is a server-side goalpost move - never a
code push into the cracked package - and an offline-only posture is
declined outright rather than answered with an empty plan.
"""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from pea.artifactscan import ArtifactEntry
from pea.fieldresponse import (
    _LAYER_BY_KIND,
    FIELD_RED_LINES,
    FieldResponseBoundaryError,
    design_field_response,
    diff_manifests,
    intake_cracked_artifact,
    intake_evidence_records,
)
from pea.mcpserver import ToolContext, call_tool

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"


def _validator(name: str) -> Draft202012Validator:
    resources = [
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in (
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        )
        if "$id" in schema
    ]
    return Draft202012Validator(
        json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8")),
        registry=Registry().with_resources(resources),
    )


def _entry(path: str, digest: str, kind: str = "flutter_dart_snapshot", size: int = 100) -> ArtifactEntry:
    return ArtifactEntry(path=path, kind=kind, size_bytes=size, sha256=digest)


# ---------------------------------------------------------------------------
# Manifest diff
# ---------------------------------------------------------------------------


class TestManifestDiff:
    def test_digest_change_is_modified(self):
        diffs = diff_manifests([_entry("libapp.so", "a" * 64)], [_entry("libapp.so", "b" * 64)])
        assert len(diffs) == 1
        assert diffs[0].change == "modified"

    def test_identical_digests_produce_no_diff(self):
        assert diff_manifests([_entry("libapp.so", "a" * 64)], [_entry("libapp.so", "a" * 64)]) == ()

    def test_one_sided_entries_are_added_or_removed(self):
        diffs = diff_manifests([_entry("keep.so", "a" * 64)], [_entry("keep.so", "a" * 64), _entry("new.so", "b" * 64, kind="asset")])
        assert [d.change for d in diffs] == ["added"]
        diffs = diff_manifests([_entry("keep.so", "a" * 64), _entry("gone.so", "c" * 64)], [_entry("keep.so", "a" * 64)])
        assert [d.change for d in diffs] == ["removed"]

    def test_size_change_without_digests_is_still_a_diff(self):
        """An unfingerprinted file cannot support a byte-level claim, but a
        size difference is observable and must not be silently dropped."""
        diffs = diff_manifests(
            [ArtifactEntry(path="x.so", kind="native_library", size_bytes=10, sha256=None)],
            [ArtifactEntry(path="x.so", kind="native_library", size_bytes=20, sha256=None)],
        )
        assert [d.change for d in diffs] == ["modified"]
        assert diffs[0].baseline_sha256 is None


# ---------------------------------------------------------------------------
# Crack intake
# ---------------------------------------------------------------------------


def _cracked_tree(tmp_path: Path) -> tuple[Path, Path]:
    baseline = tmp_path / "baseline"
    cracked = tmp_path / "cracked"
    (baseline / "lib" / "arm64-v8a").mkdir(parents=True)
    (cracked / "lib" / "arm64-v8a").mkdir(parents=True)
    (baseline / "lib" / "arm64-v8a" / "libapp.so").write_bytes(b"original-snapshot")
    (cracked / "lib" / "arm64-v8a" / "libapp.so").write_bytes(b"patched-snapshot!!")
    # An added *shippable* file: the manifest domain enumerates shippable
    # forms only, so a non-artifact file would be invisible to the diff by
    # design (and the unknowns say so).
    (cracked / "lib" / "arm64-v8a" / "libpatch.so").write_bytes(b"extra-native")
    return baseline, cracked


class TestCrackIntake:
    def test_intake_locates_the_change_and_declares_unknowns(self, tmp_path):
        baseline, cracked = _cracked_tree(tmp_path)
        result = intake_cracked_artifact(cracked, baseline, now="2026-10-14T00:00:00+00:00")
        payload = result.to_dict()
        assert [d.change for d in result.diffs] == ["modified", "added"]
        # the diff fact is an observation; the layer attribution is an inference
        diff_finding = next(f for f in result.findings if f["id"] == "crack-intake-manifest-diff")
        assert diff_finding["status"] == "observed"
        attribution = next(f for f in result.findings if f["category"] == "field_incident_layer_attribution")
        assert attribution["status"] == "inferred"
        # the added file is an unknown, not an assumed payload
        assert any("新增文件" in u and "不得假定为恶意载荷" in u for u in result.unknowns)
        assert payload["coverage"]["state"] == "partial"

    def test_findings_conform_to_exposure_finding_schema(self, tmp_path):
        baseline, cracked = _cracked_tree(tmp_path)
        result = intake_cracked_artifact(cracked, baseline, now="2026-10-14T00:00:00+00:00")
        validator = _validator("exposure-finding.schema.json")
        for finding in result.findings:
            errors = list(validator.iter_errors(finding))
            assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)

    def test_missing_root_is_a_named_refusal(self, tmp_path):
        baseline, _ = _cracked_tree(tmp_path)
        try:
            intake_cracked_artifact(tmp_path / "nope", baseline)
        except FieldResponseBoundaryError:
            pass
        else:
            raise AssertionError("a non-directory root must be refused")

    def test_evidence_records_carry_both_authority_levels(self, tmp_path):
        baseline, cracked = _cracked_tree(tmp_path)
        result = intake_cracked_artifact(cracked, baseline, now="2026-10-14T00:00:00+00:00")
        records = intake_evidence_records(result)
        authorities = {r["authority"] for r in records}
        assert authorities == {"observation", "inference"}, "diff fact and layer attribution must travel under separate labels"


# ---------------------------------------------------------------------------
# Field response
# ---------------------------------------------------------------------------


def _intake_payload(tmp_path: Path) -> dict:
    baseline, cracked = _cracked_tree(tmp_path)
    return intake_cracked_artifact(cracked, baseline, now="2026-10-14T00:00:00+00:00").to_dict()


class TestFieldResponse:
    def test_response_conforms_to_schema(self, tmp_path):
        response = design_field_response(_intake_payload(tmp_path), plan_id="plan-x")
        errors = list(_validator("field-response.schema.json").iter_errors(response))
        assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)

    def test_measures_are_server_side_goalpost_moves(self, tmp_path):
        response = design_field_response(_intake_payload(tmp_path))
        assert response["posture"] == "server_side_available"
        assert response["measures"]
        for measure in response["measures"]:
            assert measure["kind"] == "server_side_goalpost_move"
            assert measure["rollout"] == "gray", "new rules start gray; full rollout needs the negative tests first"
            assert "libapp.so" in measure["trigger_artifact"]
            assert "轮换" in measure["rationale"]

    def test_negative_tests_include_legitimate_variants(self, tmp_path):
        response = design_field_response(_intake_payload(tmp_path))
        scenarios = {t["scenario"] for t in response["negative_tests"]}
        assert "legitimate_variant_unaffected" in scenarios, "the no-collateral red line can never be dropped"
        assert "cracked_variant_fails" in scenarios

    def test_offline_posture_is_declined_not_emptied(self, tmp_path):
        response = design_field_response(_intake_payload(tmp_path), offline_required=True)
        assert response["posture"] == "declined_offline_only"
        assert response["measures"] == []
        assert any("纯离线" in u for u in response["unknowns"])

    def test_red_lines_are_fixed(self, tmp_path):
        response = design_field_response(_intake_payload(tmp_path))
        assert response["red_lines"] == list(FIELD_RED_LINES)
        joined = "\n".join(response["red_lines"])
        assert "中性失效" in joined
        assert "不触碰攻击者设备" in joined
        assert "不往已分发的破解包推送代码" in joined

    def test_response_id_is_deterministic(self, tmp_path):
        payload = _intake_payload(tmp_path)
        assert design_field_response(payload)["response_id"] == design_field_response(payload)["response_id"]

    def test_layer_map_covers_the_mobile_snapshot(self):
        assert _LAYER_BY_KIND["flutter_dart_snapshot"] == "tool_efficiency"


# ---------------------------------------------------------------------------
# MCP surface
# ---------------------------------------------------------------------------


def _ctx(root: Path) -> ToolContext:
    return ToolContext(authorized_root=root, authorization="owner")


class TestFieldResponseMcp:
    def test_intake_runs_through_dispatch(self, tmp_path):
        baseline, cracked = _cracked_tree(tmp_path)
        root = tmp_path
        result = call_tool(
            "pea.intake_cracked_artifact",
            {"cracked_path": str(cracked), "baseline_path": str(baseline)},
            _ctx(root),
        )
        assert result.ok, result.detail
        assert [d["change"] for d in result.data["diffs"]] == ["modified", "added"]

    def test_intake_refuses_paths_outside_the_authorized_root(self, tmp_path):
        baseline, cracked = _cracked_tree(tmp_path)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        result = call_tool(
            "pea.intake_cracked_artifact",
            {"cracked_path": str(cracked), "baseline_path": str(baseline)},
            _ctx(elsewhere),
        )
        assert not result.ok and result.error in {"path_outside_authorized_root", "authorization_not_confirmed"}

    def test_design_field_response_rejects_non_object_intake(self):
        result = call_tool("pea.design_field_response", {"intake": "not-an-object"}, _ctx(Path(".")))
        assert not result.ok and result.error == "intake_invalid"

    def test_design_field_response_runs(self, tmp_path):
        payload = _intake_payload(tmp_path)
        result = call_tool("pea.design_field_response", {"intake": payload}, _ctx(tmp_path))
        assert result.ok, result.detail
        assert result.data["posture"] == "server_side_available"
