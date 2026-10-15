"""Artifact-manifest domain tests: enumeration accuracy and digest honesty.

The domain's contract is that a manifest entry is either fingerprinted or
explicitly unfingerprinted - never silently missing a hash - and that an
empty manifest is an ``unknown``, not a pass.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from pea.artifactscan import (
    HASH_LIMIT_BYTES,
    MAX_HASHED_ARTIFACTS,
    ArtifactBoundaryError,
    observe_artifacts,
)

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
NOW = "2026-10-13T00:00:00+00:00"


def _finding_validator() -> Draft202012Validator:
    resources = [
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in (
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        )
        if "$id" in schema
    ]
    registry = Registry().with_resources(resources)
    schema = json.loads((SCHEMA_DIR / "exposure-finding.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=registry)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


ELF_HEADER = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32


class TestManifestAccuracy:
    def test_native_artifacts_are_classified_by_name_role(self, tmp_path: Path) -> None:
        _write(tmp_path / "build" / "app" / "outputs" / "libapp.so", ELF_HEADER + b"dart-snapshot-body")
        _write(tmp_path / "build" / "flutter" / "libflutter.so", ELF_HEADER + b"engine-body")
        result = observe_artifacts(tmp_path, now=NOW)
        kinds = {a.path: a.kind for a in result.artifacts}
        assert kinds == {
            "build/app/outputs/libapp.so": "flutter_dart_snapshot",
            "build/flutter/libflutter.so": "flutter_engine",
        }

    def test_generic_artifact_forms_are_covered(self, tmp_path: Path) -> None:
        _write(tmp_path / "app-release.apk", b"PK\x03\x04apk")
        _write(tmp_path / "core.jar", b"PK\x03\x04jar")
        _write(tmp_path / "module.wasm", b"\x00asm\x01\x00\x00\x00")
        _write(tmp_path / "classes.dex", b"dex\n035\x00")
        _write(tmp_path / "addon.node", b"\x7fELFnode")
        _write(tmp_path / "resources" / "app.asar", b"\x04\x00\x00\x00" + b"{}" * 8)  # ASAR 头部大小 + JSON 索引
        result = observe_artifacts(tmp_path, now=NOW)
        kinds = {a.path: a.kind for a in result.artifacts}
        assert kinds == {
            "app-release.apk": "android_package",
            "core.jar": "java_archive",
            "module.wasm": "webassembly_module",
            "classes.dex": "dalvik_dex",
            "addon.node": "node_native_addon",
            "resources/app.asar": "electron_asar_archive",
        }

    def test_non_artifact_files_are_not_listed(self, tmp_path: Path) -> None:
        _write(tmp_path / "pubspec.yaml", b"name: demo\n")
        _write(tmp_path / "lib" / "main.dart", b"void main() {}\n")
        _write(tmp_path / "build" / "intermediate" / "main.o", b"\x7fELFobject")  # 中间产物不入清单
        result = observe_artifacts(tmp_path, now=NOW)
        assert result.artifacts == ()
        assert result.findings[0]["status"] == "unknown"

    def test_digests_match_content_and_evidence_is_hash_kind(self, tmp_path: Path) -> None:
        body = ELF_HEADER + b"fingerprint-me"
        _write(tmp_path / "lib" / "libapp.so", body)
        result = observe_artifacts(tmp_path, now=NOW)
        entry = result.artifacts[0]
        assert entry.sha256 == hashlib.sha256(body).hexdigest()
        finding = result.findings[0]
        assert finding["status"] == "observed"
        assert len(finding["evidence"]) == 1
        record = finding["evidence"][0]
        assert record["kind"] == "hash"
        assert record["authority"] == "observation"
        assert record["artifact_digest"] == entry.sha256
        assert "libapp.so" in record["redacted_summary"]
        # finding 自身的 artifact_digest 指向首个产物
        assert finding["artifact_digest"] == entry.sha256

    def test_findings_validate_against_exposure_finding_schema(self, tmp_path: Path) -> None:
        _write(tmp_path / "libapp.so", ELF_HEADER + b"x")
        _write(tmp_path / "README.md", b"# nothing shippable here\n")
        result = observe_artifacts(tmp_path, now=NOW)
        validator = _finding_validator()
        errors = [e for finding in result.findings for e in validator.iter_errors(finding)]
        assert errors == []

    def test_to_dict_is_json_serializable(self, tmp_path: Path) -> None:
        _write(tmp_path / "libapp.so", ELF_HEADER + b"x")
        result = observe_artifacts(tmp_path, now=NOW)
        blob = json.dumps(result.to_dict(), ensure_ascii=False)
        assert '"flutter_dart_snapshot"' in blob


class TestDigestHonesty:
    def test_oversize_artifact_is_listed_without_digest_and_reported(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("pea.artifactscan.HASH_LIMIT_BYTES", 16)
        _write(tmp_path / "libapp.so", ELF_HEADER + b"much-larger-than-the-cap")
        result = observe_artifacts(tmp_path, now=NOW)
        entry = result.artifacts[0]
        assert entry.sha256 is None  # 未计算，绝不编造
        assert any("超过摘要大小上限" in o for o in result.coverage["omissions"])
        assert any("SHA-256" in u for u in result.unknowns)

    def test_hash_count_cap_is_reported_as_omission(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("pea.artifactscan.MAX_HASHED_ARTIFACTS", 1)
        _write(tmp_path / "a.so", ELF_HEADER + b"one")
        _write(tmp_path / "b.so", ELF_HEADER + b"two")
        result = observe_artifacts(tmp_path, now=NOW)
        digests = [a.sha256 for a in result.artifacts]
        assert sum(1 for d in digests if d) == 1
        assert any("超过摘要数量上限" in o for o in result.coverage["omissions"])

    def test_deterministic_for_fixed_clock(self, tmp_path: Path) -> None:
        _write(tmp_path / "libapp.so", ELF_HEADER + b"stable")
        first = observe_artifacts(tmp_path, now=NOW)
        second = observe_artifacts(tmp_path, now=NOW)
        assert first.to_dict() == second.to_dict()


class TestEmptyManifestIsUnknown:
    def test_source_only_tree_reports_unknown_with_tier_kept(self, tmp_path: Path) -> None:
        _write(tmp_path / "pubspec.yaml", b"name: demo\n")
        _write(tmp_path / "lib" / "main.dart", b"void main() {}\n")
        result = observe_artifacts(tmp_path, now=NOW)
        finding = result.findings[0]
        assert finding["status"] == "unknown"
        assert finding["severity"] == "unrated"
        # unknown 不丢序：未评估的产物面仍带 T1 标注
        assert finding["exposure_tier"] == "tool_efficiency"
        assert any("未发现" in u for u in result.unknowns)
        assert result.coverage["state"] == "partial"
        assert "未发现不等于不存在" in finding["limitations"][-1]

    def test_degradation_records_vcs_and_symlink_skips(self, tmp_path: Path) -> None:
        root = tmp_path / "project"
        _write(root / ".git" / "objects" / "libapp.so", ELF_HEADER + b"vcs-internal")
        outside = tmp_path / "outside"
        _write(outside / "libapp.so", ELF_HEADER + b"outside-root")
        (root / "escape-link").symlink_to(outside, target_is_directory=True)
        result = observe_artifacts(root, now=NOW)
        assert result.artifacts == ()  # VCS 内与越界链接都不进清单
        omissions = result.coverage["omissions"]
        assert any(".git/" in o and "跳过" in o for o in omissions)
        assert any("越出授权根" in o for o in omissions)


class TestBoundary:
    def test_non_directory_root_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "not-a-dir.txt"
        target.write_text("x", encoding="utf-8")
        with pytest.raises(ArtifactBoundaryError):
            observe_artifacts(target, now=NOW)

    def test_bounds_are_re_exported_for_tests(self) -> None:
        assert HASH_LIMIT_BYTES > 0 and MAX_HASHED_ARTIFACTS > 0
