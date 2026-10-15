"""Read-only reconnaissance tests: profile accuracy and boundary safety.

The canary project is built inside ``tmp_path`` so every test starts from a
known tree - the repository also carries a static, rebuildable canary under
``demo/canary-flutter-licensing/`` for the end-to-end demo, and
``tests/test_demo_e2e.py`` asserts the two stay in sync conceptually.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from pea.recon import MAX_DEPTH, ReconBoundaryError, observe

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"


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


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def canary(tmp_path: Path) -> Path:
    """A minimal Flutter-shaped source tree with deliberately planted markers."""
    root = tmp_path / "canary-app"
    _write(root / "pubspec.yaml", "name: canary_app\ndependencies:\n  flutter:\n    sdk: flutter\n")
    _write(root / "lib" / "main.dart", "void main() {\n  runApp(const CanaryApp());\n}\n")
    _write(
        root / "lib" / "auth" / "license_validator.dart",
        "class LicenseValidator {\n"
        "  // verifyLicense: checks the RSA signature of the license token\n"
        "  bool verifyLicense(String token) => false;\n"
        "}\n",
    )
    _write(
        root / "android" / "app" / "build.gradle",
        "android {\n  defaultConfig { applicationId 'com.example.canary' }\n}\n",
    )
    _write(
        root / "android" / "app" / "src" / "main" / "kotlin" / "com" / "example" / "canary" / "MainActivity.kt",
        "package com.example.canary\n\nclass MainActivity : FlutterActivity()\n",
    )
    _write(root / "android" / "app" / "src" / "main" / "AndroidManifest.xml", "<manifest package='com.example.canary'/>\n")
    _write(root / "ios" / "Runner" / "Info.plist", "<plist/>\n")
    _write(root / "README.md", "# canary\n")
    return root


class TestProfileAccuracy:
    def test_identifies_languages_build_and_platforms(self, canary: Path) -> None:
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        languages = {obs.language: obs.file_count for obs in result.languages}
        assert languages.get("dart") == 2
        assert languages.get("kotlin") == 1  # .gradle is not a language; kts files would be
        assert "flutter_dart" in result.build_systems
        assert "gradle" in result.build_systems
        assert "android" in result.platforms
        assert "ios" in result.platforms

    def test_locates_authorization_logic_without_leaking_content(self, canary: Path) -> None:
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        hit_paths = {hit.path for hit in result.pattern_hits}
        assert "lib/auth/license_validator.dart" in hit_paths
        serialized = json.dumps(result.to_dict(), ensure_ascii=False)
        # The pattern name is reported; the matched source line is not.
        assert "verifyLicense" in serialized  # pattern name
        assert "checks the RSA signature" not in serialized  # matched text stays out

    def test_authorization_source_becomes_key_artifact_with_digest(self, canary: Path) -> None:
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        artifact = next(a for a in result.key_artifacts if a.path == "lib/auth/license_validator.dart")
        assert artifact.kind == "authorization_logic_source"
        assert artifact.sha256 is not None and len(artifact.sha256) == 64

    def test_absence_of_release_artifacts_is_unknown_not_absent(self, canary: Path) -> None:
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        assert any("未发现构建产物" in u for u in result.unknowns)
        absent = next(f for f in result.findings if f["id"] == "recon-release-artifacts-absent")
        assert absent["status"] == "unknown"

    def test_release_artifacts_are_detected_and_hashed(self, canary: Path) -> None:
        so = canary / "build" / "app" / "outputs" / "flutter-apk" / "arm64-v8a" / "libapp.so"
        _write(so, "elf-bytes-placeholder")
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        artifact = next(a for a in result.key_artifacts if a.path.endswith("libapp.so"))
        assert artifact.kind == "flutter_dart_snapshot"
        assert artifact.sha256 is not None
        present = next(f for f in result.findings if f["id"] == "recon-release-artifacts-present")
        assert present["status"] == "observed"

    def test_findings_conform_to_exposure_finding_schema(self, canary: Path) -> None:
        validator = _finding_validator()
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        assert result.findings
        for finding in result.findings:
            errors = list(validator.iter_errors(finding))
            assert not errors, f"{finding['id']}: {[e.message for e in errors]}"

    def test_deterministic_output_for_fixed_clock(self, canary: Path) -> None:
        first = observe(canary, now="2026-10-13T00:00:00+00:00").to_dict()
        second = observe(canary, now="2026-10-13T00:00:00+00:00").to_dict()
        assert first == second


class TestBoundarySafety:
    def test_non_directory_root_is_rejected(self, tmp_path: Path) -> None:
        target = tmp_path / "file.txt"
        target.write_text("x", encoding="utf-8")
        with pytest.raises(ReconBoundaryError):
            observe(target)

    def test_missing_root_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ReconBoundaryError):
            observe(tmp_path / "nope")

    def test_symlink_escape_is_skipped_and_reported(self, canary: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside-secret.txt"
        outside.write_text("license token super-secret\n", encoding="utf-8")
        (canary / "linked.txt").symlink_to(outside)
        (canary / "linkdir").symlink_to(tmp_path / "outside-dir", target_is_directory=True)
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        escaped = [o for o in result.coverage["omissions"] if "越出授权根" in o]
        assert escaped, "symlink escape must be reported, not silently followed"
        assert "outside-secret.txt" not in json.dumps(result.to_dict(), ensure_ascii=False)

    def test_vcs_directory_is_skipped(self, canary: Path) -> None:
        _write(canary / ".git" / "config", "[core]\n")
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        assert any(".git/" in o and "跳过" in o for o in result.coverage["omissions"])
        assert all(not hit.path.startswith(".git/") for hit in result.pattern_hits)

    def test_depth_cap_reports_omission(self, canary: Path) -> None:
        deep = canary
        for level in range(MAX_DEPTH + 2):
            deep = deep / f"level{level}"
        _write(deep / "buried.dart", "// buried\n")
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        assert any("超过遍历深度上限" in o for o in result.coverage["omissions"])
        assert any("部分目录" in u for u in result.unknowns)

    def test_binary_files_are_not_sniffed(self, canary: Path) -> None:
        blob = canary / "assets" / "blob.bin"
        blob.parent.mkdir(parents=True, exist_ok=True)
        blob.write_bytes(b"\x7fELF\x00\x00license\x00token")
        result = observe(canary, now="2026-10-13T00:00:00+00:00")
        assert all(not hit.path.endswith("blob.bin") for hit in result.pattern_hits)

    def test_empty_directory_yields_profile_with_unknowns(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        result = observe(empty, now="2026-10-13T00:00:00+00:00")
        assert result.languages == ()
        assert result.build_systems == ()
        assert result.coverage["state"] == "partial"
        assert result.unknowns
