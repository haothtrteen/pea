"""Build-integration domain tests: declared vs shipped, and the honest unknown.

The domain exists to catch one specific failure - a build configuration that
declares protection for a target that never gets emitted. Its most important
assertions are therefore about the *absence* of a verdict: no declaration
found means unknown, never "the build is fine".
"""
from __future__ import annotations

from pathlib import Path

from pea.artifactscan import ArtifactEntry, ArtifactScanResult
from pea.buildint import BUILD_CONFIG_BASENAMES, discover_build_configs, verify_build_integration
from pea.tiers import TIER_TOOL_EFFICIENCY

GRADLE_TWO_ABIS = """
android {
    defaultConfig {
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a'
        }
    }
}
"""

GRADLE_THREE_ABIS = """
android {
    defaultConfig {
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'
        }
    }
}
"""

GRADLE_NO_ABI = """
android {
    defaultConfig {
        applicationId "com.example.app"
    }
}
"""

GRADLE_COMMENT_ONLY = """
// this app supports arm64-v8a in theory
android {
    compileSdk 34
}
"""


def _manifest(root: Path, entries: tuple[str, ...]) -> ArtifactScanResult:
    return ArtifactScanResult(
        project_path=str(root),
        artifacts=tuple(
            ArtifactEntry(path=rel, kind="native_shared_library", size_bytes=0, sha256=None) for rel in entries
        ),
        findings=(),
        coverage={"state": "complete_for_scope", "scope": "test fixture", "omissions": []},
        unknowns=(),
    )


def _write(root: Path, rel: str, data: str) -> str:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data)
    return rel


# --------------------------------------------------------------------------
# matched / missing / unverifiable
# --------------------------------------------------------------------------


def test_declared_abis_present_in_manifest_are_matched(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_TWO_ABIS)

    result = verify_build_integration(
        _manifest(project, ("lib/arm64-v8a/libapp.so", "lib/armeabi-v7a/libapp.so"))
    )

    assert result.findings[0]["id"] == "build-integration-verified"
    assert result.findings[0]["severity"] == "info"
    assert {c.status for c in result.checks} == {"matched"}
    assert len(result.checks) == 2
    assert result.coverage["state"] == "complete_for_scope"


def test_declared_abi_without_artifacts_is_missing_and_medium(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_THREE_ABIS)

    result = verify_build_integration(
        _manifest(project, ("lib/arm64-v8a/libapp.so", "lib/armeabi-v7a/libapp.so"))
    )

    missing = [c for c in result.checks if c.status == "missing"]
    assert [c.expectation for c in missing] == ["abi:x86_64"]
    assert result.findings[0]["severity"] == "medium"
    # 声明未落到产物：该 ABI 上的措施是否生效成为 unknown
    assert any("保护措施是否生效" in u for u in result.unknowns)


def test_abi_without_declaration_is_unverifiable_not_matched(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_TWO_ABIS)

    result = verify_build_integration(
        _manifest(project, ("lib/arm64-v8a/libapp.so", "lib/x86/libapp.so"))
    )

    unverifiable = [c for c in result.checks if c.status == "unverifiable"]
    assert [c.expectation for c in unverifiable] == ["abi:x86"]
    assert result.coverage["state"] == "partial"


def test_abi_mentioned_only_in_a_comment_is_not_a_declaration(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_COMMENT_ONLY)

    configs, _omissions = discover_build_configs(project)
    assert configs and configs[0].declared_abis == ()


def test_config_without_abi_lines_yields_no_expectations(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_NO_ABI)

    result = verify_build_integration(_manifest(project, ("lib/arm64-v8a/libapp.so",)))

    assert result.findings[0]["id"] == "build-integration-no-declaration"
    assert result.findings[0]["status"] == "unknown"
    # 无声明时实际存在的 ABI 记为 unverifiable，绝不升级为 matched：
    # 产物存在不能被当作"声明已满足"。
    assert [(c.expectation, c.status) for c in result.checks] == [("abi:arm64-v8a", "unverifiable")]


# --------------------------------------------------------------------------
# refusal paths
# --------------------------------------------------------------------------


def test_no_config_files_is_unknown_not_pass(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "src/main.dart", "void main() {}")

    result = verify_build_integration(_manifest(project, ("lib/arm64-v8a/libapp.so",)))

    finding = result.findings[0]
    assert finding["id"] == "build-integration-no-declaration"
    assert finding["status"] == "unknown"
    assert result.coverage["state"] == "not_run"
    assert finding["exposure_tier"] == TIER_TOOL_EFFICIENCY
    assert any("无声明 ≠ 构建正确" in f or "未机器读取" in f for f in [finding["summary"]])


def test_declarations_with_empty_manifest_are_unverifiable(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_TWO_ABIS)

    result = verify_build_integration(_manifest(project, ()))

    finding = result.findings[0]
    assert finding["id"] == "build-integration-no-artifacts"
    assert finding["status"] == "unknown"
    assert finding["coverage"]["state"] == "not_run"


def test_unusable_root_is_an_omission_not_an_empty_pass(tmp_path):
    sources, omissions = discover_build_configs(tmp_path / "does-not-exist")

    assert sources == ()
    assert omissions and any("项目根不可用" in o for o in omissions)


def test_finding_declares_inference_vs_observation_authority(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_TWO_ABIS)

    result = verify_build_integration(_manifest(project, ("lib/arm64-v8a/libapp.so",)))

    limitations = " ".join(result.findings[0]["limitations"])
    assert "inference" in limitations
    assert "observation" in limitations
    # 可复现性与溯源不在本域视野内
    assert any("可复现性" in u for u in result.unknowns)


# --------------------------------------------------------------------------
# contract surface
# --------------------------------------------------------------------------


def test_result_is_json_serializable(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_TWO_ABIS)

    result = verify_build_integration(_manifest(project, ("lib/arm64-v8a/libapp.so",)))

    payload = result.to_dict()
    assert payload["checks"][0]["expectation"] == "abi:arm64-v8a"
    assert payload["configs"][0]["basename"] == "build.gradle"
    assert isinstance(payload["findings"][0]["evidence"][0]["observed_at"], str)


def test_known_config_basenames_are_declared():
    for name in ("build.gradle", "pubspec.yaml", "CMakeLists.txt", "Cargo.toml"):
        assert name in BUILD_CONFIG_BASENAMES


def test_multiple_config_files_are_both_read(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "build.gradle", GRADLE_TWO_ABIS)
    _write(project, "app/build.gradle", "android { defaultConfig { ndk { abiFilters 'x86_64' } } }")

    result = verify_build_integration(
        _manifest(project, ("lib/arm64-v8a/libapp.so", "lib/armeabi-v7a/libapp.so", "lib/x86_64/libapp.so"))
    )

    assert len(result.configs) == 2
    assert {c.expectation for c in result.checks} == {"abi:arm64-v8a", "abi:armeabi-v7a", "abi:x86_64"}
    assert all(c.status == "matched" for c in result.checks)
