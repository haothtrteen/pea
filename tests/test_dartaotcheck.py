"""Dart-AOT-check domain tests: what is observed, and what is refused.

The load-bearing assertions here are the refusals. A domain that reads a
Flutter snapshot and concludes "obfuscated" or "recovery rate: 0%" from a
string scan would be manufacturing evidence, so those two answers are
asserted to stay ``unknown`` no matter what the fixture contains.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

from pea.artifactscan import ArtifactEntry, ArtifactScanResult
from pea.dartaotcheck import (
    DART_SNAPSHOT_ANCHORS,
    MAX_STRINGS_PER_SNAPSHOT,
    observe_dart_aot,
)
from pea.tiers import TIER_TOOL_EFFICIENCY

ANCHOR = "_kDartVmSnapshotInstructions"


def _elf_with_strings(strings: tuple[str, ...]) -> bytes:
    """An ELF-identifiable container whose tail carries the test strings."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack("<HHIQQQIHHHHHH", 3, 0xB7, 1, 0, 64, 0, 0, 64, 56, 0, 64, 0, 0)
    body = b"".join(s.encode() + b"\x00" for s in strings)
    return header + body


def _manifest(root: Path, entries: tuple[tuple[str, str], ...]) -> ArtifactScanResult:
    return ArtifactScanResult(
        project_path=str(root),
        artifacts=tuple(ArtifactEntry(path=rel, kind=kind, size_bytes=0, sha256=None) for rel, kind in entries),
        findings=(),
        coverage={"state": "complete_for_scope", "scope": "test fixture", "omissions": []},
        unknowns=(),
    )


def _write(root: Path, rel: str, data: bytes) -> str:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return rel


# --------------------------------------------------------------------------
# observation
# --------------------------------------------------------------------------


def test_snapshot_with_anchors_and_pool_shapes_is_observed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project,
        "lib/arm64-v8a/libapp.so",
        _elf_with_strings((ANCHOR, "_kDartIsolateSnapshotInstructions", "_LicenseService", "LicenseWidget", "https://api.example.com/v1", "3.24.3")),
    )

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libapp.so", "flutter_dart_snapshot"),)))

    finding = result.findings[0]
    assert finding["id"] == "dart-aot-observable"
    assert finding["status"] == "observed"
    assert finding["exposure_tier"] == TIER_TOOL_EFFICIENCY
    obs = result.snapshots[0]
    assert ANCHOR in obs.anchors_found
    assert obs.shape_counts.get("dart_private_identifier", 0) >= 1
    assert obs.shape_counts.get("camel_case_identifier", 0) >= 1
    assert obs.shape_counts.get("url", 0) >= 1
    assert obs.shape_counts.get("version_shape", 0) >= 1
    assert result.coverage["state"] == "complete_for_scope"


def test_snapshot_without_anchors_is_still_observed_with_lower_efficiency(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/arm64-v8a/libapp.so", _elf_with_strings(("SomeWidget", "3.24.3")))

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libapp.so", "flutter_dart_snapshot"),)))

    assert result.snapshots[0].anchors_found == ()
    # 锚点缺失只影响工具效率，不改变"快照存在"这一事实
    assert "未命中" not in result.findings[0]["summary"]
    assert "需扫描或版本匹配" in result.findings[0]["summary"]


def test_engine_only_manifest_flags_unassessed_snapshot(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/arm64-v8a/libflutter.so", _elf_with_strings(("3.24.3",)))

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libflutter.so", "flutter_engine"),)))

    assert result.findings[0]["id"] == "dart-aot-observable"
    assert "未发现快照产物" in result.findings[0]["summary"]
    assert any("快照面未评估" in u for u in result.unknowns)


def test_multi_abi_snapshots_are_each_observed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
        _write(project, f"lib/{abi}/libapp.so", _elf_with_strings((ANCHOR,)))

    result = observe_dart_aot(
        _manifest(
            project,
            tuple((f"lib/{abi}/libapp.so", "flutter_dart_snapshot") for abi in ("arm64-v8a", "armeabi-v7a", "x86_64")),
        )
    )

    assert len(result.snapshots) == 3
    assert result.findings[0]["status"] == "observed"


# --------------------------------------------------------------------------
# refusal: the two answers this domain must never manufacture
# --------------------------------------------------------------------------


def test_obfuscation_status_is_never_claimed(tmp_path):
    """No fixture may produce an obfuscation verdict - it needs build evidence."""
    project = tmp_path / "project"
    project.mkdir()
    # Even a "clean" snapshot with no readable identifiers stays unknown.
    _write(project, "lib/arm64-v8a/libapp.so", _elf_with_strings((ANCHOR,)))

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libapp.so", "flutter_dart_snapshot"),)))

    text = " ".join(result.findings[0]["limitations"]) + " ".join(result.unknowns)
    assert "混淆状态未知" in text or "是否启用 --obfuscate 无法" in text
    assert not any("obfuscated" in json_value for json_value in _flatten(result.findings))
    assert not any("已混淆" in json_value for json_value in _flatten(result.findings))


def test_recovery_rate_is_never_reported(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/arm64-v8a/libapp.so", _elf_with_strings((ANCHOR, "_LicenseService")))

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libapp.so", "flutter_dart_snapshot"),)))

    flat = " ".join(_flatten(result.findings))
    # Declaring "we do not report a recovery rate" is required; stating one
    # (any number attached to 恢复率) is the failure this asserts against.
    assert not re.search(r"恢复率\s*[:：=为]?\s*\d", flat)
    assert any("恢复率" in u for u in result.unknowns)


def test_empty_manifest_is_unknown_not_pass(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = observe_dart_aot(_manifest(project, ()))

    finding = result.findings[0]
    assert finding["id"] == "dart-aot-absent"
    assert finding["status"] == "unknown"
    assert result.coverage["state"] == "not_run"
    assert finding["exposure_tier"] == TIER_TOOL_EFFICIENCY


def test_manifest_without_dart_artifacts_is_unknown(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libnative.so", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200)

    result = observe_dart_aot(_manifest(project, (("lib/libnative.so", "native_shared_library"),)))

    assert result.findings[0]["status"] == "unknown"
    assert result.snapshots == ()


def test_unreadable_snapshot_is_an_omission_and_unknown(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libapp.so", "flutter_dart_snapshot"),)))

    finding = result.findings[0]
    assert finding["id"] == "dart-aot-unreadable"
    assert finding["status"] == "unknown"
    assert any("无法读取" in o for o in result.coverage["omissions"])
    assert result.coverage["state"] == "partial"


def test_entry_outside_root_is_refused(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "libapp.so", _elf_with_strings((ANCHOR,)))

    result = observe_dart_aot(_manifest(project, (("../outside/libapp.so", "flutter_dart_snapshot"),)))

    assert result.snapshots == ()
    assert any("越出项目边界" in o for o in result.coverage["omissions"])


def test_string_cap_is_an_omission_not_a_silent_truncation(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    payload = b"".join(f"LicenseWidget{i}\x00".encode() for i in range(MAX_STRINGS_PER_SNAPSHOT + 50))
    _write(project, "lib/arm64-v8a/libapp.so", _elf_with_strings((ANCHOR,)) + payload)

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libapp.so", "flutter_dart_snapshot"),)))

    assert result.snapshots[0].truncated is True
    assert any("超过提取上限" in o for o in result.coverage["omissions"])
    assert result.coverage["state"] == "partial"


# --------------------------------------------------------------------------
# contract surface
# --------------------------------------------------------------------------


def test_result_is_json_serializable(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/arm64-v8a/libapp.so", _elf_with_strings((ANCHOR, "LicenseWidget")))

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libapp.so", "flutter_dart_snapshot"),)))

    payload = result.to_dict()
    assert payload["snapshots"][0]["anchors_found"] == [ANCHOR]
    assert isinstance(payload["findings"][0]["evidence"][0]["observed_at"], str)


@pytest.mark.parametrize("anchor", DART_SNAPSHOT_ANCHORS)
def test_every_anchor_is_recognized(tmp_path, anchor):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/arm64-v8a/libapp.so", _elf_with_strings((anchor,)))

    result = observe_dart_aot(_manifest(project, (("lib/arm64-v8a/libapp.so", "flutter_dart_snapshot"),)))

    assert anchor in result.snapshots[0].anchors_found


def _flatten(node: object) -> list[str]:
    """All string values in a nested structure, for 'never claim X' assertions."""
    out: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            out.append(str(key))
            out.extend(_flatten(value))
    elif isinstance(node, (list, tuple)):
        for value in node:
            out.extend(_flatten(value))
    else:
        out.append(str(node))
    return out
