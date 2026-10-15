"""String-symbol-scan domain tests: bounded extraction and redaction.

The domain's contract: strings are matched in memory and discarded, bounds
report themselves, and an empty manifest is an unknown - never a pass.
"""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from pea import symbolscan
from pea.artifactscan import observe_artifacts
from pea.symbolscan import (
    MIN_STRING_LENGTH,
    STRING_SCAN_BYTES,
    SymbolScanResult,
    extract_strings,
    observe_strings_symbols,
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


def _fake_native_lib() -> bytes:
    """A binary-shaped blob with deliberately planted leak strings."""
    parts = [
        b"\x7fELF\x02\x01\x01\x00",
        b"\x00" * 8,
        b"https://api.example.invalid/v1/verify\x00",
        b"dev@example.invalid\x00",
        b"_ZN7License6verifyEv\x00",
        b"Java_com_example_nativeCheck\x00",
        b"/home/builder/project/lib/main.dart\x00",
        b"license signature token secret\x00",
        b"ab\x00",  # 短于最小串长，应被忽略
        b"plain text without leaks\x00",
        b"\x00" * 16,
    ]
    return b"".join(parts)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


class TestExtractStrings:
    def test_printable_runs_above_min_length(self, tmp_path: Path) -> None:
        blob = tmp_path / "lib.so"
        blob.write_bytes(b"\x7fELF\x00hello-world\x00ab\x00second-string\x00")
        strings, truncated = extract_strings(blob)
        assert strings == ["hello-world", "second-string"]
        assert truncated is False

    def test_non_ascii_bytes_break_runs(self, tmp_path: Path) -> None:
        blob = tmp_path / "lib.so"
        blob.write_bytes(b"caf\xc3\xa9-latte\x00tail\x00")
        strings, _ = extract_strings(blob)
        assert "tail" in strings
        assert all(s.isascii() for s in strings)

    def test_byte_cap_reports_truncated(self, tmp_path: Path) -> None:
        blob = tmp_path / "lib.so"
        blob.write_bytes(b"x" * 100)
        strings, truncated = extract_strings(blob, max_bytes=10)
        # 前 10 字节构成一个完整可打印串；截断的是*其余* 90 字节
        assert strings == ["xxxxxxxxxx"]
        assert truncated is True

    def test_string_count_cap_reports_truncated(self, tmp_path: Path) -> None:
        blob = tmp_path / "lib.so"
        blob.write_bytes(b"\x00".join(b"string-%04d" % i for i in range(50)) + b"\x00")
        strings, truncated = extract_strings(blob, max_strings=5)
        assert len(strings) == 5
        assert truncated is True

    def test_min_length_constant_is_sane(self) -> None:
        assert MIN_STRING_LENGTH >= 4
        assert STRING_SCAN_BYTES > 0


class TestArtifactScan:
    def test_planted_leak_strings_are_counted_never_emitted(self, tmp_path: Path) -> None:
        _write(tmp_path / "lib" / "arm64-v8a" / "libnative.so", _fake_native_lib())
        manifest = observe_artifacts(tmp_path, now=NOW)
        result = observe_strings_symbols(manifest, now=NOW)
        entry = result.scanned[0]
        assert entry.pattern_counts.get("url") == 1
        assert entry.pattern_counts.get("email") == 1
        assert entry.pattern_counts.get("cxx_mangled_symbol") == 1
        assert entry.pattern_counts.get("jni_symbol") == 1
        assert entry.pattern_counts.get("build_path") == 1
        assert entry.pattern_counts.get("source_file_reference") == 1
        # "license signature token secret" 与 mangled 符号 _ZN7License… 各命中一次
        # （关键字大小写不敏感——类名里的 License 同样是真实信号）
        assert entry.pattern_counts.get("license_keyword") == 2
        # 脱敏：提取的字符串不出现在任何输出里
        blob = json.dumps(result.to_dict(), ensure_ascii=False)
        assert "api.example.invalid" not in blob
        assert "_ZN7License6verifyEv" not in blob
        assert "Java_com_example_nativeCheck" not in blob
        assert "/home/builder" not in blob
        assert "dev@example.invalid" not in blob
        finding = result.findings[0]
        assert finding["status"] == "observed"
        assert finding["severity"] == "medium"
        assert finding["exposure_tier"] == "static_content"

    def test_clean_artifact_is_observed_non_result(self, tmp_path: Path) -> None:
        _write(tmp_path / "libnative.so", b"\x7fELF\x00only boring strings here\x00")
        manifest = observe_artifacts(tmp_path, now=NOW)
        result = observe_strings_symbols(manifest, now=NOW)
        assert result.findings[0]["id"] == "string-symbol-scan-no-hits"
        assert result.findings[0]["severity"] == "info"
        assert "未命中不等于不存在" in " ".join(result.findings[0]["limitations"])

    def test_empty_manifest_is_unknown_degradation(self, tmp_path: Path) -> None:
        _write(tmp_path / "pubspec.yaml", b"name: demo\n")
        manifest = observe_artifacts(tmp_path, now=NOW)
        result = observe_strings_symbols(manifest, now=NOW)
        assert isinstance(result, SymbolScanResult)
        finding = result.findings[0]
        assert finding["status"] == "unknown"
        assert finding["severity"] == "unrated"
        assert finding["coverage"]["state"] == "not_run"
        # 拒绝而非假成功：unknown 明示未评估，并保持 T2 排序位置
        assert finding["exposure_tier"] == "static_content"
        assert any("未发现可扫描的二进制产物" in u for u in result.unknowns)

    def test_unreadable_artifact_is_omission_not_skip(self, tmp_path: Path, monkeypatch) -> None:
        _write(tmp_path / "libnative.so", _fake_native_lib())
        manifest = observe_artifacts(tmp_path, now=NOW)
        real = symbolscan.extract_strings

        def fake(path: Path, **kwargs):
            if path.name == "libnative.so":
                raise OSError("permission denied")
            return real(path, **kwargs)

        monkeypatch.setattr(symbolscan, "extract_strings", fake)
        result = observe_strings_symbols(manifest, now=NOW)
        assert result.scanned == ()
        assert any("无法读取" in o for o in result.coverage["omissions"])
        assert any("无法读取" in u for u in result.unknowns)

    def test_byte_cap_on_artifact_is_reported(self, tmp_path: Path, monkeypatch) -> None:
        _write(tmp_path / "libnative.so", _fake_native_lib())
        monkeypatch.setattr(symbolscan, "STRING_SCAN_BYTES", 16)
        manifest = observe_artifacts(tmp_path, now=NOW)
        result = observe_strings_symbols(manifest, now=NOW)
        assert result.scanned[0].truncated is True
        assert any("超过字符串提取上限" in o for o in result.coverage["omissions"])
        assert any("完整字符串集未知" in u for u in result.unknowns)


class TestContract:
    def test_findings_validate_against_schema(self, tmp_path: Path) -> None:
        _write(tmp_path / "libnative.so", _fake_native_lib())
        manifest = observe_artifacts(tmp_path, now=NOW)
        result = observe_strings_symbols(manifest, now=NOW)
        validator = _finding_validator()
        errors = [e for finding in result.findings for e in validator.iter_errors(finding)]
        assert errors == []

    def test_to_dict_is_json_serializable(self, tmp_path: Path) -> None:
        _write(tmp_path / "libnative.so", _fake_native_lib())
        manifest = observe_artifacts(tmp_path, now=NOW)
        result = observe_strings_symbols(manifest, now=NOW)
        blob = json.dumps(result.to_dict(), ensure_ascii=False)
        assert '"pattern_counts"' in blob

    def test_deterministic_for_fixed_clock(self, tmp_path: Path) -> None:
        _write(tmp_path / "libnative.so", _fake_native_lib())
        manifest = observe_artifacts(tmp_path, now=NOW)
        first = observe_strings_symbols(manifest, now=NOW)
        second = observe_strings_symbols(manifest, now=NOW)
        assert first.to_dict() == second.to_dict()

    def test_standing_unknown_declares_xref_gap(self, tmp_path: Path) -> None:
        _write(tmp_path / "libnative.so", _fake_native_lib())
        manifest = observe_artifacts(tmp_path, now=NOW)
        result = observe_strings_symbols(manifest, now=NOW)
        assert any("xrefs" in u for u in result.unknowns)
