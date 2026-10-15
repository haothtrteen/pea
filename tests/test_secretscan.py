"""Secret-scan domain tests: redaction discipline and honest non-results.

The two properties that matter most: matched content never appears in the
output, and "no hits" is never presented as proof of absence.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from pea.secretscan import SECRET_SNIFF_BYTES, SecretBoundaryError, observe_secrets

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
NOW = "2026-10-13T00:00:00+00:00"

#: The canary bait values - asserting their *absence* from output is the
#: whole point of the redaction discipline.
FAKE_KEY = "CANARY-FAKE-KEY-DO-NOT-USE-0000000000000000"
FAKE_ENDPOINT = "https://license.example-canary.invalid/verify"


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


class TestPatternHits:
    def test_canary_bait_is_hit_and_never_leaked(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "lib" / "auth" / "license_store.dart",
            "class LicenseStore {\n"
            f"  static const String verifyEndpoint = '{FAKE_ENDPOINT}';\n"
            f"  static const String embeddedKey = '{FAKE_KEY}';\n"
            "}\n",
        )
        result = observe_secrets(tmp_path, now=NOW)
        patterns = {(h.path, h.pattern) for h in result.hits}
        assert ("lib/auth/license_store.dart", "hardcoded_credential") in patterns
        assert ("lib/auth/license_store.dart", "hardcoded_endpoint") in patterns
        # 脱敏纪律：命中内容不出现在任何输出里
        blob = json.dumps(result.to_dict(), ensure_ascii=False)
        assert FAKE_KEY not in blob
        assert FAKE_ENDPOINT not in blob
        assert "license.example-canary.invalid" not in blob
        finding = result.findings[0]
        assert finding["secret_value_redacted"] is True
        assert finding["severity"] == "medium"  # 最高命中严重度聚合
        assert finding["exposure_tier"] == "static_content"

    def test_private_key_block_is_high_severity(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "certs" / "signing.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj\n-----END RSA PRIVATE KEY-----\n",
        )
        result = observe_secrets(tmp_path, now=NOW)
        hit = next(h for h in result.hits if h.pattern == "private_key_block")
        assert hit.severity == "high"
        assert result.findings[0]["severity"] == "high"

    def test_cloud_and_vcs_token_shapes(self, tmp_path: Path) -> None:
        _write(tmp_path / "config.yaml", "aws_key: AKIAIOSFODNN7EXAMPLE\n")
        _write(tmp_path / "ci.env", "GITHUB_TOKEN=ghp_0123456789abcdefghij0123456789abcdef\n")
        result = observe_secrets(tmp_path, now=NOW)
        patterns = {h.pattern for h in result.hits}
        assert "cloud_access_key_id" in patterns
        assert "vcs_token" in patterns

    def test_repeats_merge_into_counted_hit(self, tmp_path: Path) -> None:
        _write(
            tmp_path / "settings.py",
            "api_key = 'aaaaaaaaaaaaaaaa'\n"  # 测试用假值，非真实凭据
            "token = 'bbbbbbbbbbbbbbbb'\n"
            "api_key = 'cccccccccccccccc'\n",
        )
        result = observe_secrets(tmp_path, now=NOW)
        api_key_hits = [h for h in result.hits if h.pattern == "hardcoded_credential"]
        assert len(api_key_hits) == 1
        assert api_key_hits[0].count == 3
        assert api_key_hits[0].line == 1  # 首行

    def test_docs_and_binaries_are_out_of_scope(self, tmp_path: Path) -> None:
        _write(tmp_path / "README.md", "api_key = 'this-is-prose-not-a-secret'\n")
        (tmp_path / "blob.bin").write_bytes(b"\x7fELF\x00api_key = 'binary-bait'\x00")
        result = observe_secrets(tmp_path, now=NOW)
        assert result.hits == ()
        assert result.findings[0]["status"] == "observed"
        assert "未命中" in result.findings[0]["title"]

    def test_dotfile_basenames_are_scanned(self, tmp_path: Path) -> None:
        _write(tmp_path / ".env", "SECRET_TOKEN=supersecretvalue123\n")
        result = observe_secrets(tmp_path, now=NOW)
        assert any(h.path == ".env" for h in result.hits)


class TestHonestNonResults:
    def test_no_hits_is_observed_non_result_not_pass(self, tmp_path: Path) -> None:
        _write(tmp_path / "main.py", "print('hello')\n")
        result = observe_secrets(tmp_path, now=NOW)
        finding = result.findings[0]
        assert finding["id"] == "secret-scan-no-hits"
        assert finding["severity"] == "info"
        assert "未命中不等于不存在" in " ".join(finding["limitations"])
        assert finding["secret_value_redacted"] is True

    def test_oversize_file_becomes_omission_and_unknown(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("pea.secretscan.SECRET_SNIFF_BYTES", 32)
        _write(tmp_path / "big.yaml", "x" * 200 + "\napi_key = 'late-in-file-secret'\n")
        result = observe_secrets(tmp_path, now=NOW)
        assert result.hits == ()  # 超限部分未被扫描，不得假称干净
        assert any("超过嗅探上限" in o for o in result.coverage["omissions"])
        assert any("未扫描" in u for u in result.unknowns)

    def test_scope_boundary_unknown_is_always_declared(self, tmp_path: Path) -> None:
        _write(tmp_path / "main.py", "print('hello')\n")
        result = observe_secrets(tmp_path, now=NOW)
        assert any("二进制产物" in u for u in result.unknowns)


class TestContract:
    def test_findings_validate_against_schema(self, tmp_path: Path) -> None:
        _write(tmp_path / "app.py", "password = 'hunter2hunter2'\n")  # 测试用假值，非真实凭据
        result = observe_secrets(tmp_path, now=NOW)
        validator = _finding_validator()
        errors = [e for finding in result.findings for e in validator.iter_errors(finding)]
        assert errors == []

    def test_to_dict_is_json_serializable(self, tmp_path: Path) -> None:
        _write(tmp_path / "app.py", "token = 'abcdefghijklmnop'\n")  # 测试用假值，非真实凭据
        result = observe_secrets(tmp_path, now=NOW)
        assert '"secret_value_redacted"' in json.dumps(result.to_dict(), ensure_ascii=False)

    def test_deterministic_for_fixed_clock(self, tmp_path: Path) -> None:
        _write(tmp_path / "app.py", "token = 'abcdefghijklmnop'\n")  # 测试用假值，非真实凭据
        first = observe_secrets(tmp_path, now=NOW)
        second = observe_secrets(tmp_path, now=NOW)
        assert first.to_dict() == second.to_dict()

    def test_non_directory_root_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "file.txt"
        target.write_text("x", encoding="utf-8")
        with pytest.raises(SecretBoundaryError):
            observe_secrets(target, now=NOW)

    def test_bound_constant_is_positive(self) -> None:
        assert SECRET_SNIFF_BYTES > 0
