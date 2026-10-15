"""Tests for the L2 verification layer itself.

The L2 layer's contract is three-state honesty: pins must bite (tampered
bytes fail the layer), dependency failures are unknown rather than pass,
and crashes on real bytes are fails rather than silent skips. These tests
tamper with staged bytes on purpose to prove each of those.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pea import l2verify
from pea.l2verify import Check, LayerResult

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

NOW = "2026-10-13T00:00:00+00:00"
ARMEABI_LIBAPP = "build/app/intermediates/merged_native_libs/release/out/lib/armeabi-v7a/libapp.so"


@pytest.fixture(scope="module")
def staged(tmp_path_factory):
    """One staged project-with-output tree shared by the read-only tests."""
    scratch = tmp_path_factory.mktemp("l2-stage")
    return l2verify.stage_project(
        ROOT / "demo" / "canary-flutter-licensing",
        ROOT / "demo" / "canary-artifacts",
        scratch,
    )


@pytest.fixture(scope="module")
def report(staged):
    return l2verify.verify_l2(staged, now=NOW)


class TestHappyPath:
    def test_every_layer_passes_on_the_real_fixture(self, report) -> None:
        assert report.status == "pass"
        assert [layer.layer for layer in report.layers] == [
            "recon",
            "secrets",
            "manifest",
            "native",
            "dart-aot",
            "build-integration",
            "cli-e2e",
        ]
        for layer in report.layers:
            assert layer.status == "pass", f"{layer.layer}: {[c for c in layer.checks if c.status != 'pass']}"

    def test_report_carries_the_synthetic_form_caveat(self, report) -> None:
        """The standing scope limitation travels with the result - it is
        never a footnote someone can drop."""
        payload = report.to_dict()
        assert any("合成形态" in note for note in payload["notes"])
        assert any("恢复率" in note for note in payload["notes"])
        markdown = report.to_markdown()
        assert "合成形态" in markdown and "恢复率" in markdown

    def test_staging_does_not_modify_the_fixtures(self, staged) -> None:
        checks = l2verify.verify_digests(ROOT / "demo" / "canary-artifacts", ROOT / "demo" / "canary-artifacts.manifest.json")
        assert all(c.status == "pass" for c in checks)
        assert (ROOT / "demo" / "canary-flutter-licensing" / "pubspec.yaml").is_file()


class TestPinsBite:
    def test_hardened_libapp_fails_the_native_layer(self, tmp_path) -> None:
        """Replace the armeabi-v7a libapp.so with a hardened ELF: the layer
        must fail the gap pin - this is the check that caught the ELF32
        p_flags offset bug, so it gets to prove it still bites."""
        import build_canary_artifacts as builder

        scratch = tmp_path / "stage"
        staged = l2verify.stage_project(
            ROOT / "demo" / "canary-flutter-licensing",
            ROOT / "demo" / "canary-artifacts",
            scratch,
        )
        hardened = builder._elf(
            bits=32,
            machine=0x28,
            endian="<",
            strings=builder.DART_ANCHORS + builder.DART_POOL_STRINGS,
            stack_flags=builder.PF_R,  # no executable stack
            symtab=False,  # stripped
        )
        (staged / ARMEABI_LIBAPP).write_bytes(hardened)
        result = l2verify.verify_l2(staged, now=NOW)
        assert result.status == "fail"
        native = next(layer for layer in result.layers if layer.layer == "native")
        failed = [c.name for c in native.checks if c.status == "fail"]
        assert "native-libapp-gaps:armeabi-v7a" in failed

    def test_tampered_bytes_fail_the_manifest_digests(self, tmp_path) -> None:
        scratch = tmp_path / "stage"
        staged = l2verify.stage_project(
            ROOT / "demo" / "canary-flutter-licensing",
            ROOT / "demo" / "canary-artifacts",
            scratch,
        )
        target = staged / ARMEABI_LIBAPP
        target.write_bytes(target.read_bytes() + b"\x00")
        result = l2verify.verify_l2(staged, now=NOW)
        assert result.status == "fail"
        manifest = next(layer for layer in result.layers if layer.layer == "manifest")
        assert any(c.status == "fail" for c in manifest.checks)

    def test_removed_artifact_fails_the_manifest_count(self, tmp_path) -> None:
        scratch = tmp_path / "stage"
        staged = l2verify.stage_project(
            ROOT / "demo" / "canary-flutter-licensing",
            ROOT / "demo" / "canary-artifacts",
            scratch,
        )
        (staged / "build/app/outputs/flutter-apk/app-release.apk").unlink()
        result = l2verify.verify_l2(staged, now=NOW)
        assert result.status == "fail"
        manifest = next(layer for layer in result.layers if layer.layer == "manifest")
        failed = [c.name for c in manifest.checks if c.status == "fail"]
        assert "manifest-count" in failed and "manifest-paths" in failed


class TestThreeStateMechanics:
    def test_domain_crash_is_a_fail_not_a_skip(self, staged, monkeypatch) -> None:
        def boom(*args, **kwargs):
            raise RuntimeError("synthetic crash on real bytes")

        monkeypatch.setattr(l2verify.recon, "observe", boom)
        result = l2verify.verify_l2(staged, now=NOW)
        assert result.status == "fail"
        recon_layer = next(layer for layer in result.layers if layer.layer == "recon")
        assert recon_layer.checks[0].name == "recon-crashed"
        assert recon_layer.checks[0].status == "fail"

    def test_manifest_dependency_failure_is_unknown_downstream(self, staged, monkeypatch) -> None:
        """The traversal crash fails the manifest layer; the three domains
        that consume it record unknown - a dependency failure is never a
        pass, and never a silent skip either."""

        def boom(*args, **kwargs):
            raise OSError("traversal refused")

        monkeypatch.setattr(l2verify.artifactscan, "observe_artifacts", boom)
        result = l2verify.verify_l2(staged, now=NOW)
        assert result.status == "fail"  # fail dominates unknown
        manifest = next(layer for layer in result.layers if layer.layer == "manifest")
        assert manifest.status == "fail"
        for layer_name in ("native", "dart-aot", "build-integration"):
            layer = next(item for item in result.layers if item.layer == layer_name)
            assert layer.status == "unknown", layer_name
            assert layer.checks[0].name == f"{layer_name}-dependency"

    def test_unknown_layer_makes_the_overall_status_unknown(self, staged, monkeypatch) -> None:
        monkeypatch.setattr(
            l2verify,
            "_layer_native",
            lambda scan, stamp: LayerResult(
                layer="native",
                purpose="patched",
                checks=(Check("native-coverage", "unknown", "domain declined to evaluate"),),
            ),
        )
        result = l2verify.verify_l2(staged, now=NOW)
        assert result.status == "unknown"
        assert l2verify.EXIT_CODES[result.status] == 2

    def test_expect_maps_three_states(self) -> None:
        assert l2verify._expect("x", True, "").status == "pass"
        assert l2verify._expect("x", False, "").status == "fail"
        assert l2verify._expect("x", None, "").status == "unknown"


class TestDigestsOnly:
    def test_checked_in_fixture_matches_manifest(self) -> None:
        checks = l2verify.verify_digests(ROOT / "demo" / "canary-artifacts", ROOT / "demo" / "canary-artifacts.manifest.json")
        assert len(checks) == 6
        assert all(c.status == "pass" for c in checks)

    def test_tampered_file_fails_digest(self, tmp_path) -> None:
        fixture = tmp_path / "fixture"
        fixture.mkdir()
        rows = json.loads((ROOT / "demo" / "canary-artifacts.manifest.json").read_text(encoding="utf-8"))["artifacts"]
        for row in rows:
            target = fixture / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"tampered")
        checks = l2verify.verify_digests(fixture, ROOT / "demo" / "canary-artifacts.manifest.json")
        assert all(c.status == "fail" for c in checks)


class TestCli:
    def test_verify_real_digests_only_exits_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_real.py"), "--digests-only"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "status: pass" in proc.stdout

    def test_verify_real_full_run_exits_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify_real.py"), "--json"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout[proc.stdout.index("{") :])
        assert payload["status"] == "pass"
        assert len(payload["layers"]) == 7
