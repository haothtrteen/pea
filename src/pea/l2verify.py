"""L2 真实工兵层：把域拿到真实字节上跑，对每条钉住的预期做三态判定。

为什么有这一层
------------
单元测试用合成 fixture 走 happy path，能证明"代码按设计运行"；这一层
把同一批域跑到**真实字节**上（ELF 程序头、zip 容器、快照锚点都是真实
结构），证明"设计本身是对的"。ELF32 程序头 ``p_flags`` 偏移错误和
ABI 目录匹配过窄两个 bug 都是在这一层暴露的——合成 fixture 的
happy path 对它们完全沉默。

三态语义（与项目纪律一致）
------------------------
* ``pass``——钉住的预期在真实字节上成立；
* ``fail``——预期不成立，或域在暂存树上崩溃（真实字节上的崩溃是缺陷，
  必须响亮，绝不降级为"跳过"）；
* ``unknown``——域自己拒绝评估（覆盖度不是 ``complete_for_scope``、
  ``not_run``/``unavailable``）。未评估从来不是通过。

``unknown`` 不丢序：整体状态在无 ``fail`` 但有 ``unknown`` 时是
``unknown``，退出码 2——验证层的绿灯只属于全量实测通过。

合成形态声明（standing scope limitation）
----------------------------------------
本层跑的是 ``demo/canary-artifacts`` 里的**合成形态**产物：ELF 头部与
埋标字符串是真实字节，但它们不是 Flutter 构建（本环境没有 Flutter
SDK）。因此"Dart AOT 恢复率"这类问题在本层恒为 ``unknown``——这一层
的存在是为了抓结构解析与域逻辑缺陷，不是为了给恢复率背书。
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import shutil
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea import artifactscan, buildint, dartaotcheck, nativecheck, recon, secretscan
from pea.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_CANARY = ROOT / "demo" / "canary-flutter-licensing"
DEFAULT_ARTIFACT_FIXTURE = ROOT / "demo" / "canary-artifacts"
DEFAULT_ARTIFACT_MANIFEST = ROOT / "demo" / "canary-artifacts.manifest.json"
DEFAULT_REQUEST = ROOT / "examples" / "protection-request.flutter-licensing.example.json"

#: Pins of the synthetic fixture design - these mirror
#: ``scripts/build_canary_artifacts.py`` on purpose: if the builder and the
#: layer disagree about what was planted, the layer must fail loudly.
EXPECTED_ARTIFACT_COUNT = 6
EXPECTED_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")
EXPECTED_ELF32_ABIS = ("armeabi-v7a",)
#: libapp.so is built unhardened on purpose; native-check must find these.
LIBAPP_GAPS = frozenset({"executable_stack", "unstripped_symbols"})
#: Planted markers: scan output may name the pattern, never the content.
MARKER_STRINGS = ("CANARY-FAKE-KEY", "license.example-canary.invalid")
EXPECTED_SECRET_PATTERNS = frozenset({"hardcoded_credential", "hardcoded_endpoint"})
#: The recovery-rate claim shape that must never appear in domain output.
_RECOVERY_RATE_CLAIM = re.compile(r"恢复率\s*[:：=为]?\s*\d")

STATUS_LABELS = {"pass": "通过（PASS）", "fail": "失败（FAIL）", "unknown": "未评估（UNKNOWN）"}
EXIT_CODES = {"pass": 0, "fail": 1, "unknown": 2}

#: Standing scope limitations, printed on every report - the synthetic-form
#: caveat travels with the result, it is never a footnote someone can drop.
STANDING_NOTES = (
    "产物为合成形态：ELF 头部与埋标字符串是真实字节，但不是 Flutter 构建（本环境无 Flutter SDK）。",
    "Dart AOT 恢复率未经本层实测，保持 unknown；本层不给出任何恢复率结论。",
    "本层按 REA 纪律单独触发，不进默认 CI。",
)


@dataclass(frozen=True)
class Check:
    """One pinned expectation and its three-state outcome."""

    name: str
    status: str  # pass | fail | unknown
    detail: str = ""


@dataclass(frozen=True)
class LayerResult:
    """One verification layer: what it proves, check by check."""

    layer: str
    purpose: str
    checks: tuple[Check, ...]

    @property
    def status(self) -> str:
        if any(c.status == "fail" for c in self.checks):
            return "fail"
        if any(c.status == "unknown" for c in self.checks):
            return "unknown"
        return "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "purpose": self.purpose,
            "status": self.status,
            "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in self.checks],
        }


@dataclass(frozen=True)
class L2Report:
    """The whole layer run: staged tree, per-layer results, standing notes."""

    staged_root: str
    generated_at: str
    layers: tuple[LayerResult, ...]
    notes: tuple[str, ...] = STANDING_NOTES

    @property
    def status(self) -> str:
        if any(layer.status == "fail" for layer in self.layers):
            return "fail"
        if any(layer.status == "unknown" for layer in self.layers):
            return "unknown"
        return "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": "L2",
            "status": self.status,
            "staged_root": self.staged_root,
            "generated_at": self.generated_at,
            "notes": list(self.notes),
            "layers": [layer.to_dict() for layer in self.layers],
        }

    def to_markdown(self) -> str:
        lines = [
            "# PEA L2 真实工兵层验证报告",
            "",
            f"- 整体状态：**{STATUS_LABELS[self.status]}**",
            f"- 暂存树：`{self.staged_root}`",
            f"- 生成时间：{self.generated_at}",
            "",
            "## 范围声明",
            "",
        ]
        lines.extend(f"- {note}" for note in self.notes)
        lines.extend(
            [
                "",
                "## 分层结果",
                "",
                "| 层 | 状态 | 通过 | 失败 | 未评估 |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for layer in self.layers:
            counts = {s: sum(1 for c in layer.checks if c.status == s) for s in ("pass", "fail", "unknown")}
            lines.append(
                f"| {layer.layer} | {STATUS_LABELS[layer.status]} | {counts['pass']} | {counts['fail']} | {counts['unknown']} |"
            )
        for layer in self.layers:
            lines.extend(
                [
                    "",
                    f"## {layer.layer}",
                    "",
                    layer.purpose,
                    "",
                    "| 检查 | 状态 | 说明 |",
                    "| --- | --- | --- |",
                ]
            )
            for check in layer.checks:
                lines.append(f"| `{check.name}` | {STATUS_LABELS[check.status]} | {check.detail or '-'} |")
        lines.append("")
        return "\n".join(lines)


def _expect(name: str, ok: bool | None, detail: str) -> Check:
    """Three-state expectation: True=pass, False=fail, None=unknown."""
    status = "pass" if ok is True else "fail" if ok is False else "unknown"
    return Check(name=name, status=status, detail=detail)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stage_project(source_canary: Path, artifact_fixture: Path, scratch: Path) -> Path:
    """Stage a project-with-build-output tree inside ``scratch``.

    Harness-only copy: the scanning domains stay read-only against the
    staged tree, and neither the source canary nor the artifact fixture is
    modified. The staged tree mirrors a real Flutter project layout -
    ``android/app/build.gradle`` next to ``build/app/outputs/...`` - which
    is the only way the build-integration domain has both sides to compare.
    """
    staged = scratch / "project"
    if staged.exists():
        shutil.rmtree(staged)
    shutil.copytree(source_canary, staged)
    shutil.copytree(artifact_fixture, staged, dirs_exist_ok=True)
    return staged


def _run_layer(layer: str, purpose: str, fn: Callable[[], tuple[Check, ...]]) -> LayerResult:
    """Run one layer; a crash on real bytes is a fail, never a silent skip."""
    try:
        checks = fn()
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        checks = (Check(f"{layer}-crashed", "fail", detail),)
        traceback.print_exc()
    return LayerResult(layer=layer, purpose=purpose, checks=checks)


def _layer_recon(staged: Path, stamp: str) -> LayerResult:
    def checks() -> tuple[Check, ...]:
        result = recon.observe(staged, now=stamp)
        state = result.coverage.get("state")
        omissions = result.coverage.get("omissions") or []
        hit_paths = {hit.path for hit in result.pattern_hits}
        built: list[Check] = [
            # recon's honest shape is partial-with-declared-limits: static
            # enumeration never covers runtime behavior. What must never
            # happen is a partial caused by skipped files inside the
            # declared scope, or limits that go undeclared.
            _expect(
                "recon-coverage-partial-by-declaration",
                state == "partial" and not omissions,
                f"coverage={state}, omissions={len(omissions)}",
            ),
        ]
        for expected in ("lib/auth/license_validator.dart", "lib/auth/license_store.dart"):
            built.append(
                _expect(
                    f"recon-pattern-hit:{expected}",
                    expected in hit_paths,
                    "planted authorization logic located" if expected in hit_paths else "planted logic not located",
                )
            )
        built.append(
            _expect(
                "recon-limits-declared",
                bool(result.unknowns),
                f"declared limits: {'; '.join(result.unknowns)}" if result.unknowns else "scope limits not declared",
            )
        )
        return tuple(built)

    return _run_layer(
        "recon",
        "项目侦察：暂存树在声明范围内完整走查（无遗漏），埋点的授权逻辑被定位，范围限制被显式声明。",
        checks,
    )


def _layer_manifest(scan: artifactscan.ArtifactScanResult, manifest_rows: list[dict[str, Any]]) -> LayerResult:
    def checks() -> tuple[Check, ...]:
        state = scan.coverage.get("state")
        found = {entry.path: entry for entry in scan.artifacts}
        pinned = {row["path"]: row for row in manifest_rows}
        built: list[Check] = [
            _expect("manifest-coverage", state == "complete_for_scope", f"coverage={state}"),
            _expect(
                "manifest-count",
                len(found) == EXPECTED_ARTIFACT_COUNT,
                f"found {len(found)}, expected {EXPECTED_ARTIFACT_COUNT}",
            ),
            _expect(
                "manifest-paths",
                set(found) == set(pinned),
                "every pinned artifact found, nothing extra" if set(found) == set(pinned) else f"diff: {set(found) ^ set(pinned)}",
            ),
        ]
        for path in sorted(set(found) & set(pinned)):
            entry, row = found[path], pinned[path]
            built.append(
                _expect(
                    f"manifest-digest:{path}",
                    entry.kind == row["kind"] and entry.sha256 == row["sha256"],
                    f"kind={entry.kind} sha256={(entry.sha256 or '')[:12]}…",
                )
            )
        built.append(
            _expect(
                "manifest-no-unknowns",
                not scan.unknowns,
                "no unknowns" if not scan.unknowns else f"unknowns: {'; '.join(scan.unknowns)}",
            )
        )
        return tuple(built)

    return _run_layer("manifest", "产物清单：暂存树里的每个产物都被枚举、分类并按清单钉住摘要。", checks)


def _layer_secrets(staged: Path, stamp: str) -> LayerResult:
    def checks() -> tuple[Check, ...]:
        result = secretscan.observe_secrets(staged, now=stamp)
        state = result.coverage.get("state")
        omissions = result.coverage.get("omissions") or []
        patterns = {hit.pattern for hit in result.hits}
        serialized = json.dumps(result.to_dict(), ensure_ascii=False)
        built: list[Check] = [
            # Same honest shape as recon: partial is the declared scope
            # (binary-internal strings belong to string-symbol-scan), and
            # omissions inside that scope would be a real defect.
            _expect(
                "secrets-coverage-partial-by-declaration",
                state == "partial" and not omissions,
                f"coverage={state}, omissions={len(omissions)}",
            ),
        ]
        for expected in sorted(EXPECTED_SECRET_PATTERNS):
            built.append(
                _expect(
                    f"secrets-pattern:{expected}",
                    expected in patterns,
                    "planted pattern located by name" if expected in patterns else "planted pattern not located",
                )
            )
        for marker in MARKER_STRINGS:
            built.append(
                _expect(
                    f"secrets-redaction:{marker.split('-')[0].split('.')[0]}",
                    marker not in serialized,
                    "marker content absent from result" if marker not in serialized else "MARKER CONTENT LEAKED",
                )
            )
        built.append(
            _expect(
                "secrets-limits-declared",
                bool(result.unknowns),
                f"declared limits: {'; '.join(result.unknowns)}" if result.unknowns else "scope limits not declared",
            )
        )
        return tuple(built)

    return _run_layer(
        "secrets",
        "秘密扫描：埋点按模式名定位，内容在结果中不可见；二进制内字符串的范围限制被显式声明。",
        checks,
    )


def _layer_native(scan: artifactscan.ArtifactScanResult, stamp: str) -> LayerResult:
    def checks() -> tuple[Check, ...]:
        result = nativecheck.observe_native(scan, now=stamp)
        state = result.coverage.get("state")
        profiles = {profile.path: profile for profile in result.profiles}
        built: list[Check] = [
            _expect("native-coverage", state == "complete_for_scope", f"coverage={state}"),
            _expect(
                "native-profile-count",
                len(profiles) == 4,
                f"{len(profiles)} native containers parsed, expected 4 (3 libapp + 1 libflutter)",
            ),
        ]
        for abi in EXPECTED_ABIS:
            path = f"build/app/intermediates/merged_native_libs/release/out/lib/{abi}/libapp.so"
            profile = profiles.get(path)
            if profile is None:
                built.append(_expect(f"native-libapp:{abi}", None, "profile missing"))
                continue
            gaps = set(profile.gaps)
            bits_ok = (profile.bits == 32) if abi in EXPECTED_ELF32_ABIS else (profile.bits == 64)
            built.extend(
                [
                    _expect(
                        f"native-libapp-parsed:{abi}",
                        profile.format == "elf" and bits_ok,
                        f"format={profile.format} bits={profile.bits}",
                    ),
                    _expect(
                        f"native-libapp-gaps:{abi}",
                        gaps >= LIBAPP_GAPS,
                        f"gaps={sorted(gaps)}",
                    ),
                ]
            )
        engine = profiles.get("build/app/intermediates/merged_native_libs/release/out/lib/arm64-v8a/libflutter.so")
        if engine is None:
            built.append(_expect("native-engine-parsed", None, "libflutter.so profile missing"))
        else:
            built.extend(
                [
                    _expect(
                        "native-engine-parsed",
                        engine.format == "elf",
                        f"format={engine.format} bits={engine.bits}",
                    ),
                    _expect(
                        "native-engine-hardened",
                        not (set(engine.gaps) & LIBAPP_GAPS),
                        f"gaps={sorted(engine.gaps)} (contrast case: must stay clean)",
                    ),
                    _expect(
                        "native-engine-relro-full",
                        engine.relro == "full",
                        f"relro={engine.relro}",
                    ),
                ]
            )
        parse_unknowns = [u for u in result.unknowns if "parse" in u.lower()]
        built.append(
            _expect(
                "native-no-parse-unknowns",
                not parse_unknowns,
                "no header-parse unknowns" if not parse_unknowns else f"parse unknowns: {'; '.join(parse_unknowns)}",
            )
        )
        return tuple(built)

    return _run_layer(
        "native",
        "native-check：libapp.so 必须报可执行栈与未剥离符号（含 ELF32 的 armeabi-v7a），libflutter.so 必须干净。",
        checks,
    )


def _layer_dart_aot(scan: artifactscan.ArtifactScanResult, stamp: str) -> LayerResult:
    def checks() -> tuple[Check, ...]:
        result = dartaotcheck.observe_dart_aot(scan, now=stamp)
        state = result.coverage.get("state")
        anchors = set(dartaotcheck.DART_SNAPSHOT_ANCHORS)
        snapshots = [s for s in result.snapshots if s.kind in dartaotcheck.SNAPSHOT_KINDS]
        engines = [s for s in result.snapshots if s.kind in dartaotcheck.ENGINE_KINDS]
        serialized = json.dumps(result.to_dict(), ensure_ascii=False)
        built: list[Check] = [
            _expect("dart-aot-coverage", state == "complete_for_scope", f"coverage={state}"),
            _expect(
                "dart-aot-snapshot-count",
                len(snapshots) == 3,
                f"{len(snapshots)} snapshot containers, expected 3",
            ),
        ]
        for snapshot in snapshots:
            built.append(
                _expect(
                    f"dart-aot-anchors:{snapshot.path.rsplit('/', 2)[-2]}",
                    set(snapshot.anchors_found) == anchors,
                    f"{len(snapshot.anchors_found)}/{len(anchors)} anchors",
                )
            )
        built.append(
            _expect(
                "dart-aot-engine-observed",
                len(engines) == 1,
                f"{len(engines)} engine container(s), expected 1",
            )
        )
        obfuscation_declared = any("obfuscat" in unknown.lower() for unknown in result.unknowns)
        built.append(
            _expect(
                "dart-aot-obfuscation-stays-unknown",
                obfuscation_declared,
                "obfuscation status declared unknown" if obfuscation_declared else "obfuscation unknown not declared",
            )
        )
        built.append(
            _expect(
                "dart-aot-no-recovery-rate-claim",
                _RECOVERY_RATE_CLAIM.search(serialized) is None,
                "no numeric recovery-rate claim" if _RECOVERY_RATE_CLAIM.search(serialized) is None else "RECOVERY RATE CLAIMED",
            )
        )
        return tuple(built)

    return _run_layer(
        "dart-aot",
        "dart-aot-check：四个快照锚点在每个 libapp.so 中全部命中；混淆状态保持 unknown；不出现恢复率数字。",
        checks,
    )


def _layer_buildint(scan: artifactscan.ArtifactScanResult, stamp: str) -> LayerResult:
    def checks() -> tuple[Check, ...]:
        result = buildint.verify_build_integration(scan, now=stamp)
        state = result.coverage.get("state")
        declared = {abi for config in result.configs for abi in config.declared_abis}
        statuses = [check.status for check in result.checks]
        built: list[Check] = [
            _expect("buildint-coverage", state == "complete_for_scope", f"coverage={state}"),
            _expect(
                "buildint-declared-abis",
                declared == set(EXPECTED_ABIS),
                f"declared={sorted(declared)}",
            ),
            _expect(
                "buildint-all-matched",
                statuses.count("matched") == len(statuses) == 3,
                f"matched={statuses.count('matched')} missing={statuses.count('missing')} "
                f"unverifiable={statuses.count('unverifiable')} of {len(statuses)} checks",
            ),
        ]
        for check in result.checks:
            built.append(
                _expect(
                    f"buildint-check:{check.expectation}",
                    check.status == "matched",
                    f"{check.status}: {check.detail}",
                )
            )
        return tuple(built)

    return _run_layer(
        "build-integration",
        "build-integration：build.gradle 声明的三个 ABI 与产物中的 lib/<abi>/ 目录逐一 matched。",
        checks,
    )


def _layer_cli_e2e(
    staged: Path,
    request_path: Path,
    stamp: str,
    cli_out_dir: Path,
) -> LayerResult:
    def checks() -> tuple[Check, ...]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli_main(
                [
                    "demo",
                    "--request",
                    str(request_path),
                    "--project",
                    str(staged),
                    "--out",
                    str(cli_out_dir),
                ]
            )
        report_path = cli_out_dir / "report.md"
        bundle_path = cli_out_dir / "bundle.json"
        built: list[Check] = [
            _expect("cli-exit-code", code == 0, f"exit={code}"),
            _expect(
                "cli-outputs-written",
                report_path.is_file() and bundle_path.is_file(),
                "report.md and bundle.json written" if report_path.is_file() and bundle_path.is_file() else "outputs missing",
            ),
        ]
        if not (report_path.is_file() and bundle_path.is_file()):
            return tuple(built)
        report = report_path.read_text(encoding="utf-8")
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        domains = bundle["domains"]
        for domain in ("native_check", "dart_aot_check", "build_integration"):
            findings = domains.get(domain, {}).get("findings", [])
            observed = any(f.get("status") == "observed" for f in findings)
            built.append(
                _expect(
                    f"cli-domain-observed:{domain}",
                    observed,
                    "domain observed real artifacts" if observed else f"domain did not observe: {[f.get('id') for f in findings]}",
                )
            )
        built.append(
            _expect(
                "cli-report-marks-measured",
                "[实测]" in report,
                "report marks measured sections" if "[实测]" in report else "no [实测] marker in report",
            )
        )
        for marker in MARKER_STRINGS:
            leaked = marker in report or marker in json.dumps(bundle, ensure_ascii=False)
            built.append(
                _expect(
                    f"cli-redaction:{marker.split('-')[0].split('.')[0]}",
                    not leaked,
                    "marker content absent from CLI outputs" if not leaked else "MARKER CONTENT LEAKED IN CLI OUTPUT",
                )
            )
        built.append(
            _expect(
                "cli-intel-channel-offline",
                "capability_intel" not in domains,
                "no transport injected: intel channel absent, not an empty success"
                if "capability_intel" not in domains
                else "intel channel present without injection",
            )
        )
        return tuple(built)

    return _run_layer(
        "cli-e2e",
        "CLI 端到端：pea demo 对暂存树跑通，新域从 unknown 翻转为实测，埋点内容不出现在任何输出。",
        checks,
    )


def _unavailable_layers(reason: str) -> tuple[LayerResult, ...]:
    """Downstream domains consume the manifest; without it they are unknown."""
    purposes = {
        "native": "native-check：libapp.so 必须报可执行栈与未剥离符号（含 ELF32 的 armeabi-v7a），libflutter.so 必须干净。",
        "dart-aot": "dart-aot-check：四个快照锚点在每个 libapp.so 中全部命中；混淆状态保持 unknown；不出现恢复率数字。",
        "build-integration": "build-integration：build.gradle 声明的三个 ABI 与产物中的 lib/<abi>/ 目录逐一 matched。",
    }
    return tuple(
        LayerResult(layer=layer, purpose=purpose, checks=(Check(f"{layer}-dependency", "unknown", reason),))
        for layer, purpose in purposes.items()
    )


def verify_l2(
    staged: Path,
    *,
    request_path: Path = DEFAULT_REQUEST,
    artifact_manifest: Path = DEFAULT_ARTIFACT_MANIFEST,
    now: str | None = None,
    cli_out_dir: Path | None = None,
) -> L2Report:
    """Run every L2 layer against a staged project-with-output tree.

    One traversal feeds the manifest layer and the three downstream domains,
    mirroring how the domains themselves share a single walk. If that
    traversal crashes on real bytes the manifest layer fails loudly and the
    downstream domains record ``unknown`` - a dependency failure is never a
    pass.
    """
    stamp = now or _utc_now()
    manifest_rows = json.loads(artifact_manifest.read_text(encoding="utf-8"))["artifacts"]
    out_dir = cli_out_dir or staged.parent / "cli-out"

    layers: list[LayerResult] = [
        _layer_recon(staged, stamp),
        _layer_secrets(staged, stamp),
    ]

    try:
        scan = artifactscan.observe_artifacts(staged, now=stamp)
    except Exception as exc:
        traceback.print_exc()
        layers.append(
            LayerResult(
                layer="manifest",
                purpose="产物清单：暂存树里的每个产物都被枚举、分类并按清单钉住摘要。",
                checks=(Check("manifest-crashed", "fail", f"{type(exc).__name__}: {exc}"),),
            )
        )
        layers.extend(_unavailable_layers(f"manifest dependency failed: {type(exc).__name__}: {exc}"))
    else:
        layers.append(_layer_manifest(scan, manifest_rows))
        layers.extend(
            [
                _layer_native(scan, stamp),
                _layer_dart_aot(scan, stamp),
                _layer_buildint(scan, stamp),
            ]
        )
    layers.append(_layer_cli_e2e(staged, request_path, stamp, out_dir))
    return L2Report(staged_root=str(staged), generated_at=stamp, layers=tuple(layers))


def verify_digests(artifact_fixture: Path, artifact_manifest: Path) -> list[Check]:
    """Digest-only mode: the checked-in fixture must match the manifest bytes."""
    rows = json.loads(artifact_manifest.read_text(encoding="utf-8"))["artifacts"]
    checks: list[Check] = []
    for row in rows:
        path = artifact_fixture / row["path"]
        if not path.is_file():
            checks.append(Check(f"digest:{row['path']}", "fail", "file missing"))
            continue

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checks.append(
            Check(
                f"digest:{row['path']}",
                "pass" if digest == row["sha256"] else "fail",
                digest[:12] + "…",
            )
        )
    return checks
