"""Build-integration domain (M3/D2): did the build actually emit what matters?

PEA deliberately does not *run* the user's build. What it can do offline is
the check that matters most for protection work and is most often skipped:
compare what the build configuration *declares* against what the manifest
*found*. A hardening flag set in Gradle that produces no ``arm64-v8a``
library has protected nothing on the devices that matter, and a snapshot
that never got emitted means every Dart finding above is moot.

So this domain is a verification record, not a build tool:

* it discovers build configuration files under the authorized root (shared
  :mod:`pea.fswalk` traversal - the same root, depth and symlink discipline);
* it extracts declared output expectations with a **text heuristic** and says
  so - this is not a Gradle/CMake semantic parser, and the limitation is
  stated in coverage and in the finding;
* it compares each expectation against the artifact manifest and records
  matched / missing / unverifiable per expectation.

Hard rules:

* no declaration found is ``unknown``, never "the build is fine" - an
  absent declaration means the expectation is unreadable, not satisfied;
* expectations are ``inference`` authority (they come from reading config
  text), while the manifest side is ``observation``; the finding states both
  and never lets the inference outrank the observation;
* build reproducibility and provenance are **not** verified: "this artifact
  exists" says nothing about which source or which machine produced it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea.artifactscan import ArtifactScanResult
from pea.fswalk import WalkReport, relpath, resolve_root, walk_project
from pea.tiers import TIER_TOOL_EFFICIENCY

#: Config files worth reading for declared outputs. Matched by basename so a
#: nested module's build file is seen without walking the whole tree twice.
BUILD_CONFIG_BASENAMES: tuple[str, ...] = (
    "build.gradle",
    "build.gradle.kts",
    "pubspec.yaml",
    "CMakeLists.txt",
    "Makefile",
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
)

#: Android ABI names recognized when scanning declaration text.
KNOWN_ABIS: tuple[str, ...] = ("armeabi-v7a", "arm64-v8a", "x86", "x86_64")

#: Read at most this many bytes of any config file.
CONFIG_READ_BYTES = 262_144
#: Keep at most this many config files per scan.
MAX_CONFIG_FILES = 50

_ABI_WORD = re.compile(r"\b(armeabi-v7a|arm64-v8a|x86_64|x86)\b")
#: Contexts in which an ABI word counts as a declared output rather than a
#: passing mention (a comment mentioning arm64 is not a declared split).
_ABI_DECLARATION_CONTEXT = re.compile(r"abiFilters|abi\b|splits|ndk\s*\{|defaultConfig", re.IGNORECASE)


@dataclass(frozen=True)
class BuildConfigSource:
    """One build configuration file found under the root."""

    path: str
    basename: str
    declared_abis: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class BuildCheck:
    """One declared expectation and its verification outcome."""

    expectation: str
    source: str
    status: str  # matched | missing | unverifiable
    detail: str


@dataclass(frozen=True)
class BuildIntegrationResult:
    """Declared expectations, their verification, and what was unreadable."""

    project_path: str
    configs: tuple[BuildConfigSource, ...]
    checks: tuple[BuildCheck, ...]
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "configs": [
                {"path": c.path, "basename": c.basename, "declared_abis": list(c.declared_abis)} for c in self.configs
            ],
            "checks": [
                {"expectation": c.expectation, "source": c.source, "status": c.status, "detail": c.detail}
                for c in self.checks
            ],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _declared_abis(text: str) -> tuple[str, ...]:
    """ABI names that appear in a declaration context.

    Heuristic by construction: a config file is matched as text because PEA
    ships no build-system parser. Matches carry ``inference`` authority and
    the caller says so in the finding.
    """
    found: list[str] = []
    for line in text.splitlines():
        if not _ABI_DECLARATION_CONTEXT.search(line):
            continue
        for match in _ABI_WORD.finditer(line):
            abi = match.group(1)
            if abi not in found:
                found.append(abi)
    return tuple(sorted(found))


def discover_build_configs(
    project_path: str | Path,
) -> tuple[tuple[BuildConfigSource, ...], tuple[str, ...]]:
    """Find build config files under the root. Returns (sources, omissions).

    A walk that fails at the boundary surfaces as an omission rather than an
    empty-but-clean result.
    """
    omissions: list[str] = []
    try:
        root = resolve_root(project_path)
    except Exception as exc:  # pragma: no cover - boundary errors are typed
        return (), (f"项目根不可用（{exc.__class__.__name__}）：未扫描构建配置",)

    report = WalkReport()
    sources: list[BuildConfigSource] = []
    try:
        for path, _size in walk_project(str(project_path), report=report):
            if path.name not in BUILD_CONFIG_BASENAMES:
                continue
            if len(sources) >= MAX_CONFIG_FILES:
                omissions.append(f"构建配置文件超过 {MAX_CONFIG_FILES} 个上限，其余未读取")
                break
            try:
                text = path.read_bytes()[:CONFIG_READ_BYTES].decode("utf-8", errors="replace")
            except OSError as exc:
                omissions.append(f"{relpath(root, path)}: 无法读取（{exc.__class__.__name__}）")
                continue
            sources.append(
                BuildConfigSource(
                    path=relpath(root, path),
                    basename=path.name,
                    declared_abis=_declared_abis(text),
                )
            )
    except Exception as exc:  # pragma: no cover - defensive; walk raises typed errors
        return tuple(sources), (*omissions, f"遍历失败（{exc.__class__.__name__}）")

    return tuple(sources), (*omissions, *report.omissions)


def verify_build_integration(
    scan: ArtifactScanResult,
    *,
    now: str | None = None,
) -> BuildIntegrationResult:
    """Compare what the build declares against what the manifest found.

    Both sides are stated in the result: expectations are inferred from
    config text, artifacts are observed. Where they disagree the observed
    side wins, and the disagreement is recorded rather than resolved.
    """
    stamp = now or _utc_now()
    configs, walk_omissions = discover_build_configs(scan.project_path)
    omissions = list(walk_omissions)

    # The observed side: which ABI directories actually carry artifacts.
    # The ``lib/<abi>/`` segment pair is matched anywhere in the path, not
    # only at the root: real Flutter builds land under
    # ``build/app/intermediates/merged_native_libs/.../lib/<abi>/``.
    observed_abis: dict[str, list[str]] = {}
    for entry in scan.artifacts:
        parts = entry.path.split("/")
        for index, part in enumerate(parts):
            if part == "lib" and index + 1 < len(parts) and parts[index + 1] in KNOWN_ABIS:
                observed_abis.setdefault(parts[index + 1], []).append(entry.path)
                break

    declared: dict[str, list[str]] = {}
    for config in configs:
        for abi in config.declared_abis:
            declared.setdefault(abi, []).append(config.path)

    checks: list[BuildCheck] = []
    for abi in sorted(declared):
        sources = ", ".join(sorted(declared[abi]))
        present = observed_abis.get(abi, [])
        if present:
            checks.append(
                BuildCheck(
                    expectation=f"abi:{abi}",
                    source=sources,
                    status="matched",
                    detail=f"manifest 中该 ABI 下有 {len(present)} 个产物",
                )
            )
        else:
            checks.append(
                BuildCheck(
                    expectation=f"abi:{abi}",
                    source=sources,
                    status="missing",
                    detail="manifest 中未发现该 ABI 的产物（声明与产物不一致）",
                )
            )

    for abi in sorted(set(observed_abis) - set(declared)):
        checks.append(
            BuildCheck(
                expectation=f"abi:{abi}",
                source="(无声明)",
                status="unverifiable",
                detail=f"manifest 中该 ABI 有 {len(observed_abis[abi])} 个产物，但构建配置未声明该 ABI（无法验证是否预期）",
            )
        )

    unknown_set: list[str] = []
    if not configs:
        unknown_set.append("未发现可读取的构建配置文件；无法机器读取产物预期，构建集成未验证")
    elif not declared:
        unknown_set.append("构建配置中未发现产物/ABI 声明；产物预期未机器读取，构建集成未验证")
    if any(c.status == "missing" for c in checks):
        unknown_set.append("存在声明但未产出对应产物的 ABI：该 ABI 上的保护措施是否生效无法确认")
    if not scan.artifacts:
        unknown_set.append("manifest 为空：无实际产物可与声明比对")
    unknown_set.append("构建配置解析为文本启发式（非构建系统语义解析）；声明可能不完备或被注释/条件分支掩盖")
    unknown_set.append("构建可复现性与产物溯源未验证：PEA 不执行构建，也不验证产物由声明配置产生")

    findings = _build_findings(
        project_path=scan.project_path,
        configs=configs,
        checks=tuple(checks),
        stamp=stamp,
        omissions=tuple(omissions),
        had_artifacts=bool(scan.artifacts),
    )

    if not configs or not declared:
        state = "not_run"
    elif not scan.artifacts:
        # 声明侧可读、产物侧为空：比对执行了但无法完成，不是 complete_for_scope。
        state = "partial"
    elif omissions or any(c.status == "unverifiable" for c in checks):
        state = "partial"
    else:
        state = "complete_for_scope"

    coverage = {
        "state": state,
        "scope": (
            f"只读扫描 {len(configs)} 个构建配置文件（{', '.join(BUILD_CONFIG_BASENAMES)}）"
            f"并比对 manifest 内 {len(observed_abis)} 个 ABI 目录的实际产物；"
            f"每文件 ≤{CONFIG_READ_BYTES} 字节、≤{MAX_CONFIG_FILES} 个文件"
        ),
        "omissions": omissions,
    }

    return BuildIntegrationResult(
        project_path=scan.project_path,
        configs=configs,
        checks=tuple(checks),
        findings=findings,
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


def _build_findings(
    *,
    project_path: str,
    configs: tuple[BuildConfigSource, ...],
    checks: tuple[BuildCheck, ...],
    stamp: str,
    omissions: tuple[str, ...],
    had_artifacts: bool,
) -> tuple[dict[str, Any], ...]:
    """One verification finding; the unknown forms are the honest default."""
    base_limitations = [
        "只读比对：不执行构建、不修改配置",
        "声明侧为文本启发式解析（authority=inference），产物侧为实际观察（authority=observation）",
        "构建可复现性与产物溯源未验证",
    ]
    if omissions:
        base_limitations.append(f"{len(omissions)} 处未覆盖（见 coverage.omissions）")

    if not configs or not any(config.declared_abis for config in configs):
        return (
            {
                "id": "build-integration-no-declaration",
                "category": "build_integration",
                "status": "unknown",
                "severity": "unrated",
                "title": "未机器读取到产物声明",
                "summary": (
                    f"扫描到 {len(configs)} 个构建配置文件但未提取到产物/ABI 声明；"
                    "构建集成未验证（无声明 ≠ 构建正确）"
                ),
                "evidence": [
                    {
                        "evidence_id": "ev-buildint-none",
                        "kind": "file_observation",
                        "source": f"pea.buildint:{project_path}",
                        "observed_at": stamp,
                        "authority": "observation",
                        "limitations": ["未读取到机器可解析的声明；预期清单缺失"],
                        "redacted_summary": f"配置文件 {len(configs)} 个，声明 0 条",
                    }
                ],
                "coverage": {"state": "not_run", "scope": "无可用声明"},
                "limitations": [*base_limitations, "需人工提供期望产物清单或补齐可解析的声明"],
                "recommended_actions": [
                    "在构建配置中显式声明 ABI/产物，或在请求中提供期望清单",
                    "人工确认当前产物集合与预期一致后记录为人工证据",
                ],
                # 构建集成是流程/工具层面的保障，属工具放大层；unknown 不丢序。
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            },
        )

    missing = [c for c in checks if c.status == "missing"]
    matched = [c for c in checks if c.status == "matched"]
    unverifiable = [c for c in checks if c.status == "unverifiable"]
    redacted = "; ".join(f"{c.expectation}@{c.source}: {c.status}" for c in checks)

    if not had_artifacts:
        return (
            {
                "id": "build-integration-no-artifacts",
                "category": "build_integration",
                "status": "unknown",
                "severity": "unrated",
                "title": "无实际产物可与声明比对",
                "summary": f"读取到 {len(checks)} 条产物声明，但 manifest 为空；构建集成无法验证",
                "evidence": [
                    {
                        "evidence_id": "ev-buildint-noartifacts",
                        "kind": "file_observation",
                        "source": f"pea.buildint:{project_path}",
                        "observed_at": stamp,
                        "authority": "observation",
                        "limitations": ["无产物侧观察；声明无法被证实或证伪"],
                        "redacted_summary": redacted,
                    }
                ],
                "coverage": {"state": "not_run", "scope": "无产物输入"},
                "limitations": [*base_limitations, "需构建产物后重扫"],
                "recommended_actions": ["构建 release 产物后重扫并重新比对"],
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            },
        )

    severity = "medium" if missing else "info"
    summary_bits = [
        f"{len(configs)} 个构建配置共 {len(checks)} 条 ABI 声明",
        f"matched {len(matched)} / missing {len(missing)} / unverifiable {len(unverifiable)}",
    ]
    if missing:
        summary_bits.append("声明与产物不一致：该 ABI 上声明的保护措施是否落到产物需人工确认")

    return (
        {
            "id": "build-integration-verified",
            "category": "build_integration",
            "status": "observed",
            "severity": severity,
            "title": "构建声明与产物比对完成",
            "summary": "；".join(summary_bits),
            "evidence": [
                {
                    "evidence_id": "ev-buildint-checked",
                    "kind": "file_observation",
                    "source": f"pea.buildint:{project_path}",
                    "observed_at": stamp,
                    "authority": "observation",
                    "limitations": ["声明侧为 inference；比对结论依赖声明完备性"],
                    "redacted_summary": redacted,
                }
            ],
            "coverage": {"state": "partial" if omissions or unverifiable else "complete_for_scope", "scope": "声明与产物比对"},
            "limitations": [
                *base_limitations,
                "一致不等于安全：产物存在不代表保护措施已生效（需 L2 实测）",
            ],
            "recommended_actions": [
                "核对 missing 项：构建配置是否真的产出该 ABI",
                "把期望产物清单纳入版本管理，作为后续每次发布的比对基线",
                "发布前对产物做一次实测验证（L2 真实工件层）",
            ],
            "exposure_tier": TIER_TOOL_EFFICIENCY,
        },
    )
