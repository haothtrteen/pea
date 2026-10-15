"""Read-only project reconnaissance - the first defense-engineering domain (M3/D2).

This module answers the first question of the defense-engineering loop: *where
is the asset I am asked to protect?* It profiles a project the user owns or is
authorized to test, using static observation only.

Hard rules encoded here, taken from the project's own security policy and the
REA parity plan (D2):

* **Read-only.** Nothing in this module executes a project script, mutates a
  file, or spawns a process. It opens files for reading and closes them.
* **Bounded.** Traversal is delegated to :mod:`pea.fswalk`, which owns the
  shared discipline: traversal never escapes the authorized root (symlinks
  are not followed and resolved paths are re-checked against the root), file
  counts and depth are capped, and every cap that fires is reported in
  ``coverage.omissions`` - a skipped path is data, not silence.
* **No invention.** Languages, build systems and platforms are reported from
  marker files and extension counts only. A profile with no signal stays
  ``unknown``; "not found" is never promoted to "not present".
* **Secrets stay redacted.** Pattern hits record the *pattern name* and line
  number, never the matched text - the scanner's own output must not become a
  second copy of the secret it was looking for.

Every conclusion is emitted as an ``observation``-authority evidence record so
the ledger can tell static observation apart from runtime claims later.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea.fswalk import (
    MAX_DEPTH,
    MAX_FILES,
    WalkBoundaryError,
    WalkReport,
    is_inside,
    relpath,
    resolve_root,
    walk_project,
)
from pea.tiers import TIER_STATIC_CONTENT, TIER_TOOL_EFFICIENCY

# ---------------------------------------------------------------------------
# Bounds - every one of them is reported when it fires
# ---------------------------------------------------------------------------

#: Only the first bytes of a text file are sniffed for authorization patterns.
SNIFF_BYTES = 65_536
#: Only files up to this size get a SHA-256 digest recorded.
HASH_LIMIT_BYTES = 1_048_576

# ---------------------------------------------------------------------------
# Recognition tables
# ---------------------------------------------------------------------------

#: Extension -> language. Data formats (json/yaml/xml) are deliberately absent:
#: they are not languages and counting them would dilute the profile.
LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".dart": "dart",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".lua": "lua",
    ".go": "go",
    ".rs": "rust",
    ".swift": "swift",
    ".m": "objective-c",
    ".mm": "objective-cpp",
    ".rb": "ruby",
    ".php": "php",
}

#: Marker file (basename or repo-relative path) -> build system id.
BUILD_MARKERS: dict[str, str] = {
    "pubspec.yaml": "flutter_dart",
    "package.json": "node_npm",
    "pyproject.toml": "python_pyproject",
    "setup.py": "python_setuptools",
    "requirements.txt": "python_pip",
    "CMakeLists.txt": "cmake",
    "Cargo.toml": "cargo",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle_kotlin_dsl",
    "settings.gradle": "gradle",
    "settings.gradle.kts": "gradle_kotlin_dsl",
    "Makefile": "make",
    "meson.build": "meson",
    "BUILD.bazel": "bazel",
    "pom.xml": "maven",
}

#: Top-level directory -> platform. Flutter's per-platform directories use the
#: same names, which is what makes this table work for both.
PLATFORM_DIRS: dict[str, str] = {
    "android": "android",
    "ios": "ios",
    "web": "web",
    "linux": "linux_desktop",
    "windows": "windows_desktop",
    "macos": "macos_desktop",
}

#: Filename fragment -> artifact kind, for assets that matter to protection.
KEY_ARTIFACT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("libapp.so", "flutter_dart_snapshot"),
    ("libflutter.so", "flutter_engine"),
    ("libgodot", "game_engine_library"),
)

#: Authorization-related pattern name -> what its presence suggests. Only the
#: *name* is ever recorded; matched text is never copied into findings.
AUTH_PATTERNS: tuple[tuple[str, str], ...] = (
    ("license", "licensing/authorization logic reference"),
    ("auth", "authorization logic reference"),
    ("token", "token handling reference"),
    ("secret", "secret material reference"),
    ("signature", "signature verification reference"),
    ("verifyLicense", "license verification routine"),
    ("rsa", "asymmetric crypto primitive reference"),
    ("checksum", "integrity check reference"),
    ("tamper", "tamper-detection reference"),
    ("root", "environment probing reference"),
    ("frida", "instrumentation-awareness reference"),
    ("debugger", "anti-debug reference"),
)

#: File extensions whose content is sniffed for the patterns above. Docs
#: (``.md``/``.txt``) are excluded on purpose: prose *mentioning* "license" is
#: noise for an authorization-logic locator, and a README describing the
#: canary would otherwise light up like source code.
SNIFFABLE_EXTENSIONS = frozenset(
    {
        ".dart",
        ".kt",
        ".kts",
        ".java",
        ".js",
        ".mjs",
        ".ts",
        ".py",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cs",
        ".lua",
        ".swift",
        ".xml",
        ".json",
        ".yaml",
        ".yml",
    }
)


@dataclass(frozen=True)
class LanguageObservation:
    """One language observed in the project, with the signal it rests on."""

    language: str
    file_count: int
    extensions: tuple[str, ...]


@dataclass(frozen=True)
class KeyArtifact:
    """A file that matters to protection, with its digest when cheap to take."""

    path: str
    kind: str
    size_bytes: int
    sha256: str | None


@dataclass(frozen=True)
class PatternHit:
    """A redacted hit: pattern name, first location and count, never the text."""

    path: str
    pattern: str
    meaning: str
    line: int
    count: int = 1


@dataclass(frozen=True)
class ReconResult:
    """Everything recon observed, plus what it could not observe."""

    project_path: str
    languages: tuple[LanguageObservation, ...]
    build_systems: tuple[str, ...]
    platforms: tuple[str, ...]
    key_artifacts: tuple[KeyArtifact, ...]
    pattern_hits: tuple[PatternHit, ...]
    files_scanned: int
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "languages": [
                {"language": obs.language, "file_count": obs.file_count, "extensions": list(obs.extensions)}
                for obs in self.languages
            ],
            "build_systems": list(self.build_systems),
            "platforms": list(self.platforms),
            "key_artifacts": [
                {"path": a.path, "kind": a.kind, "size_bytes": a.size_bytes, "sha256": a.sha256} for a in self.key_artifacts
            ],
            "pattern_hits": [
                {"path": h.path, "pattern": h.pattern, "meaning": h.meaning, "line": h.line, "count": h.count}
                for h in self.pattern_hits
            ],
            "files_scanned": self.files_scanned,
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReconResult:
        """Rebuild from ``to_dict`` output (the WP2 orchestrator's disk form).

        Recovery semantics need it: a recon that ran before a crash must be
        reusable after it - re-observing the project would burn time and
        could even produce different bytes than the recorded evidence.
        """
        return cls(
            project_path=str(data["project_path"]),
            languages=tuple(
                LanguageObservation(
                    language=str(o["language"]),
                    file_count=int(o["file_count"]),
                    extensions=tuple(o.get("extensions") or ()),
                )
                for o in data.get("languages") or ()
            ),
            build_systems=tuple(data.get("build_systems") or ()),
            platforms=tuple(data.get("platforms") or ()),
            key_artifacts=tuple(
                KeyArtifact(
                    path=str(a["path"]),
                    kind=str(a["kind"]),
                    size_bytes=int(a["size_bytes"]),
                    sha256=a.get("sha256"),
                )
                for a in data.get("key_artifacts") or ()
            ),
            pattern_hits=tuple(
                PatternHit(
                    path=str(h["path"]),
                    pattern=str(h["pattern"]),
                    meaning=str(h["meaning"]),
                    line=int(h["line"]),
                    count=int(h.get("count", 1)),
                )
                for h in data.get("pattern_hits") or ()
            ),
            files_scanned=int(data.get("files_scanned", 0)),
            findings=tuple(data.get("findings") or ()),
            coverage=dict(data.get("coverage") or {}),
            unknowns=tuple(data.get("unknowns") or ()),
        )


class ReconBoundaryError(ValueError):
    """The requested path is not a usable, authorized root for scanning."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_LIMIT_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sniff_patterns(path: Path) -> list[tuple[str, str, int]]:
    """Return every ``(pattern, meaning, line)`` hit; matched text is never kept.

    The caller merges repeats per (file, pattern) into a counted hit: a file
    mentioning "license" seven times is one finding with count 7, not seven
    findings.
    """
    hits: list[tuple[str, str, int]] = []
    try:
        with path.open("rb") as handle:
            raw = handle.read(SNIFF_BYTES)
    except OSError:
        return hits
    if b"\x00" in raw:  # binary: sniffing text patterns would be noise
        return hits
    for line_no, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
        for pattern, meaning in AUTH_PATTERNS:
            if pattern.lower() in line.lower():
                hits.append((pattern, meaning, line_no))
    return hits


def _evidence(evidence_id: str, source: str, observed_at: str, summary: str) -> dict[str, Any]:
    """One observation-authority evidence record, ready for the ledger."""
    return {
        "evidence_id": evidence_id,
        "kind": "file_observation",
        "source": source,
        "observed_at": observed_at,
        "authority": "observation",
        "limitations": ["静态只读观察；不覆盖运行期行为与未扫描路径"],
        "redacted_summary": summary,
    }


def observe(
    project_path: str | Path,
    *,
    now: str | None = None,
) -> ReconResult:
    """Profile an authorized project root. Read-only, bounded, no execution.

    ``now`` stamps the evidence records; injecting it keeps outputs
    deterministic under test. Everything else is derived from the filesystem.
    """
    stamp = now or _utc_now()
    try:
        root = resolve_root(project_path)
    except WalkBoundaryError as exc:
        raise ReconBoundaryError(str(exc)) from exc

    walk = WalkReport()
    languages: Counter[str] = Counter()
    extensions_by_language: dict[str, set[str]] = {}
    build_systems: set[str] = set()
    platforms: set[str] = set()
    key_artifacts: list[KeyArtifact] = []
    pattern_hits: list[PatternHit] = []

    # Platform markers only count at the repository top level: a nested "ios"
    # directory inside a plugin is not this project's platform. The shared
    # walk owns traversal; top-level directory *names* are a recon-level
    # observation, so they are read here instead.
    for child in sorted(root.iterdir()):
        if child.is_dir() and is_inside(root, child):
            platform = PLATFORM_DIRS.get(child.name)
            if platform:
                platforms.add(platform)

    for file_path, size in walk_project(root, report=walk):
        rel = relpath(root, file_path)
        name = file_path.name

        build_system = BUILD_MARKERS.get(name)
        if build_system:
            build_systems.add(build_system)

        lowered = name.lower()
        for fragment, kind in KEY_ARTIFACT_PATTERNS:
            if fragment in lowered:
                digest = _sha256_of(file_path) if size <= HASH_LIMIT_BYTES else None
                key_artifacts.append(KeyArtifact(path=rel, kind=kind, size_bytes=size, sha256=digest))
                break

        suffix = file_path.suffix.lower()
        language = LANGUAGE_BY_EXTENSION.get(suffix)
        if language:
            languages[language] += 1
            extensions_by_language.setdefault(language, set()).add(suffix)
        if suffix in SNIFFABLE_EXTENSIONS and size <= SNIFF_BYTES:
            for pattern, meaning, line_no in _sniff_patterns(file_path):
                # Merge repeats per (file, pattern): first line + count.
                existing = next(
                    (h for h in pattern_hits if h.path == rel and h.pattern == pattern),
                    None,
                )
                if existing is None:
                    pattern_hits.append(PatternHit(path=rel, pattern=pattern, meaning=meaning, line=line_no))
                else:
                    pattern_hits[pattern_hits.index(existing)] = PatternHit(
                        path=existing.path,
                        pattern=existing.pattern,
                        meaning=existing.meaning,
                        line=existing.line,
                        count=existing.count + 1,
                    )
                if size <= HASH_LIMIT_BYTES and not any(a.path == rel for a in key_artifacts):
                    key_artifacts.append(
                        KeyArtifact(
                            path=rel,
                            kind="authorization_logic_source",
                            size_bytes=size,
                            sha256=_sha256_of(file_path),
                        )
                    )

    omissions = walk.omissions
    truncated = walk.truncated
    files_scanned = walk.files_seen

    language_observations = tuple(
        LanguageObservation(language=lang, file_count=count, extensions=tuple(sorted(extensions_by_language[lang])))
        for lang, count in sorted(languages.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    unknown_set: list[str] = []
    if truncated:
        unknown_set.append(f"项目超过 {MAX_FILES} 个文件的上限，完整语言/资产清单未知")
    if any("未枚举" in omission for omission in omissions):
        unknown_set.append("部分目录因深度/链接/统计失败未枚举，其内容未知")
    has_release_artifact = any(a.kind in {"flutter_dart_snapshot", "flutter_engine"} for a in key_artifacts)
    if not has_release_artifact:
        unknown_set.append("未发现构建产物（如 libapp.so/libflutter.so）；release 级暴露面未评估，需构建后再扫")
    unknown_set.append("静态侦察不覆盖运行期行为、网络端点可达性与服务端配置")

    findings = _build_findings(
        project_path=str(root),
        languages=language_observations,
        build_systems=tuple(sorted(build_systems)),
        platforms=tuple(sorted(platforms)),
        key_artifacts=tuple(key_artifacts),
        pattern_hits=tuple(pattern_hits),
        stamp=stamp,
        omissions=tuple(omissions),
    )

    coverage = {
        "state": "partial" if omissions or unknown_set else "complete_for_scope",
        "scope": f"授权根 {root} 的静态只读枚举（文件数上限 {MAX_FILES}、深度 {MAX_DEPTH}、嗅探 {SNIFF_BYTES} 字节）",
        "omissions": omissions,
    }

    return ReconResult(
        project_path=str(root),
        languages=language_observations,
        build_systems=tuple(sorted(build_systems)),
        platforms=tuple(sorted(platforms)),
        key_artifacts=tuple(key_artifacts),
        pattern_hits=tuple(pattern_hits),
        files_scanned=files_scanned,
        findings=findings,
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


def _build_findings(
    *,
    project_path: str,
    languages: tuple[LanguageObservation, ...],
    build_systems: tuple[str, ...],
    platforms: tuple[str, ...],
    key_artifacts: tuple[KeyArtifact, ...],
    pattern_hits: tuple[PatternHit, ...],
    stamp: str,
    omissions: tuple[str, ...],
) -> tuple[dict[str, Any], ...]:
    """Turn raw observations into exposure-finding-shaped findings.

    The findings stay compatible with ``exposure-finding.schema.json`` so the
    ledger and the report can consume them without a second representation.
    """
    findings: list[dict[str, Any]] = []
    base_limitations = ["静态只读侦察；不执行项目脚本，不分析未构建产物"]
    if omissions:
        base_limitations.append(f"{len(omissions)} 处路径未枚举（见 coverage.omissions）")

    profile_summary = (
        f"语言分布: {', '.join(f'{o.language}×{o.file_count}' for o in languages) or 'unknown'}; "
        f"构建: {', '.join(build_systems) or 'unknown'}; "
        f"平台: {', '.join(platforms) or 'unknown'}"
    )
    findings.append(
        {
            "id": "recon-project-profile",
            "category": "project_profile",
            "status": "observed",
            "severity": "info",
            "title": "项目画像（只读静态侦察）",
            "summary": profile_summary,
            "evidence": [_evidence("ev-recon-profile", f"pea.recon:{project_path}", stamp, profile_summary)],
            "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "授权根静态枚举"},
            "limitations": base_limitations,
            "recommended_actions": ["确认画像与实际部署形态一致", "若存在未枚举路径，补齐后重扫"],
            # 画像是上下文而非暴露面：无 exposure_tier（untiered）。
        }
    )

    if pattern_hits:
        hit_paths = sorted({hit.path for hit in pattern_hits})
        pattern_names = sorted({hit.pattern for hit in pattern_hits})
        summary = (
            f"{len(hit_paths)} 个文件命中授权相关模式 {pattern_names}；"
            "命中仅记录模式名与行号，匹配内容已脱敏"
        )
        findings.append(
            {
                "id": "recon-authorization-logic-located",
                "category": "authorization_logic_surface",
                "status": "observed",
                "severity": "medium",
                "title": "授权相关代码定位",
                "summary": summary,
                "artifact_path": hit_paths[0],
                "evidence": [
                    _evidence(
                        "ev-recon-auth-hits",
                        f"pea.recon:{project_path}",
                        stamp,
                        f"命中文件: {', '.join(hit_paths)}",
                    )
                ],
                "coverage": {"state": "partial", "scope": "文本源文件模式嗅探（仅模式名，内容脱敏）"},
                "limitations": [*base_limitations, "模式命中不等于存在漏洞；需人工确认边界与威胁模型"],
                "recommended_actions": [
                    "人工审阅命中文件，确认授权逻辑边界",
                    "核对是否存在硬编码端点或密钥材料（脱敏检查）",
                ],
                "secret_value_redacted": True,
                # 代码位置是产物内容：静态内容层暴露面。
                "exposure_tier": TIER_STATIC_CONTENT,
            }
        )

    snapshot_artifacts = [a for a in key_artifacts if a.kind in {"flutter_dart_snapshot", "flutter_engine"}]
    if snapshot_artifacts:
        listed = ", ".join(f"{a.path}({a.kind})" for a in snapshot_artifacts)
        findings.append(
            {
                "id": "recon-release-artifacts-present",
                "category": "release_artifact_surface",
                "status": "observed",
                "severity": "medium",
                "title": "发现构建产物",
                "summary": f"发现 {listed}；这些是逆向分析的主战场，需纳入暴露面映射",
                "evidence": [_evidence("ev-recon-artifacts", f"pea.recon:{project_path}", stamp, listed)],
                "coverage": {"state": "partial", "scope": "授权根静态枚举"},
                "limitations": base_limitations,
                "recommended_actions": ["对产物运行 manifest 与只读分析（libapp.so 等）", "核对产物指纹并纳入证据账本"],
                # 产物是一键逆向工具的直接战场：工具放大层暴露面。
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            }
        )
    else:
        findings.append(
            {
                "id": "recon-release-artifacts-absent",
                "category": "release_artifact_surface",
                "status": "unknown",
                "severity": "unrated",
                "title": "未发现构建产物",
                "summary": "授权根内未见 libapp.so/libflutter.so 等构建产物；release 级暴露面未评估",
                "evidence": [_evidence("ev-recon-no-artifacts", f"pea.recon:{project_path}", stamp, "静态枚举未见构建产物")],
                "coverage": {"state": "partial", "scope": "授权根静态枚举"},
                "limitations": [*base_limitations, "未发现不等于不存在；仅说明当前授权根内不可见"],
                "recommended_actions": ["构建 release 产物后重扫", "或在计划中将产物分析标记为 unknown"],
                # 未见产物 = 工具放大层尚未评估；保持 tool_efficiency 标注，
                # 让"先修工具层"的顺序在 unknown 状态下也不丢失。
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            }
        )
    return tuple(findings)
