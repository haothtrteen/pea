"""String-symbol-scan domain (M3/D2): what do the binaries say when read as text?

Borrows REA's strings/xrefs output *shape* - pattern name and count, never
content - without wrapping a disassembler: a pure-stdlib printable-string
extractor plus leak patterns. Cross-references (xrefs) need a real
disassembler that PEA does not ship; that gap is declared in coverage and
in a standing unknown rather than papered over with a fake "symbol
analysis".

Input is the artifact manifest (:mod:`pea.artifactscan`): with no binary
artifacts to read, the domain records ``unknown`` and stops - it refuses
to fabricate a pass on an empty input.

Hard rules:

* extracted strings are never emitted - only pattern names and counts,
  the same redaction discipline as the secret scanner (a string dump
  would itself be a leak of everything it found);
* extraction is bounded (bytes per artifact, strings per artifact, string
  length); a bound that fires is an omission plus an unknown;
* ASCII printable runs only - UTF-16 and wide-char string forms are a
  declared coverage gap, not a silent miss;
* unreadable artifacts are omissions, never skipped quietly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea.artifactscan import ArtifactScanResult
from pea.tiers import TIER_STATIC_CONTENT

#: Shortest printable run that counts as a string (mirrors ``strings`` defaults).
MIN_STRING_LENGTH = 4
#: Read at most this many bytes of any single artifact.
STRING_SCAN_BYTES = 8_388_608
#: Keep at most this many strings per artifact; the rest is an omission.
MAX_STRINGS_PER_ARTIFACT = 5_000
#: Truncate individual strings to this length before matching.
MAX_STRING_LENGTH = 512


@dataclass(frozen=True)
class LeakPattern:
    """A named shape whose *presence* in strings suggests a leak."""

    name: str
    meaning: str
    regex: re.Pattern[str]


#: The pattern library. Names and meanings are what get reported; matched
#: strings never leave this module.
LEAK_PATTERNS: tuple[LeakPattern, ...] = (
    LeakPattern("url", "硬编码 URL", re.compile(r"https?://")),
    LeakPattern("email", "邮箱地址", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    LeakPattern("cxx_mangled_symbol", "C++ mangled 符号（_Z 前缀）", re.compile(r"^_Z")),
    LeakPattern("jni_symbol", "JNI 导出符号（Java_ 前缀）", re.compile(r"^Java_")),
    LeakPattern("build_path", "构建机路径（/home/ /Users/ /build/ /tmp/）", re.compile(r"^/(?:home|Users|build|tmp)/")),
    LeakPattern("source_file_reference", "源码文件名引用", re.compile(r"\.(?:dart|java|kt|cpp|cc|hpp|h|py|js|ts|rs|go|swift)$")),
    LeakPattern("license_keyword", "授权相关关键字", re.compile(r"(?i)license|token|secret|signature")),
    LeakPattern("private_key_marker", "私钥材料标记", re.compile(r"PRIVATE KEY")),
)


@dataclass(frozen=True)
class ArtifactSymbols:
    """One artifact's string-scan outcome: counts, never the strings."""

    path: str
    kind: str
    strings_found: int
    truncated: bool
    pattern_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SymbolScanResult:
    """Everything the string scan observed, plus what it could not read."""

    project_path: str
    scanned: tuple[ArtifactSymbols, ...]
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "scanned": [
                {
                    "path": s.path,
                    "kind": s.kind,
                    "strings_found": s.strings_found,
                    "truncated": s.truncated,
                    "pattern_counts": dict(s.pattern_counts),
                }
                for s in self.scanned
            ],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_strings(
    path: Path,
    *,
    max_bytes: int = STRING_SCAN_BYTES,
    max_strings: int = MAX_STRINGS_PER_ARTIFACT,
) -> tuple[list[str], bool]:
    """Printable ASCII runs of >= ``MIN_STRING_LENGTH``; returns (strings, truncated).

    Pure stdlib equivalent of the ``strings`` utility: bytes are read in
    one bounded pass, runs of printable characters are collected, and both
    the byte cap and the string-count cap report ``truncated=True`` instead
    of pretending the read was complete.
    """
    with path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    byte_truncated = len(raw) > max_bytes
    strings: list[str] = []
    count_truncated = False
    run: list[int] = []
    for byte in raw[:max_bytes]:
        if 0x20 <= byte <= 0x7E:
            run.append(byte)
            continue
        if len(run) >= MIN_STRING_LENGTH:
            if len(strings) >= max_strings:
                count_truncated = True
                break
            strings.append(bytes(run[:MAX_STRING_LENGTH]).decode("ascii", errors="replace"))
        run = []
    else:
        if len(run) >= MIN_STRING_LENGTH and len(strings) < max_strings:
            strings.append(bytes(run[:MAX_STRING_LENGTH]).decode("ascii", errors="replace"))
        elif len(run) >= MIN_STRING_LENGTH:
            count_truncated = True
    return strings, byte_truncated or count_truncated


def _count_patterns(strings: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for text in strings:
        for pattern in LEAK_PATTERNS:
            if pattern.regex.search(text):
                counts[pattern.name] = counts.get(pattern.name, 0) + 1
    return counts


def observe_strings_symbols(
    scan: ArtifactScanResult,
    *,
    now: str | None = None,
) -> SymbolScanResult:
    """Scan the manifest's binary artifacts for leak-shaped strings.

    Read-only and redacting: strings are matched in memory and discarded;
    only pattern names and counts survive into the result. With an empty
    manifest the domain reports ``unknown`` - an unscannable input is not
    a clean input.
    """
    stamp = now or _utc_now()

    omissions: list[str] = []
    scanned: list[ArtifactSymbols] = []
    unknown_set: list[str] = []
    unreadable = 0

    for entry in scan.artifacts:
        path = Path(scan.project_path) / entry.path
        try:
            # Bounds passed explicitly (not via defaults) so the caps stay
            # monkeypatchable in tests - and so a future per-artifact policy
            # has a seam to pass different values through.
            strings, truncated = extract_strings(
                path,
                max_bytes=STRING_SCAN_BYTES,
                max_strings=MAX_STRINGS_PER_ARTIFACT,
            )
        except OSError as exc:
            omissions.append(f"{entry.path}: 无法读取（{exc.__class__.__name__}），未扫描")
            unreadable += 1
            continue
        counts = _count_patterns(strings)
        if truncated:
            omissions.append(f"{entry.path}: 超过字符串提取上限（{STRING_SCAN_BYTES} 字节或 {MAX_STRINGS_PER_ARTIFACT} 条），未完整提取")
        scanned.append(
            ArtifactSymbols(
                path=entry.path,
                kind=entry.kind,
                strings_found=len(strings),
                truncated=truncated,
                pattern_counts=counts,
            )
        )

    if not scan.artifacts:
        unknown_set.append("未发现可扫描的二进制产物；字符串/符号级暴露面未评估，需构建或提供产物后重扫")
    else:
        if not scanned:
            unknown_set.append("清单内产物均无法读取；字符串/符号级暴露面未评估")
        if unreadable:
            unknown_set.append(f"{unreadable} 个产物无法读取，其字符串暴露面未知（见 coverage.omissions）")
        if any(s.truncated for s in scanned):
            unknown_set.append("部分产物超过字符串提取上限，其完整字符串集未知（见 coverage.omissions）")
    unknown_set.append("xrefs 交叉引用需要反汇编器，本域不提供；UTF-16 等宽字符字符串形态未覆盖")

    findings = _build_findings(
        project_path=scan.project_path,
        scanned=tuple(scanned),
        stamp=stamp,
        omissions=tuple(omissions),
        had_artifacts=bool(scan.artifacts),
    )

    if not scan.artifacts:
        state = "not_run"
    elif omissions:
        state = "partial"
    else:
        state = "complete_for_scope"

    coverage = {
        "state": state,
        "scope": (
            f"对 artifact-manifest 清单内 {len(scan.artifacts)} 个产物做只读字符串提取"
            f"（每产物 ≤{STRING_SCAN_BYTES} 字节、≤{MAX_STRINGS_PER_ARTIFACT} 条、串长 ≤{MAX_STRING_LENGTH}；"
            f"{len(LEAK_PATTERNS)} 种泄漏模式；仅记录模式名与计数）"
        ),
        "omissions": omissions,
    }

    return SymbolScanResult(
        project_path=scan.project_path,
        scanned=tuple(scanned),
        findings=findings,
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


def _build_findings(
    *,
    project_path: str,
    scanned: tuple[ArtifactSymbols, ...],
    stamp: str,
    omissions: tuple[str, ...],
    had_artifacts: bool,
) -> tuple[dict[str, Any], ...]:
    """One aggregated finding, or an explicit unknown when nothing was scannable."""
    base_limitations = ["只读字符串提取；不反汇编、不执行产物", "ASCII 可打印串；UTF-16 等宽字符形态未覆盖"]
    if omissions:
        base_limitations.append(f"{len(omissions)} 处未覆盖（见 coverage.omissions）")

    if not had_artifacts:
        return (
            {
                "id": "string-symbol-scan-no-artifacts",
                "category": "string_symbol_surface",
                "status": "unknown",
                "severity": "unrated",
                "title": "未发现可扫描的二进制产物",
                "summary": "artifact-manifest 为空；字符串/符号级暴露面未评估（不可用降级：拒绝扫描而非假成功）",
                "evidence": [
                    {
                        "evidence_id": "ev-symbolscan-none",
                        "kind": "file_observation",
                        "source": f"pea.symbolscan:{project_path}",
                        "observed_at": stamp,
                        "authority": "observation",
                        "limitations": ["输入清单为空；未扫描任何文件"],
                        "redacted_summary": "manifest 无二进制产物",
                    }
                ],
                "coverage": {"state": "not_run", "scope": "无输入产物"},
                "limitations": [*base_limitations, "未发现不等于不存在；需构建或提供产物后重扫"],
                "recommended_actions": ["构建 release 产物后重扫", "或以外部方式取得产物并更新 manifest"],
                # 未评估的字符串/符号面仍属静态内容层：unknown 不丢序。
                "exposure_tier": TIER_STATIC_CONTENT,
            },
        )

    total_patterns: dict[str, int] = {}
    for entry in scanned:
        for name, count in entry.pattern_counts.items():
            total_patterns[name] = total_patterns.get(name, 0) + count
    redacted = "; ".join(
        f"{entry.path}: {', '.join(f'{name}×{count}' for name, count in sorted(entry.pattern_counts.items()))}"
        for entry in scanned
        if entry.pattern_counts
    )
    evidence = {
        "evidence_id": "ev-symbolscan-strings",
        "kind": "file_observation",
        "source": f"pea.symbolscan:{project_path}",
        "observed_at": stamp,
        "authority": "observation",
        "limitations": ["启发式模式匹配；提取的字符串未随输出保留"],
        "redacted_summary": redacted or "未命中任何已知泄漏模式",
    }

    if total_patterns:
        return (
            {
                "id": "string-symbol-scan-hits",
                "category": "string_symbol_surface",
                "status": "observed",
                "severity": "medium",
                "title": "二进制产物字符串命中泄漏模式",
                "summary": (
                    f"{len(scanned)} 个产物共提取字符串并命中 {len(total_patterns)} 种模式"
                    f"（{', '.join(sorted(total_patterns))}）；仅记录模式名与计数，内容不保留"
                ),
                "evidence": [evidence],
                "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "产物字符串提取与模式匹配"},
                "limitations": [*base_limitations, "模式命中不等于可利用；需人工确认上下文"],
                "recommended_actions": [
                    "人工审阅命中模式对应的字符串上下文（用工具自备，勿回贴内容）",
                    "清除或外移构建路径、端点与符号名等静态内容",
                    "把 manifest 指纹纳入证据账本作为后续对比基线",
                ],
                "exposure_tier": TIER_STATIC_CONTENT,
            },
        )

    return (
        {
            "id": "string-symbol-scan-no-hits",
            "category": "string_symbol_surface",
            "status": "observed",
            "severity": "info",
            "title": "未命中已知泄漏模式",
            "summary": f"{len(scanned)} 个产物的字符串未命中 {len(LEAK_PATTERNS)} 种已知泄漏模式（启发式扫描，非证明）",
            "evidence": [evidence],
            "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "产物字符串提取与模式匹配"},
            "limitations": [*base_limitations, "未命中不等于不存在：模式库不覆盖所有泄漏形态"],
            "recommended_actions": ["把字符串扫描纳入发布前检查", "对源文件运行 secret-scan 补充覆盖"],
            "exposure_tier": TIER_STATIC_CONTENT,
        },
    )
