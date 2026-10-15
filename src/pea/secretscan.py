"""Secret-scan domain (M3/D2): is secret material sitting in static files?

The one defense domain with no REA counterpart, and the one with the
strictest output discipline: a scanner that copies what it found would
become a second copy of the secret. Hits therefore record *pattern name,
path, first line and count* - never the matched text, never a widened
context window. ``secret_value_redacted`` is ``True`` on every finding,
and the tests assert the matched content appears nowhere in the output.

Scope: text source and config files under the authorized root (same
sniffable discipline as project recon; docs are out of scope because
prose *mentioning* a key is not a key). Binary artifacts are covered by
the string-symbol-scan domain, which extracts strings instead of reading
files as text. The scanner never touches system credential stores,
keychains or environment files outside the authorized root.

Hard rules:

* "no hits" is reported as an observed *non-result*, never as proof of
  absence - the pattern library cannot cover every secret shape;
* a file past the sniff cap is an omission plus an unknown, so partial
  coverage can never masquerade as a clean scan;
* directory filtering (e.g. dependency trees) is deliberately *not* done
  here: which paths matter is an operator policy, and hiding third-party
  hits silently would be exactly the kind of quiet narrowing this
  codebase refuses. The limitation is declared instead.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea.fswalk import (
    MAX_DEPTH,
    MAX_FILES,
    WalkBoundaryError,
    WalkReport,
    relpath,
    resolve_root,
    walk_project,
)
from pea.tiers import TIER_STATIC_CONTENT

#: Only the first bytes of a text file are scanned; past the cap the file
#: is an omission plus an unknown, not a clean pass.
SECRET_SNIFF_BYTES = 262_144

#: Extensions whose content is scanned. Source and config formats only;
#: binary extensions are absent on purpose (see module docstring).
TEXT_EXTENSIONS = frozenset(
    {
        # 源码
        ".dart", ".kt", ".kts", ".java", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
        ".py", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".cs", ".lua", ".go", ".rs",
        ".swift", ".m", ".mm", ".rb", ".php", ".sh", ".bash", ".zsh", ".ps1", ".bat",
        ".sql", ".graphql", ".proto", ".vue", ".scala", ".groovy",
        # 配置与清单
        ".xml", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
        ".plist", ".gradle", ".cmake", ".bazel", ".bzl", ".mk", ".env",
        # 证书与密钥材料（文本形态；二进制形态由 NUL 检查自然排除）
        ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks", ".keystore", ".mobileprovision",
    }
)

#: Dotfiles whose *basename* marks them as config - their suffix is empty,
#: so the extension table alone would miss them.
TEXT_BASENAMES = frozenset({".env", ".npmrc", ".netrc", ".pypirc"})

#: Severity ordering for aggregating hit severities into one finding.
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unrated": 0}


@dataclass(frozen=True)
class SecretPattern:
    """A named secret shape. The name is what gets reported - never the match."""

    name: str
    severity: str
    meaning: str
    regex: re.Pattern[str]


#: The pattern library. Deliberately small and reviewable: a pattern that
#: cannot be explained to the project owner does not belong here.
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "private_key_block",
        "high",
        "PEM 私钥块",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
    SecretPattern(
        "cloud_access_key_id",
        "high",
        "云访问键 ID 形态（AKIA…）",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    SecretPattern(
        "vcs_token",
        "high",
        "代码托管平台 token 形态（gh*_…）",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    ),
    SecretPattern(
        "api_key_literal",
        "high",
        "API key 字面量形态（sk-…）",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    ),
    SecretPattern(
        "hardcoded_credential",
        "medium",
        "凭据类标识符的硬编码字符串赋值",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|credential|embedded[_-]?key)"
            r"\w*\s*[:=]\s*(?:['\"][A-Za-z0-9_\-./+=]{8,}['\"]|[A-Za-z0-9_\-./+]{8,})"
        ),
    ),
    SecretPattern(
        "hardcoded_endpoint",
        "low",
        "硬编码 URL 端点（排除 XML 命名空间等已知无害主机）",
        re.compile(
            r"https?://(?!schemas\.android\.com/|www\.w3\.org/|purl\.org/|ns\.adobe\.com/"
            r"json-schema\.org/|www\.opengis\.net/)[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s'\"<>]*)?"
        ),
    ),
)


@dataclass(frozen=True)
class SecretHit:
    """A redacted hit: pattern name, first location and count, never the text."""

    path: str
    pattern: str
    meaning: str
    severity: str
    line: int
    count: int = 1


@dataclass(frozen=True)
class SecretScanResult:
    """Everything the secret scan observed, plus what it could not read."""

    project_path: str
    hits: tuple[SecretHit, ...]
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "hits": [
                {"path": h.path, "pattern": h.pattern, "meaning": h.meaning, "severity": h.severity, "line": h.line, "count": h.count}
                for h in self.hits
            ],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


class SecretBoundaryError(ValueError):
    """The requested path is not a usable, authorized root for scanning."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_scannable(name: str, suffix: str) -> bool:
    return suffix in TEXT_EXTENSIONS or name in TEXT_BASENAMES


def _scan_file(path: Path, rel: str) -> tuple[list[SecretHit], bool]:
    """Return ``(hits, fully_read)``; matched text is never kept.

    Binary files (NUL in the first bytes) yield no hits - they belong to
    the string-symbol-scan domain. Files past the sniff cap are reported
    by the caller as omissions, not silently truncated.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(SECRET_SNIFF_BYTES + 1)
    except OSError:
        return [], True
    if b"\x00" in raw:
        return [], True
    fully_read = len(raw) <= SECRET_SNIFF_BYTES
    text = raw[:SECRET_SNIFF_BYTES].decode("utf-8", errors="replace")
    hits: list[SecretHit] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern in SECRET_PATTERNS:
            if pattern.regex.search(line):
                hits.append(
                    SecretHit(
                        path=rel,
                        pattern=pattern.name,
                        meaning=pattern.meaning,
                        severity=pattern.severity,
                        line=line_no,
                    )
                )
    return hits, fully_read


def _merge_hits(hits: list[SecretHit]) -> list[SecretHit]:
    """Merge repeats per (path, pattern): first line + count, like recon."""
    merged: dict[tuple[str, str], SecretHit] = {}
    for hit in hits:
        key = (hit.path, hit.pattern)
        existing = merged.get(key)
        if existing is None:
            merged[key] = hit
        else:
            merged[key] = SecretHit(
                path=existing.path,
                pattern=existing.pattern,
                meaning=existing.meaning,
                severity=existing.severity,
                line=existing.line,
                count=existing.count + 1,
            )
    return sorted(merged.values(), key=lambda h: (h.path, h.pattern))


def observe_secrets(
    project_path: str | Path,
    *,
    now: str | None = None,
) -> SecretScanResult:
    """Scan an authorized root for secret material. Read-only, redacting.

    ``now`` stamps the evidence record; injecting it keeps outputs
    deterministic under test.
    """
    stamp = now or _utc_now()
    try:
        root = resolve_root(project_path)
    except WalkBoundaryError as exc:
        raise SecretBoundaryError(str(exc)) from exc

    walk = WalkReport()
    raw_hits: list[SecretHit] = []
    partial_files = 0

    for file_path, size in walk_project(root, report=walk):
        suffix = file_path.suffix.lower()
        if not _is_scannable(file_path.name, suffix):
            continue
        rel = relpath(root, file_path)
        if size > SECRET_SNIFF_BYTES:
            partial_files += 1
            continue
        hits, _ = _scan_file(file_path, rel)
        raw_hits.extend(hits)

    omissions = list(walk.omissions)
    if partial_files:
        omissions.append(f"{partial_files} 个文本文件超过嗅探上限 {SECRET_SNIFF_BYTES} 字节，未完全扫描")
    hits = _merge_hits(raw_hits)

    unknown_set: list[str] = []
    if partial_files:
        unknown_set.append(f"{partial_files} 个文本文件超过嗅探上限 {SECRET_SNIFF_BYTES} 字节，其完整内容未扫描")
    if any("未枚举" in omission for omission in omissions):
        unknown_set.append("部分路径未枚举（见 coverage.omissions），其内容未知")
    unknown_set.append("秘密扫描不覆盖二进制产物内字符串（由 string-symbol-scan 负责）、运行期内存与网络传输中的秘密")

    findings = _build_findings(
        project_path=str(root),
        hits=tuple(hits),
        stamp=stamp,
        omissions=tuple(omissions),
    )

    coverage = {
        "state": "partial" if omissions or unknown_set else "complete_for_scope",
        "scope": (
            f"授权根 {root} 的文本文件扫描（文件数上限 {MAX_FILES}、深度 {MAX_DEPTH}、"
            f"嗅探 {SECRET_SNIFF_BYTES} 字节；{len(SECRET_PATTERNS)} 种模式；命中仅记模式名与行号）"
        ),
        "omissions": omissions,
    }

    return SecretScanResult(
        project_path=str(root),
        hits=tuple(hits),
        findings=findings,
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


def _build_findings(
    *,
    project_path: str,
    hits: tuple[SecretHit, ...],
    stamp: str,
    omissions: tuple[str, ...],
) -> tuple[dict[str, Any], ...]:
    """One finding: hits aggregated, or an explicit observed non-result."""
    base_limitations = [
        "静态文本扫描；不访问系统凭据存储或密钥链",
        "未按目录过滤（如依赖目录）；命中可能来自第三方代码，需人工区分",
    ]
    if omissions:
        base_limitations.append(f"{len(omissions)} 处未覆盖（见 coverage.omissions）")
    evidence = {
        "evidence_id": "ev-secret-scan",
        "kind": "file_observation",
        "source": f"pea.secretscan:{project_path}",
        "observed_at": stamp,
        "authority": "observation",
        "limitations": ["启发式模式匹配；命中内容已脱敏，仅记录模式名与行号"],
        "redacted_summary": (
            "; ".join(f"{hit.path}:{hit.pattern}(行{hit.line})×{hit.count}" for hit in hits)
            if hits
            else "未命中任何已知秘密材料模式"
        ),
    }

    if hits:
        severity = max(hits, key=lambda h: _SEVERITY_RANK.get(h.severity, 0)).severity
        pattern_names = sorted({hit.pattern for hit in hits})
        hit_paths = sorted({hit.path for hit in hits})
        return (
            {
                "id": "secret-scan-hits",
                "category": "secret_material_surface",
                "status": "observed",
                "severity": severity,
                "title": "发现秘密材料模式命中",
                "summary": (
                    f"{len(hit_paths)} 个文件命中 {len(pattern_names)} 种模式（{', '.join(pattern_names)}）；"
                    "命中仅记录模式名、行号与次数，匹配内容已脱敏"
                ),
                "artifact_path": hit_paths[0],
                "evidence": [evidence],
                "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "文本文件模式扫描（内容脱敏）"},
                "limitations": [*base_limitations, "模式命中不等于真实秘密；需人工确认边界与威胁模型"],
                "recommended_actions": [
                    "人工确认命中项是否真实秘密（脱敏检查，不在本工具输出中还原）",
                    "将秘密移至服务端或可信边界（部署姿态允许时）",
                    "把命中模式纳入预提交检查，防止再次引入",
                ],
                "secret_value_redacted": True,
                # 秘密材料是静态内容：不运行即可扫描得到。
                "exposure_tier": TIER_STATIC_CONTENT,
            },
        )

    return (
        {
            "id": "secret-scan-no-hits",
            "category": "secret_material_surface",
            "status": "observed",
            "severity": "info",
            "title": "未命中已知秘密材料模式",
            "summary": f"未命中 {len(SECRET_PATTERNS)} 种已知秘密材料模式（启发式扫描，非证明）",
            "evidence": [evidence],
            "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "文本文件模式扫描（内容脱敏）"},
            "limitations": [*base_limitations, "未命中不等于不存在：模式库不覆盖所有秘密形态"],
            "recommended_actions": [
                "把秘密扫描纳入 CI 预提交检查",
                "对二进制产物运行 string-symbol-scan 补充覆盖",
            ],
            "secret_value_redacted": True,
            "exposure_tier": TIER_STATIC_CONTENT,
        },
    )
