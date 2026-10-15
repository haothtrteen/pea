"""Artifact manifest domain (M3/D2): what shippable binaries exist, fingerprinted.

The second question of the defense-engineering loop, after *where is the
asset* (project recon) and before any claim about one-click tooling can be
tied to evidence: *what release artifacts would actually ship?* The manifest
is the evidence backbone for every later comparison - the attack self-test's
baseline/protected diff, capability-map claims about blutter/jadx-class
tooling, and the ledger's artifact digests all reference manifest entries.
A claim about an artifact that is not in the manifest cannot be tied to
evidence.

Hard rules - the shared read-only discipline of :mod:`pea.fswalk`, plus
manifest-specific ones:

* digests are computed only for files up to ``HASH_LIMIT_BYTES`` and only
  for the first ``MAX_HASHED_ARTIFACTS`` of them; everything past a bound
  is listed *without* a digest and reported as an omission - a missing
  hash is data, never invented;
* directory bundles (``.app``/``.framework``) are not enumerated because
  the walk yields files only; the limitation is stated in coverage;
* "no artifacts found" is an ``unknown`` finding plus an unknown, never a
  silent pass - a source-only tree has an unassessed release surface, and
  the tier annotation stays on the unknown (see ``pea.tiers``: unknown
  does not lose its place in the repair order).
"""
from __future__ import annotations

import hashlib
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
    relpath,
    resolve_root,
    walk_project,
)
from pea.tiers import TIER_TOOL_EFFICIENCY

#: Only files up to this size get a SHA-256 digest recorded.
HASH_LIMIT_BYTES = 1_048_576
#: Digest at most this many artifacts per scan; the rest are listed without
#: a hash and counted in an omission (bounded work, honest gap).
MAX_HASHED_ARTIFACTS = 500

#: Extension -> artifact kind. Only shippable or protection-relevant forms;
#: intermediate build outputs (``.o``) and data formats are deliberately
#: absent - they dilute a manifest whose job is to enumerate what ships.
ARTIFACT_BY_EXTENSION: dict[str, str] = {
    ".so": "native_shared_library",
    ".a": "native_static_library",
    ".dylib": "native_shared_library",
    ".dll": "native_shared_library",
    ".exe": "native_executable",
    ".apk": "android_package",
    ".aab": "android_app_bundle",
    ".jar": "java_archive",
    ".aar": "android_library_archive",
    ".dex": "dalvik_dex",
    ".wasm": "webassembly_module",
    ".node": "node_native_addon",
    ".asar": "electron_asar_archive",
    ".bc": "llvm_bitcode",
    ".pyc": "python_bytecode",
}

#: Basename fragment -> kind, checked before the extension table so an
#: artifact whose name carries its role keeps that role (``libapp.so`` is a
#: Flutter snapshot *and* a shared library; the snapshot reading is the one
#: the capability map's Dart family speaks about).
ARTIFACT_BY_NAME: tuple[tuple[str, str], ...] = (
    ("libapp.so", "flutter_dart_snapshot"),
    ("libflutter.so", "flutter_engine"),
    ("libgodot", "game_engine_library"),
)

#: Kinds that are binary by construction - the string-symbol-scan domain
#: scans exactly these.
BINARY_KINDS = frozenset(ARTIFACT_BY_EXTENSION.values()) | {
    "flutter_dart_snapshot",
    "flutter_engine",
    "game_engine_library",
}


class ArtifactBoundaryError(ValueError):
    """The requested path is not a usable, authorized root for scanning."""


@dataclass(frozen=True)
class ArtifactEntry:
    """One shippable file: where it is, what it looks like, its fingerprint."""

    path: str
    kind: str
    size_bytes: int
    sha256: str | None


@dataclass(frozen=True)
class ArtifactScanResult:
    """The manifest, plus what the scan could not fingerprint."""

    project_path: str
    artifacts: tuple[ArtifactEntry, ...]
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "artifacts": [
                {"path": a.path, "kind": a.kind, "size_bytes": a.size_bytes, "sha256": a.sha256} for a in self.artifacts
            ],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ArtifactScanResult:
        """Rebuild from ``to_dict`` output (the WP2 orchestrator's disk form).

        The downstream string/native/Dart/build domains consume this object;
        on resume they must read the recorded manifest, not re-fingerprint
        the project.
        """
        return cls(
            project_path=str(data["project_path"]),
            artifacts=tuple(
                ArtifactEntry(
                    path=str(a["path"]),
                    kind=str(a["kind"]),
                    size_bytes=int(a["size_bytes"]),
                    sha256=a.get("sha256"),
                )
                for a in data.get("artifacts") or ()
            ),
            findings=tuple(data.get("findings") or ()),
            coverage=dict(data.get("coverage") or {}),
            unknowns=tuple(data.get("unknowns") or ()),
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_LIMIT_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence(evidence_id: str, source: str, observed_at: str, summary: str, *, artifact_digest: str | None) -> dict[str, Any]:
    """One observation-authority evidence record; hash evidence carries the digest."""
    return {
        "evidence_id": evidence_id,
        "kind": "hash",
        "source": source,
        "observed_at": observed_at,
        "authority": "observation",
        "artifact_digest": artifact_digest,
        "limitations": ["静态只读观察；摘要仅覆盖文件当前内容，构建可复现性未验证"],
        "redacted_summary": summary,
    }


def _classify(name: str, suffix: str) -> str | None:
    """Artifact kind for a file, or ``None`` when it is not shippable."""
    lowered = name.lower()
    for fragment, kind in ARTIFACT_BY_NAME:
        if fragment in lowered:
            return kind
    return ARTIFACT_BY_EXTENSION.get(suffix)


def observe_artifacts(
    project_path: str | Path,
    *,
    now: str | None = None,
) -> ArtifactScanResult:
    """Enumerate shippable artifacts under an authorized root. Read-only.

    ``now`` stamps the evidence records; injecting it keeps outputs
    deterministic under test. Everything else is derived from the filesystem.
    """
    stamp = now or _utc_now()
    try:
        root = resolve_root(project_path)
    except WalkBoundaryError as exc:
        raise ArtifactBoundaryError(str(exc)) from exc

    walk = WalkReport()
    artifacts: list[ArtifactEntry] = []
    hashed = 0
    over_size = 0
    over_count = 0

    for file_path, size in walk_project(root, report=walk):
        suffix = file_path.suffix.lower()
        kind = _classify(file_path.name, suffix)
        if kind is None:
            continue
        digest: str | None = None
        if size <= HASH_LIMIT_BYTES and hashed < MAX_HASHED_ARTIFACTS:
            digest = _sha256_of(file_path)
            hashed += 1
        elif size > HASH_LIMIT_BYTES:
            over_size += 1
        else:
            over_count += 1
        artifacts.append(ArtifactEntry(path=relpath(root, file_path), kind=kind, size_bytes=size, sha256=digest))

    omissions = walk.omissions
    if over_size:
        omissions.append(f"{over_size} 个产物超过摘要大小上限 {HASH_LIMIT_BYTES} 字节，未计算 SHA-256")
    if over_count:
        omissions.append(f"{over_count} 个产物超过摘要数量上限 {MAX_HASHED_ARTIFACTS}，未计算 SHA-256")

    unknown_set: list[str] = []
    if not artifacts:
        unknown_set.append("未发现已知形态的可发布产物（native/android/java/wasm 等）；release 级暴露面未评估")
    if over_size or over_count:
        unknown_set.append("部分产物未计算 SHA-256 摘要（见 coverage.omissions），其指纹未知")
    if any("未枚举" in omission for omission in omissions):
        unknown_set.append("部分路径未枚举（见 coverage.omissions），其产物未知")

    findings = _build_findings(
        project_path=str(root),
        artifacts=tuple(artifacts),
        stamp=stamp,
        omissions=tuple(omissions),
    )

    coverage = {
        "state": "partial" if omissions or unknown_set else "complete_for_scope",
        "scope": (
            f"授权根 {root} 的静态只读枚举（文件数上限 {MAX_FILES}、深度 {MAX_DEPTH}）；"
            f"识别 {len(ARTIFACT_BY_EXTENSION) + len(ARTIFACT_BY_NAME)} 种产物形态；"
            f"摘要仅对 ≤{HASH_LIMIT_BYTES} 字节的前 {MAX_HASHED_ARTIFACTS} 个产物计算"
        ),
        "omissions": omissions,
    }

    return ArtifactScanResult(
        project_path=str(root),
        artifacts=tuple(artifacts),
        findings=findings,
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


def _build_findings(
    *,
    project_path: str,
    artifacts: tuple[ArtifactEntry, ...],
    stamp: str,
    omissions: tuple[str, ...],
) -> tuple[dict[str, Any], ...]:
    """Turn the manifest into exposure-finding-shaped findings.

    Digest evidence is one record per fingerprinted artifact (``kind:
    hash``), so the ledger can tie any later artifact claim back to a
    specific file observation.
    """
    base_limitations = ["静态只读枚举；不执行构建，不验证产物可复现性"]
    if omissions:
        base_limitations.append(f"{len(omissions)} 处未覆盖（见 coverage.omissions）")

    if artifacts:
        kind_counts: dict[str, int] = {}
        for entry in artifacts:
            kind_counts[entry.kind] = kind_counts.get(entry.kind, 0) + 1
        digest_count = sum(1 for a in artifacts if a.sha256)
        summary = (
            f"发现 {len(artifacts)} 个可发布产物（{', '.join(f'{k}×{v}' for k, v in sorted(kind_counts.items()))}）；"
            f"其中 {digest_count} 个已计算 SHA-256 指纹"
        )
        evidence = [
            _evidence(
                f"ev-artifact-{index}",
                f"pea.artifactscan:{project_path}",
                stamp,
                f"{entry.path}（{entry.kind}，{entry.size_bytes}B）",
                artifact_digest=entry.sha256,
            )
            for index, entry in enumerate((a for a in artifacts if a.sha256), start=1)
        ]
        return (
            {
                "id": "artifact-manifest-present",
                "category": "release_artifact_surface",
                "status": "observed",
                "severity": "medium",
                "title": "可发布产物清单",
                "summary": summary,
                "artifact_path": artifacts[0].path,
                "artifact_digest": artifacts[0].sha256,
                "evidence": evidence,
                "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "授权根静态枚举"},
                "limitations": base_limitations,
                "recommended_actions": [
                    "将产物指纹纳入证据账本，作为攻击自测 baseline/protected 对比的基准",
                    "对产物运行 string-symbol-scan（pea.symbolscan）",
                    "发布前核对 manifest 与 allowlist 构建清单一致",
                ],
                # 产物是一键逆向工具的直接战场：工具放大层暴露面。
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            },
        )

    return (
        {
            "id": "artifact-manifest-absent",
            "category": "release_artifact_surface",
            "status": "unknown",
            "severity": "unrated",
            "title": "未发现可发布产物",
            "summary": "授权根内未见已知形态的可发布产物（native/android/java/wasm 等）；release 级暴露面未评估",
            "evidence": [
                _evidence(
                    "ev-artifact-none",
                    f"pea.artifactscan:{project_path}",
                    stamp,
                    "静态枚举未见已知形态产物",
                    artifact_digest=None,
                )
            ],
            "coverage": {"state": "partial", "scope": "授权根静态枚举"},
            "limitations": [*base_limitations, "未发现不等于不存在；仅说明当前授权根内不可见"],
            "recommended_actions": [
                "构建 release 产物后重扫",
                "若项目仅以服务端形态分发，在计划中将产物分析标记 not_applicable 并说明理由",
            ],
            # 未见产物 = 工具放大层尚未评估；保持 tool_efficiency 标注，
            # 让"先修工具层"的顺序在 unknown 状态下也不丢失。
            "exposure_tier": TIER_TOOL_EFFICIENCY,
        },
    )
