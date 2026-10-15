"""Dart-AOT-check domain (M3/D2, D4's carrier): what does the snapshot expose?

This is the defensive mirror of the capability map's
``dart-aot-snapshot-analysis`` entry: the same questions an analyst's
tooling answers in its first pass, asked by the owner about their own
release artifact - and answered with the same honesty about what was *not*
measured.

What this domain actually does (pure stdlib, no disassembler, no execution):

* locates the Dart AOT snapshot containers in the artifact manifest
  (``libapp.so``) and the engine (``libflutter.so``);
* extracts printable strings and matches *shapes*, never content - the same
  redaction discipline as string-symbol-scan;
* looks for the snapshot anchors (``_kDartVmSnapshotInstructions`` and
  friends) that tell tooling where the snapshot begins; that is a
  tool-efficiency property, which is why the finding carries the
  tool-efficiency tier, not a content leak claim;
* counts identifier-shaped strings (CamelCase, ``_Private``, method-like
  tokens) as a *proxy* for how much structure sits in the pool.

What it refuses to do - and this is the point of the domain:

* **it does not decide whether ``--obfuscate`` was used.** Obfuscation
  status cannot be reliably read back from a binary; claiming otherwise
  would be the exact "verified by assertion" failure the ledger exists to
  block. The domain reports ``unknown`` plus the probe that would resolve
  it (build config plus the ``--split-debug-info`` symbol map);
* **it does not report recovery rates.** How much a blutter-class tool
  actually recovers belongs to the L2 real-artifact layer; until that runs,
  the number is an unknown, not a zero and not an estimate.

Hard rules, shared with the other domains: no artifacts means ``unknown``
and ``not_run``; unreadable or truncated artifacts are omissions; every
bound that fires is recorded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea.artifactscan import ArtifactScanResult
from pea.fswalk import is_inside, resolve_root
from pea.symbolscan import MIN_STRING_LENGTH, extract_strings
from pea.tiers import TIER_TOOL_EFFICIENCY

#: Bytes of any single snapshot container read for string extraction.
DART_SCAN_BYTES = 8_388_608
#: Strings kept per container; the rest is an omission.
MAX_STRINGS_PER_SNAPSHOT = 20_000

#: Manifest kinds that carry Dart state.
SNAPSHOT_KINDS = frozenset({"flutter_dart_snapshot"})
ENGINE_KINDS = frozenset({"flutter_engine"})

#: The symbols tooling uses to find the snapshot inside an ELF container.
#: Their presence is a *tool-efficiency* fact: it means a parser can go
#: straight to the snapshot instead of scanning for it.
DART_SNAPSHOT_ANCHORS: tuple[str, ...] = (
    "_kDartVmSnapshotInstructions",
    "_kDartIsolateSnapshotInstructions",
    "_kDartVmSnapshotData",
    "_kDartIsolateSnapshotData",
)

#: A version-shaped token near Dart/Flutter context. This is a *shape* probe:
#: the authoritative SDK version comes from the engine, and even then a match
#: is a hypothesis until cross-checked against a known runtime.
VERSION_SHAPE = re.compile(r"\b\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.]+)?\b")

#: Shapes counted in the pool. Counts only - no string ever leaves.
DART_SHAPES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("dart_private_identifier", "Dart 私有标识符形态（_ 开头）", re.compile(r"^_[A-Za-z][A-Za-z0-9_]*$")),
    ("camel_case_identifier", "驼峰标识符形态（类名/类型名）", re.compile(r"^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+$")),
    ("dart_package_path", "package: 引用路径", re.compile(r"^package:[a-z0-9_]+/")),
    ("url", "URL 形态", re.compile(r"^https?://")),
    ("version_shape", "版本号形态", VERSION_SHAPE),
)


@dataclass(frozen=True)
class SnapshotObservation:
    """One Dart container: anchors, shape counts, and what was not read."""

    path: str
    kind: str
    sha256: str | None
    anchors_found: tuple[str, ...]
    strings_found: int
    truncated: bool
    shape_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class DartAotCheckResult:
    """Everything observed about the Dart AOT surface, plus what was not."""

    project_path: str
    snapshots: tuple[SnapshotObservation, ...]
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "snapshots": [
                {
                    "path": s.path,
                    "kind": s.kind,
                    "sha256": s.sha256,
                    "anchors_found": list(s.anchors_found),
                    "strings_found": s.strings_found,
                    "truncated": s.truncated,
                    "shape_counts": dict(s.shape_counts),
                }
                for s in self.snapshots
            ],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _count_shapes(strings: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for text in strings:
        for name, _meaning, pattern in DART_SHAPES:
            if pattern.search(text):
                counts[name] = counts.get(name, 0) + 1
    return counts


def _find_anchors(strings: list[str]) -> tuple[str, ...]:
    found: list[str] = []
    joined = set(strings)
    for anchor in DART_SNAPSHOT_ANCHORS:
        if any(anchor in s for s in joined):
            found.append(anchor)
    return tuple(found)


def observe_dart_aot(
    scan: ArtifactScanResult,
    *,
    now: str | None = None,
) -> DartAotCheckResult:
    """Read the manifest's Dart containers for snapshot-level exposure.

    Consumes the artifact manifest like the other downstream domains: one
    traversal, one root resolution, and every entry that escapes the root
    is a refusal rather than a read.
    """
    stamp = now or _utc_now()

    try:
        root = resolve_root(scan.project_path)
    except Exception:
        root = None

    omissions: list[str] = []
    observations: list[SnapshotObservation] = []
    unknown_set: list[str] = []

    dart_entries = [e for e in scan.artifacts if e.kind in SNAPSHOT_KINDS or e.kind in ENGINE_KINDS]
    snapshot_entries = [e for e in scan.artifacts if e.kind in SNAPSHOT_KINDS]
    engine_entries = [e for e in scan.artifacts if e.kind in ENGINE_KINDS]

    unreadable = 0

    for entry in dart_entries:
        candidate = root / entry.path if root is not None else Path(scan.project_path) / entry.path
        if root is not None and not is_inside(root, candidate):
            omissions.append(f"{entry.path}: 路径越出项目边界，拒绝读取")
            continue
        try:
            strings, truncated = extract_strings(
                candidate,
                max_bytes=DART_SCAN_BYTES,
                max_strings=MAX_STRINGS_PER_SNAPSHOT,
            )
        except OSError as exc:
            omissions.append(f"{entry.path}: 无法读取（{exc.__class__.__name__}），未扫描")
            unreadable += 1
            continue
        if truncated:
            omissions.append(
                f"{entry.path}: 超过提取上限（{DART_SCAN_BYTES} 字节或 {MAX_STRINGS_PER_SNAPSHOT} 条），未完整提取"
            )
        observations.append(
            SnapshotObservation(
                path=entry.path,
                kind=entry.kind,
                sha256=entry.sha256,
                anchors_found=_find_anchors(strings),
                strings_found=len(strings),
                truncated=truncated,
                shape_counts=_count_shapes(strings),
            )
        )

    if not dart_entries:
        unknown_set.append("manifest 中无 Dart 相关产物（libapp.so / libflutter.so）；Dart AOT 快照面未评估")
    else:
        if not snapshot_entries:
            unknown_set.append("发现 Flutter 引擎但未发现 Dart 快照产物；快照面未评估（引擎存在不代表快照已识别）")
        if not observations:
            unknown_set.append("Dart 产物均无法读取；快照面未评估")
        if unreadable:
            unknown_set.append(f"{unreadable} 个 Dart 产物无法读取（见 coverage.omissions）")
        if any(o.truncated for o in observations):
            unknown_set.append("部分 Dart 产物超过提取上限；其完整字符串集未知（见 coverage.omissions）")

    # Standing unknowns: these are the domain's own declared limits, always
    # present, never resolved by a lucky parse.
    unknown_set.append(
        "是否启用 --obfuscate 无法由二进制结构可靠判定：需构建配置与 --split-debug-info 符号映射文件作为证据"
    )
    unknown_set.append(
        "blutter 类工具的实际恢复率未经本域实测（属 L2 真实工件层）；本域不给出恢复率数字"
    )
    unknown_set.append("快照解析依赖 Dart SDK 版本匹配；版本串仅做形态探测，未与已知运行时交叉确认")

    findings = _build_findings(
        project_path=scan.project_path,
        observations=tuple(observations),
        stamp=stamp,
        omissions=tuple(omissions),
        had_dart=bool(dart_entries),
        had_snapshot=bool(snapshot_entries),
    )

    if not dart_entries:
        state = "not_run"
    elif omissions or not observations:
        state = "partial"
    else:
        state = "complete_for_scope"

    coverage = {
        "state": state,
        "scope": (
            f"对 manifest 内 {len(snapshot_entries)} 个快照产物与 {len(engine_entries)} 个引擎产物做只读字符串形态探测"
            f"（每产物 ≤{DART_SCAN_BYTES} 字节、≤{MAX_STRINGS_PER_SNAPSHOT} 条、串长 ≥{MIN_STRING_LENGTH}；"
            f"{len(DART_SNAPSHOT_ANCHORS)} 个快照锚点、{len(DART_SHAPES)} 种形态；仅记录名称与计数）"
        ),
        "omissions": omissions,
    }

    return DartAotCheckResult(
        project_path=scan.project_path,
        snapshots=tuple(observations),
        findings=findings,
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


def _build_findings(
    *,
    project_path: str,
    observations: tuple[SnapshotObservation, ...],
    stamp: str,
    omissions: tuple[str, ...],
    had_dart: bool,
    had_snapshot: bool,
) -> tuple[dict[str, Any], ...]:
    """One aggregated finding, or an explicit unknown when nothing was readable."""
    base_limitations = [
        "只读字符串形态探测；不执行 blutter 类工具、不反汇编、不还原代码",
        "仅记录形态名称与计数，不保留任何字符串内容",
        "ASCII 可打印串；UTF-16 等宽字符形态未覆盖",
    ]
    if omissions:
        base_limitations.append(f"{len(omissions)} 处未覆盖（见 coverage.omissions）")

    if not had_dart:
        return (
            {
                "id": "dart-aot-absent",
                "category": "dart_snapshot_surface",
                "status": "unknown",
                "severity": "unrated",
                "title": "未发现 Dart 相关产物",
                "summary": "manifest 中无 libapp.so / libflutter.so；Dart AOT 快照面未评估（不可用降级：拒绝报告而非假成功）",
                "evidence": [
                    {
                        "evidence_id": "ev-dartaot-none",
                        "kind": "file_observation",
                        "source": f"pea.dartaotcheck:{project_path}",
                        "observed_at": stamp,
                        "authority": "observation",
                        "limitations": ["输入清单无 Dart 产物；未扫描任何文件"],
                        "redacted_summary": "manifest 无 Dart 产物",
                    }
                ],
                "coverage": {"state": "not_run", "scope": "无输入产物"},
                "limitations": [*base_limitations, "未发现不等于不存在；需构建或提供产物后重扫"],
                "recommended_actions": ["构建 Flutter release 产物后重扫", "或提供已发布产物并更新 manifest"],
                # 与能力地图一致：Dart 快照面属工具放大层，unknown 不丢序。
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            },
        )

    if not observations:
        return (
            {
                "id": "dart-aot-unreadable",
                "category": "dart_snapshot_surface",
                "status": "unknown",
                "severity": "unrated",
                "title": "Dart 产物均无法完成探测",
                "summary": (
                    f"manifest 中存在 Dart 产物，但 {len(omissions)} 个均未能完成探测；"
                    "快照面未评估（不可用降级：拒绝报告而非假成功）"
                ),
                "evidence": [
                    {
                        "evidence_id": "ev-dartaot-unreadable",
                        "kind": "file_observation",
                        "source": f"pea.dartaotcheck:{project_path}",
                        "observed_at": stamp,
                        "authority": "observation",
                        "limitations": ["无成功探测的产物；快照内容未知而非为空"],
                        "redacted_summary": f"{len(omissions)} 个产物未探测（见 coverage.omissions）",
                    }
                ],
                "coverage": {"state": "partial", "scope": "Dart 产物探测（无成功探测的产物）"},
                "limitations": [*base_limitations, "探测失败不等于无暴露；需修复产物可读性后重扫"],
                "recommended_actions": ["确认产物完整且可读后重扫"],
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            },
        )

    total_shapes: dict[str, int] = {}
    for obs in observations:
        for name, count in obs.shape_counts.items():
            total_shapes[name] = total_shapes.get(name, 0) + count
    anchors = sorted({a for obs in observations for a in obs.anchors_found})
    snapshots = [o for o in observations if o.kind in SNAPSHOT_KINDS]

    redacted = "; ".join(
        f"{obs.path}: 锚点 {len(obs.anchors_found)}/{len(DART_SNAPSHOT_ANCHORS)}"
        f"{'（' + ','.join(obs.anchors_found) + '）' if obs.anchors_found else ''}"
        f"，形态 {', '.join(f'{k}×{v}' for k, v in sorted(obs.shape_counts.items())) or '无'}"
        for obs in observations
    )

    evidence = {
        "evidence_id": "ev-dartaot-observed",
        "kind": "file_observation",
        "source": f"pea.dartaotcheck:{project_path}",
        "observed_at": stamp,
        "authority": "observation",
        "limitations": ["形态计数为启发式代理指标；不承诺任何恢复率或可读性结论"],
        "redacted_summary": redacted,
    }

    summary_bits = [
        f"{len(snapshots)} 个快照产物、{len(observations) - len(snapshots)} 个引擎产物完成形态探测",
        f"快照锚点命中 {len(anchors)}/{len(DART_SNAPSHOT_ANCHORS)}"
        + ("（工具可直接定位快照段）" if anchors else "（需扫描或版本匹配才能定位快照段）"),
        f"对象池形态 {', '.join(f'{k}×{v}' for k, v in sorted(total_shapes.items())) or '无命中'}",
    ]
    if not had_snapshot:
        summary_bits.append("未发现快照产物（仅有引擎），快照面本身未评估")

    return (
        {
            "id": "dart-aot-observable",
            "category": "dart_snapshot_surface",
            "status": "observed",
            "severity": "medium",
            "title": "Dart AOT 快照面可观测",
            "summary": "；".join(summary_bits),
            "evidence": [evidence],
            "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "Dart 产物形态探测"},
            "limitations": [
                *base_limitations,
                "锚点命中只影响分析工具的效率，不改变快照本身是否可被解析",
                "混淆状态未知：本域不做判定，需构建配置证据",
            ],
            "recommended_actions": [
                "把最终授权判定与持久密钥移到服务端或可信边界",
                "关键纯函数经 FFI 下沉到受保护的 native 库，迫使攻击者更换工具链",
                "发布前用同款分析工具对自家产物做一次实测并记录可恢复内容（L2）",
                "用 --split-debug-info 的符号映射文件补齐混淆状态的证据缺口",
            ],
            "exposure_tier": TIER_TOOL_EFFICIENCY,
        },
    )
