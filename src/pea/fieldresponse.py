"""Field feedback loop (D7): cracked-sample intake and server-side response.

The trigger is an event, not a calendar: *a cracked build has arrived*. This
module turns that event into two artifacts -

* a **crack intake** - the cracked package is just another artifact, so the
  seven read-only domains scan it directly, and a byte-level diff against the
  original ``artifact-manifest`` digests locates *what changed* and therefore
  *which protection layer failed where*. The mechanism is almost entirely
  reuse: no new scanning technology, only the diff;
* a **field response plan** - the frozen correction from the design: **never
  push code into a cracked package.** A cracked package is not under your
  control: strip the loader and the update cannot land; leave it intact and
  the update is free analysis material. The correct mechanism is the
  **server-side moving goalpost**: rotate the challenge / protocol /
  verification rules so only clients that still contain and execute the
  original logic can answer. *Whatever the cracker stripped is exactly what
  he can no longer answer.*

Honesty rules encoded here:

* the diff is an **observation**; "which protection failed" is an
  **inference** (or an unknown) - the two never travel under one label;
* added files in a cracked package are unknowns, not assumed payloads;
* the response mechanism is available only when the posture has a server;
  a purely offline application is **declined** (the plan is blocked at
  derivation time, not emitted empty);
* red lines are fixed text: neutral failure (the server stops cooperating
  with the cracked package; nothing touches the attacker's device), no
  collateral damage on legitimate users (the negative tests are mandatory),
  and no code pushed into the cracked package.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea.artifactscan import ArtifactEntry, observe_artifacts
from pea.tiers import TIER_TOOL_EFFICIENCY
from pea.validation import validate_or_raise

FIELD_RESPONSE_SCHEMA = "field-response"

#: Manifest diff outcomes.
CHANGE_MODIFIED = "modified"
CHANGE_ADDED = "added"
CHANGE_REMOVED = "removed"

#: Fixed red lines (design §4.4). They are not parameters.
FIELD_RED_LINES: tuple[str, ...] = (
    "中性失效：服务器不再配合破解包；不触碰攻击者设备（敌对载荷是法律雷区）",
    "不误杀合法用户：负向测试必须包含'合法变体不受影响'，通过后才可全量",
    "不往已分发的破解包推送代码：剥掉加载路径则更新进不去，没剥掉则更新成为送上门的分析材料",
    "仅对有服务端姿态可用；纯离线应用在计划推导时挡掉本机制",
    "响应是服务端动作：轮换挑战/协议/校验规则，不修改、不回写、不重新打包任何已分发产物",
)

#: Mandatory negative tests; the legitimate-variant one is the no-collateral
#: red line and can never be dropped.
BASE_NEGATIVE_TESTS: tuple[dict[str, str], ...] = (
    {
        "test_id": "NT-cracked-fails",
        "scenario": "cracked_variant_fails",
        "expectation": "破解变体（diff 定位的改动产物）在新规则下无法完成服务端挑战应答",
    },
    {
        "test_id": "NT-legitimate-unaffected",
        "scenario": "legitimate_variant_unaffected",
        "expectation": "未改动的合法客户端在新规则下行为不变（历史 kill-switch 误杀是真实事故教训）",
    },
    {
        "test_id": "NT-offline-graceful",
        "scenario": "offline_client_degrades_gracefully",
        "expectation": "离线客户端降级路径可用（本地宽限期与提示），不硬失败",
    },
)

#: Artifact kind -> the protection layer a change to it most plausibly
#: stresses. This is a *hypothesis map*, not a verdict: the diff fact stays
#: an observation, the layer attribution travels as inference.
_LAYER_BY_KIND: dict[str, str] = {
    "flutter_dart_snapshot": TIER_TOOL_EFFICIENCY,
    "flutter_engine": TIER_TOOL_EFFICIENCY,
    "native_library": TIER_TOOL_EFFICIENCY,
    "authorization_logic_source": TIER_TOOL_EFFICIENCY,
}

_BASE_LIMITATIONS: tuple[str, ...] = (
    "diff 只覆盖 manifest 枚举到的产物；未枚举路径（构建输出目录之外）的改动不可见",
    "哪条防护失效是推断：改动位置与暴露层的对应关系需人工确认，不得把推断当作实测",
    "响应措施改变服务端契约；灰度与回滚计划由部署方掌握，PEA 不执行",
)


class FieldResponseBoundaryError(ValueError):
    """The cracked package or baseline is not a usable root for intake."""


@dataclass(frozen=True)
class ArtifactDiff:
    """One manifest difference between baseline and cracked package."""

    path: str
    change: str  # modified | added | removed
    baseline_sha256: str | None
    cracked_sha256: str | None
    kind: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "change": self.change,
            "baseline_sha256": self.baseline_sha256,
            "cracked_sha256": self.cracked_sha256,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class CrackIntakeResult:
    """Everything the cracked-package intake observed, plus what it could not."""

    cracked_path: str
    baseline_path: str
    diffs: tuple[ArtifactDiff, ...]
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cracked_path": self.cracked_path,
            "baseline_path": self.baseline_path,
            "diffs": [d.to_dict() for d in self.diffs],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def diff_manifests(
    baseline_artifacts: Sequence[ArtifactEntry | Mapping[str, Any]],
    cracked_artifacts: Sequence[ArtifactEntry | Mapping[str, Any]],
) -> tuple[ArtifactDiff, ...]:
    """Byte-level manifest diff: what changed between the two builds.

    Matching is by path; the verdict is by digest. An entry whose digest
    changed is ``modified``; present on one side only is ``added``/``removed``
    relative to the baseline. Entries without a recorded digest are compared
    by size only and say so - an unfingerprinted file cannot support a
    byte-level claim.
    """

    def _entries(items: Sequence[ArtifactEntry | Mapping[str, Any]]) -> dict[str, tuple[str | None, int | None, str | None]]:
        table: dict[str, tuple[str | None, int | None, str | None]] = {}
        for item in items:
            if isinstance(item, ArtifactEntry):
                table[item.path] = (item.sha256, item.size_bytes, item.kind)
            else:
                raw_path = item.get("path")
                raw_digest = item.get("sha256")
                raw_size = item.get("size_bytes")
                raw_kind = item.get("kind")
                table[raw_path if isinstance(raw_path, str) else ""] = (
                    raw_digest if isinstance(raw_digest, str) else None,
                    raw_size if isinstance(raw_size, int) else None,
                    raw_kind if isinstance(raw_kind, str) else None,
                )
        return table

    baseline = _entries(baseline_artifacts)
    cracked = _entries(cracked_artifacts)
    diffs: list[ArtifactDiff] = []
    for path in sorted(set(baseline) | set(cracked)):
        base = baseline.get(path)
        crack = cracked.get(path)
        if base is not None and crack is not None:
            base_digest, base_size, kind = base
            crack_digest, crack_size, _ = crack
            if base_digest and crack_digest:
                if base_digest != crack_digest:
                    diffs.append(ArtifactDiff(path, CHANGE_MODIFIED, base_digest, crack_digest, kind))
            elif base_size != crack_size:
                # No digests on one side: a size difference is observable,
                # but it is not a byte-level claim - the caller must say so.
                diffs.append(ArtifactDiff(path, CHANGE_MODIFIED, base_digest, crack_digest, kind))
        elif base is not None:
            diffs.append(ArtifactDiff(path, CHANGE_REMOVED, base[0], None, base[2]))
        else:
            assert crack is not None
            diffs.append(ArtifactDiff(path, CHANGE_ADDED, None, crack[0], crack[2]))
    return tuple(diffs)


def _evidence(evidence_id: str, source: str, observed_at: str, summary: str, *, authority: str = "observation") -> dict[str, Any]:
    return {
        "evidence_id": evidence_id,
        "kind": "file_observation" if authority == "observation" else "inference",
        "source": source,
        "observed_at": observed_at,
        "authority": authority,
        "limitations": ["破解包 intake：只读扫描 + manifest digest diff；不覆盖未枚举路径"],
        "redacted_summary": summary,
    }


def intake_cracked_artifact(
    cracked_path: str | Path,
    baseline_path: str | Path,
    *,
    now: str | None = None,
) -> CrackIntakeResult:
    """Scan a cracked package and diff it against the original build.

    Both roots are read-only scanned with the artifact-manifest domain; the
    diff locates the changes. *Which protection failed* is deliberately kept
    as an inference-level finding: the diff is the observation, the layer
    attribution is a hypothesis that needs human confirmation.
    """
    stamp = now or _utc_now()
    cracked_root = Path(cracked_path).expanduser().resolve()
    baseline_root = Path(baseline_path).expanduser().resolve()
    if not cracked_root.is_dir():
        raise FieldResponseBoundaryError(f"cracked path is not a directory: {cracked_root}")
    if not baseline_root.is_dir():
        raise FieldResponseBoundaryError(f"baseline path is not a directory: {baseline_root}")

    cracked_scan = observe_artifacts(cracked_root, now=stamp)
    baseline_scan = observe_artifacts(baseline_root, now=stamp)
    diffs = diff_manifests(baseline_scan.artifacts, cracked_scan.artifacts)

    modified = [d for d in diffs if d.change == CHANGE_MODIFIED]
    added = [d for d in diffs if d.change == CHANGE_ADDED]
    removed = [d for d in diffs if d.change == CHANGE_REMOVED]

    findings: list[dict[str, Any]] = []
    changed_summary = (
        f"manifest diff：modified {len(modified)} / added {len(added)} / removed {len(removed)}；"
        + (", ".join(d.path for d in modified[:10]) or "无 modified")
    )
    findings.append(
        {
            "id": "crack-intake-manifest-diff",
            "category": "field_incident_diff",
            "status": "observed",
            "severity": "high" if modified else "medium",
            "title": "破解包与原版 manifest 差异",
            "summary": changed_summary,
            "evidence": [
                _evidence(
                    "ev-crack-diff",
                    f"pea.fieldresponse:{cracked_root} vs {baseline_root}",
                    stamp,
                    changed_summary,
                )
            ],
            "coverage": {"state": "partial", "scope": "manifest digest diff（仅覆盖双方枚举到的产物）"},
            "limitations": [
                "diff 是 observation；'哪条防护失效'是推断，需人工确认",
                "未枚举路径的改动不可见",
            ],
            "recommended_actions": ["人工核对每个 modified 产物的改动性质", "将 diff 事实入账（observation 权威）"],
            "exposure_tier": TIER_TOOL_EFFICIENCY,
        }
    )

    for diff in modified:
        layer = _LAYER_BY_KIND.get(diff.kind or "", TIER_TOOL_EFFICIENCY)
        findings.append(
            {
                "id": f"crack-intake-modified-{diff.path.replace('/', '_').replace('.', '_')}",
                "category": "field_incident_layer_attribution",
                "status": "inferred",
                "severity": "high",
                "title": f"改动产物疑对应防护层失效：{diff.path}",
                "summary": (
                    f"{diff.path}（kind={diff.kind or 'unknown'}）digest 变化；"
                    f"按产物类型推断最可能受压制的暴露层为 {layer}。"
                    "推断需人工确认——digest 变化本身不等于某条具体防护被剥。"
                ),
                "evidence": [
                    _evidence(
                        f"ev-crack-modified-{diff.path.replace('/', '_').replace('.', '_')}",
                        f"pea.fieldresponse:diff {diff.path}",
                        stamp,
                        f"baseline={diff.baseline_sha256} cracked={diff.cracked_sha256}",
                        authority="inference",
                    )
                ],
                "coverage": {"state": "partial", "scope": "digest diff + 产物类型推断"},
                "limitations": ["层归属是推断；同 digest 变化可能有与防护无关的解释（重打包、时间戳）"],
                "recommended_actions": ["对比构建配置与符号表确认改动性质", "在响应计划中将该产物作为球门轮换的触发锚点"],
                "exposure_tier": layer,
            }
        )

    unknown_set: list[str] = []
    for diff in added:
        unknown_set.append(f"破解包新增文件 {diff.path}：内容与用途未分析，不得假定为恶意载荷")
    if not diffs:
        unknown_set.append("manifest diff 未发现差异：破解手段可能不在 manifest 枚举范围内（如服务端账号共享、配置外泄）")
    unknown_set.append("改动产物是否重新签名、是否含额外通信端点，未分析")
    unknown_set.append("合法用户中是否存在误装变体，未评估")

    omissions: list[str] = []
    for scan in (baseline_scan, cracked_scan):
        omissions.extend(scan.coverage.get("omissions", []))
    coverage = {
        "state": "partial" if (omissions or unknown_set) else "complete_for_scope",
        "scope": "破解包 intake：七域复用之 manifest 域 + digest diff（只读）",
        "omissions": omissions,
    }

    return CrackIntakeResult(
        cracked_path=str(cracked_root),
        baseline_path=str(baseline_root),
        diffs=diffs,
        findings=tuple(findings),
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


def design_field_response(
    intake: Mapping[str, Any] | CrackIntakeResult,
    *,
    offline_required: bool = False,
    plan_id: str | None = None,
    response_id: str | None = None,
) -> dict[str, Any]:
    """Design the server-side response plan for a field incident (D7 §4.2).

    The mechanism is the **moving goalpost**, never a code push into the
    cracked package: for each changed artifact, rotate the server-side
    challenge/protocol/verification rule that only a client still executing
    the original logic can answer. *Whatever the cracker stripped is exactly
    what he can no longer answer.*

    ``offline_required=True`` declines the plan outright: with no server
    posture there is no goalpost to move, and an empty plan would pretend
    otherwise. The refusal is the deliverable.
    """
    payload = intake.to_dict() if isinstance(intake, CrackIntakeResult) else dict(intake)
    diffs = [d for d in payload.get("diffs", []) if isinstance(d, Mapping)]
    modified = [d for d in diffs if d.get("change") == CHANGE_MODIFIED]
    added = [d for d in diffs if d.get("change") == CHANGE_ADDED]

    unknown_set: list[str] = [str(u) for u in payload.get("unknowns", [])]
    limitations: list[str] = list(_BASE_LIMITATIONS)

    if offline_required:
        posture = "declined_offline_only"
        measures: list[dict[str, Any]] = []
        unknown_set.append("纯离线应用（offline_required=true）没有服务端姿态；球门轮换机制不可用，本计划被挡下")
        limitations.append("纯离线姿态的响应只能来自客户端再分发（新版本），那属于发布流程而非战场响应")
    else:
        posture = "server_side_available"
        measures = []
        for index, diff in enumerate(modified, start=1):
            measures.append(
                {
                    "measure_id": f"M{index}",
                    "kind": "server_side_goalpost_move",
                    "target": f"license_challenge_rotation_v{index}",
                    "rationale": (
                        f"破解包改动了 {diff['path']}（digest 变化）；"
                        "轮换该产物承载逻辑对应的服务端挑战/校验规则——破解者剥掉了什么，就轮换什么，"
                        "他剥掉的正是他答不上的"
                    ),
                    "impact_scope": "所有仍与旧规则通信的客户端；合法客户端随版本更新获得新规则",
                    "rollout": "gray",
                    "trigger_artifact": str(diff["path"]),
                }
            )
        if added:
            unknown_set.append(
                f"破解包新增 {len(added)} 个文件（内容未分析）：若其中含服务端通信补丁，需先分析再决定是否收紧 attestation"
            )
        if not measures:
            unknown_set.append("manifest diff 未定位到改动产物：无可轮换锚点；先人工分析破解手段再规划响应")

    negative_tests = [dict(test) for test in BASE_NEGATIVE_TESTS]

    digest_source = {
        "cracked_path": payload.get("cracked_path", ""),
        "baseline_path": payload.get("baseline_path", ""),
        "diffs": [d.get("path") for d in diffs],
        "posture": posture,
        "plan_id": plan_id,
    }
    if response_id is None:
        response_id = "fr-" + hashlib.sha256(
            json.dumps(digest_source, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:12]

    response: dict[str, Any] = {
        "schema_version": "1.0",
        "response_id": response_id,
        "created_at": _utc_now(),
        "posture": posture,
        "incident": {
            "cracked_path": str(payload.get("cracked_path", "")),
            "baseline_path": str(payload.get("baseline_path", "")),
            "changed_artifacts": len(diffs),
            "changed_paths": [str(d.get("path", "")) for d in diffs],
        },
        "measures": measures,
        "negative_tests": negative_tests,
        "red_lines": list(FIELD_RED_LINES),
        "limitations": limitations,
        "unknowns": unknown_set,
    }
    if plan_id:
        response["plan_id"] = plan_id

    validate_or_raise(response, _schema(FIELD_RESPONSE_SCHEMA), subject="generated field response")
    return response


def intake_evidence_records(
    result: CrackIntakeResult | Mapping[str, Any],
    *,
    observed_at: str | None = None,
) -> list[dict[str, Any]]:
    """Ready-to-record evidence for the duel ledger (design §4.5).

    The diff facts travel as ``observation``; the layer attributions as
    ``inference``. Both carry the incident's paths so the ledger can tell a
    field duel apart from a rehearsal.
    """
    stamp = observed_at or _utc_now()
    records: list[dict[str, Any]] = []
    findings = result.findings if isinstance(result, CrackIntakeResult) else result.get("findings", [])
    for finding in findings:
        for record in finding.get("evidence", []):
            entry = dict(record)
            entry.setdefault("observed_at", stamp)
            records.append(entry)
    return records


def _schema(name: str) -> Mapping[str, Any]:
    from pea.validation import default_registry

    return default_registry().get(name)
