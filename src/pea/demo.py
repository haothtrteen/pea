"""End-to-end prototype walkthrough: the defense-engineering loop, composed.

``run_demo`` wires the pure modules into the closed loop the architecture
spec describes - *where is the asset → how would it be taken apart → what do
we stack → how do we prove it worked* - and nothing more:

1. authorization gate (no scan happens before ownership is stated);
2. read-only recon of the authorized root (:mod:`pea.recon`);
3. the remaining M3/D2 domains, each in the unified
   findings + coverage + unknowns shape (:mod:`pea.domains`):
   artifact manifest (:mod:`pea.artifactscan`), secret scan
   (:mod:`pea.secretscan`), string-symbol scan (:mod:`pea.symbolscan`),
   native check (:mod:`pea.nativecheck`), Dart AOT check
   (:mod:`pea.dartaotcheck`), build integration (:mod:`pea.buildint`),
   candidate review (:mod:`pea.candidatereview`);
4. capability-family selection + exposure mapping from the capability map
   (:mod:`pea.attacksim`);
5. protection planning (:func:`pea.planner.build_plan`);
6. minimal attack self-test design (:func:`pea.attacksim.design_attack_simulation`);
7. evidence ledger assembly with the unknown lifecycle
   (:mod:`pea.ledger`);
8. the verification gate (``gate_for_verified``) that says whether anything
   here may be called ``verified`` - in the prototype the answer is always
   "not yet", and the report says exactly why.

Everything is pure computation over already-loaded data plus bounded
filesystem reads; the only writes are the report files the caller asked for.

The demo scenario (Flutter licensing canary) is a *simulated* fixture: it
exists to exercise the loop, not to describe any real project. Real runs
depend on the actual project state the domains observe and on up-to-date
capability intelligence (every capability-map entry carries its
``research_date``); see ``docs/Prototype-1.0-Demo-zh-CN.md``.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pea.artifactscan import ArtifactScanResult, observe_artifacts
from pea.attacksim import ArtifactRef, design_attack_simulation, family_tier, load_capability_map
from pea.buildint import BuildIntegrationResult, verify_build_integration
from pea.candidatereview import CandidateReviewResult, review_catalog
from pea.capintel import IntelQuery, IntelResponse, fetch_capability_intel
from pea.dartaotcheck import DartAotCheckResult, observe_dart_aot
from pea.domains import DomainReport
from pea.ledger import EvidenceLedger, gate_for_verified
from pea.nativecheck import NativeCheckResult, observe_native
from pea.planner import DEFAULT_CATALOG, build_plan, load_catalog
from pea.recon import ReconResult, observe
from pea.report import render_markdown
from pea.secretscan import SecretScanResult, observe_secrets
from pea.symbolscan import SymbolScanResult, observe_strings_symbols
from pea.tiers import TIER_ORDER, remediation_order

DEMO_VERSION = "1.0"

#: Default release-artifact paths assumed when neither recon nor the artifact
#: manifest finds a build output. They are *expected* paths, declared as such;
#: the attack simulation records the missing digests instead of inventing them.
_ANDROID_APK_BASELINE = "build/app/outputs/flutter-apk/app-release.apk"
_ANDROID_APK_PROTECTED = "build/app/outputs/flutter-apk/app-release-obfuscated.apk"

#: Unknown wording that blocks the verified gate, per domain. The wording is
#: the contract: a domain declares its blocking gaps with these markers and
#: the ledger's severity stays mechanical, never editorial.
BLOCKING_MARKERS: dict[str, tuple[str, ...]] = {
    "recon": ("未发现构建产物", "超过", "未枚举"),
    "artifact_manifest": ("未发现", "超过", "未枚举"),
    "secret_scan": ("超过", "未枚举"),
    "string_symbol_scan": ("未发现", "超过", "未枚举", "无法读取"),
    # The wording is chosen so a domain's *standing* limits stay informational
    # while an unassessed surface blocks: "未覆盖" (a documented parsing gap)
    # never blocks, "未评估/均无法" (nothing was measured) always does.
    "native_check": ("未评估", "均无法"),
    "dart_aot_check": ("未评估", "均无法"),
    "build_integration": ("构建集成未验证",),
    "candidate_review": ("未评估", "无法读取"),
    "capability_intel": ("未检索", "未获得可用结果"),
}


@dataclass(frozen=True)
class DemoResult:
    """Everything the demo produced, machine-readable and report-ready."""

    request: dict[str, Any]
    plan: dict[str, Any]
    recon: ReconResult | None
    artifact_scan: ArtifactScanResult | None
    secret_scan: SecretScanResult | None
    symbol_scan: SymbolScanResult | None
    native_check: NativeCheckResult | None
    dart_aot_check: DartAotCheckResult | None
    build_integration: BuildIntegrationResult | None
    candidate_review: CandidateReviewResult | None
    attack_simulation: dict[str, Any] | None
    ledger: EvidenceLedger
    ledger_audit: dict[str, Any]
    gate_blockers: list[str]
    bundle: dict[str, Any]
    report_markdown: str


def expected_artifacts(recon: ReconResult | None, artifact_scan: ArtifactScanResult | None) -> tuple[ArtifactRef, ArtifactRef]:
    """Baseline/protected artifact references for the attack simulation.

    Preference order is evidence-first: a real Flutter snapshot/engine found
    by recon, then a real packaged artifact (APK/AAB) from the manifest, then
    the declared Flutter-default paths. A protected candidate is always a
    *different* path with no digest yet, because the protected build does
    not exist until someone runs it.
    """
    if recon is not None:
        snapshots = [a for a in recon.key_artifacts if a.kind in {"flutter_dart_snapshot", "flutter_engine"}]
        if snapshots:
            baseline = snapshots[0]
            protected_path = baseline.path.replace(".so", "-protected.so")
            return (
                ArtifactRef(path=baseline.path, sha256=baseline.sha256),
                ArtifactRef(path=protected_path),
            )
    if artifact_scan is not None:
        packaged = [a for a in artifact_scan.artifacts if a.kind in {"android_package", "android_app_bundle"}]
        if packaged:
            package = packaged[0]
            protected_path = package.path.replace(".apk", "-protected.apk").replace(".aab", "-protected.aab")
            return (
                ArtifactRef(path=package.path, sha256=package.sha256),
                ArtifactRef(path=protected_path),
            )
    return (
        ArtifactRef(path=_ANDROID_APK_BASELINE),
        ArtifactRef(path=_ANDROID_APK_PROTECTED),
    )


def domain_reports(
    *,
    artifact_scan: ArtifactScanResult,
    secret_scan: SecretScanResult,
    symbol_scan: SymbolScanResult,
    native_check: NativeCheckResult | None = None,
    dart_aot_check: DartAotCheckResult | None = None,
    build_integration: BuildIntegrationResult | None = None,
    candidate_review: CandidateReviewResult | None = None,
    capability_intel: Mapping[str, Any] | None = None,
) -> list[DomainReport]:
    """Wrap each domain result in the unified report shape.

    Detail tables carry the same redaction the domains produced: digests
    and pattern names, never content. The later domains (native, Dart AOT,
    build integration, candidate review) are optional because a caller may
    run only the first three; ``None`` means the domain was not run, and a
    domain that was not run contributes nothing - it is never fabricated.
    """
    reports: list[DomainReport] = []

    artifact_rows = tuple(
        (a.path, a.kind, str(a.size_bytes), (a.sha256[:12] + "…") if a.sha256 else "未计算")
        for a in artifact_scan.artifacts
    )
    secret_rows = tuple((h.path, h.pattern, str(h.line), str(h.count)) for h in secret_scan.hits)
    symbol_rows = tuple(
        (
            s.path,
            ", ".join(f"{name}×{count}" for name, count in sorted(s.pattern_counts.items())) or "无命中",
        )
        for s in symbol_scan.scanned
    )
    reports.extend(
        [
            DomainReport(
                key="artifact_manifest",
                label="产物清单",
                coverage=artifact_scan.coverage,
                findings=artifact_scan.findings,
                unknowns=artifact_scan.unknowns,
                detail_title="产物指纹（路径/类型/摘要前缀；内容不回显）：" if artifact_rows else "",
                detail_headers=("路径", "类型", "字节", "SHA-256"),
                detail_rows=artifact_rows,
            ),
            DomainReport(
                key="secret_scan",
                label="秘密扫描",
                coverage=secret_scan.coverage,
                findings=secret_scan.findings,
                unknowns=secret_scan.unknowns,
                detail_title="秘密模式命中（仅模式名、首行与次数，内容脱敏）：" if secret_rows else "",
                detail_headers=("文件", "模式", "首行", "次数"),
                detail_rows=secret_rows,
            ),
            DomainReport(
                key="string_symbol_scan",
                label="字符串/符号",
                coverage=symbol_scan.coverage,
                findings=symbol_scan.findings,
                unknowns=symbol_scan.unknowns,
                detail_title="产物字符串模式计数（仅模式名与次数，字符串不回显）：" if symbol_rows else "",
                detail_headers=("产物", "命中模式"),
                detail_rows=symbol_rows,
            ),
        ]
    )

    if native_check is not None:
        native_rows = tuple(
            (
                p.path,
                f"{p.format}{'/' + p.arch if p.arch else ''}",
                f"{'PIE' if p.pie else '无PIE'}/{'NX' if p.nx else '无NX'}/RELRO:{p.relro or '未知'}"
                f"/{'stripped' if p.stripped else '未剥离'}",
                "、".join(p.gaps) or "未检出缺口",
            )
            for p in native_check.profiles
        )
        reports.append(
            DomainReport(
                key="native_check",
                label="Native 结构",
                coverage=native_check.coverage,
                findings=native_check.findings,
                unknowns=native_check.unknowns,
                detail_title="native 产物结构属性（格式/保护位/缺口标签）：" if native_rows else "",
                detail_headers=("产物", "格式/架构", "保护位", "结构缺口"),
                detail_rows=native_rows,
            )
        )

    if dart_aot_check is not None:
        dart_rows = tuple(
            (
                s.path,
                f"{len(s.anchors_found)}/{4}",
                ", ".join(f"{k}×{v}" for k, v in sorted(s.shape_counts.items())) or "无命中",
            )
            for s in dart_aot_check.snapshots
        )
        reports.append(
            DomainReport(
                key="dart_aot_check",
                label="Dart 快照",
                coverage=dart_aot_check.coverage,
                findings=dart_aot_check.findings,
                unknowns=dart_aot_check.unknowns,
                detail_title="Dart 产物锚点与形态计数（混淆状态未知，本域不判定）：" if dart_rows else "",
                detail_headers=("产物", "锚点命中", "对象池形态计数"),
                detail_rows=dart_rows,
            )
        )

    if build_integration is not None:
        build_rows = tuple((c.expectation, c.source, c.status, c.detail) for c in build_integration.checks)
        reports.append(
            DomainReport(
                key="build_integration",
                label="构建集成",
                coverage=build_integration.coverage,
                findings=build_integration.findings,
                unknowns=build_integration.unknowns,
                detail_title="声明与产物比对（期望/来源/状态）：" if build_rows else "",
                detail_headers=("期望", "声明来源", "状态", "明细"),
                detail_rows=build_rows,
            )
        )

    if candidate_review is not None:
        gate_rows = tuple(
            (r.candidate_id, r.decision, "、".join(g.name for g in r.gates if g.status != "pass") or "全部门控通过")
            for r in candidate_review.reviews
        )
        reports.append(
            DomainReport(
                key="candidate_review",
                label="候选门控",
                coverage=candidate_review.coverage,
                findings=candidate_review.findings,
                unknowns=candidate_review.unknowns,
                detail_title="候选门控结果（许可/维护/证据/信任）：" if gate_rows else "",
                detail_headers=("候选", "决策", "未通过门"),
                detail_rows=gate_rows,
            )
        )

    if capability_intel is not None:
        # The retrieval result arrives already normalized (``fetch_capability_intel``
        # returns the same findings/coverage/unknowns shape); it is passed as a
        # mapping so the demo does not import the connector's dataclass here.
        reports.append(
            DomainReport(
                key="capability_intel",
                label="能力情报",
                coverage=dict(capability_intel.get("coverage") or {}),
                findings=tuple(capability_intel.get("findings") or ()),
                unknowns=tuple(capability_intel.get("unknowns") or ()),
                detail_title="",
                detail_headers=(),
                detail_rows=(),
            )
        )

    return reports


def build_ledger(
    *,
    plan: Mapping[str, Any],
    recon: ReconResult | None,
    domain_reports: Sequence[DomainReport],
    attack_simulation: Mapping[str, Any] | None,
    now: str,
) -> EvidenceLedger:
    """Assemble the evidence ledger: every domain's observations in, unknowns queued.

    Unknown severities are mechanical, not editorial: each domain's blocking
    markers decide severity, intake gaps and "no release artifact seen" block
    verification; analytic boundaries recorded by the attack simulation are
    informational (they cannot be closed locally).
    """
    ledger = EvidenceLedger(created_at=now)

    if recon is not None:
        for finding in recon.findings:
            for record in finding.get("evidence", []):
                ledger.add_evidence(record)
        for question in recon.unknowns:
            severity = "blocking" if any(marker in question for marker in BLOCKING_MARKERS["recon"]) else "important"
            ledger.record_unknown(
                question=f"recon：{question}",
                severity=severity,
                domain="recon",
                recommended_probes=["补齐覆盖范围后重新侦察"],
                created_at=now,
            )

    for domain in domain_reports:
        for finding in domain.findings:
            for record in finding.get("evidence", []):
                ledger.add_evidence(record)
        markers = BLOCKING_MARKERS.get(domain.key, ())
        for question in domain.unknowns:
            severity = "blocking" if any(marker in question for marker in markers) else "important"
            ledger.record_unknown(
                question=f"{domain.key}：{question}",
                severity=severity,
                domain=domain.key,
                recommended_probes=["补齐覆盖范围后重新运行该域"],
                created_at=now,
            )

    for question in plan.get("intake_unknowns", []):
        ledger.record_unknown(
            question=f"intake 未答：{question}",
            severity="blocking",
            domain="intake",
            recommended_probes=["补答 intake 问题后重新生成计划"],
            created_at=now,
        )

    if attack_simulation is not None:
        for question in attack_simulation.get("unknowns", []):
            ledger.record_unknown(
                question=f"attack_simulation：{question}",
                severity="informational",
                domain="attack_simulation",
                recommended_probes=["在自测执行后以观察证据回填"],
                created_at=now,
            )
    return ledger


def remediation_groups(
    recon: ReconResult | None,
    domain_reports: Sequence[DomainReport],
    attack_simulation: Mapping[str, Any] | None,
) -> list[tuple[str, list[str]]]:
    """Collect repair actions per exposure tier, highest exposure first.

    Three sources, all already evidence-backed: the capability map's recorded
    ``defense_options`` for every family the attack simulation actually
    exercises, and every domain's recommended actions tagged with their
    finding tier (each action carries its domain label for traceability).
    Ordering is mechanical (attacker's marginal cost), never editorial.
    """
    if recon is None:
        return []
    capability_map = load_capability_map()
    mappings = {m["capability_family"]: m for m in capability_map["mappings"]}

    actions: list[tuple[str, str]] = []
    if attack_simulation is not None:
        exercised_families = []
        for step in attack_simulation.get("capability_steps", []):
            family = step["capability_family"]
            if family not in exercised_families:
                exercised_families.append(family)
        for family in exercised_families:
            tier = family_tier(family, capability_map)
            if tier is None:
                continue
            for option in mappings.get(family, {}).get("defense_options", []):
                actions.append((tier, f"[能力映射·{family}] {option}"))
    domain_sources: list[tuple[str, Sequence[Mapping[str, Any]]]] = [("侦察", recon.findings)]
    domain_sources.extend((domain.label, domain.findings) for domain in domain_reports)
    for label, findings in domain_sources:
        for finding in findings:
            tier = finding.get("exposure_tier")
            if not isinstance(tier, str):
                continue
            for action in finding.get("recommended_actions", []):
                actions.append((tier, f"[{label}] {action}"))

    groups: list[tuple[str, list[str]]] = []
    for tier in TIER_ORDER:
        tier_actions = [action for action_tier, action in remediation_order(actions) if action_tier == tier]
        if tier_actions:
            groups.append((tier, tier_actions))
    return groups


def run_demo(
    request: dict[str, Any],
    project_path: str | Path,
    *,
    catalog_path: str | Path | None = None,
    time_budget_minutes: int = 180,
    now: str | None = None,
    intel_transport: Callable[[str], IntelResponse] | None = None,
) -> DemoResult:
    """Run the full prototype walkthrough. Pure planning; nothing is executed.

    ``intel_transport`` is the injection seam for the D6 retrieval connector:
    with none supplied (the default) PEA stays offline and the bundle records
    the channel as ``not_attempted`` - an unqueried intelligence channel is a
    declared unknown, never a silent "nothing found".
    """
    stamp = now or "2026-10-13T00:00:00+00:00"
    catalog = load_catalog(catalog_path or DEFAULT_CATALOG)

    authorized = request.get("authorization") in {"owner", "written_authorization"}
    plan = build_plan(request, catalog)

    if not authorized:
        # No recon, no domains, no attack simulation, no ledger of
        # observations: without a stated authorization PEA does not even
        # look at the project.
        ledger = EvidenceLedger(created_at=stamp)
        for question in plan.get("intake_unknowns", []):
            ledger.record_unknown(
                question=f"intake 未答：{question}",
                severity="blocking",
                domain="intake",
                created_at=stamp,
            )
        ledger.record_unknown(
            question="项目所有权/授权未确认；只读侦察与暴露面映射均未执行",
            severity="blocking",
            domain="authorization",
            recommended_probes=["确认所有权或获取书面授权后重跑 demo"],
            created_at=stamp,
        )
        audit = ledger.audit_residual_unknowns()
        blockers = gate_for_verified(ledger)
        bundle: dict[str, Any] = {
            "demo": {"version": DEMO_VERSION, "generated_at": stamp, "mode": "plan_only", "authorized": False},
            "request": request,
            "recon": None,
            "domains": {},
            "plan": plan,
            "attack_simulation": None,
            "ledger": ledger.to_dict(),
            "ledger_audit": audit,
            "gate_blockers": blockers,
        }
        report = render_markdown(
            request=request,
            plan=plan,
            recon=None,
            attack_simulation=None,
            ledger_audit=audit,
            gate_blockers=blockers,
            generated_at=stamp,
            demo_version=DEMO_VERSION,
            remediation_groups=[],
            domains=[],
        )
        return DemoResult(
            request=request,
            plan=plan,
            recon=None,
            artifact_scan=None,
            secret_scan=None,
            symbol_scan=None,
            native_check=None,
            dart_aot_check=None,
            build_integration=None,
            candidate_review=None,
            attack_simulation=None,
            ledger=ledger,
            ledger_audit=audit,
            gate_blockers=blockers,
            bundle=bundle,
            report_markdown=report,
        )

    recon = observe(project_path, now=stamp)
    artifact_scan = observe_artifacts(project_path, now=stamp)
    secret_scan = observe_secrets(project_path, now=stamp)
    symbol_scan = observe_strings_symbols(artifact_scan, now=stamp)
    native_check = observe_native(artifact_scan, now=stamp)
    dart_aot_check = observe_dart_aot(artifact_scan, now=stamp)
    build_integration = verify_build_integration(artifact_scan, now=stamp)
    candidate_review = review_catalog(catalog_path=catalog_path or DEFAULT_CATALOG, now=stamp)
    baseline, protected = expected_artifacts(recon, artifact_scan)
    attack_simulation = design_attack_simulation(
        baseline=baseline,
        protected=protected,
        languages=[obs.language for obs in recon.languages],
        platforms=list(recon.platforms),
        goals=list(request.get("goals", [])),
        has_authorization_logic=bool(recon.pattern_hits),
        recon_unknowns=list(recon.unknowns),
        time_budget_minutes=time_budget_minutes,
        plan_id=plan.get("plan_id"),
    )
    intel_result: dict[str, Any] | None = None
    intel_channel: dict[str, Any] = {
        "status": "not_attempted",
        "reason": "离线默认：未注入检索传输实现，PEA 不主动发起网络请求（未检索 = unknown，不是空结果）",
    }
    if intel_transport is not None:
        exercised = [
            step.get("capability_family")
            for step in attack_simulation.get("capability_steps", [])
            if step.get("capability_family")
        ]
        intel_query = IntelQuery(family=exercised[0] if exercised else "protection_tooling")
        intel_outcome = fetch_capability_intel(intel_query, transport=intel_transport, now=stamp)
        intel_result = intel_outcome.to_dict()
        intel_channel = {"status": intel_result["status"], "reason": "已注入检索传输实现；结果为 external_claim"}
    domain_report_list = domain_reports(
        artifact_scan=artifact_scan,
        secret_scan=secret_scan,
        symbol_scan=symbol_scan,
        native_check=native_check,
        dart_aot_check=dart_aot_check,
        build_integration=build_integration,
        candidate_review=candidate_review,
        capability_intel=intel_result,
    )
    ledger = build_ledger(
        plan=plan,
        recon=recon,
        domain_reports=domain_report_list,
        attack_simulation=attack_simulation,
        now=stamp,
    )
    audit = ledger.audit_residual_unknowns()
    blockers = gate_for_verified(ledger)
    remediation_group_list = remediation_groups(recon, domain_report_list, attack_simulation)
    remediation_payload: list[dict[str, Any]] = [
        {"exposure_tier": tier, "actions": list(actions)} for tier, actions in remediation_group_list
    ]
    bundle = {
        "demo": {"version": DEMO_VERSION, "generated_at": stamp, "mode": "plan_only", "authorized": True},
        "request": request,
        "recon": recon.to_dict(),
        "domains": {
            "artifact_manifest": artifact_scan.to_dict(),
            "secret_scan": secret_scan.to_dict(),
            "string_symbol_scan": symbol_scan.to_dict(),
            "native_check": native_check.to_dict(),
            "dart_aot_check": dart_aot_check.to_dict(),
            "build_integration": build_integration.to_dict(),
            "candidate_review": candidate_review.to_dict(),
            **({"capability_intel": intel_result} if intel_result is not None else {}),
        },
        "capability_intel": intel_result if intel_result is not None else intel_channel,
        "plan": plan,
        "attack_simulation": attack_simulation,
        "ledger": ledger.to_dict(),
        "ledger_audit": audit,
        "gate_blockers": blockers,
        "remediation_groups": remediation_payload,
    }
    report = render_markdown(
        request=request,
        plan=plan,
        recon=recon,
        attack_simulation=attack_simulation,
        ledger_audit=audit,
        gate_blockers=blockers,
        generated_at=stamp,
        demo_version=DEMO_VERSION,
        remediation_groups=remediation_group_list,
        domains=domain_report_list,
    )
    return DemoResult(
        request=request,
        plan=plan,
        recon=recon,
        artifact_scan=artifact_scan,
        secret_scan=secret_scan,
        symbol_scan=symbol_scan,
        native_check=native_check,
        dart_aot_check=dart_aot_check,
        build_integration=build_integration,
        candidate_review=candidate_review,
        attack_simulation=attack_simulation,
        ledger=ledger,
        ledger_audit=audit,
        gate_blockers=blockers,
        bundle=bundle,
        report_markdown=report,
    )
