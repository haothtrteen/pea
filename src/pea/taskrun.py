"""Task orchestrator (Phase 4 L2 / WP2): assessment tasks as first-class
persistent entities.

An *assessment task* is "analyse this project and produce the protection
plan, evidence ledger and report" as one durable object - not a
conversation turn, not an in-process pipeline. The workflow is the demo's
orchestration extracted into a step table; ``demo.run_demo`` stays as the
preconfigured instantiation of the same steps.

Three properties the design demands, and how they are kept:

* **Durable.** A task is a directory under a store (same pattern as the
  ledger store): ``task.json`` (status + step table) plus one JSON file
  per completed step. Every step completion is flushed before the next
  step starts, so a crash loses at most the step in flight.
* **Resumable.** Each step records an input digest (canonical hash of
  its arguments plus its dependencies' output digests). On resume, a
  done step whose input digest is unchanged is not re-run; a failed step
  is retried from itself, never from the beginning. Cross-step data
  travels through the step files on disk - there is no in-process
  global state to lose.
* **Honest about failure.** A failed analysis domain does not abort the
  task and never fabricates a pass. Its hard dependents are skipped
  (``skipped-dep``, named); the *ledger* still assembles - it is the
  workflow's failure sink: every incomplete domain becomes a blocking
  unknown ("未评估，不冒充通过"), so the verified gate stays closed. The
  *report* is the success artifact: it runs only when every input it
  renders truthfully is present, otherwise it is skipped-dep rather
  than rendered around a hole. An unpassed authorization gate parks the
  task at the gate (``blocked``) - the task waits for authorization,
  it does not pretend to have analysed anything.

The ledger, remediation and report steps reuse ``demo.build_ledger`` /
``demo.remediation_groups`` / ``report.render_markdown`` verbatim: the
orchestrator adds persistence and recovery, not a second opinion about
what the evidence means. The report step's bundle is byte-comparable
with ``demo.run_demo``'s bundle on every analysis field - that
equivalence is a test, not a claim.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pea.artifactscan import ArtifactScanResult, observe_artifacts
from pea.attacksim import design_attack_simulation
from pea.buildint import verify_build_integration
from pea.candidatereview import review_catalog
from pea.dartaotcheck import observe_dart_aot
from pea.demo import DEMO_VERSION, build_ledger, domain_reports, expected_artifacts, remediation_groups
from pea.domains import DomainReport
from pea.ledger import gate_for_verified
from pea.nativecheck import observe_native
from pea.planner import DEFAULT_CATALOG, build_plan, load_catalog
from pea.recon import ReconResult, observe
from pea.report import render_markdown
from pea.secretscan import observe_secrets
from pea.symbolscan import observe_strings_symbols

ORCHESTRATOR_VERSION = "0.1.0"

#: Task status values. ``blocked`` is a waiting state, not a failure: the
#: authorization gate parks here for authorization, and a failed domain
#: parks here with its unknowns in the ledger.
TASK_CREATED = "created"
TASK_RUNNING = "running"
TASK_BLOCKED = "blocked"
TASK_DONE = "done"
TASK_FAILED = "failed"

#: Step status values. ``skipped-dep`` is named, not silent: the step did
#: not run because something upstream of it failed or was skipped.
STEP_PENDING = "pending"
STEP_RUNNING = "running"
STEP_DONE = "done"
STEP_FAILED = "failed"
STEP_SKIPPED_DEP = "skipped-dep"

_TASK_ID_PATTERN = re.compile(r"^task-[0-9a-f]{8}$")


class TaskBoundaryError(ValueError):
    """The store, task id or resume request is not usable (named, never a
    silent empty)."""


@dataclass(frozen=True)
class StepSpec:
    """One workflow step: identity, kind and dependencies.

    ``depends`` are hard: the step runs only when every one of them is
    done, otherwise it is skipped-dep. ``soft`` are degraded: loaded
    when done, absent otherwise - the executor records the absence
    itself (the ledger) or skips rather than rendering around it (the
    report lists its truth-rendering inputs as hard). Soft deps still
    feed the input digest, so re-running a domain re-runs its soft
    consumers too.
    """

    id: str
    kind: str  # "gate" | "analysis" | "synthesis"
    depends: tuple[str, ...]
    note: str
    soft: tuple[str, ...] = ()


#: The extracted demo workflow, in topological order. "Parallel" for the
#: read-only domains is expressed by their independence (no edges between
#: them); this build executes deterministically in order and introduces
#: no thread pool - determinism beats speed for an evidence pipeline, and
#: the step table already allows a parallel scheduler to be dropped in.
#:
#: Two failure shapes are encoded in the edges. ``evidence_ledger`` takes
#: every analysis domain as a *soft* dep: it must run even when a domain
#: failed, because it is where that failure becomes a blocking unknown.
#: ``report`` takes the inputs it cannot render around (recon, plan, the
#: attack simulation, the three core domains) as *hard* deps: a missing
#: one skips the report instead of producing a half-true document.
WORKFLOW: tuple[StepSpec, ...] = (
    StepSpec("authorization_gate", "gate", (), "审批门：未确认授权的任务停在这里，等待授权"),
    StepSpec("recon", "analysis", ("authorization_gate",), "只读项目画像"),
    StepSpec("artifact_scan", "analysis", ("authorization_gate",), "产物清单与指纹"),
    StepSpec("secret_scan", "analysis", ("authorization_gate",), "秘密模式扫描"),
    StepSpec("symbol_scan", "analysis", ("authorization_gate", "artifact_scan"), "字符串/符号扫描"),
    StepSpec("native_check", "analysis", ("authorization_gate", "artifact_scan"), "native 结构解析"),
    StepSpec("dart_aot_check", "analysis", ("authorization_gate", "artifact_scan"), "Dart AOT 快照检查"),
    StepSpec("build_integration", "analysis", ("authorization_gate", "artifact_scan"), "构建集成验证"),
    StepSpec("candidate_review", "analysis", ("authorization_gate",), "候选工具门控"),
    StepSpec("plan", "synthesis", ("authorization_gate",), "保护计划生成"),
    StepSpec(
        "attack_simulation",
        "synthesis",
        ("authorization_gate", "recon", "artifact_scan", "plan"),
        "攻击自测方案设计",
    ),
    StepSpec(
        "evidence_ledger",
        "synthesis",
        ("authorization_gate", "plan"),
        "证据账本汇总（失败汇聚点：未完成域记为 blocking unknown，不冒充通过）",
        soft=(
            "recon",
            "artifact_scan",
            "secret_scan",
            "symbol_scan",
            "native_check",
            "dart_aot_check",
            "build_integration",
            "candidate_review",
            "attack_simulation",
        ),
    ),
    StepSpec("verified_gate", "synthesis", ("authorization_gate", "evidence_ledger"), "verified 门机械判定"),
    StepSpec(
        "report",
        "synthesis",
        (
            "authorization_gate",
            "evidence_ledger",
            "plan",
            "recon",
            "attack_simulation",
            "artifact_scan",
            "secret_scan",
            "symbol_scan",
        ),
        "脱敏报告与 bundle 渲染（输入不齐则 skipped-dep，不渲染残缺报告）",
        soft=("native_check", "dart_aot_check", "build_integration", "candidate_review"),
    ),
)

_STEP_SPECS: dict[str, StepSpec] = {spec.id: spec for spec in WORKFLOW}


@dataclass
class StepState:
    """One step's durable record: status, input digest, output reference.

    ``depends``/``soft`` are persisted with the record so a task file is
    self-describing: the workflow shape a task ran under is recoverable
    from the file alone, not only from the matching code version.
    """

    id: str
    status: str = STEP_PENDING
    input_digest: str = ""
    output_digest: str = ""
    error: str | None = None
    unknown_count: int = 0
    depends: tuple[str, ...] = ()
    soft: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "error": self.error,
            "unknown_count": self.unknown_count,
            "depends": list(self.depends),
            "soft": list(self.soft),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StepState:
        return cls(
            id=str(data["id"]),
            status=str(data.get("status", STEP_PENDING)),
            input_digest=str(data.get("input_digest", "")),
            output_digest=str(data.get("output_digest", "")),
            error=data.get("error"),
            unknown_count=int(data.get("unknown_count", 0)),
            depends=tuple(data.get("depends") or ()),
            soft=tuple(data.get("soft") or ()),
        )


@dataclass
class AssessmentTask:
    """The task entity: identity, lifecycle status, step table, inputs."""

    task_id: str
    status: str
    created_at: str
    request: dict[str, Any]
    project_path: str
    steps: list[StepState]
    note: str = ""
    orchestrator_version: str = ORCHESTRATOR_VERSION

    def step(self, step_id: str) -> StepState:
        for state in self.steps:
            if state.id == step_id:
                return state
        raise TaskBoundaryError(f"task {self.task_id!r} has no step {step_id!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "created_at": self.created_at,
            "request": self.request,
            "project_path": self.project_path,
            "steps": [s.to_dict() for s in self.steps],
            "note": self.note,
            "orchestrator_version": self.orchestrator_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AssessmentTask:
        return cls(
            task_id=str(data["task_id"]),
            status=str(data["status"]),
            created_at=str(data["created_at"]),
            request=dict(data.get("request") or {}),
            project_path=str(data.get("project_path", "")),
            steps=[StepState.from_dict(s) for s in data.get("steps") or ()],
            note=str(data.get("note", "")),
            orchestrator_version=str(data.get("orchestrator_version", ORCHESTRATOR_VERSION)),
        )


class TaskStore:
    """Filesystem layout for tasks: one directory per task, one file per
    completed step. The store root is the caller's (CLI default
    ``.pea/tasks``; MCP via ``PEA_TASK_STORE``); nothing is written
    outside it, and every write is atomic (temp file + rename)."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()

    def task_dir(self, task_id: str) -> Path:
        _require_task_id(task_id)
        return self.root / task_id

    def task_path(self, task_id: str) -> Path:
        return self.task_dir(task_id) / "task.json"

    def step_path(self, task_id: str, step_id: str) -> Path:
        if step_id not in _STEP_SPECS:
            raise TaskBoundaryError(f"unknown workflow step {step_id!r}")
        return self.task_dir(task_id) / "steps" / f"{step_id}.json"

    def exists(self, task_id: str) -> bool:
        return self.task_path(task_id).is_file()

    def save_task(self, task: AssessmentTask) -> None:
        path = self.task_path(task.task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, task.to_dict())

    def load_task(self, task_id: str) -> AssessmentTask:
        path = self.task_path(task_id)
        if not path.is_file():
            raise TaskBoundaryError(f"task {task_id!r} not found under {self.root}")
        return AssessmentTask.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def save_step(self, task_id: str, step_id: str, output: Mapping[str, Any]) -> str:
        path = self.step_path(task_id, step_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, dict(output))
        return _file_digest(path)

    def load_step(self, task_id: str, step_id: str) -> dict[str, Any]:
        path = self.step_path(task_id, step_id)
        if not path.is_file():
            raise TaskBoundaryError(f"task {task_id!r} has no output for step {step_id!r}")
        return json.loads(path.read_text(encoding="utf-8"))

    def list_tasks(self) -> list[AssessmentTask]:
        if not self.root.is_dir():
            return []
        tasks = []
        for task_json in sorted(self.root.glob("task-*/task.json")):
            tasks.append(AssessmentTask.from_dict(json.loads(task_json.read_text(encoding="utf-8"))))
        return tasks


def valid_task_id(task_id: str) -> bool:
    """A task id is a filename component: validate before touching disk."""
    return bool(_TASK_ID_PATTERN.match(task_id))


def _require_task_id(task_id: str) -> None:
    if not valid_task_id(task_id):
        raise TaskBoundaryError(f"task_id {task_id!r} 非法：必须是 task- 前缀加 8 位十六进制（它同时是目录名）")


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    """Write via a temp file + rename: a crash mid-write leaves the old
    file intact, never a half-parsed JSON."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(payload: Any) -> str:
    """Canonical digest: sorted keys, no whitespace variance, UTF-8."""
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Read-only views over the recorded domain dicts.
#
# demo.domain_reports() consumes per-domain dataclasses; the orchestrator
# holds the domains' to_dict payloads (its disk form). These views expose
# exactly the attributes the wrapper reads, each mapping 1:1 onto a
# recorded field - they are adapters, not re-implementations, and the
# equivalence test pins them to the demo's output.
# ---------------------------------------------------------------------------


class _SecretScanView:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.coverage = data.get("coverage") or {}
        self.findings = tuple(data.get("findings") or ())
        self.unknowns = tuple(data.get("unknowns") or ())
        self.hits = tuple(_Hit(h) for h in data.get("hits") or ())


class _Hit:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.path = data.get("path", "")
        self.pattern = data.get("pattern", "")
        self.line = data.get("line", 0)
        self.count = data.get("count", 1)


class _SymbolScanView:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.coverage = data.get("coverage") or {}
        self.findings = tuple(data.get("findings") or ())
        self.unknowns = tuple(data.get("unknowns") or ())
        self.scanned = tuple(_Scanned(s) for s in data.get("scanned") or ())


class _Scanned:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.path = data.get("path", "")
        self.pattern_counts = dict(data.get("pattern_counts") or {})


class _NativeCheckView:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.coverage = data.get("coverage") or {}
        self.findings = tuple(data.get("findings") or ())
        self.unknowns = tuple(data.get("unknowns") or ())
        self.profiles = tuple(_Profile(p) for p in data.get("profiles") or ())


class _Profile:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.path = data.get("path", "")
        self.format = data.get("format", "")
        self.arch = data.get("arch")
        self.pie = data.get("pie")
        self.nx = data.get("nx")
        self.relro = data.get("relro")
        self.stripped = data.get("stripped")
        self.gaps = tuple(data.get("gaps") or ())


class _DartAotCheckView:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.coverage = data.get("coverage") or {}
        self.findings = tuple(data.get("findings") or ())
        self.unknowns = tuple(data.get("unknowns") or ())
        self.snapshots = tuple(_Snapshot(s) for s in data.get("snapshots") or ())


class _Snapshot:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.path = data.get("path", "")
        self.anchors_found = tuple(data.get("anchors_found") or ())
        self.shape_counts = dict(data.get("shape_counts") or {})


class _BuildIntegrationView:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.coverage = data.get("coverage") or {}
        self.findings = tuple(data.get("findings") or ())
        self.unknowns = tuple(data.get("unknowns") or ())
        self.checks = tuple(_Check(c) for c in data.get("checks") or ())


class _Check:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.expectation = data.get("expectation", "")
        self.source = data.get("source", "")
        self.status = data.get("status", "")
        self.detail = data.get("detail", "")


class _CandidateReviewView:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.coverage = data.get("coverage") or {}
        self.findings = tuple(data.get("findings") or ())
        self.unknowns = tuple(data.get("unknowns") or ())
        self.reviews = tuple(_Review(r) for r in data.get("reviews") or ())


class _Review:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.candidate_id = data.get("candidate_id", "")
        self.decision = data.get("decision", "")
        self.gates = tuple(_Gate(g) for g in data.get("gates") or ())


class _Gate:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.name = data.get("name", "")
        self.status = data.get("status", "")


#: Step id -> domain key, for the two steps whose disk id differs from
#: the key the ledger and the report use for the same domain.
_STEP_TO_DOMAIN_KEY = {"artifact_scan": "artifact_manifest", "symbol_scan": "string_symbol_scan"}


def _domain_key(step_id: str) -> str:
    return _STEP_TO_DOMAIN_KEY.get(step_id, step_id)


#: Disk payload -> the view ``demo.domain_reports`` consumes for that step.
_VIEWS: dict[str, Callable[[Mapping[str, Any]], Any]] = {
    "artifact_scan": ArtifactScanResult.from_dict,
    "secret_scan": _SecretScanView,
    "symbol_scan": _SymbolScanView,
    "native_check": _NativeCheckView,
    "dart_aot_check": _DartAotCheckView,
    "build_integration": _BuildIntegrationView,
    "candidate_review": _CandidateReviewView,
}


class _GapDomainView:
    """A domain that did not complete, in the shape ``domain_reports``
    consumes.

    It carries no findings, no unknowns and no detail rows - the gap
    itself is recorded by the ledger step as a blocking unknown, because
    "an unassessed surface blocks" is an orchestration rule that must not
    depend on domain wording. The coverage line states the gap so a
    rendered section can never read as "ran and found nothing".
    """

    def __init__(self, step_id: str, status: str, error: str | None) -> None:
        detail = f"：{error}" if error else ""
        self.artifacts: tuple[Any, ...] = ()
        self.hits: tuple[Any, ...] = ()
        self.scanned: tuple[Any, ...] = ()
        self.profiles: tuple[Any, ...] = ()
        self.snapshots: tuple[Any, ...] = ()
        self.checks: tuple[Any, ...] = ()
        self.reviews: tuple[Any, ...] = ()
        self.coverage = {"state": "未运行", "scope": f"该域未完成（{status}）{detail}——未评估，不冒充通过"}
        self.findings: tuple[Any, ...] = ()
        self.unknowns: tuple[Any, ...] = ()


def _analysis_domain_reports(products: Mapping[str, Any], coverage: Mapping[str, Mapping[str, Any]]) -> list[DomainReport]:
    """Wrap the recorded domain outputs in the unified report shape.

    The domain products on disk are the domains' own ``to_dict`` payloads;
    ``demo.domain_reports`` is the single wrapper, so the orchestrator's
    report shape cannot drift from the demo's. A domain that did not
    complete becomes a gap view - never a fabricated pass, and never a
    silently omitted surface either (its coverage line says 未运行 and
    the ledger records the blocking unknown).
    """
    resolved: dict[str, Any] = {}
    for step_id in (
        "artifact_scan",
        "secret_scan",
        "symbol_scan",
        "native_check",
        "dart_aot_check",
        "build_integration",
        "candidate_review",
    ):
        if products.get(step_id) is not None:
            resolved[step_id] = _VIEWS[step_id](products[step_id])
            continue
        record = coverage.get(step_id) or {}
        resolved[step_id] = _GapDomainView(step_id, str(record.get("status", "pending")), record.get("error"))
    return domain_reports(
        artifact_scan=resolved["artifact_scan"],
        secret_scan=resolved["secret_scan"],
        symbol_scan=resolved["symbol_scan"],
        native_check=resolved["native_check"],
        dart_aot_check=resolved["dart_aot_check"],
        build_integration=resolved["build_integration"],
        candidate_review=resolved["candidate_review"],
        capability_intel=None,
    )


# ---------------------------------------------------------------------------
# Step executors. Each reads its inputs from the step files on disk (the
# scheduler passes loaded products), computes one output dict, and raises
# on a domain failure - the scheduler decides what a failure means, the
# executor only reports it.
#
# ``coverage`` is the per-step view of the dependency table: for every
# hard and soft dep, its status and recorded error. Executors that only
# run when their inputs are present ignore it; the ledger - the failure
# sink - turns every non-done dep into a blocking unknown.
# ---------------------------------------------------------------------------


def _exec_authorization_gate(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    authorized = request.get("authorization") in {"owner", "written_authorization"}
    return {
        "authorized": authorized,
        "authorization": request.get("authorization"),
        "blocking": None
        if authorized
        else {
            "code": "authorization_not_confirmed",
            "detail": "项目所有权/授权未确认；只读侦察与暴露面映射均未执行（任务停在审批门）",
        },
    }


def _exec_recon(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    return observe(str(settings["project_path"]), now=settings["now"]).to_dict()


def _exec_artifact_scan(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    return observe_artifacts(str(settings["project_path"]), now=settings["now"]).to_dict()


def _exec_secret_scan(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    return observe_secrets(str(settings["project_path"]), now=settings["now"]).to_dict()


def _exec_symbol_scan(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    scan = ArtifactScanResult.from_dict(products["artifact_scan"])
    return observe_strings_symbols(scan, now=settings["now"]).to_dict()


def _exec_native_check(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    scan = ArtifactScanResult.from_dict(products["artifact_scan"])
    return observe_native(scan, now=settings["now"]).to_dict()


def _exec_dart_aot_check(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    scan = ArtifactScanResult.from_dict(products["artifact_scan"])
    return observe_dart_aot(scan, now=settings["now"]).to_dict()


def _exec_build_integration(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    scan = ArtifactScanResult.from_dict(products["artifact_scan"])
    return verify_build_integration(scan, now=settings["now"]).to_dict()


def _exec_candidate_review(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    return review_catalog(catalog_path=settings["catalog_path"], now=settings["now"]).to_dict()


def _exec_plan(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    catalog = load_catalog(settings["catalog_path"])
    return build_plan(dict(request), catalog)


def _exec_attack_simulation(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    plan = products["plan"]
    recon = ReconResult.from_dict(products["recon"])
    baseline, protected = expected_artifacts(recon, ArtifactScanResult.from_dict(products["artifact_scan"]))
    return design_attack_simulation(
        baseline=baseline,
        protected=protected,
        languages=[obs.language for obs in recon.languages],
        platforms=list(recon.platforms),
        goals=list(request.get("goals", [])),
        has_authorization_logic=bool(recon.pattern_hits),
        recon_unknowns=list(recon.unknowns),
        time_budget_minutes=int(settings.get("time_budget_minutes", 180)),
        plan_id=plan.get("plan_id"),
    )


def _exec_evidence_ledger(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    """Assemble the ledger from recorded products.

    The evidence rules are the demo's (``build_ledger``): severities are
    mechanical, not editorial. This step is the workflow's failure sink:
    a domain that did not complete contributes no observations, and its
    absence is recorded here as a *blocking* unknown - an unassessed
    surface never passes the gate. The severity rule lives in the
    orchestrator (not smuggled through domain wording), so no marker
    edit can silently downgrade an unrun domain to "important".
    """
    recon = ReconResult.from_dict(products["recon"]) if products.get("recon") else None
    domain_report_list = _analysis_domain_reports(products, coverage)
    ledger = build_ledger(
        plan=products["plan"],
        recon=recon,
        domain_reports=domain_report_list,
        attack_simulation=products.get("attack_simulation"),
        now=settings["now"],
    )
    for step_id, record in coverage.items():
        if str(record.get("status")) == STEP_DONE:
            continue
        status = str(record.get("status", "pending"))
        error = record.get("error") or "原因未记录"
        ledger.record_unknown(
            question=f"{_domain_key(step_id)} 未完成（{status}）：{error}——未评估，不冒充通过",
            severity="blocking",
            domain=_domain_key(step_id),
            recommended_probes=["修复失败原因后重跑任务；恢复时输入未变的 done 步骤不重跑"],
            created_at=settings["now"],
        )
    audit = ledger.audit_residual_unknowns()
    blockers = gate_for_verified(ledger)
    return {
        "ledger": ledger.to_dict(),
        "ledger_audit": audit,
        "gate_blockers": blockers,
        "ledger_digest": _digest(ledger.to_dict()),
    }


def _exec_verified_gate(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    ledger_product = products["evidence_ledger"]
    blockers = ledger_product.get("gate_blockers") or []
    return {
        "status": "verified" if not blockers else "blocked",
        "blockers": list(blockers),
        "audit": ledger_product.get("ledger_audit"),
        "gate_rule": "任何 blocking unknown 未消解即 blocked；verified 只表示账本内没有阻塞项，不证明覆盖完整",
    }


def _exec_report(
    request: Mapping[str, Any],
    products: Mapping[str, Any],
    coverage: Mapping[str, Any],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    """Render the report and assemble the task bundle.

    The bundle is byte-comparable with ``demo.run_demo``'s on every
    analysis field (a test pins it); the metadata block differs on
    purpose - it records the orchestrator, not the demo. The ``domains``
    keys are the demo's domain keys (``artifact_manifest``,
    ``string_symbol_scan``), so the two bundles line up field for field.
    """
    plan = products["plan"]
    recon = ReconResult.from_dict(products["recon"]) if products.get("recon") else None
    attack_simulation = products.get("attack_simulation")
    ledger_product = products["evidence_ledger"]
    domain_report_list = _analysis_domain_reports(products, coverage)
    groups = remediation_groups(recon, domain_report_list, attack_simulation)
    markdown = render_markdown(
        request=dict(request),
        plan=plan,
        recon=recon,
        attack_simulation=attack_simulation,
        ledger_audit=ledger_product.get("ledger_audit"),
        gate_blockers=ledger_product.get("gate_blockers") or [],
        generated_at=settings["now"],
        demo_version=DEMO_VERSION,
        remediation_groups=groups,
        domains=domain_report_list,
    )
    authorized = bool(products["authorization_gate"].get("authorized"))
    bundle: dict[str, Any] = {
        "orchestrator": {
            "version": ORCHESTRATOR_VERSION,
            "generated_at": settings["now"],
            "mode": "plan_only",
            "authorized": authorized,
        },
        "request": dict(request),
        "recon": products.get("recon"),
        "domains": {
            _domain_key(step_id): products[step_id]
            for step_id in (
                "artifact_scan",
                "secret_scan",
                "symbol_scan",
                "native_check",
                "dart_aot_check",
                "build_integration",
                "candidate_review",
            )
            if products.get(step_id) is not None
        },
        "capability_intel": {
            "status": "not_attempted",
            "reason": "编排工作流不查询能力情报通道（未检索 = unknown，不是空结果）；需要时由调用方另行调用 pea.fetch_capability_intel 并把结果并入",
        },
        "plan": plan,
        "attack_simulation": attack_simulation,
        "ledger": ledger_product.get("ledger"),
        "ledger_audit": ledger_product.get("ledger_audit"),
        "gate_blockers": ledger_product.get("gate_blockers") or [],
        "remediation_groups": [{"exposure_tier": tier, "actions": list(actions)} for tier, actions in groups],
        "report_markdown": markdown,
    }
    return {"report_markdown": markdown, "bundle": bundle}


_Executor = Callable[
    [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
    dict[str, Any],
]

_EXECUTORS: dict[str, _Executor] = {
    "authorization_gate": _exec_authorization_gate,
    "recon": _exec_recon,
    "artifact_scan": _exec_artifact_scan,
    "secret_scan": _exec_secret_scan,
    "symbol_scan": _exec_symbol_scan,
    "native_check": _exec_native_check,
    "dart_aot_check": _exec_dart_aot_check,
    "build_integration": _exec_build_integration,
    "candidate_review": _exec_candidate_review,
    "plan": _exec_plan,
    "attack_simulation": _exec_attack_simulation,
    "evidence_ledger": _exec_evidence_ledger,
    "verified_gate": _exec_verified_gate,
    "report": _exec_report,
}


# ---------------------------------------------------------------------------
# The scheduler: resume-aware, failure-isolating.
# ---------------------------------------------------------------------------


def _step_input_digest(
    spec: StepSpec,
    request: Mapping[str, Any],
    settings: Mapping[str, Any],
    dep_digests: Mapping[str, str],
) -> str:
    payload: dict[str, Any] = {"request": _digest(dict(request))}
    if spec.kind == "analysis":
        payload["project_path"] = str(settings["project_path"])
    payload["deps"] = {dep: dep_digests.get(dep, "") for dep in (*spec.depends, *spec.soft)}
    return _digest(payload)


def _products_for(task: AssessmentTask, store: TaskStore, spec: StepSpec) -> dict[str, Any]:
    """Load every completed dependency's recorded output (the step's inputs).

    Hard deps are all done when this runs (the scheduler checked); soft
    deps are loaded when done and absent otherwise - the executor sees
    the absence and records it, never a fabricated stand-in.
    """
    products: dict[str, Any] = {}
    for dep in (*spec.depends, *spec.soft):
        if task.step(dep).status == STEP_DONE:
            products[dep] = store.load_step(task.task_id, dep)
    return products


def _gate_parks(task: AssessmentTask, store: TaskStore, spec: StepSpec) -> bool:
    """True when the authorization gate is done-but-unauthorized.

    Parking covers the whole workflow after the gate: no step may read
    the project before authorization is stated, so every later step is
    marked skipped-dep with the named reason and the walk stops. A task
    parked here resumes into the same gate - it waits for authorization,
    it does not pretend to have analysed anything.
    """
    if spec.id != "authorization_gate":
        return False
    state = task.step(spec.id)
    if state.status != STEP_DONE:
        return False
    gate_output = _safe_step_output(task, store, spec.id)
    if gate_output is None or gate_output.get("authorized", False):
        return False
    park_index = next(i for i, s in enumerate(WORKFLOW) if s.id == spec.id)
    for later in WORKFLOW[park_index + 1 :]:
        later_state = task.step(later.id)
        if later_state.status != STEP_DONE:
            later_state.status = STEP_SKIPPED_DEP
            later_state.error = "授权门未通过：未确认项目所有权/授权，未执行任何项目读取（任务停在审批门）"
    store.save_task(task)
    return True


def _run_to_completion(task: AssessmentTask, store: TaskStore, settings: Mapping[str, Any]) -> AssessmentTask:
    """Walk the workflow; run, skip or reuse each step per its record."""
    task.status = TASK_RUNNING
    store.save_task(task)
    for spec in WORKFLOW:
        state = task.step(spec.id)
        hard_states = {dep: task.step(dep) for dep in spec.depends}
        soft_states = {dep: task.step(dep) for dep in spec.soft}

        # Dependencies that did not complete (failed or skipped) make this
        # step skipped-dep: named, never silently dropped. Only hard deps
        # gate a step - a soft dep's absence is the executor's to record.
        broken = [dep for dep, dep_state in hard_states.items() if dep_state.status in {STEP_FAILED, STEP_SKIPPED_DEP}]
        if broken:
            if state.status != STEP_DONE:
                state.status = STEP_SKIPPED_DEP
                state.error = f"依赖未完成：{', '.join(sorted(broken))}"
                store.save_task(task)
            continue

        coverage: dict[str, dict[str, Any]] = {
            dep: {"status": dep_state.status, "error": dep_state.error}
            for dep, dep_state in (*hard_states.items(), *soft_states.items())
        }
        dep_digests = {dep: dep_state.output_digest for dep, dep_state in (*hard_states.items(), *soft_states.items())}
        input_digest = _step_input_digest(spec, task.request, settings, dep_digests)

        # Resume semantics: a done step whose inputs are unchanged is not
        # re-run - its recorded output stays the truth.
        if state.status == STEP_DONE and state.input_digest == input_digest:
            if _gate_parks(task, store, spec):
                break
            continue

        state.status = STEP_RUNNING
        state.input_digest = input_digest
        store.save_task(task)
        try:
            products = _products_for(task, store, spec)
            output = _EXECUTORS[spec.id](task.request, products, coverage, settings)
            output_digest = store.save_step(task.task_id, spec.id, output)
        except Exception as exc:  # a domain failure is named, never fatal
            state.status = STEP_FAILED
            state.error = f"{type(exc).__name__}: {exc}"
            state.output_digest = ""
            store.save_task(task)
            continue

        state.status = STEP_DONE
        state.output_digest = output_digest
        state.error = None
        state.unknown_count = _count_unknowns(spec.id, output)
        store.save_task(task)
        if _gate_parks(task, store, spec):
            break

    task.status = _terminal_status(task, store)
    store.save_task(task)
    return task


def _count_unknowns(step_id: str, output: Mapping[str, Any]) -> int:
    if step_id == "evidence_ledger":
        return len(output.get("ledger", {}).get("unknowns") or ())
    if step_id in {
        "recon",
        "artifact_scan",
        "secret_scan",
        "symbol_scan",
        "native_check",
        "dart_aot_check",
        "build_integration",
        "candidate_review",
    }:
        return len(output.get("unknowns") or ())
    return 0


def _terminal_status(task: AssessmentTask, store: TaskStore) -> str:
    """Mechanical lifecycle resolution - no editorial judgement.

    * authorization gate not passed -> blocked (waiting at the gate);
    * any failed or skipped step -> blocked (its unknowns hold the gate);
    * verified gate says blocked -> blocked;
    * otherwise done.
    """
    gate = task.step("authorization_gate")
    if gate.status == STEP_DONE:
        gate_output = _safe_step_output(task, store, "authorization_gate")
        if gate_output is not None and not gate_output.get("authorized", False):
            return TASK_BLOCKED
    for state in task.steps:
        if state.status in {STEP_FAILED, STEP_SKIPPED_DEP}:
            return TASK_BLOCKED
    verified = task.step("verified_gate")
    if verified.status == STEP_DONE:
        gate_output = _safe_step_output(task, store, "verified_gate")
        if gate_output is not None and gate_output.get("status") != "verified":
            return TASK_BLOCKED
    return TASK_DONE


def _safe_step_output(task: AssessmentTask, store: TaskStore, step_id: str) -> dict[str, Any] | None:
    """Load a step's recorded output, or None when it is not on disk."""
    try:
        return store.load_step(task.task_id, step_id)
    except (TaskBoundaryError, OSError, json.JSONDecodeError):
        return None


def _new_task_id() -> str:
    return f"task-{uuid.uuid4().hex[:8]}"


def create_task(
    request: Mapping[str, Any],
    project_path: str | Path,
    *,
    store: TaskStore,
    now: str | None = None,
) -> AssessmentTask:
    """Create (but do not run) a task entity, persisted to the store."""
    stamp = now or _utc_now()
    task = AssessmentTask(
        task_id=_new_task_id(),
        status=TASK_CREATED,
        created_at=stamp,
        request=dict(request),
        project_path=str(project_path),
        steps=[StepState(id=spec.id, depends=spec.depends, soft=spec.soft) for spec in WORKFLOW],
    )
    store.save_task(task)
    return task


def run_assessment(
    request: Mapping[str, Any],
    project_path: str | Path,
    *,
    store: TaskStore,
    catalog_path: str | Path | None = None,
    time_budget_minutes: int = 180,
    now: str | None = None,
    task: AssessmentTask | None = None,
) -> AssessmentTask:
    """Create (or continue) a task and run it to a terminal or parked state.

    The analysis workflow deliberately does not query the capability-intel
    channel: the bundle records it as ``not_attempted`` (a declared
    unknown), never as an offline empty success. Callers that hold a
    transport call ``pea.fetch_capability_intel`` separately and merge
    the result - the orchestrator does not fake a channel it was not
    given.
    """
    stamp = now or _utc_now()
    settings: dict[str, Any] = {
        "project_path": str(project_path),
        "catalog_path": str(catalog_path or DEFAULT_CATALOG),
        "now": stamp,
        "time_budget_minutes": time_budget_minutes,
    }
    if task is None:
        task = create_task(request, project_path, store=store, now=stamp)
    return _run_to_completion(task, store, settings)


def resume_task(
    task_id: str,
    *,
    store: TaskStore,
    catalog_path: str | Path | None = None,
    time_budget_minutes: int = 180,
    now: str | None = None,
) -> AssessmentTask:
    """Resume a parked/failed task from its recorded state.

    Steps whose input digest is unchanged are not re-run; everything else
    runs. A task parked at the authorization gate resumes into the same
    gate - if the request now carries an authorization the analysis steps
    run; if not, it parks again with the same named blocker.
    """
    task = store.load_task(task_id)
    if task.status == TASK_DONE:
        raise TaskBoundaryError(f"task {task_id!r} is already done; nothing to resume")
    return run_assessment(
        task.request,
        task.project_path,
        store=store,
        catalog_path=catalog_path,
        time_budget_minutes=time_budget_minutes,
        now=now,
        task=task,
    )


def get_task(task_id: str, *, store: TaskStore) -> AssessmentTask:
    """Load one task's entity (status + step table)."""
    return store.load_task(task_id)


def list_tasks(*, store: TaskStore) -> list[AssessmentTask]:
    """Every task in the store, oldest first."""
    return store.list_tasks()
