<div align="center">

**English** · [简体中文](README_zh.md)

# PEA: Protective Engineering Assistant

### Evidence-driven protection planning for software you own or are authorized to test.

**Analyze what is exposed. Choose what to protect. Prove what changed — with evidence, not claims.**

[![license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![runtime deps](https://img.shields.io/badge/runtime%20deps-zero-44cc11?style=flat-square)](#quick-start)
[![tests](https://img.shields.io/badge/tests-2451%20passed-2ea44f?style=flat-square)](#quality-gates)
[![MCP tools](https://img.shields.io/badge/MCP-35%20tools-5c4ee5?style=flat-square)](mcp/tool-contract.json)

[Quick start](#quick-start) · [How PEA works](#how-pea-works) · [What it observes](#what-it-observes) · [Honesty boundaries](#honesty-boundaries) · [Documentation](#documentation) · [Responsible use](#responsible-use) · [License](#license)

</div>

---

PEA turns the protection question — *"what is actually exposed in this binary, what should I harden, and how do I prove the hardening worked?"* — into an engineering loop with mechanical evidence at every step. It maps analysis capability to software exposure, selects protection measures, and produces verifiable evidence for what changed and what did not.

The goal is never to make a specific reversing tool "fail". The goal is to know what your software exposes, choose the right measures, and state — with observations, digests and named unknowns — what those measures changed.

Everything runs **locally and offline**. Runtime dependencies are **zero** (standard library only); analysis domains never execute your project's code.

> **Execution stays inside PEA's managed workspace.** PEA plans, previews and verifies; when you approve a run it applies the reviewed transform to a *copy* of your project — your source tree is read, never written. See [Honesty boundaries](#honesty-boundaries).

## Quick start

Requires Python 3.10+.

```bash
pip install -e ".[dev]"        # dev install (pytest / jsonschema / ruff / mypy)

pea demo --request examples/protection-request.flutter-licensing.example.json --project demo/canary-flutter-licensing --out build/demo-out
                                # run the end-to-end prototype: recon → plan → attack simulation → ledger → report
pea task run --request examples/protection-request.flutter-licensing.example.json --project demo/canary-flutter-licensing --store .pea/tasks --out build/task-out
                                # the same walk as a durable, resumable task: gate → domains → plan → ledger → gate → report
pea protect demo/canary-js-licensing
                                # one command, one decision: plan → preview → y/N → isolated apply → verify → diff → report
                                # (your project is never written; the run's workspace and evidence live under --store)
```

Without installing (from a source checkout):

```bash
PYTHONPATH=src python3 -m pea.cli demo --request examples/protection-request.flutter-licensing.example.json --project demo/canary-flutter-licensing --out build/demo-out
```

Quality gates:

```bash
make check                     # ruff + mypy + full test suite + contract gates
make verify-real               # L2 layer: run the real analysis domains over real (synthetic-form) artifact bytes
make verify-loop               # WP4: the seven-step execution loop on a JS canary with the real tool (not in `make check`)
```

## How PEA works

The loop, and where each stage is enforced in code:

| Stage | What happens | Where |
| --- | --- | --- |
| Authorization gate | Read-only work happens only under an explicitly authorized root; everything else is a named refusal | `src/pea/paths.py`, `src/pea/mcpserver.py` |
| Reconnaissance | Project profile, artifact manifest, secret scan, string/symbol scan, native structure, Dart AOT, build integration — every domain emits `findings + coverage + unknowns` | `src/pea/recon.py`, `src/pea/artifactscan.py`, `src/pea/secretscan.py`, `src/pea/symbolscan.py`, `src/pea/nativecheck.py`, `src/pea/dartaotcheck.py`, `src/pea/buildint.py` |
| Exposure mapping | Findings are tiered T1–T4 (tool amplification → algorithm logic); repair order = attacker's marginal cost | `src/pea/tiers.py` |
| Protection planning | Capability families match the exposure; deployment posture is derived from an intake interview, unanswered questions stay open as `intake_unknowns` | `src/pea/planner.py`, `src/pea/intake.py`, `src/pea/attacksim.py` |
| Attack simulation | Adversarial self-test design with red lines in the schema: artifacts read-only, tool failure can only record `unknown`, no "absolute protection" in the explanation enum | `src/pea/attacksim.py` |
| Evidence ledger | Every domain observation enters an append-only ledger; resolving an unknown requires two-sided evidence and at least one observation-grade record | `src/pea/ledger.py` |
| Verified gate | The gate is mechanical: any blocking unknown blocks. "No finding" is never treated as "proof of safety" | `src/pea/ledger.py` (`gate_for_verified`) |
| Report | Redacted Markdown plus a byte-reproducible JSON bundle | `src/pea/report.py`, `src/pea/demo.py` |

**Evidence authority is explicit on every record** — `observation` / `inference` / `external_claim` / `human_assertion`. There is no default and no silent upgrade path: static evidence never impersonates runtime observation.

## What it observes

Eight read-only domains, each with a declared capability boundary — when a provider is unavailable the domain records `unknown`, never a fake success:

- **project-recon** — languages, build system, platform, secrets posture (pattern names only, values stay redacted)
- **artifact-manifest** — paths plus SHA-256 digests of build outputs
- **secret-scan** — pattern hits recorded by name and count, never by content
- **string-symbol-scan** — known-leak string/symbol patterns in binaries
- **native-check** — read-only ELF / PE / Mach-O structure parsing (stack flags, symbols, RELRO)
- **dart-aot-check** — snapshot anchors in `libapp.so`; obfuscation status stays `unknown` when it cannot be established
- **build-integration** — ABI splits, packaging expectations, declared build flags
- **testbench** — environment reconnaissance (T0–T4): detects what tier the machine can reach without installing or starting anything

On top of the domains: a capability-intel connector (allowlist + offline default `unknown`) and a candidate-review gate (license / maintenance / evidence / trust — `blocked` beats everything).

## The MCP surface

`src/pea/tooleffects.py` is the single registry that generates both `mcp/tool-contract.json` and `mcp/tool-effects.json`; a contract gate fails the build on any drift. All **35 contracted tools are wired** through `mcpserver.call_tool` with approval enforcement before execution (`tool_not_wired` no longer applies to any contracted tool; the guard remains for whatever is added next). The four executors (`apply_plan` / `verify_output` / `compare_results` / `rollback`) run only inside a PEA-managed workspace, under a one-time token whose replay, expiry, scope change or path escape is a named refusal *at the consumption point*.

The execution loop is one implementation (`src/pea/protect.py`) shared by the CLI, the MCP tools and the integration script: snapshot the target into a managed workspace → apply the reviewed adapter (structured argv, no shell) → verify independently (three-state gates, including a **transformation-effectiveness** gate: outputs byte-identical to the snapshot fail, whatever exit code the tool reported) → diff before/after with the read-only analysis stack → rollback confined to the managed workspace. Execution roots come from the operator's environment (`PEA_AUTHORIZED_ROOTS`); with it unset the executors refuse (`execution_roots_unconfigured`) instead of falling back to a caller-supplied path.

Approval tokens are one-time and bound to the tool, plan digest, artifact digest, normalized argument digest, tool version, authorized root and target path — replay, expiry, plan/argument/version changes and path escapes are all named refusals.

The six ledger tools (`pea.ledger_record` / `ledger_query` / `ledger_audit_unknowns` / `ledger_gate` / `ledger_resolve` / `ledger_export`) expose the evidence contract to agents, with per-run ledgers that can persist across processes.

Four task-orchestrator tools (`pea.run_assessment` / `get_task` / `list_tasks` / `resume_task`) make "analyse this project and produce the protection plan, ledger and report" a durable entity: a 14-step workflow (authorization gate → recon → seven read-only domains → plan → attack self-test design → evidence ledger → verified gate → report) persisted as one directory per task, with atomic writes and input-digest-based resume. Failure is honest by construction: the ledger is the failure sink (an incomplete domain becomes a *blocking* unknown, never a fabricated pass), the report skips itself rather than rendering around a missing input, and an unpassed authorization gate parks the task with zero project reads. The task store root comes from the environment (`PEA_TASK_STORE`), never from a tool argument; the CLI equivalent is `pea task run/status/list/resume/report` (exit 0 done / 3 blocked / 4 authorization unconfirmed / 2 named boundary errors).

PEA also runs as a standard MCP server process: `pip install "pea[mcp]"` (the official SDK stays an optional extra; the core package remains standard-library only) and `pea mcp-server` speaks JSON-RPC over stdio. `tools/list` is generated from the same registry and `mcp/tool-schemas.json` - never from function signatures - and `tools/call` lands directly in `mcpserver.call_tool`: schema validation at the protocol edge, then the same approval gates, authorized-root checks and named refusals as the CLI, with zero protocol-layer exemptions. A contract gate fails the build if the protocol surface cannot express a contract's own approval requirement (the class of break that would make every call to a tool refused before its handler runs).

The stage-3 additions close the "sandbox → live-fire" loop: `pea.check_testbench` (environment reconnaissance), `pea.design_mission_brief` (the five-element handoff to an attack agent), and the D7 field-feedback pair `pea.intake_cracked_artifact` / `pea.design_field_response` (cracked-package diff intake, server-side goalpost rotation). Evidence returned from the field must carry an `environment` block — the ledger refuses records without one.

## Honesty boundaries

PEA states what it cannot do as plainly as what it can:

- **Execution only ever touches a managed copy.** The executors apply the reviewed transform inside a PEA-managed workspace snapshot; your project directory is read, never written, and rollback discards or restores that workspace only. `pea protect <path>` is the one-command path, with a single human decision (the final y/N on the exact preview).
- **Approval is not a model's "yes".** The executors require an approval event from a trusted channel — your own shell (`pea approve`, or the interactive confirmation in `pea protect`). A model-supplied `authorization` / `explicit_user_approval` flag is intent, never approval.
- **A client-side check stays client-side.** Obfuscating a licence check does not make it authoritative; the honest recommendation is to move the decision behind a trust boundary (that is what the `logic_extraction` advice in the plan is for).
- **The MCP server is a protocol shell, nothing more.** `pea mcp-server` runs over stdio with the official SDK, but it carries no cross-process state of its own: one-time approval tokens live and die with the server process. The WP2 task orchestrator makes tasks and step outputs durable across processes (store + input-digest resume), but resuming a parked task is not the same as resuming a token.
- **Not a build verification.** The L2 layer runs the domains over real bytes of *synthetic-form* artifacts (ELF headers and marker strings are real bytes, but not Flutter builds — no Flutter SDK in the authoring environment). Dart AOT recovery rates stay `unknown` until a real build exists.
- **Demo scenarios are simulations, not templates.** They show how the pipeline behaves; they are not conclusions about any real project. The only valid inputs for a real target are what the domains actually observed, plus the capability map's `research_date` community status.
- **No absolute protection is ever claimed.** PEA does not promise un-reverse-engineerability, and never interprets tool crashes, unavailable providers or empty output as protection success.

## Quality gates

```text
ruff + mypy ................ clean (36 source files)
pytest ..................... 2451 passed
contract gates ............. 36 (schemas are the single source of truth; drift fails CI)
make verify-real ........... exit 0 — L2 seven-layer three-state verification, 55 checks
make verify-loop ........... exit 0 — WP4 seven-step execution loop, all eight criteria checked (real tool; not in `make check`)
```

The test suite pins the refusals, not just the happy paths: tampered bytes fail the manifest layer, a crashing domain is FAIL (never a skip), a failed dependency makes downstream layers UNKNOWN, and the L2 gates have already caught two real bugs (ELF32 program-header flag offset; ABI matching must accept `lib/<abi>/` at any path depth).

## Documentation

- `docs/Prototype-1.0-Demo-zh-CN.md` — the end-to-end prototype walkthrough, with the REA parity status per dimension (Chinese)
- `docs/REA-Parity-Plan-zh-CN.md` — the six-dimension parity plan against REA (Chinese)
- `docs/Exposure-Tier-Model-zh-CN.md` — the T1–T4 exposure tier model (Chinese)
- `docs/PEA-Architecture-Spec-zh-CN.md` — architecture, MCP contracts, threat model (Chinese)
- `docs/Adversarial-Self-Test-and-Tool-Integration-zh-CN.md` — adversarial self-test and layered tool integration (Chinese)
- `docs/Attack-Verification-and-Field-Feedback-Design-zh-CN.md` — the stage-3 design freeze: real-attack verification via REA as self-test oracle (mission briefs, environment tiers T0–T4, testbench recon) plus the field-feedback loop D7 (Chinese)
- `docs/Phase4-Access-Orchestration-Execution-Design-zh-CN.md` — the phase-4 design freeze: the official-SDK MCP stdio server, the `pea.run_assessment` task orchestrator, the four controlled executors (apply/verify/compare/rollback) and the first real protection loop (Chinese)
- `docs/Execution-Loop-Implementation-Plan-zh-CN.md` — the WP0–WP6 landing plan for the controlled-execution loop, with the external-review disposition and the delivered-acceptance record (Chinese)
- `docs/Dual-MCP-Wiring-Guide-zh-CN.md` — wiring guide for one agent carrying both PEA and REA: brief → REA execution → evidence return (Chinese)
- `docs/Scenario-Walkthrough-Flutter-Licensing-zh-CN.md` — full-loop scenario walkthrough (Chinese)
- `CHANGELOG.md` — version history and the 0.x versioning policy
- `CONTRIBUTING.md` — the non-negotiable disciplines, gates and commit conventions
- `mcp/tool-contract.json` — the generated tool contract (35 tools)
- `sources.md` — reference sources and their verification status

English documentation is a work in progress; the Chinese docs are the maintained baseline.

## Responsible use

PEA is built for lawful protection engineering on software you own or are authorized to test. It does not execute third-party protection tools, does not connect to the network at runtime, and does not modify your project. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

## License

[MIT](LICENSE) © 2026 haothtrteen
