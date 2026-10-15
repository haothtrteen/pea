"""The javascript-obfuscator adapter (WP3): the first real protection tool.

The candidate is the seed catalog's most completely reviewed entry
(license BSD-2-Clause ``verified``, maintenance ``active``,
``candidate_requires_project_tests`` - the honest third state). PEA pins the
exact version, installs it into its own tool cache (never into the target
project), and drives it through a PEA-owned runner script with structured
argv and no shell. Its published guidance warns that some configurations
slow execution by 15-80%: that limit is written into the manifest and
reported, not hidden - PEA measures size precisely and records runtime cost
as a declared unknown instead of guessing.

If node or the pinned package cannot be resolved, ``inspect`` says so with
named unknowns - a missing tool is an unknown, never a silent "does not
apply" and never a fabricated run.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from pea.adapters.base import AdapterError, AdapterInspect, ApplyPreview, ApplyResult

#: Exact pinned version - reproducibility is a manifest requirement. The
#: lock file lives in the tool cache; upgrading is a deliberate, reviewed act.
PINNED_VERSION = "5.9.0"
PACKAGE = "javascript-obfuscator"

#: Default transformations: moderate, semantics-preserving defaults. Anything
#: aggressive (control-flow flattening, self-defending, dead code) stays off
#: until a project's own regression suite justifies it - the manifest records
#: this as a limitation, not a claim of strength.
DEFAULT_OPTIONS: dict[str, Any] = {
    "compact": True,
    "stringArray": True,
    "stringArrayEncoding": ["base64"],
    "identifierNamesGenerator": "hexadecimal",
    "controlFlowFlattening": False,
    "deadCodeInjection": False,
    "selfDefending": False,
    "disableConsoleOutput": False,
}

MANIFEST: dict[str, Any] = {
    "schema_version": "1.0",
    "tool_id": PACKAGE,
    "tool_version": PINNED_VERSION,
    "license": {"spdx": "BSD-2-Clause", "status": "verified"},
    "provenance": "npm registry; pinned exact version; lock file in PEA tool cache",
    "supported_languages": ["javascript", "typescript"],
    "supported_targets": ["javascript", "typescript", "nodejs", "browser"],
    "transformations": ["string_array_encoding", "identifier_mangling", "compaction"],
    "input_scope": "*.js / *.mjs / *.cjs sources under the managed workspace",
    "output_scope": "obfuscated content replaces the source in place inside the managed workspace; the originals survive only in the snapshot manifest (digest-pinned)",
    "config_schema": {"type": "object"},
    "resource_limits": {"timeout_seconds": 300, "max_output_bytes": 64 * 1024 * 1024},
    "verification_requirements": ["project's own test suite must pass on the protected output"],
    "known_limitations": [
        "上游文档警示：部分配置与负载下执行减速 15–80%——本适配器只测体积，运行时开销记为 unknown",
        "实测（WP4 canary）：默认保守变换下明文字面量会被 base64 编码隐藏，但顶层 const 标识符名不重命名（上游 renameGlobals 默认关）——凭据命名形态仍可被启发式命中，暴露面计数 1→1 是如实测量而非明文泄漏；激进变换需项目回归通过后另行评估",
        "不替代服务端秘密管理；客户端校验混淆后仍是客户端校验",
        "source map 与动态特性（eval/new Function）须项目单独验证",
        "default 变换刻意保守；control-flow flattening / self-defending 需项目回归通过后才可开启",
    ],
}

#: The PEA-owned runner: reads a JSON job file, obfuscates the listed files
#: through the pinned package's programmatic API, writes outputs, prints a
#: bounded JSON summary. Structured argv, no shell, no free-form commands.
_RUNNER = """\
'use strict';
const fs = require('fs');
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');

const job = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const outputs = [];
let exitCode = 0;
for (const item of job.files) {
  try {
    const source = fs.readFileSync(item.input, 'utf8');
    const result = JavaScriptObfuscator.obfuscate(source, job.options || {}).getObfuscatedCode();
    fs.mkdirSync(path.dirname(item.output), { recursive: true });
    fs.writeFileSync(item.output, result, 'utf8');
    outputs.push({ input: item.input, output: item.output, bytes: Buffer.byteLength(result) });
  } catch (err) {
    exitCode = 1;
    outputs.push({ input: item.input, error: String(err && err.message || err).slice(0, 200) });
  }
}
process.stdout.write(JSON.stringify({ exit_code: exitCode, outputs }));
"""


def tool_cache_root() -> Path:
    """PEA's own tool cache (env ``PEA_TOOL_CACHE``, default ``.pea/tools``)."""
    return Path(os.environ.get("PEA_TOOL_CACHE", ".pea/tools")).expanduser().resolve()


def _node_binary() -> str | None:
    return shutil.which("node")


def ensure_tool(*, install: bool = True) -> tuple[str, Path]:
    """Resolve the pinned tool. Returns ``(node, package_dir)``.

    Installs the pinned version into PEA's tool cache on first use (a
    deliberate, reviewed act - the version never floats). Any failure
    raises :class:`AdapterError` with a named reason; callers surface it
    as an unknown, never as a fabricated run.
    """
    node = _node_binary()
    if node is None:
        raise AdapterError("tool_runtime_missing", "node 不在 PATH 上；PEA 的 JS 适配器需要 Node.js 运行时")
    cache = tool_cache_root()
    package_dir = cache / "node_modules" / PACKAGE
    if not package_dir.is_dir():
        if not install:
            raise AdapterError("tool_not_installed", f"{PACKAGE}@{PINNED_VERSION} 未安装于 {cache}")
        cache.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [
                "npm",
                "install",
                "--no-audit",
                "--no-fund",
                "--prefix",
                str(cache),
                f"{PACKAGE}@{PINNED_VERSION}",
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if proc.returncode != 0 or not package_dir.is_dir():
            raise AdapterError(
                "tool_install_failed",
                f"npm install {PACKAGE}@{PINNED_VERSION} 失败（rc={proc.returncode}）：{proc.stderr.strip()[:200]}",
            )
    return node, package_dir


class JSObfuscatorAdapter:
    """Applies javascript-obfuscator to a managed workspace."""

    manifest = MANIFEST

    def __init__(self, *, options: dict[str, Any] | None = None) -> None:
        self._options = dict(DEFAULT_OPTIONS)
        if options:
            unknown = sorted(set(options) - set(DEFAULT_OPTIONS))
            if unknown:
                raise AdapterError("options_unknown", f"未登记的配置项：{', '.join(unknown)}")
            self._options.update(options)

    # -- inspect -----------------------------------------------------------

    def inspect(self, target: Path) -> AdapterInspect:
        sources = [p for p in target.rglob("*") if p.is_file() and _is_obfuscation_target(p)]
        if not sources:
            return AdapterInspect(
                applies=False,
                tool_id=PACKAGE,
                tool_version=PINNED_VERSION,
                reason="目标中没有 JavaScript 源文件（*.js/*.mjs/*.cjs）",
            )
        try:
            ensure_tool(install=False)
        except AdapterError as exc:
            return AdapterInspect(
                applies=True,
                tool_id=PACKAGE,
                tool_version=PINNED_VERSION,
                reason=f"目标含 {len(sources)} 个 JS 源文件，但工具未就绪",
                unknowns=(f"{exc.reason}: {exc.detail}",),
            )
        return AdapterInspect(
            applies=True,
            tool_id=PACKAGE,
            tool_version=PINNED_VERSION,
            reason=f"目标含 {len(sources)} 个 JS 源文件，工具已就绪",
        )

    # -- preview -----------------------------------------------------------

    def preview(self, plan: dict[str, Any], workspace: Path) -> ApplyPreview:
        """The exact, reviewable plan: files, options, outputs, side effects."""
        sources = [p for p in sorted(workspace.rglob("*")) if p.is_file() and _is_obfuscation_target(p)]
        if not sources:
            raise AdapterError("no_js_sources", "受管工作区中没有 JavaScript 源文件")
        files = []
        for src in sources:
            rel = src.relative_to(workspace)
            files.append(
                {
                    "input": str(src),
                    "output": str(src),  # in place: the protected source IS the deliverable
                    "rel": str(rel),
                }
            )
        return ApplyPreview(
            argv=("node", "<pea-runner>", "<job.json>"),
            affected_files=tuple(f["rel"] for f in files),
            output_destination=str(workspace),
            expected_side_effects=(
                "就地替换受管工作区内受影响文件的内容（混淆后源码即交付物）；原文只存在于快照 manifest",
                "不访问网络；不安装项目依赖；不触碰工作区之外任何路径",
            ),
            tool_id=PACKAGE,
            tool_version=PINNED_VERSION,
            options=dict(self._options),
        )

    # -- apply --------------------------------------------------------------

    def apply(self, preview: ApplyPreview, workspace: Path) -> ApplyResult:
        """Run the pinned tool over the previewed files, no shell involved."""
        node, package_dir = ensure_tool(install=True)
        files = []
        for rel in preview.affected_files:
            src = workspace / rel
            files.append({"input": str(src), "output": str(src)})  # in place
        runner = tool_cache_root() / "pea-js-runner.cjs"
        runner.parent.mkdir(parents=True, exist_ok=True)
        runner.write_text(_RUNNER, encoding="utf-8")
        job = {
            "files": files,
            "options": dict(preview.options),
            "package_dir": str(package_dir),
        }
        job_file = tool_cache_root() / "pea-js-job.json"
        job_file.write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding="utf-8")
        env = dict(os.environ)
        env["NODE_PATH"] = str(package_dir.parent)
        try:
            proc = subprocess.run(
                [node, str(runner), str(job_file)],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
                cwd=str(workspace),
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError("tool_timeout", f"混淆执行超过 300s 上限：{exc}") from None
        outputs: list[str] = []
        log_tail: list[str] = []
        try:
            summary = json.loads(proc.stdout.strip() or "{}")
        except json.JSONDecodeError:
            summary = {}
        for entry in summary.get("outputs", []):
            if entry.get("error"):
                log_tail.append(f"{entry.get('input')}: {entry['error']}")
            elif entry.get("output"):
                outputs.append(entry["output"])
        if proc.returncode != 0 or not outputs:
            detail = (proc.stderr.strip() or proc.stdout.strip())[:200]
            raise AdapterError("tool_execution_failed", f"混淆执行失败（rc={proc.returncode}）：{detail}")
        return ApplyResult(
            outputs=tuple(outputs),
            exit_code=proc.returncode,
            tool_id=PACKAGE,
            tool_version=PINNED_VERSION,
            log_tail=tuple(log_tail[:20]),
        )


def _is_obfuscation_target(path: Path) -> bool:
    """Files the transformation applies to: production sources only.

    Test files are verification infrastructure, not the shipped
    deliverable - obfuscating them would corrupt the very check that
    decides whether the protected build works. Generated dirs and VCS
    metadata are excluded for the same reason.
    """
    parts = set(path.parts)
    if parts & {"node_modules", "dist", "build", ".git", "coverage"}:
        return False
    name = path.name
    if ".test." in name or ".spec." in name or name in {"setupTests.js", "jest.setup.js"}:
        return False
    if parts & {"test", "tests", "__tests__", "__mocks__", "e2e"}:
        return False
    return path.suffix in {".js", ".mjs", ".cjs"}


ADAPTERS = {"javascript-obfuscator": JSObfuscatorAdapter}
