"""Shared read-only traversal discipline for filesystem-based domains (M3/D2).

Every defense domain that looks at project files reaches them the same way:
bounded, read-only, symlink-safe, and every skip reported as data
(:attr:`WalkReport.omissions`) instead of silence. Domains differ in what
they *do* with each file - profile languages, fingerprint artifacts, sniff
for secrets, extract strings - this module owns only *how files are
reached*, so a new domain inherits the discipline by construction.

The bounds are the project's own security policy made executable:

* traversal never escapes the authorized root - symlinks are resolved
  before the containment check, and out-of-root links are skipped and
  reported;
* depth and file count are capped, and every cap that fires is reported -
  a skipped path is data, not a pass;
* VCS internals are never scanned;
* nothing here executes a project script, mutates a file or spawns a
  process: files are stat'ed, never opened, never written.
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

#: Stop enumerating after this many files; the rest is an omission, not a pass.
MAX_FILES = 20_000
#: Directories deeper than this relative to the root are skipped.
MAX_DEPTH = 12
#: Never scan VCS internals; report the skip instead.
SKIP_DIR_NAMES = frozenset({".git", ".hg", ".svn"})


class WalkBoundaryError(ValueError):
    """The requested path is not a usable root for a read-only walk."""


@dataclass
class WalkReport:
    """What the walk could not reach, and how far it got.

    ``omissions`` is the domain's raw material for ``coverage.omissions``
    and for coverage-derived unknowns: a caller that drops it turns
    "skipped" into a silent pass, which is the one failure mode this
    module exists to prevent.
    """

    omissions: list[str] = field(default_factory=list)
    files_seen: int = 0
    truncated: bool = False


def resolve_root(project_path: str | Path) -> Path:
    """Validate and resolve the authorized root; raises when unusable."""
    root = Path(project_path).expanduser()
    if not root.is_dir():
        raise WalkBoundaryError(f"project path is not a directory: {project_path}")
    return root.resolve()


def is_inside(root: Path, candidate: Path) -> bool:
    """True when ``candidate`` resolves to something under ``root``.

    Symlinks are resolved *before* the check, so a link pointing outside the
    authorized root fails here even though it is reachable by name.
    """
    try:
        candidate.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def relpath(root: Path, path: Path) -> str:
    """Lexical POSIX path of ``path`` under ``root``; never resolves links.

    Callers use this for *reporting*, including paths that failed the
    containment check - resolving them would either escape the root or raise,
    so the lexical form (which is always well-defined for walked entries) is
    the safe thing to print.
    """
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def walk_project(
    project_path: str | Path,
    *,
    report: WalkReport | None = None,
) -> Iterator[tuple[Path, int]]:
    """Yield ``(path, size)`` for every reachable regular file under the root.

    Read-only and bounded: entries are stat'ed, never opened. Skips (VCS
    directories, symlink escapes, depth/file-count caps, stat failures) are
    appended to ``report`` as omission records; the caller decides how to
    surface them. An already-resolved root may be passed in - resolution is
    idempotent - which lets a caller validate the root once and reuse the
    resolved form.
    """
    if report is None:
        report = WalkReport()
    root = resolve_root(project_path)

    for dir_root, dir_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current = Path(dir_root)
        rel_dir = current.relative_to(root)
        depth = 0 if rel_dir == Path(".") else len(rel_dir.parts)
        if depth >= MAX_DEPTH:
            report.omissions.append(f"{relpath(root, current)}/: 超过遍历深度上限 {MAX_DEPTH}，未枚举")
            dir_names[:] = []
            continue
        kept_dirs: list[str] = []
        for name in dir_names:
            child = current / name
            if name in SKIP_DIR_NAMES:
                report.omissions.append(f"{relpath(root, child)}/: 版本控制目录，按策略跳过")
                continue
            if not is_inside(root, child):
                report.omissions.append(f"{relpath(root, child)}/: 符号链接或解析路径越出授权根，已跳过")
                continue
            kept_dirs.append(name)
        dir_names[:] = kept_dirs

        for name in file_names:
            if report.files_seen >= MAX_FILES:
                report.truncated = True
                break
            file_path = current / name
            if not is_inside(root, file_path):
                report.omissions.append(f"{relpath(root, file_path)}: 符号链接或解析路径越出授权根，已跳过")
                continue
            try:
                size = file_path.stat().st_size
            except OSError as exc:
                report.omissions.append(f"{relpath(root, file_path)}: 无法 stat（{exc.__class__.__name__}），已跳过")
                continue
            report.files_seen += 1
            yield file_path, size
        if report.truncated:
            report.omissions.append(f"文件数达到上限 {MAX_FILES}，其余文件未枚举")
            break
