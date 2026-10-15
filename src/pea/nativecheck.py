"""Native-check domain (M3/D2): what hardening do the shipped binaries carry?

The REA parity plan's ``native`` mirror - not a disassembler wrapper but a
structural reader. For every native container in the artifact manifest
(ELF / PE / Mach-O / ar) this domain reads the headers that decide the
cheapest attacks: executable stack, missing NX, missing PIE/ASLR, missing
RELRO, unstripped symbol tables. These are the properties an attacker's
own tooling reports in its first seconds, so the defender reads them first.

Hard rules:

* pure stdlib ``struct`` parsing - no third-party engine, no execution of
  the artifacts, ever; reading a header is not running the binary;
* a container whose format is not recognized is an omission plus an
  unknown - "we could not read it" is never upgraded to "it is fine";
* truncated headers (a file cut mid-header) are omissions, not parse
  successes - a truncated read must not silently yield "no gaps found";
* with no native containers in the manifest the whole domain is
  ``unknown``/``not_run``: a source-only tree has an unassessed native
  surface, and the tier annotation stays on the unknown (``pea.tiers``:
  unknown does not lose its place in the repair order);
* container formats PEA does not parse (``.apk`` zip structure, ``.wasm``,
  ``.dex``, ``.pyc``, ``.asar``, ``.jar``) are declared coverage gaps in
  the finding's limitations - the domain states what it did not read
  instead of implying completeness.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea.artifactscan import ArtifactScanResult
from pea.fswalk import is_inside, resolve_root
from pea.tiers import TIER_RUNTIME_BEHAVIOR

#: Manifest kinds this domain parses structurally. Everything else in the
#: manifest (archives, bytecode, wasm) is a declared gap, not a silent skip.
NATIVE_KINDS = frozenset(
    {
        "native_shared_library",
        "native_static_library",
        "native_executable",
        "node_native_addon",
        "flutter_dart_snapshot",
        "flutter_engine",
        "game_engine_library",
    }
)

#: Read at most this many bytes of any single artifact (headers live in the
#: first pages; a cap keeps a corrupt or adversarial file bounded).
NATIVE_READ_BYTES = 1_048_576

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = {
    0xFEEDFACE: "macho32",
    0xCEFAEDFE: "macho32",
    0xFEEDFACF: "macho64",
    0xCFFAEDFE: "macho64",
    0xCAFEBABE: "macho_fat",
    0xBEBAFECA: "macho_fat",
}
AR_MAGIC = b"!<arch>\n"

# ELF constants
ET_EXEC = 2
ET_DYN = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_DYNAMIC = 2
SHT_SYMTAB = 2
PF_X = 1
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

ELF_MACHINES = {
    0x03: "x86",
    0x28: "arm",
    0x3E: "x86-64",
    0xB7: "aarch64",
    0xF3: "riscv",
}

# PE constants
PE_SIGNATURE = b"PE\x00\x00"
IMAGE_FILE_EXECUTABLE = 0x0002
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0xAA64: "arm64",
}

# Mach-O constants
MH_EXECUTE = 2
MH_DYLIB = 6
MH_BUNDLE = 8
MH_PIE = 0x200000
MACHO_CPUTYPES = {
    0x00000007: "x86",
    0x01000007: "x86-64",
    0x0100000C: "arm64",
    0x0000000C: "arm",
}

#: Gap label -> what is not parsed. Surfaced verbatim in finding limitations.
UNPARSED_CONTAINER_NOTE = "apk/aab/jar/aar/dex/pyc/bc/asar/wasm 等容器格式本域不做结构解析"


@dataclass(frozen=True)
class NativeProfile:
    """One artifact's structural outcome: what the headers do and do not say."""

    path: str
    kind: str
    format: str  # elf | pe | macho | ar | unknown
    bits: int | None = None
    endian: str | None = None  # little | big | None
    arch: str | None = None
    role: str | None = None  # executable | shared_library | universal | static_archive | None
    nx: bool | None = None
    pie: bool | None = None
    relro: str | None = None  # full | partial | none | None
    stripped: bool | None = None
    gaps: tuple[str, ...] = ()  # machine-readable gap labels, e.g. "executable_stack"


@dataclass(frozen=True)
class NativeCheckResult:
    """Everything the structural read observed, plus what it could not read."""

    project_path: str
    profiles: tuple[NativeProfile, ...]
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "profiles": [
                {
                    "path": p.path,
                    "kind": p.kind,
                    "format": p.format,
                    "bits": p.bits,
                    "endian": p.endian,
                    "arch": p.arch,
                    "role": p.role,
                    "nx": p.nx,
                    "pie": p.pie,
                    "relro": p.relro,
                    "stripped": p.stripped,
                    "gaps": list(p.gaps),
                }
                for p in self.profiles
            ],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_header(path: Path) -> bytes:
    """Bounded read of the artifact's leading bytes.

    OSError propagates to the caller, which turns it into an omission - an
    unreadable artifact stays visible in coverage instead of becoming a
    fake profile.
    """
    with path.open("rb") as handle:
        return handle.read(NATIVE_READ_BYTES)


# --------------------------------------------------------------------------
# ELF
# --------------------------------------------------------------------------


def _parse_elf(data: bytes) -> NativeProfile | None:
    """Structural ELF read. Returns None when this is not an ELF file.

    Raises ``ValueError`` when the magic claims ELF but the header is
    truncated or malformed - a file that *says* ELF and cannot be read is
    damage, and damage must surface as ``header_parse_error``, never as
    "unrecognized format".
    """
    if len(data) < 20 or data[:4] != ELF_MAGIC:
        return None
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ValueError(f"invalid ELF ident: class={ei_class} data={ei_data}")
    bits = 32 if ei_class == 1 else 64
    endian = "little" if ei_data == 1 else "big"
    e = "<" if ei_data == 1 else ">"

    if bits == 64:
        if len(data) < 64:
            raise ValueError("truncated ELF64 header")
        e_type, e_machine = struct.unpack_from(e + "HH", data, 16)
        e_phoff, e_shoff = struct.unpack_from(e + "QQ", data, 32)
        e_phentsize, e_phnum = struct.unpack_from(e + "HH", data, 54)
        e_shentsize, e_shnum = struct.unpack_from(e + "HH", data, 58)
    else:
        if len(data) < 52:
            raise ValueError("truncated ELF32 header")
        e_type, e_machine = struct.unpack_from(e + "HH", data, 16)
        e_phoff, e_shoff = struct.unpack_from(e + "II", data, 28)
        e_phentsize, e_phnum = struct.unpack_from(e + "HH", data, 42)
        e_shentsize, e_shnum = struct.unpack_from(e + "HH", data, 46)

    gaps: list[str] = []
    nx: bool | None = None
    relro = "none"
    bind_now = False
    has_dynamic = False

    # Program headers: stack permissions and RELRO presence.
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        if offset + (56 if bits == 64 else 32) > len(data):
            gaps.append("program_headers_truncated")
            break
        if bits == 64:
            # ELF64: p_type @0, p_flags @4.
            p_type, p_flags = struct.unpack_from(e + "II", data, offset)
        else:
            # ELF32: p_type @0, p_offset @4, ..., p_flags @24 - the flags do
            # NOT sit at offset 4 (this was a real bug the L2 layer caught).
            p_type = struct.unpack_from(e + "I", data, offset)[0]
            p_flags = struct.unpack_from(e + "I", data, offset + 24)[0]
        if p_type == PT_GNU_STACK:
            nx = not bool(p_flags & PF_X)
            if p_flags & PF_X:
                gaps.append("executable_stack")
        elif p_type == PT_GNU_RELRO:
            relro = "partial"
        elif p_type == PT_DYNAMIC:
            has_dynamic = True

    # Section headers: symbol table presence decides "stripped"; the
    # SHT_DYNAMIC section anchors the BIND_NOW read below.
    stripped: bool | None = None
    has_symtab = False
    dynamic_offset: int | None = None
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        if offset + (64 if bits == 64 else 40) > len(data):
            gaps.append("section_headers_truncated")
            break
        sh_type = struct.unpack_from(e + "I", data, offset + 4)[0]
        if sh_type == SHT_SYMTAB:
            has_symtab = True
        elif sh_type == 6 and dynamic_offset is None:  # SHT_DYNAMIC
            if bits == 64:
                dynamic_offset = struct.unpack_from(e + "Q", data, offset + 24)[0]
            else:
                dynamic_offset = struct.unpack_from(e + "I", data, offset + 16)[0]

    if e_shnum > 0:
        stripped = not has_symtab
        if not stripped:
            gaps.append("unstripped_symbols")

    # Dynamic section: BIND_NOW upgrades RELRO from partial to full. The
    # anchor comes from the section table above, so the read happens after it.
    if has_dynamic and dynamic_offset is not None:
        bind_now = _dynamic_bind_now(data, e, bits, dynamic_offset)
    if relro == "partial" and bind_now:
        relro = "full"
    if relro == "none" and e_type == ET_EXEC:
        gaps.append("no_relro")

    pie: bool | None = None
    if e_type == ET_EXEC:
        pie = False
        gaps.append("no_pie")
    elif e_type == ET_DYN:
        pie = True  # position-independent by type; final binding is a loader property

    role = "executable" if e_type == ET_EXEC else "shared_library"
    return NativeProfile(
        path="",
        kind="",
        format="elf",
        bits=bits,
        endian=endian,
        arch=ELF_MACHINES.get(e_machine, f"unknown({e_machine})"),
        role=role,
        nx=nx,
        pie=pie,
        relro=relro,
        stripped=stripped,
        gaps=tuple(gaps),
    )


def _dynamic_bind_now(data: bytes, e: str, bits: int, dynamic_offset: int) -> bool:
    """Read DT_FLAGS/DT_FLAGS_1 for BIND_NOW from a dynamic section.

    Only called with a section offset the section-header walk located;
    bounded by the bytes actually read.
    """
    entry_size = 16 if bits == 64 else 8
    offset = dynamic_offset
    for _ in range(512):  # bounded: dynamic sections are small
        if offset + entry_size > len(data):
            return False
        if bits == 64:
            d_tag = struct.unpack_from(e + "q", data, offset)[0]
            d_val = struct.unpack_from(e + "Q", data, offset + 8)[0]
        else:
            d_tag = struct.unpack_from(e + "i", data, offset)[0]
            d_val = struct.unpack_from(e + "I", data, offset + 4)[0]
        if d_tag == 0:  # DT_NULL terminates
            break
        if d_tag in (DT_FLAGS, DT_FLAGS_1) and (d_val & (DF_BIND_NOW if d_tag == DT_FLAGS else DF_1_NOW)):
            return True
        offset += entry_size
    return False


# --------------------------------------------------------------------------
# PE
# --------------------------------------------------------------------------


def _parse_pe(data: bytes) -> NativeProfile | None:
    """Structural PE read (MZ + COFF + optional header).

    Raises ``ValueError`` when the MZ magic is present but the PE structure
    is truncated or the signature is absent - the same damage rule as ELF.
    """
    if len(data) < 64 or data[:2] != PE_MAGIC:
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return None
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != PE_SIGNATURE:
        raise ValueError("MZ without a reachable PE signature")

    coff = e_lfanew + 4
    machine, _n_sections, _timestamp, _symtab_ptr, _n_syms, size_opt, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    if size_opt == 0:
        return None
    opt = coff + 20
    if opt + 2 > len(data):
        return None
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        return None

    gaps: list[str] = []
    dll_characteristics = 0
    #: ``None`` when the data-directory area was not covered by the read -
    #  an unread directory is a gap in coverage, not evidence of no debug info.
    debug_directory_size: int | None = None
    if opt + 70 + 2 <= len(data):
        dll_characteristics = struct.unpack_from("<H", data, opt + 70)[0]
    dirs_offset = opt + (96 if magic == 0x10B else 112)
    # Data directory index 6 is the debug directory (0 export, 1 import,
    # 2 resource, 3 exception, 4 certificate, 5 relocation, 6 debug).
    if dirs_offset + 7 * 8 <= len(data):
        _debug_rva, debug_directory_size = struct.unpack_from("<II", data, dirs_offset + 6 * 8)
    if debug_directory_size == 0:
        gaps.append("no_debug_directory")

    if not characteristics & IMAGE_FILE_EXECUTABLE:
        return None  # an OBJ or resource-only file: not a shippable binary
    if not dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        gaps.append("no_aslr")
    if not dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT:
        gaps.append("no_nx")

    return NativeProfile(
        path="",
        kind="",
        format="pe",
        bits=64 if magic == 0x20B else 32,
        endian="little",
        arch=PE_MACHINES.get(machine, f"unknown({machine})"),
        role="executable",
        nx=bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) or None,
        pie=bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) or None,
        relro=None,  # no PE equivalent; declared as a limitation, not a gap
        stripped=None,
        gaps=tuple(gaps),
    )


# --------------------------------------------------------------------------
# Mach-O
# --------------------------------------------------------------------------


def _parse_macho(data: bytes) -> NativeProfile | None:
    """Structural Mach-O read (thin and fat/universal).

    Raises ``ValueError`` on a Mach-O magic with a truncated header.
    """
    if len(data) < 16:
        return None
    magic = struct.unpack_from(">I", data, 0)[0]
    variant = MACHO_MAGICS.get(magic)
    if variant is None:
        return None

    if variant == "macho_fat":
        return NativeProfile(
            path="",
            kind="",
            format="macho_fat",
            role="universal",
            gaps=("fat_header_not_enumerated",),
        )

    # The magic is decoded big-endian, so a little-endian file's magic reads
    # back byte-swapped (0xCFFAEDFE): swapped value => little-endian file.
    e = ">" if magic in (0xFEEDFACE, 0xFEEDFACF) else "<"
    bits = 64 if variant == "macho64" else 32
    header_size = 32 if bits == 64 else 28
    if len(data) < header_size:
        raise ValueError("truncated Mach-O header")
    cputype, _cpusubtype, filetype, _ncmds, _sizeofcmds, flags = struct.unpack_from(e + "IIIIII", data, 4)

    gaps: list[str] = []
    pie = bool(flags & MH_PIE) if filetype in (MH_EXECUTE, MH_BUNDLE) else None
    if filetype == MH_EXECUTE and not flags & MH_PIE:
        gaps.append("no_pie")

    role = {MH_EXECUTE: "executable", MH_DYLIB: "shared_library", MH_BUNDLE: "bundle"}.get(filetype, "unknown")
    return NativeProfile(
        path="",
        kind="",
        format="macho",
        bits=bits,
        endian="little" if e == "<" else "big",
        arch=MACHO_CPUTYPES.get(cputype, f"unknown({cputype})"),
        role=role,
        nx=None,  # stack flags live in load commands; declared gap
        pie=pie,
        relro=None,
        stripped=None,
        gaps=tuple(gaps),
    )


# --------------------------------------------------------------------------
# ar
# --------------------------------------------------------------------------


def _parse_ar(data: bytes) -> NativeProfile | None:
    """Recognize a static archive; member enumeration is a declared gap."""
    if not data.startswith(AR_MAGIC):
        return None
    return NativeProfile(
        path="",
        kind="",
        format="ar",
        role="static_archive",
        gaps=("archive_members_not_enumerated",),
    )


_PARSERS = (_parse_elf, _parse_pe, _parse_macho, _parse_ar)


def _profile_artifact(path: Path, rel: str, kind: str, data: bytes) -> tuple[NativeProfile | None, str | None]:
    """Try each parser in turn. Returns (profile, error_label)."""
    for parser in _PARSERS:
        try:
            profile = parser(data)
        except (struct.error, ValueError):
            return None, "header_parse_error"
        if profile is not None:
            return (
                NativeProfile(
                    path=rel,
                    kind=kind,
                    format=profile.format,
                    bits=profile.bits,
                    endian=profile.endian,
                    arch=profile.arch,
                    role=profile.role,
                    nx=profile.nx,
                    pie=profile.pie,
                    relro=profile.relro,
                    stripped=profile.stripped,
                    gaps=profile.gaps,
                ),
                None,
            )
    return None, "format_unrecognized"


# --------------------------------------------------------------------------
# Domain entry point
# --------------------------------------------------------------------------


def observe_native(
    scan: ArtifactScanResult,
    *,
    now: str | None = None,
) -> NativeCheckResult:
    """Read the manifest's native containers structurally.

    Consumes the artifact manifest the same way string-symbol-scan does:
    no second walk, no second root resolution - the manifest is the single
    traversal record. Artifacts outside the project root (a manifest entry
    that escaped the boundary) are refusals, not reads.
    """
    stamp = now or _utc_now()

    try:
        root = resolve_root(scan.project_path)
    except Exception:
        root = None

    omissions: list[str] = []
    profiles: list[NativeProfile] = []
    unknown_set: list[str] = []
    unreadable = 0
    unrecognized = 0

    for entry in scan.artifacts:
        if entry.kind not in NATIVE_KINDS:
            continue
        candidate = root / entry.path if root is not None else Path(scan.project_path) / entry.path
        if root is not None and not is_inside(root, candidate):
            omissions.append(f"{entry.path}: 路径越出项目边界，拒绝读取")
            continue
        try:
            data = _read_header(candidate)
        except OSError as exc:
            omissions.append(f"{entry.path}: 无法读取（{exc.__class__.__name__}），未解析")
            unreadable += 1
            continue
        if not data:
            omissions.append(f"{entry.path}: 空文件，未解析")
            unreadable += 1
            continue
        profile, error = _profile_artifact(candidate, entry.path, entry.kind, data)
        if profile is None:
            label = "头部解析失败（文件可能截断或损坏）" if error == "header_parse_error" else "无法识别的二进制格式"
            omissions.append(f"{entry.path}: {label}")
            unrecognized += 1
            continue
        profiles.append(profile)

    native_entries = [e for e in scan.artifacts if e.kind in NATIVE_KINDS]

    if not native_entries:
        unknown_set.append("manifest 中无 native 容器类产物；native 结构级暴露面未评估，需构建或提供产物后重扫")
    else:
        if not profiles:
            unknown_set.append("manifest 中 native 产物均无法解析；native 结构级暴露面未评估")
        if unreadable:
            unknown_set.append(f"{unreadable} 个 native 产物无法读取，其结构未知（见 coverage.omissions）")
        if unrecognized:
            unknown_set.append(f"{unrecognized} 个 native 产物格式未识别或头部损坏，其结构未知（见 coverage.omissions）")
    unknown_set.append("Mach-O 的 stack/NX 需解析 load commands，本域未覆盖；RELRO 的 full 判定依赖 dynamic 段，解析失败时按 partial/none 保守报告")
    unknown_set.append(f"{UNPARSED_CONTAINER_NOTE}；目录包（.app/.framework）内容未枚举")

    findings = _build_findings(
        project_path=scan.project_path,
        profiles=tuple(profiles),
        stamp=stamp,
        omissions=tuple(omissions),
        had_native=bool(native_entries),
        had_profiles=bool(profiles),
    )

    if not native_entries:
        state = "not_run"
    elif omissions or not profiles:
        state = "partial"
    else:
        state = "complete_for_scope"

    coverage = {
        "state": state,
        "scope": (
            f"对 manifest 内 {len(native_entries)} 个 native 容器做只读结构解析"
            f"（ELF/PE/Mach-O/ar；每文件 ≤{NATIVE_READ_BYTES} 字节头区）"
        ),
        "omissions": omissions,
    }

    return NativeCheckResult(
        project_path=scan.project_path,
        profiles=tuple(profiles),
        findings=findings,
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


_GAP_LABELS = {
    "executable_stack": ("栈可执行（无 NX）", "high"),
    "no_nx": ("DEP/NX 未启用", "high"),
    "no_pie": ("无 PIE/ASLR（固定加载基址）", "medium"),
    "no_aslr": ("无 ASLR（DYNAMIC_BASE 未置位）", "medium"),
    "no_relro": ("无 RELRO（GOT 可写）", "medium"),
    "unstripped_symbols": ("符号表未剥离", "medium"),
    "no_debug_directory": ("无调试目录（弱信号，仅参考）", "low"),
    "program_headers_truncated": ("program headers 超出读取范围", "medium"),
    "section_headers_truncated": ("section headers 超出读取范围", "medium"),
    "fat_header_not_enumerated": ("fat 架构片未逐一枚举", "low"),
    "archive_members_not_enumerated": ("归档成员未逐一枚举", "low"),
}

_SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _gap_label(gap: str) -> str:
    """Human label for a gap id; unknown ids keep their id (never invent)."""
    return _GAP_LABELS.get(gap, (gap, "medium"))[0]


def _build_findings(
    *,
    project_path: str,
    profiles: tuple[NativeProfile, ...],
    stamp: str,
    omissions: tuple[str, ...],
    had_native: bool,
    had_profiles: bool,
) -> tuple[dict[str, Any], ...]:
    """One aggregated finding, or an explicit unknown when nothing was readable."""
    base_limitations = [
        "只读结构解析；不反汇编、不执行产物",
        UNPARSED_CONTAINER_NOTE,
        "目录包（.app/.framework）内容未枚举",
    ]
    if omissions:
        base_limitations.append(f"{len(omissions)} 处未覆盖（见 coverage.omissions）")

    if not had_native:
        return (
            {
                "id": "native-check-no-input",
                "category": "native_hardening",
                "status": "unknown",
                "severity": "unrated",
                "title": "未发现 native 容器类产物",
                "summary": "manifest 中无 ELF/PE/Mach-O/ar 类产物；native 结构级暴露面未评估（不可用降级：拒绝报告而非假成功）",
                "evidence": [
                    {
                        "evidence_id": "ev-nativecheck-none",
                        "kind": "file_observation",
                        "source": f"pea.nativecheck:{project_path}",
                        "observed_at": stamp,
                        "authority": "observation",
                        "limitations": ["输入清单无 native 容器；未解析任何文件"],
                        "redacted_summary": "manifest 无 native 容器",
                    }
                ],
                "coverage": {"state": "not_run", "scope": "无输入产物"},
                "limitations": [*base_limitations, "未发现不等于不存在；需构建或提供产物后重扫"],
                "recommended_actions": ["构建 release 产物后重扫", "或以外部方式取得产物并更新 manifest"],
                # 未评估的 native 结构面仍属运行期行为层：unknown 不丢序。
                "exposure_tier": TIER_RUNTIME_BEHAVIOR,
            },
        )

    # Native artifacts exist but none could be parsed: reporting "no gaps"
    # here would be the fake pass this domain exists to refuse.
    if not had_profiles:
        return (
            {
                "id": "native-check-unparseable",
                "category": "native_hardening",
                "status": "unknown",
                "severity": "unrated",
                "title": "native 产物均无法完成结构解析",
                "summary": (
                    f"manifest 中存在 native 容器类产物，但 {len(omissions)} 个均未能完成结构解析；"
                    "native 结构级暴露面未评估（不可用降级：拒绝报告而非假成功）"
                ),
                "evidence": [
                    {
                        "evidence_id": "ev-nativecheck-unparseable",
                        "kind": "file_observation",
                        "source": f"pea.nativecheck:{project_path}",
                        "observed_at": stamp,
                        "authority": "observation",
                        "limitations": ["无成功解析的容器；缺口集合未知而非为空"],
                        "redacted_summary": f"{len(omissions)} 个产物未解析（见 coverage.omissions）",
                    }
                ],
                "coverage": {"state": "partial", "scope": "native 容器结构解析（无成功解析的容器）"},
                "limitations": [*base_limitations, "解析失败不等于无缺口；需修复产物可读性后重扫"],
                "recommended_actions": ["确认产物完整且可读后重扫", "核对构建产物在传输或打包环节是否损坏"],
                "exposure_tier": TIER_RUNTIME_BEHAVIOR,
            },
        )

    gap_totals: dict[str, int] = {}
    gap_severity: dict[str, str] = {}
    for profile in profiles:
        for gap in profile.gaps:
            gap_totals[gap] = gap_totals.get(gap, 0) + 1
            severity = _GAP_LABELS.get(gap, ("未命名缺口", "medium"))[1]
            if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER.get(gap_severity.get(gap, "info"), 0):
                gap_severity[gap] = severity

    redacted = "; ".join(
        f"{profile.path}: {profile.format}{'/' + profile.arch if profile.arch else ''} "
        f"[{', '.join(_gap_label(g) for g in profile.gaps) or '未检出结构缺口'}]"
        for profile in profiles
    )

    if not gap_totals:
        evidence = {
            "evidence_id": "ev-nativecheck-clean",
            "kind": "file_observation",
            "source": f"pea.nativecheck:{project_path}",
            "observed_at": stamp,
            "authority": "observation",
            "limitations": ["结构解析只覆盖已识别格式的头部属性", "无缺口不等于加固充分：混淆/虚拟化等 T4 措施不在本域视野"],
            "redacted_summary": redacted,
        }
        return (
            {
                "id": "native-check-no-gaps",
                "category": "native_hardening",
                "status": "observed",
                "severity": "info",
                "title": "未检出已知结构缺口",
                "summary": f"{len(profiles)} 个 native 容器的头部属性未命中已知缺口模式（结构解析，非加固证明）",
                "evidence": [evidence],
                "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "native 容器结构解析"},
                "limitations": [*base_limitations, "未命中不等于不存在：解析维度有限，且不覆盖算法层"],
                "recommended_actions": ["把结构解析纳入发布前检查", "按需引入更深层的二进制分析工具（清单外，人工执行）"],
                "exposure_tier": TIER_RUNTIME_BEHAVIOR,
            },
        )

    top_severity = max(gap_severity.values(), key=lambda s: _SEVERITY_ORDER[s])
    evidence = {
        "evidence_id": "ev-nativecheck-gaps",
        "kind": "file_observation",
        "source": f"pea.nativecheck:{project_path}",
        "observed_at": stamp,
        "authority": "observation",
        "limitations": ["结构解析；缺口为头部属性判定，不含动态验证"],
        "redacted_summary": redacted,
    }
    return (
        {
            "id": "native-check-gaps",
            "category": "native_hardening",
            "status": "observed",
            "severity": top_severity,
            "title": "native 产物存在结构级加固缺口",
            "summary": (
                f"{len(profiles)} 个 native 容器共检出 {len(gap_totals)} 类结构缺口"
                f"（{', '.join(f'{_gap_label(g)}×{c}' for g, c in sorted(gap_totals.items()))}）；"
                "这些属性是攻击者工具最先报告的内容"
            ),
            "evidence": [evidence],
            "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "native 容器结构解析"},
            "limitations": [
                *base_limitations,
                "缺口存在不等于可利用；修复顺序按暴露层由高到低机械决定（pea.tiers）",
            ],
            "recommended_actions": [
                "优先处置 high 级缺口（可执行栈 / 无 NX）",
                "可执行产物启用 PIE 与完整 RELRO，共享库保持 RELRO 检查",
                "发布构建剥离符号表（或迁移调试符号到独立文件）",
                "修复后重扫并以 manifest 指纹更新证据账本基线",
            ],
            "exposure_tier": TIER_RUNTIME_BEHAVIOR,
        },
    )
