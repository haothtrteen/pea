"""Native-check domain tests: structural reads, and the refusal discipline.

The binaries here are synthesized byte-by-byte with ``struct`` - no third-party
fixture, no downloaded sample, no executed code. That is deliberate: the
domain's job is header reading, so the fixtures are headers. Each parser has a
happy path and a damage path, because a parser that turns a truncated file
into "no gaps found" is worse than a parser that refuses.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pea.artifactscan import ArtifactEntry, ArtifactScanResult
from pea.nativecheck import NATIVE_KINDS, observe_native
from pea.tiers import TIER_RUNTIME_BEHAVIOR

# ELF constants mirrored from the module under test (kept literal so a
# constant change in the module breaks a test instead of silently passing).
ET_EXEC = 2
ET_DYN = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_DYNAMIC = 2
SHT_SYMTAB = 2
SHT_DYNAMIC = 6
PF_X = 1
PF_R = 4
DT_FLAGS = 30
DF_BIND_NOW = 0x8


def _elf64(
    *,
    e_type: int = ET_DYN,
    machine: int = 0x3E,
    stack_flags: int = PF_R,
    relro: bool = True,
    dynamic: bool = True,
    symtab: bool = False,
    bind_now: bool = True,
) -> bytes:
    """Minimal parseable ELF64: one PT_GNU_STACK plus optional RELRO/dynamic."""
    e = "<"
    entries = [PT_GNU_STACK]
    if relro:
        entries.append(PT_GNU_RELRO)
    if dynamic:
        entries.append(PT_DYNAMIC)
    phoff = 64
    dynoff = phoff + 56 * len(entries)
    dynsize = 32 if dynamic else 0
    shoff = dynoff + dynsize
    shnum = (1 if symtab else 0) + (1 if dynamic else 0)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        e + "HHIQQQIHHHHHH", e_type, machine, 1, 0, phoff, shoff, 0, 64, 56, len(entries), 64, shnum, 0
    )
    phdrs = b"".join(
        struct.pack(e + "IIQQQQQQ", t, stack_flags if t == PT_GNU_STACK else 6, 0, 0, 0, 0, 0, 1) for t in entries
    )
    dyn = b""
    if dynamic:
        dyn = struct.pack(e + "qQ", DT_FLAGS, DF_BIND_NOW if bind_now else 0) + struct.pack(e + "qQ", 0, 0)
    shdrs = b""
    if symtab:
        shdrs += struct.pack(e + "IIQQQQIIQQ", 0, SHT_SYMTAB, 0, 0, 0, 0, 0, 0, 8, 24)
    if dynamic:
        shdrs += struct.pack(e + "IIQQQQIIQQ", 0, SHT_DYNAMIC, 2, 0, dynoff, dynsize, 0, 0, 8, 16)
    return header + phdrs + dyn + shdrs


def _elf32(*, machine: int = 0x28, big: bool = True, stack_flags: int = PF_R) -> bytes:
    """Minimal parseable ELF32 (big-endian ARM by default)."""
    e = ">" if big else "<"
    ident = b"\x7fELF" + bytes([1, 2 if big else 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(e + "HHIIIIIHHHHHH", ET_DYN, machine, 1, 0, 52, 84, 0, 52, 32, 1, 40, 1, 0)
    phdr = struct.pack(e + "IIIIIIII", PT_GNU_STACK, 0, 0, 0, 0, 0, stack_flags, 1)
    shdr = struct.pack(e + "IIIIIIIIII", 0, SHT_SYMTAB, 0, 0, 0, 0, 0, 0, 8, 24)
    return header + phdr + shdr


def _macho(*, magic: int = 0xFEEDFACF, cputype: int = 0x0100000C, filetype: int = 6, flags: int = 0) -> bytes:
    """Mach-O header; the magic is packed so the file byte order matches."""
    e = "<" if magic in (0xFEEDFACF, 0xFEEDFACE) else ">"
    return struct.pack(e + "IIIIIIII", magic, cputype, 0, filetype, 0, 0, flags, 0)


def _pe(*, dllchars: int = 0x0140, debug_size: int = 0, pe32plus: bool = True) -> bytes:
    """Minimal parseable PE: MZ -> PE signature -> COFF -> optional header."""
    size_opt = 240
    lfanew = 0x40
    head = bytearray(b"MZ" + b"\x00" * (lfanew - 2))
    struct.pack_into("<I", head, 0x3C, lfanew)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, size_opt, 0x0002)
    opt = bytearray(size_opt)
    struct.pack_into("<H", opt, 0, 0x20B if pe32plus else 0x10B)
    struct.pack_into("<H", opt, 70, dllchars)
    struct.pack_into("<II", opt, 112 + 6 * 8, 0x1000, debug_size)
    return bytes(head) + b"PE\x00\x00" + coff + bytes(opt)


def _manifest(root: Path, entries: tuple[str, str], project_path: str | None = None) -> ArtifactScanResult:
    """Build a manifest result directly: this domain consumes a manifest, it
    does not walk a tree, so the fixture is the manifest itself."""
    artifacts = tuple(
        ArtifactEntry(path=rel, kind=kind, size_bytes=0, sha256=None) for rel, kind in entries
    )
    return ArtifactScanResult(
        project_path=project_path or str(root),
        artifacts=artifacts,
        findings=(),
        coverage={"state": "complete_for_scope", "scope": "test fixture", "omissions": []},
        unknowns=(),
    )


def _write(root: Path, rel: str, data: bytes) -> str:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return rel


# --------------------------------------------------------------------------
# happy paths: one per format
# --------------------------------------------------------------------------


def test_hardened_elf64_reports_full_relro_and_no_gaps(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/arm64-v8a/libapp.so", _elf64())

    result = observe_native(_manifest(project, (("lib/arm64-v8a/libapp.so", "native_shared_library"),)))

    profile = result.profiles[0]
    assert profile.format == "elf"
    assert (profile.bits, profile.endian, profile.arch) == (64, "little", "x86-64")
    assert profile.role == "shared_library"
    assert profile.nx is True  # stack is RW, not RX
    assert profile.pie is True  # ET_DYN
    assert profile.relro == "full"  # GNU_RELRO + DF_BIND_NOW
    assert profile.stripped is True  # no SHT_SYMTAB
    assert profile.gaps == ()
    assert result.findings[0]["id"] == "native-check-no-gaps"
    assert result.coverage["state"] == "complete_for_scope"


def test_executable_elf_with_rwx_stack_and_symtab_reports_high_severity(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project,
        "bin/tool",
        _elf64(e_type=ET_EXEC, stack_flags=PF_R | PF_X, relro=False, dynamic=False, symtab=True),
    )

    result = observe_native(_manifest(project, (("bin/tool", "native_executable"),)))

    profile = result.profiles[0]
    assert profile.role == "executable"
    assert profile.nx is False
    assert profile.pie is False
    assert profile.stripped is False
    assert set(profile.gaps) == {"executable_stack", "no_relro", "no_pie", "unstripped_symbols"}
    finding = result.findings[0]
    assert finding["id"] == "native-check-gaps"
    assert finding["severity"] == "high"  # executable stack dominates
    assert finding["status"] == "observed"


def test_elf_relro_without_bind_now_is_partial_not_full(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/x86/libnative.so", _elf64(bind_now=False))

    result = observe_native(_manifest(project, (("lib/x86/libnative.so", "native_shared_library"),)))

    assert result.profiles[0].relro == "partial"


def test_elf32_big_endian_arm_is_identified(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libnative.so", _elf32())

    result = observe_native(_manifest(project, (("lib/libnative.so", "native_shared_library"),)))

    profile = result.profiles[0]
    assert (profile.bits, profile.endian, profile.arch) == (32, "big", "arm")


def test_elf32_executable_stack_is_a_gap(tmp_path):
    """ELF32 program headers put p_flags at offset 24, not 4 - the L2 layer
    caught that confusion on real bytes, so it gets its own test."""
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libnative.so", _elf32(stack_flags=PF_R | PF_X))

    result = observe_native(_manifest(project, (("lib/libnative.so", "native_shared_library"),)))

    profile = result.profiles[0]
    assert profile.nx is False
    assert "executable_stack" in profile.gaps
    assert result.findings[0]["severity"] == "high"


def test_pe_with_aslr_and_nx_reports_no_gaps(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "Release/App.exe", _pe(dllchars=0x0140, debug_size=64))

    result = observe_native(_manifest(project, (("Release/App.exe", "native_executable"),)))

    profile = result.profiles[0]
    assert profile.format == "pe"
    assert (profile.bits, profile.arch) == (64, "x86-64")
    assert profile.nx is True and profile.pie is True
    assert profile.gaps == ()


def test_pe_without_dllcharacteristics_reports_aslr_and_nx_gaps(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "Release/App.exe", _pe(dllchars=0, debug_size=0))

    result = observe_native(_manifest(project, (("Release/App.exe", "native_executable"),)))

    gaps = set(result.profiles[0].gaps)
    assert {"no_aslr", "no_nx", "no_debug_directory"} <= gaps
    assert result.findings[0]["severity"] == "high"


def test_macho_dylib_with_pie_is_profiled(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libnative.dylib", _macho(filetype=6, flags=0))

    result = observe_native(_manifest(project, (("lib/libnative.dylib", "native_shared_library"),)))

    profile = result.profiles[0]
    assert profile.format == "macho"
    assert (profile.bits, profile.arch) == (64, "arm64")
    assert profile.role == "shared_library"


def test_macho_executable_without_pie_is_a_gap(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "bin/app", _macho(filetype=2, flags=0))

    result = observe_native(_manifest(project, (("bin/app", "native_executable"),)))

    profile = result.profiles[0]
    assert profile.role == "executable"
    assert profile.pie is False
    assert "no_pie" in profile.gaps


def test_fat_macho_declares_unenumerated_slices(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "bin/universal", struct.pack(">II", 0xCAFEBABE, 2) + b"\x00" * 64)

    result = observe_native(_manifest(project, (("bin/universal", "native_executable"),)))

    profile = result.profiles[0]
    assert profile.format == "macho_fat"
    assert "fat_header_not_enumerated" in profile.gaps


def test_static_archive_is_recognized_without_member_enumeration(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libfoo.a", b"!<arch>\n" + b"\x00" * 60)

    result = observe_native(_manifest(project, (("lib/libfoo.a", "native_static_library"),)))

    profile = result.profiles[0]
    assert profile.format == "ar"
    assert profile.role == "static_archive"
    assert "archive_members_not_enumerated" in profile.gaps


# --------------------------------------------------------------------------
# degradation paths: refusal, never a fake pass
# --------------------------------------------------------------------------


def test_empty_manifest_is_unknown_not_pass(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = observe_native(_manifest(project, ()))

    finding = result.findings[0]
    assert finding["id"] == "native-check-no-input"
    assert finding["status"] == "unknown"
    assert result.coverage["state"] == "not_run"
    # unknown 不丢序：未评估的 native 面仍标注运行期行为层。
    assert finding["exposure_tier"] == TIER_RUNTIME_BEHAVIOR
    assert any("未评估" in u for u in result.unknowns)


def test_manifest_without_native_kinds_is_unknown(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "app.apk", b"PK\x03\x04" + b"\x00" * 100)
    _write(project, "main.pyc", b"\x61\x0d\x0d\x0a" + b"\x00" * 100)

    result = observe_native(
        _manifest(project, (("app.apk", "android_package"), ("main.pyc", "python_bytecode")))
    )

    assert result.findings[0]["status"] == "unknown"
    assert result.coverage["state"] == "not_run"
    assert result.profiles == ()


def test_unrecognized_binary_is_an_omission_and_unknown(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libmystery.so", b"NOTABINARY\x00" + b"\x01" * 200)

    result = observe_native(_manifest(project, (("lib/libmystery.so", "native_shared_library"),)))

    assert result.profiles == ()
    assert any("无法识别" in o for o in result.coverage["omissions"])
    assert result.coverage["state"] == "partial"
    assert result.findings[0]["status"] == "unknown"
    assert any("格式未识别" in u for u in result.unknowns)


def test_truncated_elf_is_damage_not_unrecognized(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    # Claims ELF, then stops - a truncated header, not a mystery format.
    _write(project, "lib/libcut.so", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 14)

    result = observe_native(_manifest(project, (("lib/libcut.so", "native_shared_library"),)))

    assert any("截断或损坏" in o for o in result.coverage["omissions"])


def test_unreadable_artifact_is_an_omission(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    # A manifest entry whose file is gone is the strongest failure case:
    # chmod-based unreadability does not hold when tests run as root.
    rel = "lib/libmissing.so"

    result = observe_native(_manifest(project, ((rel, "native_shared_library"),)))

    assert any("无法读取" in o for o in result.coverage["omissions"])
    assert result.coverage["state"] == "partial"
    assert any("无法读取" in u for u in result.unknowns)


def test_empty_file_is_not_a_profile(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libempty.so", b"")

    result = observe_native(_manifest(project, (("lib/libempty.so", "native_shared_library"),)))

    assert result.profiles == ()
    assert any("空文件" in o for o in result.coverage["omissions"])


def test_manifest_entry_outside_root_is_refused(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "libapp.so", _elf64())

    result = observe_native(_manifest(project, (("../outside/libapp.so", "native_shared_library"),)))

    assert result.profiles == ()
    assert any("越出项目边界" in o for o in result.coverage["omissions"])


def test_mixed_success_and_failure_is_partial_coverage(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libgood.so", _elf64())
    _write(project, "lib/libbad.so", b"\x00" * 200)

    result = observe_native(
        _manifest(
            project,
            (("lib/libgood.so", "native_shared_library"), ("lib/libbad.so", "native_shared_library")),
        )
    )

    assert len(result.profiles) == 1
    assert result.coverage["state"] == "partial"
    assert result.findings[0]["coverage"]["state"] == "partial"


# --------------------------------------------------------------------------
# contract surface
# --------------------------------------------------------------------------


def test_finding_carries_runtime_tier_and_unparsed_container_note(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libapp.so", _elf64(symtab=True))

    result = observe_native(_manifest(project, (("lib/libapp.so", "native_shared_library"),)))

    finding = result.findings[0]
    assert finding["exposure_tier"] == TIER_RUNTIME_BEHAVIOR
    limitations = " ".join(finding["limitations"])
    assert "apk/aab/jar" in limitations
    # 结构解析不代表可执行验证
    assert any("不执行" in item for item in finding["limitations"])


def test_result_is_json_serializable(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "lib/libapp.so", _elf64())

    result = observe_native(_manifest(project, (("lib/libapp.so", "native_shared_library"),)))

    payload = result.to_dict()
    assert payload["profiles"][0]["format"] == "elf"
    assert isinstance(payload["findings"][0]["evidence"][0]["observed_at"], str)
    assert payload["coverage"]["state"] == "complete_for_scope"


def test_native_kinds_cover_the_shipped_binary_forms():
    for kind in ("native_shared_library", "native_executable", "node_native_addon", "flutter_dart_snapshot"):
        assert kind in NATIVE_KINDS
    # 容器与字节码不属于结构解析范围
    for kind in ("android_package", "python_bytecode", "electron_asar_archive"):
        assert kind not in NATIVE_KINDS


@pytest.mark.parametrize("kind", sorted(NATIVE_KINDS))
def test_every_native_kind_is_parsed_when_format_matches(tmp_path, kind):
    project = tmp_path / "project"
    project.mkdir()
    _write(project, "bin/artifact", _elf64())

    result = observe_native(_manifest(project, (("bin/artifact", kind),)))

    assert len(result.profiles) == 1
    assert result.profiles[0].kind == kind
