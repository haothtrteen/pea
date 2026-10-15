"""Rebuild the L2 canary *artifacts*: synthetic, marked, byte-rebuildable.

Why synthetic, and why that is honest
------------------------------------
This script emits build-output-shaped files (an APK, an AAB, one
``libapp.so`` per declared ABI, ``libflutter.so``) so the L2 verification
layer has real bytes to read. They are **not** Flutter builds - this
environment has no Flutter SDK - and this script never claims otherwise:

* every binary is written byte-by-byte with ``struct``: the ELF headers are
  real (the native-check domain parses them for real), and the planted
  strings are real bytes that the string/symbol and Dart-AOT domains find
  for real;
* planted markers are the same harmless ones the source canary uses
  (``CANARY-`` prefix, ``*.invalid`` endpoints), so even an accidental leak
  of scan output is harmless;
* running this script rewrites the tree deterministically (fixed zip
  timestamps, no clocks); ``scripts/verify_real.py --digests-only`` asserts
  the checked-in digests match, and drift fails the layer.

What this deliberately does *not* do: produce a real Dart AOT snapshot. The
recovery-rate question ("what does blutter actually recover from this
artifact?") stays ``unknown`` until a real build exists - see
``verify_real.py dart-aot``, which reports that gap instead of faking it.

The libapp.so files are built *unhardened on purpose* (executable stack, no
RELRO, symbol table present): the native-check domain must have something
real to find, and the L2 manifest layer pins the exact bytes.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
#: The synthetic artifacts live in their own fixture tree, separate from the
#: source canary (``demo/canary-flutter-licensing``): the source canary is
#: the honest-degradation walkthrough target and must stay build-output-free,
#: while this tree is the L2 layer's real-bytes material.
ARTIFACTS = ROOT / "demo" / "canary-artifacts"
MANIFEST = ROOT / "demo" / "canary-artifacts.manifest.json"

#: Same harmless planted material as the source canary (build_canary.py).
CANARY_KEY = "CANARY-FAKE-KEY-DO-NOT-USE-0000000000000000"
CANARY_ENDPOINT = "https://license.example-canary.invalid/v1/verify"
DART_VERSION = "3.24.3"

#: The four snapshot anchors tooling uses to find the snapshot in an ELF.
DART_ANCHORS = (
    "_kDartVmSnapshotInstructions",
    "_kDartIsolateSnapshotInstructions",
    "_kDartVmSnapshotData",
    "_kDartIsolateSnapshotData",
)

#: Object-pool shapes planted in the synthetic snapshot (counts only are
#: ever reported; the strings themselves stay in the artifact).
DART_POOL_STRINGS = (
    "LicenseService",
    "LicenseWidget",
    "_LicenseStore",
    "package:flutter_licensing/auth/license_store.dart",
    CANARY_ENDPOINT,
    CANARY_KEY,
)

#: Declared ABIs (mirrors android/app/build.gradle's abiFilters).
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")

# ELF constants (mirrors pea.nativecheck).
ET_DYN = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_DYNAMIC = 2
SHT_SYMTAB = 2
SHT_DYNAMIC = 6
PF_R = 4
DT_FLAGS = 30
DF_BIND_NOW = 0x8

#: Fixed zip timestamp - determinism beats realism here.
ZIP_DATE = (2026, 10, 13, 0, 0, 0)


def _elf(
    *,
    bits: int,
    machine: int,
    endian: str,
    strings: tuple[str, ...],
    stack_flags: int = PF_R,
    relro: bool = False,
    bind_now: bool = False,
    symtab: bool = True,
) -> bytes:
    """A structurally real ELF whose tail carries the planted strings."""
    e = endian
    if bits == 64:
        entries = [PT_GNU_STACK]
        if relro:
            entries.append(PT_GNU_RELRO)
        entries.append(PT_DYNAMIC)
        phoff = 64
        dynoff = phoff + 56 * len(entries)
        dynsize = 32
        shoff = dynoff + dynsize
        shnum = (1 if symtab else 0) + 1
        header = (
            b"\x7fELF"
            + bytes([2, 1 if endian == "<" else 2, 1, 0])
            + b"\x00" * 8
            + struct.pack(e + "HHIQQQIHHHHHH", ET_DYN, machine, 1, 0, phoff, shoff, 0, 64, 56, len(entries), 64, shnum, 0)
        )
        phdrs = b"".join(
            struct.pack(e + "IIQQQQQQ", t, stack_flags if t == PT_GNU_STACK else 6, 0, 0, 0, 0, 0, 1) for t in entries
        )
        dyn = struct.pack(e + "qQ", DT_FLAGS, DF_BIND_NOW if bind_now else 0) + struct.pack(e + "qQ", 0, 0)
        shdrs = b""
        if symtab:
            shdrs += struct.pack(e + "IIQQQQIIQQ", 0, SHT_SYMTAB, 0, 0, 0, 0, 0, 0, 8, 24)
        shdrs += struct.pack(e + "IIQQQQIIQQ", 0, SHT_DYNAMIC, 2, 0, dynoff, dynsize, 0, 0, 8, 16)
    else:
        entries = [PT_GNU_STACK]
        phoff = 52
        shoff = phoff + 32
        header = (
            b"\x7fELF"
            + bytes([1, 1 if endian == "<" else 2, 1, 0])
            + b"\x00" * 8
            + struct.pack(e + "HHIIIIIHHHHHH", ET_DYN, machine, 1, 0, phoff, shoff, 0, 52, 32, 1, 40, 1, 0)
        )
        phdrs = struct.pack(e + "IIIIIIII", PT_GNU_STACK, 0, 0, 0, 0, 0, stack_flags, 1)
        dyn = b""
        shdrs = struct.pack(e + "IIIIIIIIII", 0, SHT_SYMTAB, 0, 0, 0, 0, 0, 0, 8, 24)
    body = b"".join(s.encode() + b"\x00" for s in strings)
    return header + phdrs + dyn + shdrs + body


def _libapp(abi: str) -> bytes:
    """One synthetic libapp.so: unhardened on purpose, markers planted."""
    strings = DART_ANCHORS + DART_POOL_STRINGS
    if abi == "arm64-v8a":
        return _elf(
            bits=64,
            machine=0xB7,
            endian="<",
            strings=strings,
            stack_flags=PF_R | 1,  # executable stack: a real gap for native-check
            relro=False,
            symtab=True,  # symbol table present: another real gap
        )
    if abi == "armeabi-v7a":
        return _elf(bits=32, machine=0x28, endian="<", strings=strings, stack_flags=PF_R | 1, symtab=True)
    return _elf(
        bits=64,
        machine=0x3E,
        endian="<",
        strings=strings,
        stack_flags=PF_R | 1,
        symtab=True,
    )


def _libflutter() -> bytes:
    """The engine, built hardened: the contrast case for native-check."""
    return _elf(
        bits=64,
        machine=0xB7,
        endian="<",
        strings=("Flutter engine", f"Dart {DART_VERSION}", "libflutter"),
        stack_flags=PF_R,
        relro=True,
        bind_now=True,
        symtab=False,
    )


def _zip(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def _apk() -> bytes:
    return _zip(
        (
            ("AndroidManifest.xml", b"<manifest xmlns:android='http://schemas.android.com/apk/res/android'/>\n"),
            ("classes.dex", b"dex\n035\x00" + b"\x00" * 64),
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            ("assets/flutter_assets/AssetManifest.json", b'{"packages":{}}\n'),
        )
    )


def _aab() -> bytes:
    return _zip(
        (
            ("BundleManifest.pb", b"\x0a\x10\x00" + b"\x00" * 32),
            ("base/manifest/AndroidManifest.xml", b"<manifest/>\n"),
            ("base/dex/classes.dex", b"dex\n035\x00" + b"\x00" * 64),
        )
    )


def build(root: Path) -> list[dict[str, object]]:
    """(Re)write the synthetic artifacts under ``root``; return manifest rows.

    ``root`` is a parameter so the drift test can rebuild into a scratch
    directory and compare bytes without touching the checked-in tree.
    """
    root.mkdir(parents=True, exist_ok=True)
    outputs: list[tuple[str, str, bytes]] = []

    merged = "build/app/intermediates/merged_native_libs/release/out/lib"
    for abi in ABIS:
        outputs.append((f"{merged}/{abi}/libapp.so", "flutter_dart_snapshot", _libapp(abi)))
    outputs.append((f"{merged}/arm64-v8a/libflutter.so", "flutter_engine", _libflutter()))
    outputs.append(
        (
            "build/app/outputs/flutter-apk/app-release.apk",
            "android_package",
            _apk(),
        )
    )
    outputs.append(
        (
            "build/app/outputs/bundle/release/app-release.aab",
            "android_app_bundle",
            _aab(),
        )
    )

    rows: list[dict[str, object]] = []
    for rel, kind, data in outputs:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        rows.append(
            {
                "path": rel,
                "kind": kind,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )

    payload = {
        "generated_by": "scripts/build_canary_artifacts.py",
        "note": (
            "Synthetic form-canaries: ELF headers and planted strings are real bytes, "
            "but these are NOT Flutter builds (no Flutter SDK in this environment). "
            "Dart AOT recovery-rate claims stay unknown until a real build exists."
        ),
        "artifacts": rows,
    }
    MANIFEST.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rows


def main() -> int:
    rows = build(ARTIFACTS)
    print(f"canary artifacts rebuilt at {ARTIFACTS} ({len(rows)} files)")
    for row in rows:
        print(f"  {row['path']}  {row['bytes']:>7} bytes  sha256={row['sha256'][:12]}…")
    print(f"manifest: {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
