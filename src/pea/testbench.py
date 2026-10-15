"""Testbench reconnaissance - the environment layer of the third ring (D7 §3).

The seven project domains answer *what the artifact exposes*. This module
answers the other half of a live-fire exercise: *what environment can the
owner actually attack from*. It is the defensive mirror of the environment the
attacker uses, observed on the owner's own machine.

What it does (pure detection, never installation):

* locates ``adb`` on PATH and lists connected devices (``adb devices -l``);
* enumerates local AVD images (``~/.android/avd/*.ini``) - a filesystem fact,
  no emulator is started;
* probes ``frida-server`` reachability on each connected device;
* detects ``docker`` and any local ``redroid`` image.

What it refuses to do - and this is the point of the domain:

* **it installs nothing.** No SDK, no emulator image, no frida-server. The
  discipline is symmetric with REA's own ("REA never installs the Android SDK,
  an emulator, or a system image"): the user prepares the environment, PEA
  only reports what it found;
* **it never starts anything.** Devices are queried read-only; ``adb root``
  (which restarts adbd) is deliberately *not* executed, so root status is
  reported as unknown rather than provoked;
* **a missing environment is a named UNKNOWN, not a failure.** "No emulator
  connected" is a coverage fact about this run, never evidence that dynamic
  testing passed or that protection works;
* **every probe command is a fixed string.** No model-generated shell, ever;
  each runs with a timeout and a bounded output, and a probe that cannot run
  at all becomes an omission plus an unknown, never a silent zero.

The output mirrors the project domains exactly (``findings + coverage +
unknowns``), so the ledger, the report and the mission-brief generator can
consume it without a second representation.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pea.tiers import TIER_TOOL_EFFICIENCY

# ---------------------------------------------------------------------------
# Environment ladder (T0-T4)
# ---------------------------------------------------------------------------

#: The environment ladder, cheapest reachability first. ``T4`` is an
#: architectural answer (move the surface server-side), never a test gap.
TIER_T0 = "T0"  # pure static analysis - an ordinary computer
TIER_T1 = "T1"  # full desktop permissions - the owner's machine *is* the attacker's
TIER_T2 = "T2"  # rooted emulator (AVD + frida-server ~= 95% of real-device attacks)
TIER_T3 = "T3"  # rooted real device
TIER_T4 = "T4"  # hardware-level (TEE / hardware attestation) - not simulatable

ENVIRONMENT_TIERS: tuple[str, ...] = (TIER_T0, TIER_T1, TIER_T2, TIER_T3, TIER_T4)

#: Probe commands are fixed strings; a probe that cannot run becomes an
#: omission + unknown, never a silent zero.
ADB_PROBE_TIMEOUT_SECONDS = 10
DOCKER_PROBE_TIMEOUT_SECONDS = 10
#: Bounded output for any probe command.
MAX_PROBE_OUTPUT_BYTES = 65_536

#: Serial prefixes that identify an emulator (AVD) versus a real device.
EMULATOR_SERIAL_PREFIXES = ("emulator-", "127.0.0.1:")


@dataclass(frozen=True)
class DeviceObservation:
    """One adb-visible device: identity, connection state, frida reachability.

    ``frida_server_running`` is ``None`` when it could not be determined
    (unauthorized device, missing tooling, probe failure) - unknown, not no.
    """

    serial: str
    state: str
    kind: str  # "emulator" | "real_device" | "unknown"
    frida_server_running: bool | None
    frida_note: str = ""


@dataclass(frozen=True)
class AvdObservation:
    """One locally installed AVD image (filesystem fact; not started)."""

    name: str
    ini_path: str


@dataclass(frozen=True)
class TestbenchResult:
    """Everything observed about the testbench, plus what was not."""

    adb_available: bool
    adb_path: str | None
    devices: tuple[DeviceObservation, ...]
    avds: tuple[AvdObservation, ...]
    docker_available: bool | None
    docker_note: str
    redroid_images: tuple[str, ...]
    reachable_tier: str
    tier_basis: tuple[str, ...]
    findings: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "adb_available": self.adb_available,
            "adb_path": self.adb_path,
            "devices": [
                {
                    "serial": d.serial,
                    "state": d.state,
                    "kind": d.kind,
                    "frida_server_running": d.frida_server_running,
                    "frida_note": d.frida_note,
                }
                for d in self.devices
            ],
            "avds": [{"name": a.name, "ini_path": a.ini_path} for a in self.avds],
            "docker_available": self.docker_available,
            "docker_note": self.docker_note,
            "redroid_images": list(self.redroid_images),
            "reachable_tier": self.reachable_tier,
            "tier_basis": list(self.tier_basis),
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


class TestbenchBoundaryError(ValueError):
    """The testbench observation could not be performed at all."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _run_probe(argv: tuple[str, ...], timeout: int) -> tuple[int, str, str] | None:
    """Run one fixed probe command.

    Returns ``(returncode, bounded_stdout, bounded_stderr)`` or ``None`` when
    the command could not run at all (missing binary, timeout, OS error).
    ``None`` is an omission the caller must record; it is never interpreted as
    a negative result.
    """
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    return (
        proc.returncode,
        (proc.stdout or "")[:MAX_PROBE_OUTPUT_BYTES],
        (proc.stderr or "")[:MAX_PROBE_OUTPUT_BYTES],
    )


def _parse_adb_devices(output: str) -> list[tuple[str, str]]:
    """Parse ``adb devices -l`` into ``(serial, state)`` pairs.

    The first line is a header; malformed lines are skipped - a device that
    cannot be parsed is one that cannot be used, and saying so is better than
    guessing.
    """
    devices: list[tuple[str, str]] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    return devices


def _device_kind(serial: str) -> str:
    lowered = serial.lower()
    if lowered.startswith(EMULATOR_SERIAL_PREFIXES):
        return "emulator"
    if serial.replace(":", "").replace(".", "").isdigit() or ":" in serial:
        return "unknown"  # networked endpoint; emulator or not is not observable here
    return "real_device"


def _probe_frida(adb: str, serial: str, omissions: list[str]) -> tuple[bool | None, str]:
    """Probe frida-server reachability on one device. Read-only query only.

    The probe runs ``pidof frida-server`` on the device. adb reports refusals
    (unauthorized, offline) on *stderr* while ``pidof`` reports "process
    absent" as a non-zero exit with empty output - the two must not be
    confused, so a refusal yields ``None`` (unknown) plus an omission, and
    only a clean empty ``pidof`` result is reported as not-running.
    """
    probe = _run_probe((adb, "-s", serial, "shell", "pidof frida-server"), ADB_PROBE_TIMEOUT_SECONDS)
    if probe is None:
        omissions.append(f"frida-server 探测无法执行（设备 {serial}：命令超时或不可用）")
        return None, "探测命令无法执行"
    code, out, err = probe
    combined = f"{out}\n{err}".lower()
    if code == 0 and out.strip():
        return True, f"frida-server 运行中（pidof 输出 {len(out.split())} 个进程）"
    refusal_markers = ("unauthorized", "offline", "error", "no devices", "permission denied", "not found", "device not found")
    if any(marker in combined for marker in refusal_markers):
        omissions.append(f"frida-server 探测被拒（设备 {serial}：未授权/离线/命令不可用）")
        return None, "设备未授权、离线或命令不可用"
    if code == 0 and not out.strip():
        # Success with no output is not pidof's contract; treat as ambiguous.
        omissions.append(f"frida-server 探测结果不可判定（设备 {serial}：命令成功但无输出）")
        return None, "探测结果不可判定"
    # Clean non-zero exit with empty output: pidof's "process absent" answer.
    return False, "pidof 未发现 frida-server 进程"


def _enumerate_avds() -> tuple[tuple[AvdObservation, ...], list[str]]:
    """List local AVD images from ``~/.android/avd``. Filesystem fact only."""
    omissions: list[str] = []
    avd_dir = Path.home() / ".android" / "avd"
    if not avd_dir.is_dir():
        return (), omissions
    avds: list[AvdObservation] = []
    for ini in sorted(avd_dir.glob("*.ini")):
        try:
            if not ini.is_file():
                continue
        except OSError:
            omissions.append(f"AVD ini 不可读: {ini.name}")
            continue
        avds.append(AvdObservation(name=ini.stem, ini_path=str(ini)))
    return tuple(avds), omissions


def _probe_docker() -> tuple[bool | None, str, tuple[str, ...], list[str]]:
    """Detect docker and local redroid images. Nothing is pulled or started."""
    omissions: list[str] = []
    docker = shutil.which("docker")
    if docker is None:
        return None, "PATH 中无 docker 二进制", (), omissions
    probe = _run_probe((docker, "images", "--format", "{{.Repository}}:{{.Tag}}"), DOCKER_PROBE_TIMEOUT_SECONDS)
    if probe is None:
        omissions.append("docker images 探测超时或失败（daemon 可能未运行）")
        return None, "docker 存在但镜像列表不可读（daemon 状态未知）", (), omissions
    _code, out, _err = probe
    images = tuple(sorted({line.strip() for line in out.splitlines() if line.strip()}))
    redroid = tuple(img for img in images if "redroid" in img.lower())
    return True, f"docker 可用，本地镜像 {len(images)} 个", redroid, omissions


def _derive_reachable_tier(
    *,
    devices: tuple[DeviceObservation, ...],
    avds: tuple[AvdObservation, ...],
    docker_available: bool | None,
    redroid_images: tuple[str, ...],
) -> tuple[str, tuple[str, ...]]:
    """The highest environment tier this testbench can evidence, plus its basis.

    T0 and T1 are *declared* reachable - they are architectural facts (static
    analysis runs anywhere; a desktop target's full permissions live on the
    owner's machine), not observations. T2/T3 require a connected device.
    T4 is never claimed: it is an architectural answer, not a test result.

    The basis strings travel with the verdict so the tier can be re-audited
    without re-running anything.
    """
    basis = [
        "T0 纯静态：一台普通电脑即可（架构事实，非观察）",
        "T1 桌面全权限：桌面/Electron/Python/Lua/JS 目标的动态分析在本机权限对称（架构事实，非观察）",
    ]
    tier = TIER_T1
    online = [d for d in devices if d.state == "device"]
    if online:
        kinds = {d.kind for d in online}
        if "emulator" in kinds:
            tier = TIER_T2
            basis.append("T2 root 模拟器：检测到在线模拟器设备（root/frida 状态见设备注记，未执行 adb root）")
        if "real_device" in kinds:
            tier = TIER_T3
            basis.append("T3 root 真机：检测到在线真机设备（root 状态未探测，记 unknown）")
        if kinds == {"unknown"}:
            tier = TIER_T2 if avds else TIER_T1
            basis.append("检测到在线设备但类型不可判定（网络端点）；已安装 AVD 镜像佐证 T2 可达性")
    elif avds:
        tier = TIER_T2
        basis.append("T2 root 模拟器：本机已安装 AVD 镜像（未启动；启动后 adb 可见即达 T2）")
    elif redroid_images:
        tier = TIER_T2
        basis.append("T2 root 模拟器：检测到本地 redroid 镜像（未启动）")
    elif docker_available:
        basis.append("docker 可用但未见 redroid 镜像与 AVD 镜像；T2 待用户准备")
    else:
        basis.append("未检测到任何移动端执行环境；T2/T3 不可达，动态步骤记 unknown")
    basis.append("T4 硬件级：无法模拟也无需模拟——该层暴露面的答案是服务端迁移（架构答案，非测试缺口）")
    return tier, tuple(basis)


def observe_testbench(*, now: str | None = None) -> TestbenchResult:
    """Observe the local testbench. Detection only: installs nothing, starts nothing.

    ``now`` stamps the evidence records; injecting it keeps outputs
    deterministic under test.
    """
    stamp = now or _utc_now()
    omissions: list[str] = []

    adb = shutil.which("adb")
    adb_available = adb is not None
    devices: list[DeviceObservation] = []
    if adb:
        probe = _run_probe((adb, "devices", "-l"), ADB_PROBE_TIMEOUT_SECONDS)
        if probe is None:
            omissions.append("adb devices 探测超时或失败")
        else:
            _code, out, _err = probe
            for serial, state in _parse_adb_devices(out):
                if state != "device":
                    devices.append(DeviceObservation(serial=serial, state=state, kind=_device_kind(serial), frida_server_running=None, frida_note=f"设备状态 {state}，未探测 frida"))
                    continue
                running, note = _probe_frida(adb, serial, omissions)
                devices.append(DeviceObservation(serial=serial, state=state, kind=_device_kind(serial), frida_server_running=running, frida_note=note))
    else:
        omissions.append("PATH 中未找到 adb；移动端动态环境未检测（不是'不存在'，是未观测）")

    avds, avd_omissions = _enumerate_avds()
    omissions.extend(avd_omissions)
    docker_available, docker_note, redroid_images, docker_omissions = _probe_docker()
    omissions.extend(docker_omissions)

    reachable_tier, tier_basis = _derive_reachable_tier(
        devices=tuple(devices),
        avds=avds,
        docker_available=docker_available,
        redroid_images=redroid_images,
    )

    findings = _build_findings(
        stamp=stamp,
        adb_available=adb_available,
        adb_path=adb,
        devices=tuple(devices),
        avds=avds,
        docker_available=docker_available,
        docker_note=docker_note,
        redroid_images=redroid_images,
        reachable_tier=reachable_tier,
        tier_basis=tier_basis,
        omissions=tuple(omissions),
    )

    unknown_set: list[str] = []
    if not adb_available:
        unknown_set.append("adb 未安装或不在 PATH；移动端动态环境（T2/T3）可达性未知")
    online_devices = [d for d in devices if d.state == "device"]
    for device in online_devices:
        if device.frida_server_running is None:
            unknown_set.append(f"设备 {device.serial} 的 frida-server 状态未知（探测被拒或无法执行）")
        elif not device.frida_server_running:
            unknown_set.append(f"设备 {device.serial} 未检测到运行中的 frida-server；hook 类步骤将不可用（记 unknown 而非通过）")
    if online_devices:
        unknown_set.append("设备 root 状态未探测（不执行 adb root 以避免重启 adbd）；T2/T3 的 root 前提需用户确认")
    unknown_set.append("T4 硬件级暴露面无法在任何测试台模拟；该层结论只能来自服务端架构评审")
    if not avds and not redroid_images:
        unknown_set.append("本机无 AVD/redroid 镜像；若无真机连接，移动端动态演练不可执行")

    coverage = {
        "state": "partial" if omissions or unknown_set else "complete_for_scope",
        "scope": "本机测试台环境侦察（PATH 二进制 + adb 只读查询 + ~/.android/avd 枚举 + docker 镜像列表；不安装、不启动任何组件）",
        "omissions": omissions,
    }

    return TestbenchResult(
        adb_available=adb_available,
        adb_path=adb,
        devices=tuple(devices),
        avds=avds,
        docker_available=docker_available,
        docker_note=docker_note,
        redroid_images=redroid_images,
        reachable_tier=reachable_tier,
        tier_basis=tier_basis,
        findings=findings,
        coverage=coverage,
        unknowns=tuple(unknown_set),
    )


def _evidence(evidence_id: str, source: str, observed_at: str, summary: str) -> dict[str, Any]:
    return {
        "evidence_id": evidence_id,
        "kind": "tool_output",
        "source": source,
        "observed_at": observed_at,
        "authority": "observation",
        "limitations": ["测试台环境侦察；检测而非安装，不覆盖未安装工具的潜在能力"],
        "redacted_summary": summary,
    }


def _build_findings(
    *,
    stamp: str,
    adb_available: bool,
    adb_path: str | None,
    devices: tuple[DeviceObservation, ...],
    avds: tuple[AvdObservation, ...],
    docker_available: bool | None,
    docker_note: str,
    redroid_images: tuple[str, ...],
    reachable_tier: str,
    tier_basis: tuple[str, ...],
    omissions: tuple[str, ...],
) -> tuple[dict[str, Any], ...]:
    """Turn raw observations into exposure-finding-shaped findings."""
    findings: list[dict[str, Any]] = []
    base_limitations = ["测试台环境侦察只覆盖本机已安装/已连接的环境；环境可被用户随时改变"]
    if omissions:
        base_limitations.append(f"{len(omissions)} 处探测未完成（见 coverage.omissions）")

    online = [d for d in devices if d.state == "device"]
    device_summary = (
        "; ".join(
            f"{d.serial}[{d.state}/{d.kind}/frida={d.frida_server_running}]" for d in devices
        )
        or "无"
    )
    findings.append(
        {
            "id": "testbench-environment-tier",
            "category": "testbench_environment",
            "status": "observed",
            "severity": "info",
            "title": "测试台环境分层（本次可执行到 T 几）",
            "summary": f"最高可达环境层: {reachable_tier}；依据: " + " | ".join(tier_basis),
            "evidence": [
                _evidence(
                    "ev-testbench-tier",
                    f"pea.testbench:local (adb={adb_path or 'absent'}, docker={docker_available})",
                    stamp,
                    f"reachable_tier={reachable_tier}; devices={device_summary}; avds={len(avds)}; redroid={len(redroid_images)}",
                )
            ],
            "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "测试台环境侦察"},
            "limitations": base_limitations,
            "recommended_actions": [
                "动态步骤的环境未达层时记 unknown，不得以跳过记为通过",
                "T4 暴露面按架构答案处理：迁移服务端，而非采购设备",
            ],
            # 环境是演练上下文而非产物暴露面：无 exposure_tier（untiered）。
        }
    )

    if adb_available and online:
        frida_ready = [d for d in online if d.frida_server_running]
        findings.append(
            {
                "id": "testbench-mobile-dynamic-available",
                "category": "testbench_environment",
                "status": "observed",
                "severity": "info",
                "title": "移动端动态环境可用",
                "summary": (
                    f"{len(online)} 台在线设备（{device_summary}）；"
                    f"其中 {len(frida_ready)} 台检测到运行中的 frida-server。"
                    "root 状态未探测——不执行 adb root，避免重启 adbd 影响用户环境。"
                ),
                "evidence": [
                    _evidence(
                        "ev-testbench-devices",
                        f"pea.testbench:adb devices -l (adb={adb_path})",
                        stamp,
                        f"online={len(online)}; frida_ready={len(frida_ready)}",
                    )
                ],
                "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "adb 只读查询 + pidof 探测"},
                "limitations": [*base_limitations, "在线≠rooted；root 前提未验证"],
                "recommended_actions": ["确认设备 root 状态后再执行 T2/T3 步骤", "hook 类步骤绑定设备 serial 入账"],
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            }
        )
    else:
        findings.append(
            {
                "id": "testbench-mobile-dynamic-unavailable",
                "category": "testbench_environment",
                "status": "unknown",
                "severity": "unrated",
                "title": "移动端动态环境未就绪",
                "summary": (
                    f"adb={'可用' if adb_available else '不可用'}，在线设备 {len(online)} 台，"
                    f"本地 AVD 镜像 {len(avds)} 个，redroid 镜像 {len(redroid_images)} 个。"
                    "移动端动态步骤（hook/dump/重打包）本次不可执行——记 unknown，不是失败也不是通过。"
                ),
                "evidence": [
                    _evidence(
                        "ev-testbench-no-mobile",
                        f"pea.testbench:local (adb={adb_path or 'absent'}, docker={docker_available})",
                        stamp,
                        f"avds={len(avds)}; redroid={len(redroid_images)}; docker_note={docker_note}",
                    )
                ],
                "coverage": {"state": "partial", "scope": "测试台环境侦察"},
                "limitations": [*base_limitations, "未检测到不等于不可准备；用户装好环境后重跑本域即可"],
                "recommended_actions": [
                    "安装 Android 平台工具并连接/启动 AVD（PEA 不代装）",
                    "或将该次演练的移动端动态步骤显式降级为 unknown 入账",
                ],
                # 未就绪 = 工具放大层尚未评估；保持 tool_efficiency 标注，
                # 让"先修工具层"的顺序在 unknown 状态下也不丢失。
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            }
        )

    return tuple(findings)
