"""Testbench reconnaissance domain tests.

The CI machine has no adb and no docker, which is exactly the "environment
missing" case the domain must report honestly - so the default-path tests run
unpatched. Device/tier behaviour is exercised through patched probes, the same
way the other domains test bounded observations.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from pea.testbench import (
    ENVIRONMENT_TIERS,
    TIER_T1,
    TIER_T2,
    TIER_T3,
    AvdObservation,
    DeviceObservation,
    _derive_reachable_tier,
    _device_kind,
    _parse_adb_devices,
    observe_testbench,
)

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"


def _finding_validator() -> Draft202012Validator:
    """The same registry construction the other domain tests use: the
    ``evidence`` items are a relative ``$ref`` into the schemas directory, so
    a bare validator would try to fetch it over the network."""
    resources = [
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012))
        for schema in (
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
        )
        if "$id" in schema
    ]
    registry = Registry().with_resources(resources)
    schema = json.loads((SCHEMA_DIR / "exposure-finding.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=registry)
STAMP = "2026-10-14T00:00:00+00:00"


@pytest.fixture()
def sandbox_home(tmp_path, monkeypatch):
    """A home without AVD images, so avd enumeration is deterministic."""
    fake_home = tmp_path / "home"
    (fake_home / ".android").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    return fake_home


# ---------------------------------------------------------------------------
# Parsing / classification helpers
# ---------------------------------------------------------------------------


def test_parse_adb_devices_skips_header_and_malformed_lines():
    output = "List of devices attached\nemulator-5554          device product:sdk\n192.168.0.9:5555       offline\n\nbroken-line\n"
    assert _parse_adb_devices(output) == [("emulator-5554", "device"), ("192.168.0.9:5555", "offline")]


def test_device_kind_classifies_emulator_and_real():
    assert _device_kind("emulator-5554") == "emulator"
    assert _device_kind("127.0.0.1:5555") == "emulator"
    assert _device_kind("R5CT90ABCDE") == "real_device"
    assert _device_kind("10.0.0.7:5555") == "unknown"


# ---------------------------------------------------------------------------
# Tier derivation
# ---------------------------------------------------------------------------


def test_tiers_are_a_declared_ladder():
    assert ENVIRONMENT_TIERS == ("T0", "T1", "T2", "T3", "T4")


def test_no_mobile_environment_never_claims_above_t1():
    tier, basis = _derive_reachable_tier(devices=(), avds=(), docker_available=None, redroid_images=())
    assert tier == TIER_T1
    assert any("T4" in line and "架构答案" in line for line in basis)


def test_emulator_device_reaches_t2_without_provoking_root():
    devices = (DeviceObservation(serial="emulator-5554", state="device", kind="emulator", frida_server_running=None),)
    tier, basis = _derive_reachable_tier(devices=devices, avds=(), docker_available=True, redroid_images=())
    assert tier == TIER_T2
    assert any("未执行 adb root" in line for line in basis)


def test_real_device_reaches_t3():
    devices = (DeviceObservation(serial="R5CT90ABCDE", state="device", kind="real_device", frida_server_running=True),)
    tier, _basis = _derive_reachable_tier(devices=devices, avds=(), docker_available=True, redroid_images=())
    assert tier == TIER_T3


def test_avd_images_alone_evidence_t2_without_starting_anything():
    tier, basis = _derive_reachable_tier(
        devices=(), avds=(AvdObservation(name="Pixel_6_API_34", ini_path="/x.ini"),), docker_available=None, redroid_images=()
    )
    assert tier == TIER_T2
    assert any("未启动" in line for line in basis)


def test_t4_is_never_claimed():
    """No input combination may reach T4: it is an architectural answer."""
    devices = (DeviceObservation(serial="R5CT90ABCDE", state="device", kind="real_device", frida_server_running=True),)
    tier, _basis = _derive_reachable_tier(devices=devices, avds=(), docker_available=True, redroid_images=("redroid/redroid:12",))
    assert tier == TIER_T3


# ---------------------------------------------------------------------------
# Full observation on a bare machine (the CI path)
# ---------------------------------------------------------------------------


def test_bare_machine_observation_is_honest_unknown(sandbox_home):
    result = observe_testbench(now=STAMP)
    payload = result.to_dict()
    # findings validate against the exposure-finding contract
    validator = _finding_validator()
    for finding in result.findings:
        errors = list(validator.iter_errors(finding))
        assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
    # a missing mobile environment is unknown, never a pass and never a fail
    assert result.reachable_tier in {TIER_T1, TIER_T2, TIER_T3}
    assert payload["unknowns"], "a bare testbench must declare unknowns"
    assert any("adb" in u for u in payload["unknowns"])
    assert payload["coverage"]["state"] == "partial"
    assert payload["coverage"]["omissions"]


def test_findings_declare_untiered_context_and_missing_tool_tier(sandbox_home):
    result = observe_testbench(now=STAMP)
    by_id = {f["id"]: f for f in result.findings}
    assert set(by_id) == {"testbench-environment-tier", "testbench-mobile-dynamic-unavailable"}
    # the tier finding is context: no exposure_tier claim
    assert "exposure_tier" not in by_id["testbench-environment-tier"]
    # the unavailable-mobile finding keeps the tool-efficiency tier so repair
    # order survives an unknown state
    assert by_id["testbench-mobile-dynamic-unavailable"]["exposure_tier"] == "tool_efficiency"
    assert by_id["testbench-mobile-dynamic-unavailable"]["status"] == "unknown"


# ---------------------------------------------------------------------------
# Patched probes: adb present with devices
# ---------------------------------------------------------------------------


def _fake_probe_factory(adb_output: str, frida_outputs: dict[str, tuple[int, str]] | None = None):
    frida_outputs = frida_outputs or {}

    def fake_run(argv, timeout=None, check=False, capture_output=False, text=False):
        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        proc = Proc()
        if argv[1] == "devices":
            proc.stdout = adb_output
        elif argv[1] == "-s":
            proc.returncode, proc.stdout = frida_outputs.get(argv[2], (1, ""))
        else:
            proc.returncode = 1
        return proc

    return fake_run


def test_online_emulator_with_frida_reports_t2_and_evidence(monkeypatch, sandbox_home):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/adb" if name == "adb" else None)
    monkeypatch.setattr(
        "subprocess.run",
        _fake_probe_factory(
            "List of devices attached\nemulator-5554          device product:sdk_gphone64\n",
            {"emulator-5554": (0, "1234\n")},
        ),
    )
    result = observe_testbench(now=STAMP)
    payload = result.to_dict()
    assert payload["adb_available"] is True
    assert payload["devices"][0]["frida_server_running"] is True
    assert result.reachable_tier == TIER_T2
    by_id = {f["id"]: f for f in result.findings}
    assert "testbench-mobile-dynamic-available" in by_id
    assert payload["coverage"]["state"] == "partial"  # root status is still unknown


def test_frida_probe_refusal_is_unknown_not_false(monkeypatch, sandbox_home):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/adb" if name == "adb" else None)

    def refusing_run(argv, timeout=None, check=False, capture_output=False, text=False):
        class Proc:
            returncode = 0
            stdout = "List of devices attached\nemulator-5554          device product:sdk\n"
            stderr = ""

        proc = Proc()
        if argv[1] == "-s":
            # the device answers adb, but refuses the shell probe (unauthorized)
            proc.returncode = 1
            proc.stdout = ""
            proc.stderr = "error: device unauthorized\n"
        return proc

    monkeypatch.setattr("subprocess.run", refusing_run)
    result = observe_testbench(now=STAMP)
    device = result.devices[0]
    assert device.frida_server_running is None, "an unauthorized device is unknown, not frida-absent"
    assert any("frida-server 状态未知" in u for u in result.unknowns)
    assert any("frida-server 探测被拒" in o for o in result.coverage["omissions"])


def test_offline_device_is_not_online(monkeypatch, sandbox_home):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/adb" if name == "adb" else None)
    monkeypatch.setattr(
        "subprocess.run",
        _fake_probe_factory("List of devices attached\nemulator-5554          offline\n"),
    )
    result = observe_testbench(now=STAMP)
    assert result.devices[0].state == "offline"
    assert result.devices[0].frida_server_running is None
    assert any("未检测到运行中的 frida-server" not in u for u in result.unknowns)


def test_avd_enumeration_reads_ini_files(monkeypatch, sandbox_home):
    avd_dir = sandbox_home / ".android" / "avd"
    avd_dir.mkdir(parents=True)
    (avd_dir / "Pixel_6_API_34.ini").write_text("avd.ini.displayname=Pixel 6\n", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = observe_testbench(now=STAMP)
    assert [a.name for a in result.avds] == ["Pixel_6_API_34"]
    assert result.reachable_tier == TIER_T2


def test_docker_probe_failure_is_omission_not_absence(monkeypatch, sandbox_home):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker" if name == "docker" else None)

    def timing_out_run(argv, timeout=None, check=False, capture_output=False, text=False):
        raise TimeoutError()

    monkeypatch.setattr("subprocess.run", timing_out_run)
    result = observe_testbench(now=STAMP)
    assert result.docker_available is None
    assert any("docker images 探测超时" in o for o in result.coverage["omissions"])


def test_redroid_images_are_detected_without_pulling(monkeypatch, sandbox_home):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker" if name == "docker" else None)

    def fake_run(argv, timeout=None, check=False, capture_output=False, text=False):
        class Proc:
            returncode = 0
            stdout = "redroid/redroid:12.0-64bit\nubuntu:22.04\n"
            stderr = ""

        return Proc()

    monkeypatch.setattr("subprocess.run", fake_run)
    result = observe_testbench(now=STAMP)
    assert result.docker_available is True
    assert result.redroid_images == ("redroid/redroid:12.0-64bit",)
    assert result.reachable_tier == TIER_T2


def test_evidence_records_carry_no_device_secrets(sandbox_home):
    """Declared-redaction discipline: every finding's evidence carries a
    ``redacted_summary``; the raw probe output is never the summary itself."""
    result = observe_testbench(now=STAMP)
    for finding in result.findings:
        for record in finding["evidence"]:
            assert record.get("redacted_summary"), f"{finding['id']}: evidence without a declared redacted summary"
            assert record["authority"] == "observation"


def test_online_frida_output_is_counted_not_copied(monkeypatch, sandbox_home):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/adb" if name == "adb" else None)
    monkeypatch.setattr(
        "subprocess.run",
        _fake_probe_factory(
            "List of devices attached\nemulator-5554          device product:sdk\n",
            {"emulator-5554": (0, "1234\n")},
        ),
    )
    result = observe_testbench(now=STAMP)
    blob = json.dumps(result.to_dict(), ensure_ascii=False)
    assert "frida-server 运行中" in blob
    assert "1234" not in blob, "raw pidof output must not be copied into the result"
