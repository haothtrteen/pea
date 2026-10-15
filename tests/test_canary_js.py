"""WP4 canary 判据（方案 §4.3 八条中可离线钉住的部分）。

canary 是测量载体：测试文件不含明文秘密（差分隔离生产文件）、埋设秘密
恰好命中一种已知模式（基线可复现）、verify_loop 的八条判据逐条在案、
适配器 manifest 记录了实测归因（顶层标识符默认不重命名 → 1→1 是命名
形态残留）。真实闭环（装真实工具、跑 node 子进程）由
``scripts/verify_loop.py`` 单独触发，不进默认 CI。
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANARY = ROOT / "demo" / "canary-js-licensing"
LOOP = ROOT / "scripts" / "verify_loop.py"


class CanaryStructureTests(unittest.TestCase):
    def test_package_uses_node_test_runner(self):
        package = json.loads((CANARY / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["scripts"]["test"], "node --test")
        self.assertTrue(package["name"].startswith("pea-canary-js-licensing"))

    def test_honest_declaration_is_present(self):
        readme = (CANARY / "README.md").read_text(encoding="utf-8")
        self.assertIn("测量载体", readme)
        self.assertNotIn("安全授权实现", readme.replace("不是安全授权实现", ""))
        license_module = (CANARY / "license.js").read_text(encoding="utf-8")
        self.assertIn("PLANTED CANARY", license_module)
        self.assertIn("NOT a security authorization implementation", license_module)

    def test_baseline_tests_contain_no_plaintext_secret(self):
        """The before/after diff must isolate the production file: a secret
        literal in the test file would dilute the measurement."""
        test_source = (CANARY / "license.test.js").read_text(encoding="utf-8")
        self.assertNotIn("sk-canary", test_source)

    def test_planted_secret_matches_exactly_one_known_pattern(self):
        """The baseline must be reproducible: the planted canary hits the
        hardcoded_credential shape and (by construction, hyphenated value)
        not the api_key_literal shape."""
        from pea.secretscan import observe_secrets

        result = observe_secrets(CANARY, now="2026-10-15T00:00:00+00:00")
        observed = [f for f in result.findings if f.get("status") == "observed"]
        self.assertEqual(len(observed), 1, f"基线应恰好 1 个 observed 发现，实际 {len(observed)}")
        self.assertEqual(observed[0]["summary"].count("hardcoded_credential"), 1)

    def test_canary_baseline_tests_pass(self):
        if shutil.which("node") is None:
            self.skipTest("node 不在 PATH 上")
        proc = subprocess.run(["node", "--test"], cwd=str(CANARY), capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout[-400:])


class LoopCriteriaTests(unittest.TestCase):
    def test_verify_loop_declares_all_eight_criteria(self):
        source = LOOP.read_text(encoding="utf-8")
        for name in (
            "original_intact",
            "tool_really_ran",
            "protected_outputs_exist",
            "function_preserved",
            "measurable_effect",
            "overhead_declared",
            "failure_handled_safely",
            "report_reproducible",
        ):
            self.assertIn(f'"{name}"', source, f"八条判据缺 {name}")

    def test_verify_loop_is_not_part_of_default_check(self):
        """与 verify_real 同纪律：集成脚本单独触发。make check 的绿灯不依赖它。"""
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        check_target = re.search(r"^check:.*?(?=\n\S)", makefile, re.S | re.M)
        self.assertIsNotNone(check_target)
        self.assertNotIn("verify_loop", check_target.group(0))

    def test_adapter_manifest_records_the_measured_attribution(self):
        """1→1 的如实测量必须有归因在案（顶层标识符默认不重命名）。"""
        from pea.adapters import manifests

        manifest = manifests()["javascript-obfuscator"]
        attribution = " ".join(manifest["known_limitations"])
        self.assertIn("renameGlobals", attribution)
        self.assertIn("1→1", attribution)


if __name__ == "__main__":
    unittest.main()
