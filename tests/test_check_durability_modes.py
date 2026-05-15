"""Tests for scripts/check_durability_modes.py (bd-18ud)."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_durability_modes",
    ROOT / "scripts" / "check_durability_modes.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCheckFileHelper(TestCase):
    def test_file_exists(self):
        result = mod.check_file(mod.IMPL, "self")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = mod.check_file(ROOT / "nonexistent.rs", "missing")
        self.assertFalse(result["pass"])


class TestCheckContentHelper(TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False)
        self.tmp.write("pub enum DurabilityMode {\n  Local,\n}\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_found(self):
        results = mod.check_content(Path(self.tmp.name), ["pub enum DurabilityMode"], "type")
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = mod.check_content(Path(self.tmp.name), ["pub struct Missing"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = mod.check_content(Path("/nonexistent.rs"), ["x"], "type")
        self.assertFalse(results[0]["pass"])


class TestCheckModuleRegistered(TestCase):
    def test_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTestCount(TestCase):
    def test_real_impl(self):
        result = mod.check_test_count()
        self.assertTrue(result["pass"])


class TestCheckSerdeDerive(TestCase):
    def test_serde(self):
        result = mod.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckClaimMatrixArtifact(TestCase):
    def test_artifact_checks(self):
        results = mod.check_claim_matrix_artifact()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r}")


class TestCheckTwoModes(TestCase):
    def test_modes(self):
        result = mod.check_two_modes()
        self.assertTrue(result["pass"])


class TestCheckFailClosed(TestCase):
    def test_fail_closed(self):
        result = mod.check_fail_closed()
        self.assertTrue(result["pass"])


class TestCheckModeSwitchPolicy(TestCase):
    def test_policy(self):
        result = mod.check_mode_switch_policy()
        self.assertTrue(result["pass"])


class TestCheckClaimDeterminism(TestCase):
    def test_determinism(self):
        result = mod.check_claim_determinism()
        self.assertTrue(result["pass"])


class TestRunChecks(TestCase):
    def test_full_run(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-18ud")
        self.assertEqual(result["section"], "10.14")

    def test_verdict_is_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_pass(self):
        result = mod.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0, f"Failing: {failing}")

    def test_check_count_reasonable(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 80)


class TestSelfTest(TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)


class TestRequiredConstants(TestCase):
    def test_types_count(self):
        self.assertEqual(len(mod.REQUIRED_TYPES), 8)

    def test_methods_count(self):
        self.assertEqual(len(mod.REQUIRED_METHODS), 9)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 7)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.ERROR_CODES), 3)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_required_tests_count(self):
        self.assertEqual(len(mod.REQUIRED_TESTS), 50)


class TestJsonOutput(TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        serialized = json.dumps(result)
        parsed = json.JSONDecoder().decode(serialized)
        self.assertEqual(parsed["bead_id"], "bd-18ud")

    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_durability_modes.py"), "--json"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        data = json.JSONDecoder().decode(result.stdout)
        self.assertEqual(data["verdict"], "PASS")


class TestCommentOnlyRegression(TestCase):
    def test_comment_only_source_markers_fail_closed(self):
        commented_impl = "\n".join(
            [
                *(f"// {marker}" for marker in mod.REQUIRED_TYPES),
                *(f"// {marker}" for marker in mod.REQUIRED_METHODS),
                *(f"// {marker}" for marker in mod.EVENT_CODES),
                *(f"// {marker}" for marker in mod.ERROR_CODES),
                *(f"// {marker}" for marker in mod.INVARIANTS),
                *(f"// {marker}" for marker in mod.REQUIRED_TESTS),
                "// Serialize Deserialize",
                "// Local Quorum min_acks",
                "// ERR_QUORUM_INSUFFICIENT acked >= min_acks",
                "// ModeSwitchPolicy is_authorized",
                "// fn derive( deterministic: true",
                "/*",
                *("// #[test]\n// fn commented_test() {}" for _ in range(40)),
                "*/",
            ]
        )

        original_impl = mod.IMPL
        original_mod = mod.MOD_RS
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            impl_path = tmp / "durability.rs"
            mod_path = tmp / "mod.rs"
            impl_path.write_text(commented_impl, encoding="utf-8")
            mod_path.write_text("// pub mod durability;\n", encoding="utf-8")

            try:
                mod.IMPL = impl_path
                mod.MOD_RS = mod_path
                result = mod.run_checks()
            finally:
                mod.IMPL = original_impl
                mod.MOD_RS = original_mod

        checks = {check["check"]: check["pass"] for check in result["checks"]}
        self.assertTrue(checks["file: implementation"])
        self.assertTrue(checks["file: spec contract"])
        self.assertTrue(checks["file: claim matrix artifact"])
        self.assertTrue(checks["claim matrix artifact exists"])
        self.assertTrue(checks["claim matrix: all deterministic"])

        expected_failures = [
            "module registered in mod.rs",
            "unit test count",
            "Serialize/Deserialize derives",
            "two mode variants",
            "fail-closed quorum semantics",
            "mode switch policy",
            "claim determinism implementation",
        ]
        expected_failures.extend(f"type: {marker}" for marker in mod.REQUIRED_TYPES)
        expected_failures.extend(f"method: {marker}" for marker in mod.REQUIRED_METHODS)
        expected_failures.extend(f"event_code: {marker}" for marker in mod.EVENT_CODES)
        expected_failures.extend(f"error_code: {marker}" for marker in mod.ERROR_CODES)
        expected_failures.extend(f"invariant: {marker}" for marker in mod.INVARIANTS)
        expected_failures.extend(f"test: {marker}" for marker in mod.REQUIRED_TESTS)
        for check_name in expected_failures:
            self.assertIn(check_name, checks)
            self.assertFalse(checks[check_name], check_name)


if __name__ == "__main__":
    main()
