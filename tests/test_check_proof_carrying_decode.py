"""Tests for scripts/check_proof_carrying_decode.py (bd-20uo)."""

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
    "check_proof_carrying_decode",
    ROOT / "scripts" / "check_proof_carrying_decode.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def decode_json_object(payload):
    try:
        decoded = json.JSONDecoder().decode(payload)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"expected valid JSON: {exc}: {payload}") from exc
    if not isinstance(decoded, dict):
        raise AssertionError("expected a JSON object")
    return decoded


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
        self.tmp.write("pub struct Foo;\npub enum Bar;\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_found(self):
        results = mod.check_content(Path(self.tmp.name), ["pub struct Foo"], "type")
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = mod.check_content(Path(self.tmp.name), ["pub struct Baz"], "type")
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


class TestCheckSha256Usage(TestCase):
    def test_sha256(self):
        result = mod.check_sha256_usage()
        self.assertTrue(result["pass"])


class TestCheckGoldenVectors(TestCase):
    def test_golden(self):
        result = mod.check_golden_vectors()
        self.assertTrue(result["pass"])


class TestRunChecks(TestCase):
    def test_full_run(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-20uo")
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
        self.assertGreaterEqual(result["summary"]["total"], 50)

    def test_test_count_field(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["test_count"], 25)

    def test_comment_only_source_markers_fail_closed(self):
        commented_tests = "\n".join(
            f"// #[test]\n// fn {test_name}() {{}}" for test_name in mod.REQUIRED_TESTS
        )
        comment_only_impl = "\n".join(
            [
                *(f"// {marker}" for marker in mod.REQUIRED_TYPES),
                *(f"// {marker}" for marker in mod.REQUIRED_METHODS),
                *(f"// {code}" for code in mod.EVENT_CODES),
                *(f"// {invariant}" for invariant in mod.INVARIANTS),
                "// Serialize Deserialize Sha256",
                "/*",
                commented_tests,
                "*/",
            ]
        )

        original_impl = mod.IMPL
        original_mod = mod.MOD_RS
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            impl_path = tmp / "proof_carrying_decode.rs"
            mod_path = tmp / "mod.rs"
            impl_path.write_text(comment_only_impl, encoding="utf-8")
            mod_path.write_text("pub mod proof_carrying_decode;\n", encoding="utf-8")

            try:
                mod.IMPL = impl_path
                mod.MOD_RS = mod_path
                result = mod.run_checks()
            finally:
                mod.IMPL = original_impl
                mod.MOD_RS = original_mod

        checks = {check["check"]: check["pass"] for check in result["checks"]}
        self.assertTrue(checks["file: implementation"])
        self.assertTrue(checks["module registered in mod.rs"])
        self.assertFalse(checks["unit test count"])
        self.assertFalse(checks["Serialize/Deserialize derives"])
        self.assertFalse(checks["SHA-256 hashing"])
        self.assertEqual(result["test_count"], 0)
        for invariant in mod.INVARIANTS:
            self.assertTrue(checks[f"invariant: {invariant}"], invariant)

        expected_failures = []
        expected_failures.extend(f"type: {marker}" for marker in mod.REQUIRED_TYPES)
        expected_failures.extend(f"method: {marker}" for marker in mod.REQUIRED_METHODS)
        expected_failures.extend(f"event_code: {code}" for code in mod.EVENT_CODES)
        expected_failures.extend(f"test: {test_name}" for test_name in mod.REQUIRED_TESTS)
        for check_name in expected_failures:
            self.assertIn(check_name, checks)
            self.assertFalse(checks[check_name], check_name)


class TestSelfTest(TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)


class TestRequiredConstants(TestCase):
    def test_types_count(self):
        self.assertEqual(len(mod.REQUIRED_TYPES), 11)

    def test_methods_count(self):
        self.assertEqual(len(mod.REQUIRED_METHODS), 5)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 3)

    def test_required_tests_count(self):
        self.assertEqual(len(mod.REQUIRED_TESTS), 35)


class TestJsonOutput(TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        serialized = json.dumps(result)
        parsed = decode_json_object(serialized)
        self.assertEqual(parsed["bead_id"], "bd-20uo")

    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_proof_carrying_decode.py"), "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0)
        data = decode_json_object(result.stdout)
        self.assertEqual(data["verdict"], "PASS")


if __name__ == "__main__":
    main()
