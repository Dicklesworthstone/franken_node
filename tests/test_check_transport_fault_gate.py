"""Unit tests for scripts/check_transport_fault_gate.py (bd-3u6o)."""

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_transport_fault_gate.py"


def run_checker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def decode_json(payload: str) -> dict:
    try:
        decoded = json.JSONDecoder().decode(payload)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"checker did not emit valid JSON: {exc}: {payload}") from exc
    if not isinstance(decoded, dict):
        raise AssertionError("checker JSON output was not an object")
    return decoded


def checker_json(*args: str) -> dict:
    result = run_checker(*args, "--json")
    if result.returncode != 0:
        raise AssertionError(f"checker failed: {result.stdout}{result.stderr}")
    return decode_json(result.stdout)


def _load_checker():
    """Dynamically load the checker module."""
    spec = importlib.util.spec_from_file_location("checker", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSelfTest(TestCase):
    """Verify the self-test mode of the checker script."""

    def test_self_test_passes(self):
        data = checker_json("--self-test")
        self.assertTrue(data["all_passed"])
        self.assertGreater(data["total"], 0)

    def test_self_test_check_counts(self):
        data = checker_json("--self-test")
        self.assertGreaterEqual(data["total"], 14)
        self.assertEqual(data["passed"], data["total"])


class TestJsonOutput(TestCase):
    """Verify JSON output format of the checker."""

    def test_json_mode_output(self):
        data = checker_json()
        self.assertIn("bead_id", data)
        self.assertEqual(data["bead_id"], "bd-3u6o")
        self.assertEqual(data["section"], "10.15")
        self.assertIn("passed", data)
        self.assertIn("total", data)
        self.assertIn("checks", data)
        self.assertIn("verdict", data)
        self.assertIsInstance(data["checks"], list)

    def test_all_checks_have_required_fields(self):
        data = checker_json()
        for check in data["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIsInstance(check["passed"], bool)


class TestCheckerModule(TestCase):
    """Test the checker module's internal functions."""

    def setUp(self):
        self.mod = _load_checker()
        self.mod.ALL_CHECKS.clear()
        self.mod.RESULTS.clear()

    def test_required_types_are_comprehensive(self):
        self.assertGreaterEqual(len(self.mod.REQUIRED_TYPES), 10)
        self.assertIn("pub struct TransportFaultGate", self.mod.REQUIRED_TYPES)
        self.assertIn("pub enum ControlProtocol", self.mod.REQUIRED_TYPES)
        self.assertIn("pub enum FaultMode", self.mod.REQUIRED_TYPES)

    def test_required_event_codes_count(self):
        self.assertEqual(len(self.mod.REQUIRED_EVENT_CODES), 8)
        self.assertIn("TFG-001", self.mod.REQUIRED_EVENT_CODES)
        self.assertIn("TFG-008", self.mod.REQUIRED_EVENT_CODES)

    def test_required_error_codes_count(self):
        self.assertEqual(len(self.mod.REQUIRED_ERROR_CODES), 6)
        self.assertIn("ERR_TFG_INVALID_CONFIG", self.mod.REQUIRED_ERROR_CODES)
        self.assertIn("ERR_TFG_GATE_FAILED", self.mod.REQUIRED_ERROR_CODES)

    def test_required_invariants_count(self):
        self.assertEqual(len(self.mod.REQUIRED_INVARIANTS), 6)
        self.assertIn("INV-TFG-DETERMINISTIC", self.mod.REQUIRED_INVARIANTS)
        self.assertIn("INV-TFG-PARTITION-CLOSED", self.mod.REQUIRED_INVARIANTS)

    def test_required_protocols_count(self):
        self.assertEqual(len(self.mod.REQUIRED_PROTOCOLS), 6)
        self.assertIn("EpochTransition", self.mod.REQUIRED_PROTOCOLS)
        self.assertIn("HealthCheck", self.mod.REQUIRED_PROTOCOLS)

    def test_required_fault_modes_count(self):
        self.assertEqual(len(self.mod.REQUIRED_FAULT_MODES), 4)

    def test_required_functions_count(self):
        self.assertEqual(len(self.mod.REQUIRED_FUNCTIONS), 8)
        self.assertIn("fn run_full_gate", self.mod.REQUIRED_FUNCTIONS)
        self.assertIn("fn test_protocol", self.mod.REQUIRED_FUNCTIONS)

    def test_record_function(self):
        self.mod.record("test_check", True, "detail")
        self.assertEqual(len(self.mod.ALL_CHECKS), 1)
        self.assertTrue(self.mod.ALL_CHECKS[0]["passed"])

    def test_file_contains_positive(self):
        self.assertTrue(self.mod.file_contains(SCRIPT, "bd-3u6o"))

    def test_file_contains_negative(self):
        self.assertFalse(
            self.mod.file_contains(SCRIPT, "DEFINITELY_NOT_IN_FILE_xyzzy")
        )

    def test_file_contains_missing_file(self):
        self.assertFalse(
            self.mod.file_contains(Path("/nonexistent/file.rs"), "anything")
        )

    def test_run_checks_returns_dict(self):
        result = self.mod.run_checks()
        self.assertIsInstance(result, dict)
        self.assertEqual(result["bead_id"], "bd-3u6o")
        self.assertEqual(result["section"], "10.15")
        self.assertIn("verdict", result)
        self.assertIn("checks", result)
        self.assertIn("passed", result)
        self.assertIn("total", result)

    def test_comment_only_impl_markers_fail_closed(self):
        commented_tests = "\n".join(
            f"// #[test]\n// fn commented_transport_test_{idx}() {{}}" for idx in range(18)
        )
        comment_only_impl = "\n".join(
            [
                "// use crate::remote::virtual_transport_faults",
                *(f"// {marker}" for marker in self.mod.REQUIRED_TYPES),
                *(f"// {code}" for code in self.mod.REQUIRED_EVENT_CODES),
                *(f"// {code}" for code in self.mod.REQUIRED_ERROR_CODES),
                *(f"// {inv}" for inv in self.mod.REQUIRED_INVARIANTS),
                *(f"// {proto}" for proto in self.mod.REQUIRED_PROTOCOLS),
                *(f"// {mode}" for mode in self.mod.REQUIRED_FAULT_MODES),
                *(f"// {fn_sig}" for fn_sig in self.mod.REQUIRED_FUNCTIONS),
                '// "tfg-v1.0" "bd-3u6o" "10.15"',
                "// Serialize, Deserialize",
                "/*",
                commented_tests,
                "*/",
            ]
        )

        original_impl = self.mod.IMPL_FILE
        original_mod = self.mod.MOD_FILE
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                impl_path = tmp / "transport_fault_gate.rs"
                mod_path = tmp / "mod.rs"
                impl_path.write_text(comment_only_impl, encoding="utf-8")
                mod_path.write_text("pub mod transport_fault_gate;\n", encoding="utf-8")

                self.mod.IMPL_FILE = impl_path
                self.mod.MOD_FILE = mod_path
                result = self.mod.run_checks()
        finally:
            self.mod.IMPL_FILE = original_impl
            self.mod.MOD_FILE = original_mod

        checks = {check["name"]: check["passed"] for check in result["checks"]}
        self.assertTrue(checks["file_exists:impl_file"])
        self.assertTrue(checks["module_wired"])
        expected_failures = [
            "upstream_import",
            "schema_version",
            "bead_id",
            "bead_section",
            "rust_unit_tests",
            "serde_derives",
        ]
        expected_failures.extend(f"type:{marker}" for marker in self.mod.REQUIRED_TYPES)
        expected_failures.extend(f"event_code:{code}" for code in self.mod.REQUIRED_EVENT_CODES)
        expected_failures.extend(f"error_code:{code}" for code in self.mod.REQUIRED_ERROR_CODES)
        expected_failures.extend(f"invariant_impl:{inv}" for inv in self.mod.REQUIRED_INVARIANTS)
        expected_failures.extend(f"protocol:{proto}" for proto in self.mod.REQUIRED_PROTOCOLS)
        expected_failures.extend(f"fault_mode:{mode}" for mode in self.mod.REQUIRED_FAULT_MODES)
        expected_failures.extend(f"function:{fn_sig}" for fn_sig in self.mod.REQUIRED_FUNCTIONS)

        for check_name in expected_failures:
            self.assertIn(check_name, checks)
            self.assertFalse(checks[check_name], check_name)


class TestVerificationPasses(TestCase):
    """Verify that the checker reports all checks passing."""

    def test_all_checks_pass(self):
        data = checker_json()
        failed = [c for c in data["checks"] if not c["passed"]]
        self.assertEqual(
            len(failed),
            0,
            f"Failed checks: {json.dumps(failed, indent=2)}",
        )

    def test_sufficient_rust_tests(self):
        data = checker_json()
        self.assertGreaterEqual(
            data.get("rust_test_count", 0),
            18,
            "Need at least 18 Rust unit tests",
        )

    def test_verdict_is_pass(self):
        data = checker_json()
        self.assertEqual(data["verdict"], "PASS")


if __name__ == "__main__":
    main()
