"""Unit tests for scripts/check_universal_verifier_sdk.py (bd-nbwo)."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_universal_verifier_sdk.py"

# Load the module via importlib to match the bead spec
spec = importlib.util.spec_from_file_location("check_universal_verifier_sdk", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestVerdict(unittest.TestCase):
    """Test that the overall verdict is PASS."""

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestBeadId(unittest.TestCase):
    """Test that bead_id is correct."""

    def test_bead_id_correct(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-nbwo")


class TestSection(unittest.TestCase):
    """Test that section is correct."""

    def test_section_correct(self):
        result = mod.run_all()
        self.assertEqual(result["section"], "10.17")


class TestNoFailures(unittest.TestCase):
    """Test that there are no failing checks."""

    def test_no_failures(self):
        result = mod.run_all()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestEvents(unittest.TestCase):
    """Test that events are present."""

    def test_events_present(self):
        result = mod.run_all()
        self.assertIn("events", result)
        self.assertIsInstance(result["events"], list)
        self.assertGreater(len(result["events"]), 0)

    def test_event_codes_count(self):
        result = mod.run_all()
        self.assertEqual(len(result["events"]), 7)


class TestAllChecksPass(unittest.TestCase):
    """Test that every individual check passes."""

    def test_all_checks_pass(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertTrue(c["passed"], f"Check failed: {c['check']}: {c['detail']}")


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Commented Rust markers must not satisfy implementation checks."""

    def test_comment_only_rust_markers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            impl_file = tmp_path / "universal_verifier_sdk.rs"
            mod_file = tmp_path / "mod.rs"

            markers = (
                mod.REQUIRED_EVENT_CODES
                + mod.REQUIRED_ERROR_CODES
                + mod.REQUIRED_INVARIANTS
                + mod.CORE_OPERATIONS
                + ["pub struct " + name for name in mod.REQUIRED_TYPES]
                + [
                    "vsdk-v1.0",
                    "BTreeMap",
                    "Serialize",
                    "Deserialize",
                    "pub signature:",
                    "pub schema_version:",
                    "pub sealed:",
                    "pub final_verdict:",
                    "pub expected_output_hash:",
                    "without privileged",
                    "fn build_reference_capsule",
                    "fn build_reference_session",
                    "fn deterministic_hash",
                    "VSDK_SCHEMA_VERSION",
                ]
            )

            impl_file.write_text(
                "\n".join(f"// {marker}" for marker in markers)
                + "\n/*\n"
                + "\n".join("#[test]" for _ in range(30))
                + "\n*/\n",
                encoding="utf-8",
            )
            mod_file.write_text("// pub mod universal_verifier_sdk;\n", encoding="utf-8")

            with (
                patch.object(mod, "IMPL_FILE", impl_file),
                patch.object(mod, "MOD_FILE", mod_file),
            ):
                checks = mod._checks()

        by_name = {check["check"]: check for check in checks}
        self.assertTrue(by_name["Rust module exists"]["passed"])
        self.assertFalse(by_name["Wired into connector/mod.rs"]["passed"])

        rust_marker_prefixes = (
            "Event code ",
            "Error code ",
            "Invariant ",
            "Core operation ",
            "Type ",
        )
        rust_marker_names = [
            check["check"]
            for check in checks
            if check["check"].startswith(rust_marker_prefixes)
            or check["check"]
            in {
                "Schema version vsdk-v1.0",
                "BTreeMap usage for determinism",
                "Serialize/Deserialize derives",
                "ReplayCapsule has signature field",
                "CapsuleManifest has schema_version field",
                "VerificationSession has sealed field",
                "VerificationSession has final_verdict field",
                "CapsuleManifest has expected_output_hash",
                "No-privilege invariant documented",
                "Reference capsule builder exists",
                "Reference session builder exists",
                "Deterministic hash helper",
                "VSDK_SCHEMA_VERSION constant",
            }
            or check["check"].startswith("Rust unit tests")
        ]
        self.assertTrue(rust_marker_names)
        self.assertTrue(all(not by_name[name]["passed"] for name in rust_marker_names))


class TestMinimumCheckCount(unittest.TestCase):
    """Test that there is a minimum number of checks."""

    def test_minimum_checks(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 25)


class TestCheckStructure(unittest.TestCase):
    """Test that each check has the required structure."""

    def test_check_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)
            self.assertIsInstance(c["check"], str)
            self.assertIsInstance(c["passed"], bool)
            self.assertIsInstance(c["detail"], str)


class TestJsonCliOutput(unittest.TestCase):
    """Test that --json CLI output is valid JSON."""

    def test_json_output(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"json CLI failed:\n{proc.stdout}\n{proc.stderr}")
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-nbwo")
        self.assertIn("verdict", parsed)
        self.assertIn("checks", parsed)


class TestSelfTestCliExit(unittest.TestCase):
    """Test that --self-test exits 0."""

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"self-test failed:\n{proc.stdout}\n{proc.stderr}")


class TestMissingEvidenceCausesFail(unittest.TestCase):
    """Test that missing evidence file would cause FAIL verdict."""

    def test_missing_evidence_fails(self):
        original = mod.EVIDENCE_FILE
        mod.EVIDENCE_FILE = ROOT / "artifacts" / "section_10_17" / "bd-nbwo" / "nonexistent.json"
        try:
            result = mod.run_all()
            evidence_checks = [c for c in result["checks"]
                               if "evidence" in c["check"].lower() or "Evidence" in c["check"]]
            self.assertTrue(
                any(not c["passed"] for c in evidence_checks),
                "Missing evidence should cause at least one check failure",
            )
        finally:
            mod.EVIDENCE_FILE = original


class TestResultFields(unittest.TestCase):
    """Test that run_all returns all required fields."""

    def test_required_fields(self):
        result = mod.run_all()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed",
                     "failed", "checks", "events", "summary", "timestamp"]:
            self.assertIn(key, result, f"Missing field: {key}")


class TestSelfTestFunction(unittest.TestCase):
    """Test self_test function directly."""

    def test_self_test_passes(self):
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS",
                         f"self_test failed: {[c for c in result['checks'] if not c['passed']]}")


class TestTitleContent(unittest.TestCase):
    """Test that the title is correctly set."""

    def test_title_matches(self):
        result = mod.run_all()
        self.assertIn("Universal Verifier SDK", result["title"])


if __name__ == "__main__":
    unittest.main()
