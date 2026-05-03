"""Unit tests for check_crash_loop_detector.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_crash_loop_detector.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-2yc4/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestCrashLoopFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = ROOT / "fixtures/runtime/crash_loop_scenarios.json"
        self.assertTrue(path.is_file())

    def test_fixture_has_cases(self):
        path = ROOT / "fixtures/runtime/crash_loop_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_threshold_case(self):
        path = ROOT / "fixtures/runtime/crash_loop_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        threshold = [c for c in data["cases"] if "threshold" in c.get("id", "")]
        self.assertGreater(len(threshold), 0)

    def test_fixture_has_error_code_cases(self):
        path = ROOT / "fixtures/runtime/crash_loop_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        codes = {c.get("expected_error_code") for c in data["cases"] if c.get("expected_error_code")}
        self.assertIn("CLD_NO_KNOWN_GOOD", codes)
        self.assertIn("CLD_PIN_UNTRUSTED", codes)


class TestCrashLoopBundle(unittest.TestCase):

    def test_bundle_exists(self):
        path = ROOT / "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json"
        self.assertTrue(path.is_file())

    def test_bundle_valid(self):
        path = ROOT / "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("incidents", data)
        self.assertGreaterEqual(len(data["incidents"]), 2)

    def test_bundle_has_rollback_allowed(self):
        path = ROOT / "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        allowed = [i for i in data["incidents"] if i["decision"]["rollback_allowed"]]
        self.assertGreater(len(allowed), 0)

    def test_bundle_has_rollback_denied(self):
        path = ROOT / "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        denied = [i for i in data["incidents"] if not i["decision"]["rollback_allowed"]]
        self.assertGreater(len(denied), 0)


class TestCrashLoopImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/runtime/crash_loop_detector.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_crash_loop_config(self):
        self.assertIn("struct CrashLoopConfig", self.content)

    def test_has_crash_event(self):
        self.assertIn("struct CrashEvent", self.content)

    def test_has_known_good_pin(self):
        self.assertIn("struct KnownGoodPin", self.content)

    def test_has_rollback_decision(self):
        self.assertIn("struct RollbackDecision", self.content)

    def test_has_crash_loop_detector(self):
        self.assertIn("struct CrashLoopDetector", self.content)

    def test_has_evaluate(self):
        self.assertIn("fn evaluate", self.content)

    def test_has_sliding_window(self):
        self.assertIn("crashes_in_window", self.content)

    def test_has_cooldown(self):
        self.assertIn("in_cooldown", self.content)

    def test_has_all_error_codes(self):
        for code in ["CLD_THRESHOLD_EXCEEDED", "CLD_NO_KNOWN_GOOD",
                     "CLD_PIN_UNTRUSTED", "CLD_COOLDOWN_ACTIVE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_incident_type(self):
        self.assertIn("struct CrashLoopIncident", self.content)


class TestCrashLoopSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-2yc4_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-CLD-THRESHOLD", "INV-CLD-ROLLBACK-AUTO",
                    "INV-CLD-TRUST-POLICY", "INV-CLD-AUDIT"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["CLD_THRESHOLD_EXCEEDED", "CLD_NO_KNOWN_GOOD",
                     "CLD_PIN_UNTRUSTED", "CLD_COOLDOWN_ACTIVE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestCrashLoopIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/crash_loop_rollback.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_threshold(self):
        self.assertIn("inv_cld_threshold", self.content)

    def test_covers_rollback(self):
        self.assertIn("inv_cld_rollback", self.content)

    def test_covers_trust(self):
        self.assertIn("inv_cld_trust", self.content)

    def test_covers_audit(self):
        self.assertIn("inv_cld_audit", self.content)


class TestCrashLoopCli(unittest.TestCase):

    def test_json_mode_is_structural_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "crash_loop_detector_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["CLD-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-2yc4:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
