"""Unit tests for check_anti_amplification.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_anti_amplification.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-3b8m/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestAntiAmplificationReport(unittest.TestCase):

    def test_report_exists(self):
        path = ROOT / "artifacts/section_10_13/bd-3b8m/anti_amplification_test_results.json"
        self.assertTrue(path.is_file())

    def test_report_valid_json(self):
        path = ROOT / "artifacts/section_10_13/bd-3b8m/anti_amplification_test_results.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(len(data["scenarios"]), 3)

    def test_report_has_block_scenarios(self):
        path = ROOT / "artifacts/section_10_13/bd-3b8m/anti_amplification_test_results.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        verdicts = [s.get("verdict") for s in data["scenarios"]]
        self.assertIn("BLOCK", verdicts)


class TestAntiAmplificationImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/anti_amplification.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_amplification_policy(self):
        self.assertIn("struct AmplificationPolicy", self.content)

    def test_has_response_bound(self):
        self.assertIn("struct ResponseBound", self.content)

    def test_has_bound_check_request(self):
        self.assertIn("struct BoundCheckRequest", self.content)

    def test_has_bound_check_verdict(self):
        self.assertIn("struct BoundCheckVerdict", self.content)

    def test_has_check_function(self):
        self.assertIn("fn check_response_bound", self.content)

    def test_has_harness_function(self):
        self.assertIn("fn run_adversarial_harness", self.content)

    def test_has_all_error_codes(self):
        for code in ["AAR_RESPONSE_TOO_LARGE", "AAR_RATIO_EXCEEDED", "AAR_UNAUTH_LIMIT",
                     "AAR_ITEMS_EXCEEDED", "AAR_INVALID_POLICY"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestAntiAmplificationSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-3b8m_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-AAR-BOUNDED", "INV-AAR-UNAUTH-STRICT",
                    "INV-AAR-AUDITABLE", "INV-AAR-DETERMINISTIC"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["AAR_RESPONSE_TOO_LARGE", "AAR_RATIO_EXCEEDED", "AAR_UNAUTH_LIMIT",
                     "AAR_ITEMS_EXCEEDED", "AAR_INVALID_POLICY"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestAntiAmplificationIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/anti_amplification_harness.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_bounded(self):
        self.assertIn("inv_aar_bounded", self.content)

    def test_covers_unauth_strict(self):
        self.assertIn("inv_aar_unauth_strict", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_aar_auditable", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_aar_deterministic", self.content)


class TestAntiAmplificationCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "anti_amplification_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["AAR-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-3b8m:", result.stdout)

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
