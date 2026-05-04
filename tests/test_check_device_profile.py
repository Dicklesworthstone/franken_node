"""Unit tests for check_device_profile.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts import check_device_profile

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_device_profile.py"
FIXTURES_PATH = ROOT / "artifacts/section_10_13/bd-8vby/device_profile_examples.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-8vby/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestDeviceProfileFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        self.assertTrue(FIXTURES_PATH.is_file())

    def test_fixtures_valid(self):
        data = decode_json_object(FIXTURES_PATH.read_text(encoding="utf-8"))
        self.assertIn("profiles", data)
        self.assertGreaterEqual(len(data["profiles"]), 3)

    def test_fixtures_have_policies(self):
        data = decode_json_object(FIXTURES_PATH.read_text(encoding="utf-8"))
        self.assertIn("policies", data)
        self.assertGreaterEqual(len(data["policies"]), 3)


class TestDeviceProfileImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/device_profile.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_device_profile(self):
        self.assertIn("struct DeviceProfile", self.content)

    def test_has_placement_constraint(self):
        self.assertIn("struct PlacementConstraint", self.content)

    def test_has_placement_policy(self):
        self.assertIn("struct PlacementPolicy", self.content)

    def test_has_placement_result(self):
        self.assertIn("struct PlacementResult", self.content)

    def test_has_device_profile_registry(self):
        self.assertIn("struct DeviceProfileRegistry", self.content)

    def test_has_validate_profile(self):
        self.assertIn("fn validate_profile", self.content)

    def test_has_evaluate_placement(self):
        self.assertIn("fn evaluate_placement", self.content)

    def test_has_all_error_codes(self):
        for code in ["DPR_SCHEMA_INVALID", "DPR_STALE_PROFILE",
                     "DPR_INVALID_CONSTRAINT", "DPR_NO_MATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestDeviceProfileSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-8vby_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-DPR-SCHEMA", "INV-DPR-FRESHNESS",
                    "INV-DPR-DETERMINISTIC", "INV-DPR-REJECT-INVALID"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["DPR_SCHEMA_INVALID", "DPR_STALE_PROFILE",
                     "DPR_INVALID_CONSTRAINT", "DPR_NO_MATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestDeviceProfileConformance(unittest.TestCase):

    def setUp(self):
        self.conf_path = ROOT / "tests/conformance/placement_policy_schema.rs"
        self.assertTrue(self.conf_path.is_file())
        self.content = self.conf_path.read_text(encoding="utf-8")

    def test_covers_schema(self):
        self.assertIn("inv_dpr_schema", self.content)

    def test_covers_freshness(self):
        self.assertIn("inv_dpr_freshness", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_dpr_deterministic", self.content)

    def test_covers_reject_invalid(self):
        self.assertIn("inv_dpr_reject_invalid", self.content)


class TestDeviceProfileCli(unittest.TestCase):

    def test_json_mode_requests_full_proof_by_default(self):
        args = check_device_profile.parse_args(["--json"])

        self.assertTrue(check_device_profile.should_run_rust_tests(args))

    def test_structural_json_mode_is_partial_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "device_profile_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        self.assertEqual(statuses["DPR-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("bd-8vby:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(before, after)

    def test_skipped_structural_verdict_is_partial(self):
        self.assertEqual(
            check_device_profile.compute_verdict(failing=0, skipped=1, mode="structural"),
            "PARTIAL",
        )
        self.assertEqual(
            check_device_profile.compute_verdict(failing=0, skipped=1, mode="full"),
            "FAIL",
        )


if __name__ == "__main__":
    unittest.main()
