"""Unit tests for check_conformance_profile.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestProfileReport(unittest.TestCase):

    def test_report_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-ck2h/profile_claim_report.json")
        self.assertTrue(os.path.isfile(path))

    def test_report_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-ck2h/profile_claim_report.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("profiles", data)
        self.assertIn("MVP", data["profiles"])
        self.assertIn("Full", data["profiles"])

    def test_report_has_evaluation(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-ck2h/profile_claim_report.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("sample_evaluation", data)
        self.assertIn("verdict", data["sample_evaluation"])


class TestProfileImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/conformance_profile.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_profile_matrix(self):
        self.assertIn("struct ProfileMatrix", self.content)

    def test_has_claim_evaluation(self):
        self.assertIn("struct ClaimEvaluation", self.content)

    def test_has_profile_enum(self):
        self.assertIn("enum Profile", self.content)

    def test_has_all_error_codes(self):
        for code in ["CPM_UNKNOWN_PROFILE", "CPM_MISSING_RESULT", "CPM_CAPABILITY_FAILED",
                     "CPM_CLAIM_BLOCKED", "CPM_INVALID_MATRIX"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestProfileSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-ck2h_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-CPM-MATRIX", "INV-CPM-MEASURED",
                    "INV-CPM-BLOCKED", "INV-CPM-METADATA"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestProfileIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/profile_claim_gate.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_matrix(self):
        self.assertIn("inv_cpm_matrix", self.content)

    def test_covers_measured(self):
        self.assertIn("inv_cpm_measured", self.content)

    def test_covers_blocked(self):
        self.assertIn("inv_cpm_blocked", self.content)

    def test_covers_metadata(self):
        self.assertIn("inv_cpm_metadata", self.content)


if __name__ == "__main__":
    unittest.main()
