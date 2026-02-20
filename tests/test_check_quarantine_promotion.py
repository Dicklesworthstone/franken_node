"""Unit tests for check_quarantine_promotion.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestPromotionReceipts(unittest.TestCase):

    def test_receipts_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3cm3/quarantine_promotion_receipts.json")
        self.assertTrue(os.path.isfile(path))

    def test_receipts_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3cm3/quarantine_promotion_receipts.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("receipts", data)
        self.assertGreaterEqual(len(data["receipts"]), 1)

    def test_has_rejections(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3cm3/quarantine_promotion_receipts.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("rejections", data)
        self.assertGreaterEqual(len(data["rejections"]), 1)


class TestPromotionImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/quarantine_promotion.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_promotion_rule(self):
        self.assertIn("struct PromotionRule", self.content)

    def test_has_promotion_request(self):
        self.assertIn("struct PromotionRequest", self.content)

    def test_has_provenance_receipt(self):
        self.assertIn("struct ProvenanceReceipt", self.content)

    def test_has_promotion_result(self):
        self.assertIn("struct PromotionResult", self.content)

    def test_has_evaluate_promotion(self):
        self.assertIn("fn evaluate_promotion", self.content)

    def test_has_all_error_codes(self):
        for code in ["QPR_SCHEMA_FAILED", "QPR_NOT_AUTHENTICATED", "QPR_NOT_REACHABLE",
                     "QPR_NOT_PINNED", "QPR_INVALID_RULE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestPromotionSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3cm3_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-QPR-SCHEMA-GATED", "INV-QPR-AUTHENTICATED",
                    "INV-QPR-RECEIPT", "INV-QPR-FAIL-CLOSED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["QPR_SCHEMA_FAILED", "QPR_NOT_AUTHENTICATED", "QPR_NOT_REACHABLE",
                     "QPR_NOT_PINNED", "QPR_INVALID_RULE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestPromotionIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/quarantine_promotion_gate.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_schema_gated(self):
        self.assertIn("inv_qpr_schema_gated", self.content)

    def test_covers_authenticated(self):
        self.assertIn("inv_qpr_authenticated", self.content)

    def test_covers_receipt(self):
        self.assertIn("inv_qpr_receipt", self.content)

    def test_covers_fail_closed(self):
        self.assertIn("inv_qpr_fail_closed", self.content)


if __name__ == "__main__":
    unittest.main()
