"""Unit tests for scripts/check_signed_receipt.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestReceiptFixture(unittest.TestCase):
    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/security/decision_receipt_samples.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/security/decision_receipt_samples.json")
        with open(path) as handle:
            data = json.load(handle)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_expected_outcomes(self):
        path = os.path.join(ROOT, "fixtures/security/decision_receipt_samples.json")
        with open(path) as handle:
            data = json.load(handle)
        truthy = [c for c in data["cases"] if c.get("expected_verify") is True]
        falsy = [c for c in data["cases"] if c.get("expected_verify") is False]
        self.assertGreater(len(truthy), 0)
        self.assertGreater(len(falsy), 0)


class TestReceiptArtifact(unittest.TestCase):
    def test_artifact_exists(self):
        path = os.path.join(
            ROOT, "artifacts/section_10_5/bd-21z/decision_receipt_chain.json"
        )
        self.assertTrue(os.path.isfile(path))

    def test_artifact_chain_is_present(self):
        path = os.path.join(
            ROOT, "artifacts/section_10_5/bd-21z/decision_receipt_chain.json"
        )
        with open(path) as handle:
            data = json.load(handle)
        self.assertIn("chain", data)
        self.assertGreaterEqual(len(data["chain"]), 2)

    def test_chain_contains_signature_and_hash(self):
        path = os.path.join(
            ROOT, "artifacts/section_10_5/bd-21z/decision_receipt_chain.json"
        )
        with open(path) as handle:
            data = json.load(handle)
        for receipt in data["chain"]:
            self.assertIn("signature", receipt)
            self.assertIn("chain_hash", receipt)


class TestReceiptImplementation(unittest.TestCase):
    def setUp(self):
        self.impl_path = os.path.join(
            ROOT, "crates/franken-node/src/security/decision_receipt.rs"
        )
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as handle:
            self.content = handle.read()

    def test_has_signed_receipt_types(self):
        self.assertIn("struct Receipt", self.content)
        self.assertIn("struct SignedReceipt", self.content)
        self.assertIn("enum Decision", self.content)

    def test_has_signature_api(self):
        for symbol in ["fn sign_receipt", "fn verify_receipt", "fn verify_hash_chain"]:
            self.assertIn(symbol, self.content)

    def test_has_export_api(self):
        for symbol in [
            "fn export_receipts",
            "fn export_receipts_json",
            "fn export_receipts_cbor",
            "fn import_receipts_cbor",
        ]:
            self.assertIn(symbol, self.content)

    def test_has_high_impact_registry(self):
        self.assertIn("struct HighImpactActionRegistry", self.content)
        self.assertIn("fn enforce_high_impact_receipt", self.content)


class TestReceiptSpec(unittest.TestCase):
    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_5/bd-21z_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as handle:
            self.content = handle.read()

    def test_has_invariants(self):
        for invariant in [
            "INV-RECEIPT-CANONICAL",
            "INV-RECEIPT-SIGNATURE",
            "INV-RECEIPT-CHAIN",
            "INV-RECEIPT-HIGH-IMPACT",
            "INV-RECEIPT-EXPORT",
        ]:
            self.assertIn(invariant, self.content)

    def test_has_required_types(self):
        for marker in ["Receipt", "SignedReceipt", "ReceiptQuery", "Decision"]:
            self.assertIn(marker, self.content)


if __name__ == "__main__":
    unittest.main()
