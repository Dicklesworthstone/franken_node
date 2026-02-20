"""Unit tests for check_error_code_registry.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestErrorCodeCatalog(unittest.TestCase):

    def test_catalog_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-novi/error_code_registry.json")
        self.assertTrue(os.path.isfile(path))

    def test_catalog_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-novi/error_code_registry.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("error_codes", data)
        self.assertGreaterEqual(len(data["error_codes"]), 4)

    def test_catalog_has_subsystems(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-novi/error_code_registry.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("subsystems", data)
        for s in ["PROTOCOL", "SECURITY", "EGRESS", "CONNECTOR"]:
            self.assertIn(s, data["subsystems"])


class TestErrorCodeImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/error_code_registry.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_error_code_registry(self):
        self.assertIn("struct ErrorCodeRegistry", self.content)

    def test_has_error_code_entry(self):
        self.assertIn("struct ErrorCodeEntry", self.content)

    def test_has_recovery_info(self):
        self.assertIn("struct RecoveryInfo", self.content)

    def test_has_register_fn(self):
        self.assertIn("fn register", self.content)

    def test_has_all_error_codes(self):
        for code in ["ECR_INVALID_NAMESPACE", "ECR_DUPLICATE_CODE", "ECR_MISSING_RECOVERY",
                     "ECR_FROZEN_CONFLICT", "ECR_NOT_FOUND"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestErrorCodeSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-novi_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-ECR-NAMESPACED", "INV-ECR-UNIQUE",
                    "INV-ECR-RECOVERY", "INV-ECR-FROZEN"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestErrorCodeIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/error_contract_stability.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_namespaced(self):
        self.assertIn("inv_ecr_namespaced", self.content)

    def test_covers_unique(self):
        self.assertIn("inv_ecr_unique", self.content)

    def test_covers_recovery(self):
        self.assertIn("inv_ecr_recovery", self.content)

    def test_covers_frozen(self):
        self.assertIn("inv_ecr_frozen", self.content)


if __name__ == "__main__":
    unittest.main()
