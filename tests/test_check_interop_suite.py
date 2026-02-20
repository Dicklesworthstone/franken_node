"""Unit tests for check_interop_suite.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestInteropFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        path = os.path.join(ROOT, "fixtures/interop/interop_test_vectors.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixtures_valid_json(self):
        path = os.path.join(ROOT, "fixtures/interop/interop_test_vectors.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("test_vectors", data)
        self.assertGreaterEqual(len(data["test_vectors"]), 5)

    def test_results_matrix_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-35by/interop_results_matrix.csv")
        self.assertTrue(os.path.isfile(path))


class TestInteropImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/interop_suite.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_interop_class(self):
        self.assertIn("enum InteropClass", self.content)

    def test_has_interop_result(self):
        self.assertIn("struct InteropResult", self.content)

    def test_has_run_suite(self):
        self.assertIn("fn run_suite", self.content)

    def test_has_all_error_codes(self):
        for code in ["IOP_SERIALIZATION_MISMATCH", "IOP_OBJECT_ID_MISMATCH",
                     "IOP_SIGNATURE_INVALID", "IOP_REVOCATION_DISAGREEMENT",
                     "IOP_SOURCE_DIVERSITY_INSUFFICIENT"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestInteropSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-35by_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-IOP-SERIALIZATION", "INV-IOP-OBJECT-ID",
                    "INV-IOP-SIGNATURE", "INV-IOP-REVOCATION",
                    "INV-IOP-SOURCE-DIVERSITY"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestInteropIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/interop_mandatory_suites.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_serialization(self):
        self.assertIn("inv_iop_serialization", self.content)

    def test_covers_object_id(self):
        self.assertIn("inv_iop_object_id", self.content)

    def test_covers_signature(self):
        self.assertIn("inv_iop_signature", self.content)

    def test_covers_revocation(self):
        self.assertIn("inv_iop_revocation", self.content)

    def test_covers_source_diversity(self):
        self.assertIn("inv_iop_source_diversity", self.content)


if __name__ == "__main__":
    unittest.main()
