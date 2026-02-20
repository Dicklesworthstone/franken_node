"""Unit tests for check_golden_vectors.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestGoldenVectors(unittest.TestCase):

    def test_vectors_exist(self):
        path = os.path.join(ROOT, "vectors/fnode_trust_vectors_v1.json")
        self.assertTrue(os.path.isfile(path))

    def test_vectors_valid_json(self):
        path = os.path.join(ROOT, "vectors/fnode_trust_vectors_v1.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("vectors", data)
        self.assertGreaterEqual(len(data["vectors"]), 4)

    def test_schema_exists(self):
        path = os.path.join(ROOT, "spec/FNODE_TRUST_SCHEMA_V1.cddl")
        self.assertTrue(os.path.isfile(path))

    def test_report_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3n2u/vector_verification_report.json")
        self.assertTrue(os.path.isfile(path))


class TestGoldenVectorsImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/golden_vectors.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_schema_registry(self):
        self.assertIn("struct SchemaRegistry", self.content)

    def test_has_golden_vector(self):
        self.assertIn("struct GoldenVector", self.content)

    def test_has_all_error_codes(self):
        for code in ["GSV_MISSING_SCHEMA", "GSV_MISSING_VECTOR", "GSV_VECTOR_MISMATCH",
                     "GSV_NO_CHANGELOG", "GSV_INVALID_VERSION"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestGoldenVectorsSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3n2u_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-GSV-SCHEMA", "INV-GSV-VECTORS",
                    "INV-GSV-VERIFIED", "INV-GSV-CHANGELOG"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestGoldenVectorsIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/golden_vector_verification.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_schema(self):
        self.assertIn("inv_gsv_schema", self.content)

    def test_covers_vectors(self):
        self.assertIn("inv_gsv_vectors", self.content)

    def test_covers_verified(self):
        self.assertIn("inv_gsv_verified", self.content)

    def test_covers_changelog(self):
        self.assertIn("inv_gsv_changelog", self.content)


if __name__ == "__main__":
    unittest.main()
