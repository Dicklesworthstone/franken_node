"""Unit tests for check_golden_vectors.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_golden_vectors.py"
VECTORS_PATH = ROOT / "vectors/fnode_trust_vectors_v1.json"
SCHEMA_PATH = ROOT / "spec/FNODE_TRUST_SCHEMA_V1.cddl"
REPORT_PATH = ROOT / "artifacts/section_10_13/bd-3n2u/vector_verification_report.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-3n2u/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestGoldenVectors(unittest.TestCase):

    def test_vectors_exist(self):
        self.assertTrue(VECTORS_PATH.is_file())

    def test_vectors_valid_json(self):
        data = decode_json_object(VECTORS_PATH.read_text(encoding="utf-8"))
        self.assertIn("vectors", data)
        self.assertGreaterEqual(len(data["vectors"]), 4)

    def test_schema_exists(self):
        self.assertTrue(SCHEMA_PATH.is_file())

    def test_report_exists(self):
        self.assertTrue(REPORT_PATH.is_file())


class TestGoldenVectorsImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/golden_vectors.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

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
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-3n2u_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-GSV-SCHEMA", "INV-GSV-VECTORS",
                    "INV-GSV-VERIFIED", "INV-GSV-CHANGELOG"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestGoldenVectorsIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/golden_vector_verification.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_schema(self):
        self.assertIn("inv_gsv_schema", self.content)

    def test_covers_vectors(self):
        self.assertIn("inv_gsv_vectors", self.content)

    def test_covers_verified(self):
        self.assertIn("inv_gsv_verified", self.content)

    def test_covers_changelog(self):
        self.assertIn("inv_gsv_changelog", self.content)


class TestGoldenVectorsCheckerCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "golden_vectors_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["GSV-TESTS"], "SKIP")
        self.assertEqual(statuses["GSV-REPORT"], "PASS")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-3n2u:", result.stdout)

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
