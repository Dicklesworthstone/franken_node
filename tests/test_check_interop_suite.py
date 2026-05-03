"""Unit tests for check_interop_suite.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_interop_suite.py"
FIXTURE_PATH = ROOT / "fixtures/interop/interop_test_vectors.json"
MATRIX_PATH = ROOT / "artifacts/section_10_13/bd-35by/interop_results_matrix.csv"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-35by/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestInteropFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        self.assertTrue(FIXTURE_PATH.is_file())

    def test_fixtures_valid_json(self):
        data = decode_json_object(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertIn("test_vectors", data)
        self.assertGreaterEqual(len(data["test_vectors"]), 5)

    def test_results_matrix_exists(self):
        self.assertTrue(MATRIX_PATH.is_file())


class TestInteropImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/interop_suite.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

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
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-35by_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-IOP-SERIALIZATION", "INV-IOP-OBJECT-ID",
                    "INV-IOP-SIGNATURE", "INV-IOP-REVOCATION",
                    "INV-IOP-SOURCE-DIVERSITY"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestInteropIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/interop_mandatory_suites.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

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


class TestInteropCheckerCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "interop_suite_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["IOP-TESTS"], "SKIP")
        self.assertEqual(statuses["IOP-MATRIX"], "PASS")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-35by:", result.stdout)

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
