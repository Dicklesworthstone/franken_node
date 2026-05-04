"""Unit tests for check_transparency_verifier.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import check_transparency_verifier

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_transparency_verifier.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-1z9s/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


def has_expected_verified(case: dict[str, object], expected: bool) -> bool:
    value = case.get("expected_verified")
    return isinstance(value, bool) and value == expected


class TestTransparencyFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = ROOT / "fixtures/transparency_log/inclusion_proof_scenarios.json"
        self.assertTrue(path.is_file())

    def test_fixture_has_cases(self):
        path = ROOT / "fixtures/transparency_log/inclusion_proof_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_pass_and_fail(self):
        path = ROOT / "fixtures/transparency_log/inclusion_proof_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        verified = [case for case in data["cases"] if has_expected_verified(case, True)]
        rejected = [case for case in data["cases"] if has_expected_verified(case, False)]
        self.assertGreater(len(verified), 0)
        self.assertGreater(len(rejected), 0)


class TestTransparencyReceipts(unittest.TestCase):

    def test_receipts_exist(self):
        path = ROOT / "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json"
        self.assertTrue(path.is_file())

    def test_receipts_valid(self):
        path = ROOT / "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("receipts", data)
        self.assertGreaterEqual(len(data["receipts"]), 2)

    def test_receipts_have_both_outcomes(self):
        path = ROOT / "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        verified = [r for r in data["receipts"] if r["verified"]]
        rejected = [r for r in data["receipts"] if not r["verified"]]
        self.assertGreater(len(verified), 0)
        self.assertGreater(len(rejected), 0)

    def test_receipts_have_trace_ids(self):
        path = ROOT / "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        for r in data["receipts"]:
            self.assertIn("trace_id", r)


class TestTransparencyReadHelpers(unittest.TestCase):

    def test_read_utf8_invalid_utf8_returns_none(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.rs"
            path.write_bytes(b"\xff")

            self.assertIsNone(check_transparency_verifier.read_utf8(path))

    def test_load_json_object_invalid_utf8_fails_closed(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            path.write_bytes(b"\xff")

            parsed, error = check_transparency_verifier.load_json_object(path)

        self.assertIsNone(parsed)
        self.assertIsNotNone(error)
        self.assertIn("invalid UTF-8", error)


class TestTransparencyImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/supply_chain/transparency_verifier.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_log_root(self):
        self.assertIn("struct LogRoot", self.content)

    def test_has_inclusion_proof(self):
        self.assertIn("struct InclusionProof", self.content)

    def test_has_transparency_policy(self):
        self.assertIn("struct TransparencyPolicy", self.content)

    def test_has_proof_receipt(self):
        self.assertIn("struct ProofReceipt", self.content)

    def test_has_verify_inclusion(self):
        self.assertIn("fn verify_inclusion", self.content)

    def test_has_recompute_root(self):
        self.assertIn("fn recompute_root", self.content)

    def test_has_all_failure_types(self):
        for ft in ["ProofMissing", "RootNotPinned", "PathInvalid", "LeafMismatch"]:
            self.assertIn(ft, self.content, f"Missing failure type {ft}")

    def test_has_all_error_codes(self):
        for code in ["TLOG_PROOF_MISSING", "TLOG_ROOT_NOT_PINNED",
                     "TLOG_PATH_INVALID", "TLOG_LEAF_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestTransparencySpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-1z9s_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-TLOG-REQUIRED", "INV-TLOG-VERIFY",
                    "INV-TLOG-PINNED-ROOT", "INV-TLOG-REPLAYABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["TLOG_PROOF_MISSING", "TLOG_ROOT_NOT_PINNED",
                     "TLOG_PATH_INVALID", "TLOG_LEAF_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_proof_failure_type(self):
        self.assertIn("ProofFailure", self.content)


class TestTransparencyCli(unittest.TestCase):

    def test_json_mode_requests_full_proof_by_default(self):
        args = check_transparency_verifier.parse_args(["--json"])

        self.assertTrue(check_transparency_verifier.should_run_rust_tests(args))

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

        self.assertEqual(evidence["gate"], "transparency_verifier_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        self.assertEqual(statuses["TL-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("bd-1z9s:", result.stdout)

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
            check_transparency_verifier.compute_verdict(failing=0, skipped=1, mode="structural"),
            "PARTIAL",
        )
        self.assertEqual(
            check_transparency_verifier.compute_verdict(failing=0, skipped=1, mode="full"),
            "FAIL",
        )


if __name__ == "__main__":
    unittest.main()
