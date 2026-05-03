"""Unit tests for check_threshold_sig.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_threshold_sig.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-35q1/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestThresholdSigFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = ROOT / "fixtures/threshold_sig/verification_scenarios.json"
        self.assertTrue(path.is_file())

    def test_fixture_has_cases(self):
        path = ROOT / "fixtures/threshold_sig/verification_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_pass_and_fail(self):
        path = ROOT / "fixtures/threshold_sig/verification_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        verified = [
            c for c in data["cases"]
            if isinstance(c.get("expected_verified"), bool) and c["expected_verified"]
        ]
        rejected = [
            c for c in data["cases"]
            if isinstance(c.get("expected_verified"), bool) and not c["expected_verified"]
        ]
        self.assertGreater(len(verified), 0)
        self.assertGreater(len(rejected), 0)


class TestThresholdSigVectors(unittest.TestCase):

    def test_vectors_exist(self):
        path = ROOT / "artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json"
        self.assertTrue(path.is_file())

    def test_vectors_valid(self):
        path = ROOT / "artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("vectors", data)
        self.assertGreaterEqual(len(data["vectors"]), 2)

    def test_vectors_have_both_results(self):
        path = ROOT / "artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        results = [v["result"] for v in data["vectors"]]
        self.assertIn("verified", results)
        self.assertIn("rejected", results)


class TestThresholdSigImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/security/threshold_sig.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_threshold_config(self):
        self.assertIn("struct ThresholdConfig", self.content)

    def test_has_signer_key(self):
        self.assertIn("struct SignerKey", self.content)

    def test_has_partial_signature(self):
        self.assertIn("struct PartialSignature", self.content)

    def test_has_publication_artifact(self):
        self.assertIn("struct PublicationArtifact", self.content)

    def test_has_verification_result(self):
        self.assertIn("struct VerificationResult", self.content)

    def test_has_failure_reason(self):
        self.assertIn("enum FailureReason", self.content)

    def test_has_verify_threshold(self):
        self.assertIn("fn verify_threshold", self.content)

    def test_has_all_failure_reasons(self):
        for reason in ["BelowThreshold", "UnknownSigner", "InvalidSignature", "DuplicateSigner"]:
            self.assertIn(reason, self.content, f"Missing reason {reason}")

    def test_has_all_error_codes(self):
        for code in ["THRESH_BELOW_QUORUM", "THRESH_UNKNOWN_SIGNER",
                     "THRESH_INVALID_SIG", "THRESH_CONFIG_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestThresholdSigSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-35q1_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-THRESH-QUORUM", "INV-THRESH-PARTIAL-REJECT",
                    "INV-THRESH-STABLE-REASON", "INV-THRESH-NO-DUPLICATE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["THRESH_BELOW_QUORUM", "THRESH_UNKNOWN_SIGNER",
                     "THRESH_INVALID_SIG", "THRESH_CONFIG_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_failure_reason_type(self):
        self.assertIn("FailureReason", self.content)


class TestThresholdSigCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "threshold_sig_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["TS-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-35q1:", result.stdout)

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
