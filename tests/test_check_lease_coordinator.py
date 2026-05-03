"""Unit tests for check_lease_coordinator.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_lease_coordinator.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-2vs4/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestLeaseCoordinatorVectors(unittest.TestCase):

    def test_vectors_exist(self):
        path = ROOT / "artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json"
        self.assertTrue(path.is_file())

    def test_vectors_valid(self):
        path = ROOT / "artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("vectors", data)
        self.assertGreaterEqual(len(data["vectors"]), 4)

    def test_vectors_have_pass_and_fail(self):
        path = ROOT / "artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        passed = [
            v for v in data["vectors"]
            if isinstance(v.get("expected_passed"), bool) and v["expected_passed"]
        ]
        failed = [
            v for v in data["vectors"]
            if isinstance(v.get("expected_passed"), bool) and not v["expected_passed"]
        ]
        self.assertGreater(len(passed), 0)
        self.assertGreater(len(failed), 0)


class TestLeaseCoordinatorImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/lease_coordinator.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_coordinator_candidate(self):
        self.assertIn("struct CoordinatorCandidate", self.content)

    def test_has_coordinator_selection(self):
        self.assertIn("struct CoordinatorSelection", self.content)

    def test_has_quorum_config(self):
        self.assertIn("struct QuorumConfig", self.content)

    def test_has_select_coordinator(self):
        self.assertIn("fn select_coordinator", self.content)

    def test_has_verify_quorum(self):
        self.assertIn("fn verify_quorum", self.content)

    def test_has_verification_failure(self):
        self.assertIn("enum VerificationFailure", self.content)

    def test_has_all_error_codes(self):
        for code in ["LC_BELOW_QUORUM", "LC_INVALID_SIGNATURE",
                     "LC_UNKNOWN_SIGNER", "LC_NO_CANDIDATES"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseCoordinatorSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-2vs4_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-LC-DETERMINISTIC", "INV-LC-QUORUM-TIER",
                    "INV-LC-VERIFY-CLASSIFIED", "INV-LC-REPLAY"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["LC_BELOW_QUORUM", "LC_INVALID_SIGNATURE",
                     "LC_UNKNOWN_SIGNER", "LC_NO_CANDIDATES"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseCoordinatorConformance(unittest.TestCase):

    def setUp(self):
        self.conf_path = ROOT / "tests/conformance/lease_coordinator_selection.rs"
        self.assertTrue(self.conf_path.is_file())
        self.content = self.conf_path.read_text(encoding="utf-8")

    def test_covers_deterministic(self):
        self.assertIn("inv_lc_deterministic", self.content)

    def test_covers_quorum_tier(self):
        self.assertIn("inv_lc_quorum_tier", self.content)

    def test_covers_classified(self):
        self.assertIn("inv_lc_verify_classified", self.content)

    def test_covers_replay(self):
        self.assertIn("inv_lc_replay", self.content)


class TestLeaseCoordinatorCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "lease_coordinator_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["LC-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-2vs4:", result.stdout)

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
