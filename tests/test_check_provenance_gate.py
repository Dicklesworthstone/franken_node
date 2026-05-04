"""Unit tests for check_provenance_gate.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from scripts import check_provenance_gate

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_provenance_gate.py"
FIXTURE_PATH = ROOT / "fixtures/provenance/gate_scenarios.json"
DECISIONS_PATH = ROOT / "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-3i9o/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestProvenanceFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        self.assertTrue(FIXTURE_PATH.is_file())

    def test_fixture_has_cases(self):
        data = decode_json_object(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_pass_and_fail(self):
        data = decode_json_object(FIXTURE_PATH.read_text(encoding="utf-8"))
        passed = [case for case in data["cases"] if case.get("expected_passed") in {True}]
        failed = [case for case in data["cases"] if case.get("expected_passed") in {False}]
        self.assertGreater(len(passed), 0)
        self.assertGreater(len(failed), 0)


class TestProvenanceDecisions(unittest.TestCase):

    def test_decisions_exist(self):
        self.assertTrue(DECISIONS_PATH.is_file())

    def test_decisions_valid(self):
        data = decode_json_object(DECISIONS_PATH.read_text(encoding="utf-8"))
        self.assertIn("decisions", data)
        self.assertGreaterEqual(len(data["decisions"]), 2)

    def test_decisions_have_both_outcomes(self):
        data = decode_json_object(DECISIONS_PATH.read_text(encoding="utf-8"))
        passed = [d for d in data["decisions"] if d["passed"]]
        failed = [d for d in data["decisions"] if not d["passed"]]
        self.assertGreater(len(passed), 0)
        self.assertGreater(len(failed), 0)


class TestProvenanceReadHelpers(unittest.TestCase):

    def test_read_utf8_invalid_utf8_returns_none(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.rs"
            path.write_bytes(b"\xff")

            self.assertIsNone(check_provenance_gate.read_utf8(path))

    def test_load_json_object_invalid_utf8_fails_closed(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            path.write_bytes(b"\xff")

            parsed, error = check_provenance_gate.load_json_object(path)

        self.assertIsNone(parsed)
        self.assertIsNotNone(error)
        self.assertIn("invalid UTF-8", error)


class TestProvenanceImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/supply_chain/provenance_gate.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_provenance_policy(self):
        self.assertIn("struct ProvenancePolicy", self.content)

    def test_has_artifact_provenance(self):
        self.assertIn("struct ArtifactProvenance", self.content)

    def test_has_gate_decision(self):
        self.assertIn("struct GateDecision", self.content)

    def test_has_evaluate_gate(self):
        self.assertIn("fn evaluate_gate", self.content)

    def test_has_attestation_types(self):
        for at in ["Slsa", "Sigstore", "InToto"]:
            self.assertIn(at, self.content, f"Missing attestation type {at}")

    def test_has_build_assurance_levels(self):
        for level in ["None", "Basic", "Verified", "Hardened"]:
            self.assertIn(level, self.content, f"Missing assurance level {level}")

    def test_has_all_error_codes(self):
        for code in ["PROV_ATTEST_MISSING", "PROV_ASSURANCE_LOW",
                     "PROV_BUILDER_UNTRUSTED", "PROV_POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestProvenanceCheckerLogic(unittest.TestCase):

    def test_cargo_harness_wires_security_test(self):
        harness_path = ROOT / "crates/franken-node/tests/attestation_gate.rs"
        self.assertTrue(harness_path.is_file())
        content = harness_path.read_text(encoding="utf-8")
        self.assertIn("../../../tests/security/attestation_gate.rs", content)

    def test_parse_rust_test_summary_handles_singular_and_plural(self):
        output = """
running 1 test
test smoke ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 3 tests
test alpha ... ok
test beta ... ok
test gamma ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out
"""
        summary = check_provenance_gate.parse_rust_test_summary(output)
        self.assertEqual(summary["running"], 4)
        self.assertEqual(summary["passed"], 4)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["filtered"], 2)

    def test_parse_rust_test_summary_counts_failed_tests(self):
        output = """
running 2 tests
test alpha ... ok
test beta ... FAILED

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
"""
        summary = check_provenance_gate.parse_rust_test_summary(output)
        self.assertEqual(summary["running"], 2)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["filtered"], 0)

    def test_summarize_failure_output_strips_ansi_and_focuses_error(self):
        output = (
            "\x1b[32mCompiling\x1b[0m frankenengine-engine\n"
            "\x1b[31merror[E0753]\x1b[0m: expected outer doc comment\n"
            " --> /data/projects/franken_engine/crates/franken-engine/src/parser.rs:2:1\n"
        )
        summary = check_provenance_gate.summarize_failure_output(output, max_lines=2)
        self.assertIn("error[E0753]: expected outer doc comment", summary)
        self.assertNotIn("\x1b", summary)

    def test_select_failure_excerpt_prefers_first_non_empty_excerpt(self):
        excerpt = check_provenance_gate.select_failure_excerpt(
            "",
            "\x1b[31merror[E0004]\x1b[0m: non-exhaustive patterns\n",
        )
        self.assertIn("error[E0004]: non-exhaustive patterns", excerpt)

    def test_json_mode_requests_full_proof_by_default(self):
        args = check_provenance_gate.parse_args(["--json"])

        self.assertTrue(check_provenance_gate.should_run_rust_tests(args))

    def test_skipped_structural_verdict_is_partial(self):
        self.assertEqual(
            check_provenance_gate.compute_verdict(failing=0, skipped=1, mode="structural"),
            "PARTIAL",
        )
        self.assertEqual(
            check_provenance_gate.compute_verdict(failing=0, skipped=1, mode="full"),
            "FAIL",
        )

    @mock.patch("scripts.check_provenance_gate.subprocess.run")
    def test_run_gate_unit_tests_uses_rch_and_lib_filter(self, run_mock):
        run_mock.return_value = mock.Mock(
            stdout="running 2 tests\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            stderr="",
            returncode=0,
        )

        summary, _ = check_provenance_gate.run_gate_unit_tests()

        run_mock.assert_called_once_with(
            [
                "rch",
                "exec",
                "--",
                "cargo",
                "test",
                "-p",
                "frankenengine-node",
                "--lib",
                "--",
                check_provenance_gate.PROVENANCE_GATE_UNIT_FILTER,
            ],
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=check_provenance_gate.ROOT,
            check=False,
        )
        self.assertEqual(summary["returncode"], 0)
        self.assertEqual(summary["passed"], 2)

    @mock.patch("scripts.check_provenance_gate.subprocess.run")
    def test_run_gate_security_tests_uses_named_target(self, run_mock):
        run_mock.return_value = mock.Mock(
            stdout="running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            stderr="",
            returncode=0,
        )

        summary, _ = check_provenance_gate.run_gate_security_tests()

        run_mock.assert_called_once_with(
            [
                "rch",
                "exec",
                "--",
                "cargo",
                "test",
                "-p",
                "frankenengine-node",
                "--test",
                check_provenance_gate.PROVENANCE_GATE_SECURITY_TARGET,
            ],
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=check_provenance_gate.ROOT,
            check=False,
        )
        self.assertEqual(summary["returncode"], 0)
        self.assertEqual(summary["passed"], 1)


class TestProvenanceSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-3i9o_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-PROV-REQUIRED-ATTEST", "INV-PROV-BUILD-ASSURANCE",
                    "INV-PROV-TRUSTED-BUILDER", "INV-PROV-GATE-LOGGED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["PROV_ATTEST_MISSING", "PROV_ASSURANCE_LOW",
                     "PROV_BUILDER_UNTRUSTED", "PROV_POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestProvenanceCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "provenance_gate_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        self.assertEqual(statuses["PG-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("bd-3i9o:", result.stdout)

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


if __name__ == "__main__":
    unittest.main()
