"""Unit tests for check_provenance_gate.py verification logic."""

import json
import os
import unittest
from unittest import mock

from scripts import check_provenance_gate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestProvenanceFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/provenance/gate_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/provenance/gate_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_pass_and_fail(self):
        path = os.path.join(ROOT, "fixtures/provenance/gate_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        passed = [c for c in data["cases"] if c.get("expected_passed") is True]
        failed = [c for c in data["cases"] if c.get("expected_passed") is False]
        self.assertGreater(len(passed), 0)
        self.assertGreater(len(failed), 0)


class TestProvenanceDecisions(unittest.TestCase):

    def test_decisions_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json")
        self.assertTrue(os.path.isfile(path))

    def test_decisions_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("decisions", data)
        self.assertGreaterEqual(len(data["decisions"]), 2)

    def test_decisions_have_both_outcomes(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json")
        with open(path) as f:
            data = json.load(f)
        passed = [d for d in data["decisions"] if d["passed"]]
        failed = [d for d in data["decisions"] if not d["passed"]]
        self.assertGreater(len(passed), 0)
        self.assertGreater(len(failed), 0)


class TestProvenanceImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/supply_chain/provenance_gate.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

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
        harness_path = os.path.join(ROOT, "crates/franken-node/tests/attestation_gate.rs")
        self.assertTrue(os.path.isfile(harness_path))
        with open(harness_path) as f:
            content = f.read()
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
        )
        self.assertEqual(summary["returncode"], 0)
        self.assertEqual(summary["passed"], 1)


class TestProvenanceSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3i9o_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-PROV-REQUIRED-ATTEST", "INV-PROV-BUILD-ASSURANCE",
                    "INV-PROV-TRUSTED-BUILDER", "INV-PROV-GATE-LOGGED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["PROV_ATTEST_MISSING", "PROV_ASSURANCE_LOW",
                     "PROV_BUILDER_UNTRUSTED", "PROV_POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


if __name__ == "__main__":
    unittest.main()
