#!/usr/bin/env python3
"""Unit tests for check_conformance_harness.py."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_conformance_harness as ch

MOCKED_HARNESS_TESTS = {
    "id": "HARNESS-TESTS",
    "status": "PASS",
    "details": {"summary": "mocked"},
}


class TestCheckHarnessImpl(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(ch.check_harness_impl()["status"], "PASS")


class TestCheckGateErrorCodes(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(ch.check_gate_error_codes()["status"], "PASS")


class TestCheckOverrideSupport(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(ch.check_override_support()["status"], "PASS")


class TestRustTestCommand(unittest.TestCase):
    def test_targets_real_feature_gated_protocol_harness_tests(self):
        command = ch.rust_test_command()
        self.assertIn("RUSTUP_TOOLCHAIN=nightly", command)
        self.assertIn("--lib", command)
        self.assertIn("advanced-features", command)
        self.assertEqual(command[-1], "conformance::protocol_harness")


class TestCheckRustTests(unittest.TestCase):
    def test_extracts_stderr_only_cargo_summary(self):
        fake_result = SimpleNamespace(
            returncode=0,
            stdout="[RCH] remote ts2\n",
            stderr=(
                "running 4 tests\n"
                "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
            ),
        )
        with patch.object(ch.subprocess, "run", return_value=fake_result):
            result = ch.check_rust_tests()

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["details"]["summary"],
            "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
        )

    def test_uses_last_summary_across_stdout_and_stderr(self):
        summary = ch.extract_rust_test_summary(
            "test result: ok. 1 passed; 0 failed\n",
            "test result: ok. 2 passed; 0 failed\n",
        )
        self.assertEqual(summary, "test result: ok. 2 passed; 0 failed")


class TestCheckCIWorkflow(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(ch.check_ci_workflow()["status"], "PASS")


class TestCheckConformanceFile(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(ch.check_conformance_test_file()["status"], "PASS")

    def test_rejects_synthetic_boolean_harness(self):
        synthetic = "\n".join(
            [
                "fn fail_closed_default() { let has_override = false; }",
                "fn expired_override_rejected() { let current_time = \"2026\"; let expires_at = \"2020\"; assert!(current_time > expires_at); }",
                "fn deterministic_outcome() {}",
            ]
        )
        result = ch.conformance_test_content_findings(synthetic)
        self.assertIn(
            "let has_override = false",
            result["forbidden_synthetic_snippets"],
        )


class TestCheckSpec(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(ch.check_spec_document()["status"], "PASS")


class TestCheckEvidence(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(ch.check_publication_evidence()["status"], "PASS")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        with patch.object(
            ch,
            "check_rust_tests",
            return_value=MOCKED_HARNESS_TESTS,
        ):
            result = ch.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_present(self):
        with patch.object(
            ch,
            "check_rust_tests",
            return_value=MOCKED_HARNESS_TESTS,
        ):
            result = ch.self_test()
        self.assertGreaterEqual(result["summary"]["total_checks"], 8)

    def test_no_failures(self):
        with patch.object(
            ch,
            "check_rust_tests",
            return_value=MOCKED_HARNESS_TESTS,
        ):
            result = ch.self_test()
        self.assertEqual(result["summary"]["failing_checks"], 0)


if __name__ == "__main__":
    unittest.main()
