"""Unit tests for check_network_guard.py verification logic."""

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from scripts import check_network_guard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestNetworkGuardFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/network_guard/egress_policy_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = Path(ROOT) / "fixtures/network_guard/egress_policy_scenarios.json"
        with path.open(encoding="utf-8") as fixture_file:
            data = json.load(fixture_file)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_allow_and_deny(self):
        path = Path(ROOT) / "fixtures/network_guard/egress_policy_scenarios.json"
        with path.open(encoding="utf-8") as fixture_file:
            data = json.load(fixture_file)
        actions = [c["expected_action"] for c in data["cases"]]
        self.assertIn("allow", actions)
        self.assertIn("deny", actions)

    def test_fixture_cases_have_fields(self):
        path = Path(ROOT) / "fixtures/network_guard/egress_policy_scenarios.json"
        with path.open(encoding="utf-8") as fixture_file:
            data = json.load(fixture_file)
        for case in data["cases"]:
            self.assertIn("host", case)
            self.assertIn("port", case)
            self.assertIn("protocol", case)
            self.assertIn("expected_action", case)


class TestAuditSamples(unittest.TestCase):

    def test_audit_jsonl_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl")
        self.assertTrue(os.path.isfile(path))

    def test_audit_jsonl_valid(self):
        path = Path(ROOT) / "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl"
        with path.open(encoding="utf-8") as audit_file:
            lines = [line.strip() for line in audit_file if line.strip()]
        self.assertGreaterEqual(len(lines), 2)
        for line in lines:
            event = json.loads(line)
            self.assertIn("trace_id", event)
            self.assertIn("action", event)
            self.assertIn("connector_id", event)

    def test_audit_has_allow_and_deny(self):
        path = Path(ROOT) / "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl"
        with path.open(encoding="utf-8") as audit_file:
            lines = [line.strip() for line in audit_file if line.strip()]
        actions = [json.loads(line)["action"] for line in lines]
        self.assertIn("allow", actions)
        self.assertIn("deny", actions)


class TestNetworkGuardScriptHelpers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.module = check_network_guard

    def test_build_guard_test_command_uses_rch_exec(self):
        self.assertEqual(
            self.module.build_guard_test_command(),
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
                self.module.NETWORK_GUARD_TEST_FILTER,
            ],
        )

    def test_build_guard_security_test_command_uses_named_target(self):
        self.assertEqual(
            self.module.build_guard_security_test_command(),
            [
                "rch",
                "exec",
                "--",
                "cargo",
                "test",
                "-p",
                "frankenengine-node",
                "--test",
                self.module.NETWORK_GUARD_SECURITY_TARGET,
            ],
        )

    def test_parse_rust_test_summary_handles_singular_and_plural(self):
        output = """
running 1 test
test smoke ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 2 tests
test alpha ... ok
test beta ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out
"""
        summary = self.module.parse_rust_test_summary(output)
        self.assertEqual(summary["running"], 3)
        self.assertEqual(summary["passed"], 3)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["filtered"], 1)

    def test_parse_rust_test_summary_counts_failed_tests(self):
        output = """
running 3 tests
test alpha ... ok
test beta ... FAILED
test gamma ... ok

test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
"""
        summary = self.module.parse_rust_test_summary(output)
        self.assertEqual(summary["running"], 3)
        self.assertEqual(summary["passed"], 2)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["filtered"], 0)

    def test_summarize_failure_output_strips_ansi_and_focuses_error(self):
        output = (
            "\x1b[32mCompiling\x1b[0m frankenengine-engine\n"
            "\x1b[31merror[E0428]\x1b[0m: the name `foo` is defined multiple times\n"
            " --> src/lib.rs:12:1\n"
        )
        summary = self.module.summarize_failure_output(output, max_lines=2)
        self.assertIn("error[E0428]: the name `foo` is defined multiple times", summary)
        self.assertNotIn("\x1b", summary)

    def test_select_failure_excerpt_prefers_first_non_empty_excerpt(self):
        excerpt = self.module.select_failure_excerpt(
            "",
            "\x1b[31merror[E0428]\x1b[0m: duplicate definitions\n",
        )
        self.assertIn("error[E0428]: duplicate definitions", excerpt)

    def test_cargo_harness_wires_security_test(self):
        harness_path = Path(ROOT) / "crates/franken-node/tests/remote_cap_enforcement.rs"
        self.assertTrue(harness_path.is_file())
        self.assertIn(
            "../../../tests/security/remote_cap_enforcement.rs",
            harness_path.read_text(encoding="utf-8"),
        )

    @mock.patch("scripts.check_network_guard.subprocess.run")
    def test_run_guard_unit_tests_uses_rch_and_lib_filter(self, run_mock):
        run_mock.return_value = mock.Mock(
            stdout="running 2 tests\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            stderr="",
            returncode=0,
        )

        summary, _ = self.module.run_guard_unit_tests()

        run_mock.assert_called_once_with(
            self.module.build_guard_test_command(),
            capture_output=True,
            text=True,
            timeout=self.module.GUARD_TEST_TIMEOUT_SECONDS,
            cwd=self.module.ROOT,
        )
        self.assertEqual(summary["returncode"], 0)
        self.assertEqual(summary["passed"], 2)

    @mock.patch("scripts.check_network_guard.subprocess.run")
    def test_run_guard_security_tests_uses_named_target(self, run_mock):
        run_mock.return_value = mock.Mock(
            stdout="running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            stderr="",
            returncode=0,
        )

        summary, _ = self.module.run_guard_security_tests()

        run_mock.assert_called_once_with(
            self.module.build_guard_security_test_command(),
            capture_output=True,
            text=True,
            timeout=self.module.GUARD_TEST_TIMEOUT_SECONDS,
            cwd=self.module.ROOT,
        )
        self.assertEqual(summary["returncode"], 0)
        self.assertEqual(summary["passed"], 1)

    def test_audit_samples_helper_accepts_current_artifact(self):
        path = Path(ROOT) / "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl"
        self.assertTrue(self.module.audit_samples_are_valid(path))


class TestNetworkGuardImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/network_guard.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path, encoding="utf-8") as impl_file:
            self.content = impl_file.read()

    def test_has_network_guard(self):
        self.assertIn("struct NetworkGuard", self.content)

    def test_has_egress_policy(self):
        self.assertIn("struct EgressPolicy", self.content)

    def test_has_audit_event(self):
        self.assertIn("struct AuditEvent", self.content)

    def test_has_process_egress(self):
        self.assertIn("fn process_egress", self.content)

    def test_has_host_matching(self):
        self.assertIn("fn host_matches", self.content)

    def test_has_both_protocols(self):
        self.assertIn("Http", self.content)
        self.assertIn("Tcp", self.content)

    def test_has_all_error_codes(self):
        for code in ["GUARD_POLICY_INVALID", "GUARD_EGRESS_DENIED", "GUARD_AUDIT_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestNetworkGuardSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2m2b_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path, encoding="utf-8") as spec_file:
            self.content = spec_file.read()

    def test_has_invariants(self):
        for inv in ["INV-GUARD-ALL-EGRESS", "INV-GUARD-DEFAULT-DENY",
                    "INV-GUARD-AUDIT", "INV-GUARD-ORDERED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["GUARD_POLICY_INVALID", "GUARD_EGRESS_DENIED", "GUARD_AUDIT_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_audit_event_schema(self):
        self.assertIn("Audit Event", self.content)
        self.assertIn("trace_id", self.content)


if __name__ == "__main__":
    unittest.main()
