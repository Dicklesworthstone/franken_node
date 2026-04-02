"""Unit tests for check_network_guard.py verification logic."""

import importlib.util
import json
import os
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_check_network_guard_module():
    script_path = Path(ROOT) / "scripts" / "check_network_guard.py"
    spec = importlib.util.spec_from_file_location("check_network_guard", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        cls.module = load_check_network_guard_module()

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
