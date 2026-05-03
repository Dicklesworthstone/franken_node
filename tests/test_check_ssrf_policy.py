"""Unit tests for check_ssrf_policy.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_ssrf_policy.py"
DENY_FIXTURE_PATH = ROOT / "fixtures/ssrf_policy/ssrf_deny_scenarios.json"
ALLOWLIST_FIXTURE_PATH = ROOT / "fixtures/ssrf_policy/allowlist_scenarios.json"
REPORT_PATH = ROOT / "artifacts/section_10_13/bd-1nk5/ssrf_policy_test_report.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-1nk5/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestSsrfPolicyFixtures(unittest.TestCase):

    def test_deny_fixture_exists(self):
        self.assertTrue(DENY_FIXTURE_PATH.is_file())

    def test_deny_fixture_has_cases(self):
        data = decode_json_object(DENY_FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 8)

    def test_deny_fixture_has_deny_and_allow(self):
        data = decode_json_object(DENY_FIXTURE_PATH.read_text(encoding="utf-8"))
        actions = [c["expected_action"] for c in data["cases"]]
        self.assertIn("allow", actions)
        self.assertIn("deny", actions)

    def test_deny_fixture_cases_have_fields(self):
        data = decode_json_object(DENY_FIXTURE_PATH.read_text(encoding="utf-8"))
        for case in data["cases"]:
            self.assertIn("host", case)
            self.assertIn("port", case)
            self.assertIn("expected_action", case)
            self.assertIn("category", case)

    def test_deny_fixture_covers_all_categories(self):
        data = decode_json_object(DENY_FIXTURE_PATH.read_text(encoding="utf-8"))
        categories = {c["category"] for c in data["cases"]}
        for cat in ["loopback", "private", "metadata", "tailnet", "public"]:
            self.assertIn(cat, categories, f"Missing category {cat}")

    def test_allowlist_fixture_exists(self):
        self.assertTrue(ALLOWLIST_FIXTURE_PATH.is_file())

    def test_allowlist_fixture_has_cases(self):
        data = decode_json_object(ALLOWLIST_FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 2)


class TestSsrfPolicyTestReport(unittest.TestCase):

    def test_report_exists(self):
        self.assertTrue(REPORT_PATH.is_file())

    def test_report_valid_json(self):
        data = decode_json_object(REPORT_PATH.read_text(encoding="utf-8"))
        self.assertIn("ssrf_patterns_tested", data)
        self.assertEqual(data["verdict"], "PASS")

    def test_report_covers_all_patterns(self):
        data = decode_json_object(REPORT_PATH.read_text(encoding="utf-8"))
        patterns = [p["pattern"] for p in data["ssrf_patterns_tested"]]
        for pat in ["ipv4_loopback", "rfc1918_class_a", "rfc1918_class_b",
                    "rfc1918_class_c", "cloud_metadata", "cgnat_tailnet",
                    "ipv6_loopback", "public_ip"]:
            self.assertIn(pat, patterns, f"Missing pattern {pat}")

    def test_report_has_allowlist_tests(self):
        data = decode_json_object(REPORT_PATH.read_text(encoding="utf-8"))
        self.assertIn("allowlist_tests", data)
        self.assertGreaterEqual(len(data["allowlist_tests"]), 2)


class TestSsrfPolicyImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/security/ssrf_policy.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_ssrf_policy_template(self):
        self.assertIn("struct SsrfPolicyTemplate", self.content)

    def test_has_cidr_range(self):
        self.assertIn("struct CidrRange", self.content)

    def test_has_policy_receipt(self):
        self.assertIn("struct PolicyReceipt", self.content)

    def test_has_allowlist_entry(self):
        self.assertIn("struct AllowlistEntry", self.content)

    def test_has_check_ssrf(self):
        self.assertIn("fn check_ssrf", self.content)

    def test_has_is_private_ip(self):
        self.assertIn("fn is_private_ip", self.content)

    def test_has_default_template(self):
        self.assertIn("fn default_template", self.content)

    def test_has_to_egress_policy(self):
        self.assertIn("fn to_egress_policy", self.content)

    def test_has_all_error_codes(self):
        for code in ["SSRF_DENIED", "SSRF_INVALID_IP", "SSRF_RECEIPT_MISSING", "SSRF_TEMPLATE_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_all_cidr_ranges(self):
        for cidr_label in ["ipv4_loopback", "rfc1918_class_a", "rfc1918_class_b",
                           "rfc1918_class_c", "link_local", "cgnat_tailnet", "this_network"]:
            self.assertIn(cidr_label, self.content, f"Missing CIDR label {cidr_label}")

    def test_has_ipv6_loopback_handling(self):
        self.assertIn("::1", self.content)


class TestSsrfPolicyToml(unittest.TestCase):

    def setUp(self):
        self.toml_path = ROOT / "config/policies/network_guard_default.toml"
        self.assertTrue(self.toml_path.is_file())
        self.content = self.toml_path.read_text(encoding="utf-8")

    def test_has_template_name(self):
        self.assertIn("ssrf_deny_default", self.content)

    def test_has_blocked_cidrs(self):
        self.assertIn("blocked_cidrs", self.content)

    def test_has_default_action(self):
        self.assertIn('default_action = "deny"', self.content)

    def test_has_all_networks(self):
        for network in ["127.0.0.0", "10.0.0.0", "172.16.0.0", "192.168.0.0",
                        "169.254.0.0", "100.64.0.0", "0.0.0.0"]:
            self.assertIn(network, self.content, f"Missing network {network}")


class TestSsrfPolicySpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-1nk5_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-SSRF-DEFAULT-DENY", "INV-SSRF-RECEIPT",
                    "INV-SSRF-CIDR-COMPLETE", "INV-SSRF-METADATA"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["SSRF_DENIED", "SSRF_INVALID_IP", "SSRF_RECEIPT_MISSING", "SSRF_TEMPLATE_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_policy_receipt_schema(self):
        self.assertIn("PolicyReceipt", self.content)
        self.assertIn("trace_id", self.content)


class TestSsrfChecker(unittest.TestCase):

    def setUp(self):
        self.assertTrue(SCRIPT.is_file())
        self.content = SCRIPT.read_text(encoding="utf-8")

    def test_checker_uses_local_check_state(self):
        self.assertIn("checks: list[dict[str, str]] = []", self.content)
        self.assertNotIn("CHECKS = []", self.content)

    def test_checker_uses_rch_exec_not_local_cargo(self):
        for token in ['"rch"', '"exec"', '"--"', '"cargo"', '"test"']:
            self.assertIn(token, self.content)
        self.assertIn("check=False", self.content)


class TestSsrfPolicyCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "ssrf_policy_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["SSRF-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-1nk5:", result.stdout)

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
