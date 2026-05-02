"""Unit tests for check_ssrf_policy.py verification logic."""

import json
import os
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSsrfPolicyFixtures(unittest.TestCase):

    def test_deny_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/ssrf_policy/ssrf_deny_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_deny_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/ssrf_policy/ssrf_deny_scenarios.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 8)

    def test_deny_fixture_has_deny_and_allow(self):
        path = os.path.join(ROOT, "fixtures/ssrf_policy/ssrf_deny_scenarios.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        actions = [c["expected_action"] for c in data["cases"]]
        self.assertIn("allow", actions)
        self.assertIn("deny", actions)

    def test_deny_fixture_cases_have_fields(self):
        path = os.path.join(ROOT, "fixtures/ssrf_policy/ssrf_deny_scenarios.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        for case in data["cases"]:
            self.assertIn("host", case)
            self.assertIn("port", case)
            self.assertIn("expected_action", case)
            self.assertIn("category", case)

    def test_deny_fixture_covers_all_categories(self):
        path = os.path.join(ROOT, "fixtures/ssrf_policy/ssrf_deny_scenarios.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        categories = {c["category"] for c in data["cases"]}
        for cat in ["loopback", "private", "metadata", "tailnet", "public"]:
            self.assertIn(cat, categories, f"Missing category {cat}")

    def test_allowlist_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/ssrf_policy/allowlist_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_allowlist_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/ssrf_policy/allowlist_scenarios.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 2)


class TestSsrfPolicyTestReport(unittest.TestCase):

    def test_report_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1nk5/ssrf_policy_test_report.json")
        self.assertTrue(os.path.isfile(path))

    def test_report_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1nk5/ssrf_policy_test_report.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        self.assertIn("ssrf_patterns_tested", data)
        self.assertEqual(data["verdict"], "PASS")

    def test_report_covers_all_patterns(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1nk5/ssrf_policy_test_report.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        patterns = [p["pattern"] for p in data["ssrf_patterns_tested"]]
        for pat in ["ipv4_loopback", "rfc1918_class_a", "rfc1918_class_b",
                    "rfc1918_class_c", "cloud_metadata", "cgnat_tailnet",
                    "ipv6_loopback", "public_ip"]:
            self.assertIn(pat, patterns, f"Missing pattern {pat}")

    def test_report_has_allowlist_tests(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1nk5/ssrf_policy_test_report.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        self.assertIn("allowlist_tests", data)
        self.assertGreaterEqual(len(data["allowlist_tests"]), 2)


class TestSsrfPolicyImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/ssrf_policy.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        self.content = Path(self.impl_path).read_text(encoding="utf-8")

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
        self.toml_path = os.path.join(ROOT, "config/policies/network_guard_default.toml")
        self.assertTrue(os.path.isfile(self.toml_path))
        self.content = Path(self.toml_path).read_text(encoding="utf-8")

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
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1nk5_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        self.content = Path(self.spec_path).read_text(encoding="utf-8")

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
        self.check_path = os.path.join(ROOT, "scripts/check_ssrf_policy.py")
        self.assertTrue(os.path.isfile(self.check_path))
        self.content = Path(self.check_path).read_text(encoding="utf-8")

    def test_checker_clears_accumulated_checks(self):
        self.assertIn("CHECKS.clear()", self.content)

    def test_checker_uses_rch_exec_not_local_cargo(self):
        self.assertIn('"rch", "exec", "--", "cargo"', self.content)
        self.assertIn("check=False", self.content)


if __name__ == "__main__":
    unittest.main()
