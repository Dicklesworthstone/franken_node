"""Unit tests for scripts/check_packaging_profiles.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_packaging_profiles as mod


class TestConstants(unittest.TestCase):
    def test_valid_profiles_count(self):
        self.assertEqual(len(mod.VALID_PROFILES), 3)

    def test_valid_profiles_names(self):
        self.assertEqual(mod.VALID_PROFILES, ["local", "dev", "enterprise"])

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_event_codes_values(self):
        self.assertEqual(mod.EVENT_CODES, ["PKG-001", "PKG-002", "PKG-003", "PKG-004"])

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 8)

    def test_invariants_prefix(self):
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-PKG-"), f"{inv} missing INV-PKG- prefix")

    def test_components_count(self):
        self.assertEqual(len(mod.COMPONENTS), 8)

    def test_telemetry_levels(self):
        self.assertEqual(mod.TELEMETRY_LEVELS["local"], "off")
        self.assertEqual(mod.TELEMETRY_LEVELS["dev"], "debug-local")
        self.assertEqual(mod.TELEMETRY_LEVELS["enterprise"], "structured-export")

    def test_size_budgets(self):
        self.assertEqual(mod.SIZE_BUDGETS["local"], 25)
        self.assertEqual(mod.SIZE_BUDGETS["dev"], 60)
        self.assertEqual(mod.SIZE_BUDGETS["enterprise"], 80)

    def test_all_checks_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 18)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok = mod.self_test()
        self.assertTrue(ok, "self_test should pass")


class TestRunAll(unittest.TestCase):
    def test_structure_keys(self):
        result = mod.run_all()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result, f"missing key: {key}")

    def test_bead_id(self):
        self.assertEqual(mod.run_all()["bead_id"], "bd-3kn")

    def test_section(self):
        self.assertEqual(mod.run_all()["section"], "10.6")

    def test_verdict_pass(self):
        self.assertEqual(mod.run_all()["verdict"], "PASS")

    def test_total_equals_all_checks(self):
        result = mod.run_all()
        self.assertEqual(result["total"], len(mod.ALL_CHECKS))

    def test_no_failures(self):
        result = mod.run_all()
        self.assertEqual(result["failed"], 0)

    def test_check_names_unique(self):
        result = mod.run_all()
        names = [c["check"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), f"duplicate check names: {names}")


class TestIndividualChecks(unittest.TestCase):
    def _run(self, fn):
        mod.RESULTS.clear()
        fn()
        return mod.RESULTS[-1]

    def test_spec_exists(self):
        self.assertTrue(self._run(mod.check_spec_exists)["pass"])

    def test_policy_exists(self):
        self.assertTrue(self._run(mod.check_policy_exists)["pass"])

    def test_profiles_toml_exists(self):
        self.assertTrue(self._run(mod.check_profiles_toml_exists)["pass"])

    def test_profiles_toml_three_profiles(self):
        self.assertTrue(self._run(mod.check_profiles_toml_defines_three_profiles)["pass"])

    def test_profiles_toml_components(self):
        self.assertTrue(self._run(mod.check_profiles_toml_components)["pass"])

    def test_profiles_toml_defaults(self):
        self.assertTrue(self._run(mod.check_profiles_toml_defaults)["pass"])

    def test_profiles_toml_startup(self):
        self.assertTrue(self._run(mod.check_profiles_toml_startup)["pass"])

    def test_profiles_toml_size_budget(self):
        self.assertTrue(self._run(mod.check_profiles_toml_size_budget)["pass"])

    def test_spec_event_codes(self):
        self.assertTrue(self._run(mod.check_spec_event_codes)["pass"])

    def test_spec_invariants(self):
        self.assertTrue(self._run(mod.check_spec_invariants)["pass"])

    def test_policy_event_codes(self):
        self.assertTrue(self._run(mod.check_policy_event_codes)["pass"])

    def test_policy_invariants(self):
        self.assertTrue(self._run(mod.check_policy_invariants)["pass"])

    def test_local_telemetry_off(self):
        self.assertTrue(self._run(mod.check_local_telemetry_off)["pass"])

    def test_enterprise_audit_mandatory(self):
        self.assertTrue(self._run(mod.check_enterprise_audit_mandatory)["pass"])

    def test_enterprise_integrity_check(self):
        self.assertTrue(self._run(mod.check_enterprise_integrity_self_check)["pass"])

    def test_spec_size_constraint(self):
        self.assertTrue(self._run(mod.check_spec_size_constraint)["pass"])

    def test_spec_cli_flag(self):
        self.assertTrue(self._run(mod.check_spec_cli_flag)["pass"])

    def test_spec_env_var(self):
        self.assertTrue(self._run(mod.check_spec_env_var)["pass"])


class TestValidateProfile(unittest.TestCase):
    def _make_profile(self, name):
        return {
            "components": {
                "core_binary": True,
                "debug_symbols": name == "dev",
                "lockstep_harness": name == "dev",
                "fixture_generators": name == "dev",
                "compliance_evidence": name == "enterprise",
                "audit_log_infra": name == "enterprise",
                "signed_binary_verification": name == "enterprise",
                "telemetry_export": name == "enterprise",
            },
            "defaults": {
                "telemetry": mod.TELEMETRY_LEVELS[name],
                "audit_logging": name == "enterprise",
                "binary_signing_verification": name == "enterprise",
                "verbose_logging": name == "dev",
                "strict_policy_evaluation": name == "enterprise",
            },
            "startup": {
                "mode": {"local": "lazy", "dev": "eager", "enterprise": "full-integrity"}[name],
                "integrity_self_check": name == "enterprise",
            },
            "size_budget": {
                "max_binary_mb": mod.SIZE_BUDGETS[name],
                "strip_debug_symbols": name != "dev",
            },
        }

    def test_valid_local(self):
        results = mod.validate_profile("local", self._make_profile("local"))
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_valid_dev(self):
        results = mod.validate_profile("dev", self._make_profile("dev"))
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_valid_enterprise(self):
        results = mod.validate_profile("enterprise", self._make_profile("enterprise"))
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_invalid_profile_name(self):
        results = mod.validate_profile("staging", self._make_profile("local"))
        name_check = [r for r in results if r["name"] == "profile_name_valid"][0]
        self.assertFalse(name_check["passed"])

    def test_missing_core_binary(self):
        profile = self._make_profile("local")
        profile["components"]["core_binary"] = False
        results = mod.validate_profile("local", profile)
        core_check = [r for r in results if r["name"] == "core_binary_true"][0]
        self.assertFalse(core_check["passed"])

    def test_wrong_telemetry_level(self):
        profile = self._make_profile("local")
        profile["defaults"]["telemetry"] = "debug-local"  # wrong for local
        results = mod.validate_profile("local", profile)
        telemetry_check = [r for r in results if r["name"] == "telemetry_level"][0]
        self.assertFalse(telemetry_check["passed"])

    def test_wrong_size_budget(self):
        profile = self._make_profile("local")
        profile["size_budget"]["max_binary_mb"] = 100  # wrong for local
        results = mod.validate_profile("local", profile)
        size_check = [r for r in results if r["name"] == "size_budget_value"][0]
        self.assertFalse(size_check["passed"])


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-3kn")

    def test_json_verdict(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["verdict"], "PASS")


class TestSafeRel(unittest.TestCase):
    def test_root_path(self):
        p = mod.ROOT / "foo" / "bar.txt"
        self.assertEqual(mod._safe_rel(p), "foo/bar.txt")

    def test_non_root_path(self):
        p = Path("/tmp/some/other/path.txt")
        self.assertEqual(mod._safe_rel(p), "/tmp/some/other/path.txt")


if __name__ == "__main__":
    unittest.main()
