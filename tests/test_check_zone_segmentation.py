"""Unit tests for scripts/check_zone_segmentation.py (bd-1vp)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_zone_segmentation as checker  # noqa: E402


class TestSelfTest(unittest.TestCase):
    """self_test() must not raise."""

    def test_self_test_runs(self):
        ok = checker.self_test()
        self.assertTrue(ok)


class TestRunAllStructure(unittest.TestCase):
    """run_all() returns a well-formed result dict."""

    def test_structure(self):
        result = checker.run_all()
        for key in ("bead_id", "section", "title", "checks", "verdict",
                     "passed", "failed", "total", "all_passed", "status"):
            self.assertIn(key, result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-1vp")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.10")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"],
                         "Zone/Tenant Trust Segmentation Policies")

    def test_all_checks_have_required_keys(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_pass_values_are_bool(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIsInstance(check["passed"], bool)

    def test_verdict_consistency(self):
        result = checker.run_all()
        if result["failed"] == 0:
            self.assertEqual(result["verdict"], "PASS")
            self.assertTrue(result["all_passed"])
        else:
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["all_passed"])

    def test_passed_lte_total(self):
        result = checker.run_all()
        self.assertLessEqual(result["passed"], result["total"])

    def test_failed_consistency(self):
        result = checker.run_all()
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    def test_check_names_unique(self):
        result = checker.run_all()
        names = [c["name"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names found")

    def test_all_passed_consistency(self):
        result = checker.run_all()
        self.assertEqual(result["all_passed"], result["passed"] == result["total"])


class TestIndividualChecks(unittest.TestCase):
    """Each individual check function populates RESULTS correctly."""

    def _run_check(self, fn):
        checker.RESULTS.clear()
        fn()
        self.assertGreaterEqual(len(checker.RESULTS), 1)
        return checker.RESULTS[-1]

    def test_check_spec_exists(self):
        r = self._run_check(checker.check_spec_exists)
        self.assertEqual(r["name"], "spec_exists")
        self.assertTrue(r["passed"])

    def test_check_spec_event_codes(self):
        r = self._run_check(checker.check_spec_event_codes)
        self.assertEqual(r["name"], "spec_event_codes")
        self.assertTrue(r["passed"])

    def test_check_spec_invariants(self):
        r = self._run_check(checker.check_spec_invariants)
        self.assertEqual(r["name"], "spec_invariants")
        self.assertTrue(r["passed"])

    def test_check_spec_error_codes(self):
        r = self._run_check(checker.check_spec_error_codes)
        self.assertEqual(r["name"], "spec_error_codes")
        self.assertTrue(r["passed"])

    def test_check_spec_threshold(self):
        r = self._run_check(checker.check_spec_threshold)
        self.assertEqual(r["name"], "spec_threshold")
        self.assertTrue(r["passed"])

    def test_check_spec_alert_pipeline(self):
        r = self._run_check(checker.check_spec_alert_pipeline)
        self.assertEqual(r["name"], "spec_alert_pipeline")
        self.assertTrue(r["passed"])

    def test_check_policy_exists(self):
        r = self._run_check(checker.check_policy_exists)
        self.assertEqual(r["name"], "policy_exists")
        self.assertTrue(r["passed"])

    def test_check_policy_risk_documented(self):
        r = self._run_check(checker.check_policy_risk_documented)
        self.assertEqual(r["name"], "policy_risk_documented")
        self.assertTrue(r["passed"])

    def test_check_policy_countermeasures(self):
        r = self._run_check(checker.check_policy_countermeasures)
        self.assertEqual(r["name"], "policy_countermeasures")
        self.assertTrue(r["passed"])

    def test_check_policy_escalation(self):
        r = self._run_check(checker.check_policy_escalation)
        self.assertEqual(r["name"], "policy_escalation")
        self.assertTrue(r["passed"])

    def test_check_policy_monitoring(self):
        r = self._run_check(checker.check_policy_monitoring)
        self.assertEqual(r["name"], "policy_monitoring")
        self.assertTrue(r["passed"])

    def test_check_policy_evidence_requirements(self):
        r = self._run_check(checker.check_policy_evidence_requirements)
        self.assertEqual(r["name"], "policy_evidence_requirements")
        self.assertTrue(r["passed"])

    def test_check_rust_module_exists(self):
        r = self._run_check(checker.check_rust_module_exists)
        self.assertEqual(r["name"], "rust_module_exists")
        self.assertTrue(r["passed"])

    def test_check_rust_module_registered(self):
        r = self._run_check(checker.check_rust_module_registered)
        self.assertEqual(r["name"], "rust_module_registered")
        self.assertTrue(r["passed"])

    def test_check_rust_structs(self):
        r = self._run_check(checker.check_rust_structs)
        self.assertEqual(r["name"], "rust_structs")
        self.assertTrue(r["passed"])

    def test_check_rust_methods(self):
        r = self._run_check(checker.check_rust_methods)
        self.assertEqual(r["name"], "rust_methods")
        self.assertTrue(r["passed"])

    def test_check_rust_event_codes(self):
        r = self._run_check(checker.check_rust_event_codes)
        self.assertEqual(r["name"], "rust_event_codes")
        self.assertTrue(r["passed"])

    def test_check_rust_invariants(self):
        r = self._run_check(checker.check_rust_invariants)
        self.assertEqual(r["name"], "rust_invariants")
        self.assertTrue(r["passed"])

    def test_check_rust_isolation_levels(self):
        r = self._run_check(checker.check_rust_isolation_levels)
        self.assertEqual(r["name"], "rust_isolation_levels")
        self.assertTrue(r["passed"])

    def test_check_rust_test_count(self):
        r = self._run_check(checker.check_rust_test_count)
        self.assertEqual(r["name"], "rust_test_count")
        self.assertTrue(r["passed"])

    def test_check_rust_segmentation_errors(self):
        r = self._run_check(checker.check_rust_segmentation_errors)
        self.assertEqual(r["name"], "rust_segmentation_errors")
        self.assertTrue(r["passed"])

    def test_check_rust_freshness_gate(self):
        r = self._run_check(checker.check_rust_freshness_gate)
        self.assertEqual(r["name"], "rust_freshness_gate")
        self.assertTrue(r["passed"])

    def test_check_rust_key_zone_binding(self):
        r = self._run_check(checker.check_rust_key_zone_binding)
        self.assertEqual(r["name"], "rust_key_zone_binding")
        self.assertTrue(r["passed"])

    def test_check_verification_evidence(self):
        r = self._run_check(checker.check_verification_evidence)
        self.assertEqual(r["name"], "verification_evidence")
        self.assertTrue(r["passed"])

    def test_check_verification_summary(self):
        r = self._run_check(checker.check_verification_summary)
        self.assertEqual(r["name"], "verification_summary")
        self.assertTrue(r["passed"])


class TestCommentOnlyRustRegression(unittest.TestCase):
    """Rust-source checks must not pass from commented-out markers."""

    def test_comment_only_rust_markers_fail_closed(self):
        variants = [
            "CrossZoneViolation", "TenantNotBound", "ZoneNotFound",
            "DelegationDepthExceeded", "IsolationViolation", "DuplicateZone",
            "DuplicateTenant", "BridgeAuthIncomplete", "FreshnessStale",
            "KeyZoneMismatch",
        ]
        commented_module = "\n".join(
            [
                *(f"// {item}" for item in checker.REQUIRED_STRUCTS),
                *(f"// fn {item}()" for item in checker.REQUIRED_METHODS),
                *(f"// {item}" for item in checker.EVENT_CODES),
                *(f"// {item}" for item in checker.INVARIANTS),
                "// Strict Permissive Custom",
                *(f"// {item}" for item in variants),
                "// FreshnessStale freshness_valid",
                "// KeyZoneMismatch key_zone_bindings",
                "/*",
                *("// #[test]\n// fn commented_test() {}" for _ in range(25)),
                "*/",
            ]
        )

        original_module = checker.RUST_MODULE
        original_mod_rs = checker.MOD_RS
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            module_path = tmp / "trust_zone.rs"
            mod_path = tmp / "mod.rs"
            module_path.write_text(commented_module, encoding="utf-8")
            mod_path.write_text("// pub mod trust_zone;\n", encoding="utf-8")

            try:
                checker.RUST_MODULE = module_path
                checker.MOD_RS = mod_path
                checker.RESULTS.clear()
                for fn in [
                    checker.check_rust_module_exists,
                    checker.check_rust_module_registered,
                    checker.check_rust_structs,
                    checker.check_rust_methods,
                    checker.check_rust_event_codes,
                    checker.check_rust_invariants,
                    checker.check_rust_isolation_levels,
                    checker.check_rust_test_count,
                    checker.check_rust_segmentation_errors,
                    checker.check_rust_freshness_gate,
                    checker.check_rust_key_zone_binding,
                ]:
                    fn()
                results = {item["name"]: item["passed"] for item in checker.RESULTS}
            finally:
                checker.RUST_MODULE = original_module
                checker.MOD_RS = original_mod_rs
                checker.RESULTS.clear()

        self.assertTrue(results["rust_module_exists"])
        for name in [
            "rust_module_registered",
            "rust_structs",
            "rust_methods",
            "rust_event_codes",
            "rust_invariants",
            "rust_isolation_levels",
            "rust_test_count",
            "rust_segmentation_errors",
            "rust_freshness_gate",
            "rust_key_zone_binding",
        ]:
            self.assertIn(name, results)
            self.assertFalse(results[name], name)


class TestCheckHelper(unittest.TestCase):
    """_check() appends to RESULTS correctly."""

    def setUp(self):
        checker.RESULTS.clear()

    def test_check_pass(self):
        checker._check("test_pass", True, "it passed")
        self.assertEqual(len(checker.RESULTS), 1)
        self.assertTrue(checker.RESULTS[0]["passed"])
        self.assertEqual(checker.RESULTS[0]["name"], "test_pass")
        self.assertEqual(checker.RESULTS[0]["detail"], "it passed")

    def test_check_fail(self):
        checker._check("test_fail", False, "it failed")
        self.assertEqual(len(checker.RESULTS), 1)
        self.assertFalse(checker.RESULTS[0]["passed"])


class TestConstants(unittest.TestCase):
    """Module-level constants are correct."""

    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 4)

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_error_code_count(self):
        self.assertEqual(len(checker.ERROR_CODES), 10)

    def test_struct_count(self):
        self.assertEqual(len(checker.REQUIRED_STRUCTS), 7)

    def test_method_count(self):
        self.assertEqual(len(checker.REQUIRED_METHODS), 9)

    def test_all_checks_count(self):
        self.assertEqual(len(checker.ALL_CHECKS), 25)

    def test_event_code_prefix(self):
        for code in checker.EVENT_CODES:
            self.assertTrue(code.startswith("ZTS-"))

    def test_invariant_prefix(self):
        for inv in checker.INVARIANTS:
            self.assertTrue(inv.startswith("INV-ZTS-"))

    def test_error_code_prefix(self):
        for code in checker.ERROR_CODES:
            self.assertTrue(code.startswith("ERR_ZTS_"))


class TestJsonOutput(unittest.TestCase):
    """--json flag produces valid JSON."""

    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result, indent=2)
        parsed = json.JSONDecoder().decode(json_str)
        self.assertEqual(parsed["bead_id"], "bd-1vp")

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_zone_segmentation.py"), "--json"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-1vp")
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_zone_segmentation.py"), "--self-test"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test passed", proc.stdout)


class TestSafeRel(unittest.TestCase):
    """_safe_rel handles both ROOT-based and non-ROOT paths."""

    def test_root_based_path(self):
        p = ROOT / "docs" / "test.md"
        result = checker._safe_rel(p)
        self.assertNotIn(str(ROOT), result)
        self.assertIn("docs", result)

    def test_non_root_path(self):
        p = Path("/tmp/fake/test.md")
        result = checker._safe_rel(p)
        self.assertEqual(result, str(p))


class TestOverallVerdict(unittest.TestCase):
    """Final gate: all checks must pass."""

    def test_all_pass(self):
        result = checker.run_all()
        failing = [c["name"] for c in result["checks"] if not c["passed"]]
        self.assertEqual(result["verdict"], "PASS",
                         f"Failed checks: {failing}")


if __name__ == "__main__":
    unittest.main()
