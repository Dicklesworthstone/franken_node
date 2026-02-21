"""Unit tests for scripts/check_incident_bundles.py (bd-f2y)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_incident_bundles",
    ROOT / "scripts" / "check_incident_bundles.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Test: run_all structure
# ---------------------------------------------------------------------------

class TestRunAllStructure(unittest.TestCase):
    def test_run_all_returns_dict(self):
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_run_all_has_required_keys(self):
        result = mod.run_all()
        for key in ["bead_id", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_bead_id(self):
        self.assertEqual(mod.run_all()["bead_id"], "bd-f2y")

    def test_section(self):
        self.assertEqual(mod.run_all()["section"], "10.8")

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_total_equals_passed_plus_failed(self):
        result = mod.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_checks_is_list(self):
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)

    def test_check_entry_structure(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


# ---------------------------------------------------------------------------
# Test: self_test
# ---------------------------------------------------------------------------

class TestSelfTest(unittest.TestCase):
    def test_self_test_returns_bool(self):
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


# ---------------------------------------------------------------------------
# Test: individual check functions
# ---------------------------------------------------------------------------

class TestIndividualChecks(unittest.TestCase):
    def _run_check(self, fn):
        mod.RESULTS.clear()
        fn()
        self.assertGreater(len(mod.RESULTS), 0)
        return mod.RESULTS[-1]

    def test_check_spec_exists(self):
        result = self._run_check(mod.check_spec_exists)
        self.assertTrue(result["pass"])

    def test_check_policy_exists(self):
        result = self._run_check(mod.check_policy_exists)
        self.assertTrue(result["pass"])

    def test_check_impl_exists(self):
        result = self._run_check(mod.check_impl_exists)
        self.assertTrue(result["pass"])

    def test_check_upstream_retention_policy(self):
        result = self._run_check(mod.check_upstream_retention_policy)
        self.assertTrue(result["pass"])

    def test_check_upstream_replay_bundle(self):
        result = self._run_check(mod.check_upstream_replay_bundle)
        self.assertTrue(result["pass"])

    def test_check_upstream_config(self):
        result = self._run_check(mod.check_upstream_config)
        self.assertTrue(result["pass"])

    def test_check_upstream_health_gate(self):
        result = self._run_check(mod.check_upstream_health_gate)
        self.assertTrue(result["pass"])

    def test_check_module_wiring(self):
        result = self._run_check(mod.check_module_wiring)
        self.assertTrue(result["pass"])

    def test_check_spec_event_codes(self):
        result = self._run_check(mod.check_spec_event_codes)
        self.assertTrue(result["pass"])

    def test_check_spec_invariants(self):
        result = self._run_check(mod.check_spec_invariants)
        self.assertTrue(result["pass"])

    def test_check_spec_export_formats(self):
        result = self._run_check(mod.check_spec_export_formats)
        self.assertTrue(result["pass"])

    def test_check_spec_retention_tiers(self):
        result = self._run_check(mod.check_spec_retention_tiers)
        self.assertTrue(result["pass"])

    def test_check_spec_retention_periods(self):
        result = self._run_check(mod.check_spec_retention_periods)
        self.assertTrue(result["pass"])

    def test_check_spec_bundle_format(self):
        result = self._run_check(mod.check_spec_bundle_format)
        self.assertTrue(result["pass"])

    def test_check_spec_dependencies(self):
        result = self._run_check(mod.check_spec_dependencies)
        self.assertTrue(result["pass"])

    def test_check_spec_acceptance_criteria(self):
        result = self._run_check(mod.check_spec_acceptance_criteria)
        self.assertTrue(result["pass"])

    def test_check_policy_retention_schedule(self):
        result = self._run_check(mod.check_policy_retention_schedule)
        self.assertTrue(result["pass"])

    def test_check_policy_export_procedures(self):
        result = self._run_check(mod.check_policy_export_procedures)
        self.assertTrue(result["pass"])

    def test_check_policy_compliance(self):
        result = self._run_check(mod.check_policy_compliance)
        self.assertTrue(result["pass"])

    def test_check_policy_governance(self):
        result = self._run_check(mod.check_policy_governance)
        self.assertTrue(result["pass"])

    def test_check_policy_event_codes(self):
        result = self._run_check(mod.check_policy_event_codes)
        self.assertTrue(result["pass"])

    def test_check_policy_invariants(self):
        result = self._run_check(mod.check_policy_invariants)
        self.assertTrue(result["pass"])

    def test_check_policy_automated_cleanup(self):
        result = self._run_check(mod.check_policy_automated_cleanup)
        self.assertTrue(result["pass"])

    def test_check_policy_audit_trail(self):
        result = self._run_check(mod.check_policy_audit_trail)
        self.assertTrue(result["pass"])

    def test_check_impl_types(self):
        result = self._run_check(mod.check_impl_types)
        self.assertTrue(result["pass"])

    def test_check_impl_functions(self):
        result = self._run_check(mod.check_impl_functions)
        self.assertTrue(result["pass"])

    def test_check_impl_event_codes(self):
        result = self._run_check(mod.check_impl_event_codes)
        self.assertTrue(result["pass"])

    def test_check_impl_invariant_comments(self):
        result = self._run_check(mod.check_impl_invariant_comments)
        self.assertTrue(result["pass"])

    def test_check_impl_retention_defaults(self):
        result = self._run_check(mod.check_impl_retention_defaults)
        self.assertTrue(result["pass"])

    def test_check_impl_has_tests(self):
        result = self._run_check(mod.check_impl_has_tests)
        self.assertTrue(result["pass"])

    def test_check_impl_severity_enum(self):
        result = self._run_check(mod.check_impl_severity_enum)
        self.assertTrue(result["pass"])

    def test_check_impl_export_formats(self):
        result = self._run_check(mod.check_impl_export_formats)
        self.assertTrue(result["pass"])

    def test_check_impl_archive_protection(self):
        result = self._run_check(mod.check_impl_archive_protection)
        self.assertTrue(result["pass"])

    def test_check_impl_integrity_verification(self):
        result = self._run_check(mod.check_impl_integrity_verification)
        self.assertTrue(result["pass"])


# ---------------------------------------------------------------------------
# Test: missing file detection
# ---------------------------------------------------------------------------

class TestMissingFileDetection(unittest.TestCase):
    def test_missing_spec_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "spec.md"
        with patch.object(mod, "SPEC", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("spec" in c["check"].lower() for c in failed))

    def test_missing_policy_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "policy.md"
        with patch.object(mod, "POLICY", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("policy" in c["check"].lower() for c in failed))

    def test_missing_impl_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "impl.rs"
        with patch.object(mod, "IMPL", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("impl" in c["check"].lower() for c in failed))

    def test_missing_retention_policy_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "retention.rs"
        with patch.object(mod, "RETENTION_POLICY", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(any("retention" in c["check"].lower() for c in failed))


# ---------------------------------------------------------------------------
# Test: validate_retention_period helper
# ---------------------------------------------------------------------------

class TestValidateRetentionPeriod(unittest.TestCase):
    def test_hot_valid(self):
        result = mod.validate_retention_period("hot", 90)
        self.assertTrue(result["passed"])

    def test_hot_above_minimum(self):
        result = mod.validate_retention_period("hot", 120)
        self.assertTrue(result["passed"])

    def test_hot_below_minimum(self):
        result = mod.validate_retention_period("hot", 30)
        self.assertFalse(result["passed"])

    def test_cold_valid(self):
        result = mod.validate_retention_period("cold", 365)
        self.assertTrue(result["passed"])

    def test_cold_below_minimum(self):
        result = mod.validate_retention_period("cold", 100)
        self.assertFalse(result["passed"])

    def test_archive_valid(self):
        result = mod.validate_retention_period("archive", 2555)
        self.assertTrue(result["passed"])

    def test_archive_below_minimum(self):
        result = mod.validate_retention_period("archive", 365)
        self.assertFalse(result["passed"])

    def test_unknown_tier(self):
        result = mod.validate_retention_period("unknown", 90)
        self.assertFalse(result["passed"])


# ---------------------------------------------------------------------------
# Test: validate_bundle_fields helper
# ---------------------------------------------------------------------------

class TestValidateBundleFields(unittest.TestCase):
    def _make_bundle(self, **overrides):
        bundle = {
            "bundle_id": "ibr-001",
            "incident_id": "INC-001",
            "created_at": "2026-02-20T12:00:00Z",
            "severity": "critical",
            "retention_tier": "hot",
            "metadata": {"title": "Test"},
            "logs": [],
            "traces": [],
            "metrics_snapshots": [],
            "evidence_refs": [],
            "integrity_hash": "abc123",
        }
        bundle.update(overrides)
        return bundle

    def test_complete_bundle(self):
        results = mod.validate_bundle_fields(self._make_bundle())
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_missing_bundle_id(self):
        bundle = self._make_bundle()
        del bundle["bundle_id"]
        results = mod.validate_bundle_fields(bundle)
        bid_check = [r for r in results if r["name"] == "bundle_field_bundle_id"][0]
        self.assertFalse(bid_check["passed"])

    def test_missing_integrity_hash(self):
        bundle = self._make_bundle()
        del bundle["integrity_hash"]
        results = mod.validate_bundle_fields(bundle)
        hash_check = [r for r in results if r["name"] == "bundle_field_integrity_hash"][0]
        self.assertFalse(hash_check["passed"])

    def test_none_field(self):
        bundle = self._make_bundle(severity=None)
        results = mod.validate_bundle_fields(bundle)
        sev_check = [r for r in results if r["name"] == "bundle_field_severity"][0]
        self.assertFalse(sev_check["passed"])


# ---------------------------------------------------------------------------
# Test: validate_severity helper
# ---------------------------------------------------------------------------

class TestValidateSeverity(unittest.TestCase):
    def test_critical(self):
        self.assertTrue(mod.validate_severity("critical")["passed"])

    def test_high(self):
        self.assertTrue(mod.validate_severity("high")["passed"])

    def test_medium(self):
        self.assertTrue(mod.validate_severity("medium")["passed"])

    def test_low(self):
        self.assertTrue(mod.validate_severity("low")["passed"])

    def test_invalid(self):
        self.assertFalse(mod.validate_severity("unknown")["passed"])

    def test_empty(self):
        self.assertFalse(mod.validate_severity("")["passed"])


# ---------------------------------------------------------------------------
# Test: validate_retention_tier helper
# ---------------------------------------------------------------------------

class TestValidateRetentionTier(unittest.TestCase):
    def test_hot(self):
        self.assertTrue(mod.validate_retention_tier("hot")["passed"])

    def test_cold(self):
        self.assertTrue(mod.validate_retention_tier("cold")["passed"])

    def test_archive(self):
        self.assertTrue(mod.validate_retention_tier("archive")["passed"])

    def test_invalid(self):
        self.assertFalse(mod.validate_retention_tier("unknown")["passed"])

    def test_empty(self):
        self.assertFalse(mod.validate_retention_tier("")["passed"])


# ---------------------------------------------------------------------------
# Test: validate_export_format helper
# ---------------------------------------------------------------------------

class TestValidateExportFormat(unittest.TestCase):
    def test_json(self):
        self.assertTrue(mod.validate_export_format("json")["passed"])

    def test_csv(self):
        self.assertTrue(mod.validate_export_format("csv")["passed"])

    def test_sarif(self):
        self.assertTrue(mod.validate_export_format("sarif")["passed"])

    def test_json_uppercase(self):
        self.assertTrue(mod.validate_export_format("JSON")["passed"])

    def test_invalid(self):
        self.assertFalse(mod.validate_export_format("xml")["passed"])

    def test_empty(self):
        self.assertFalse(mod.validate_export_format("")["passed"])


# ---------------------------------------------------------------------------
# Test: constants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_export_formats_count(self):
        self.assertEqual(len(mod.EXPORT_FORMATS), 3)

    def test_retention_tiers_count(self):
        self.assertEqual(len(mod.RETENTION_TIERS), 3)

    def test_severity_levels_count(self):
        self.assertEqual(len(mod.SEVERITY_LEVELS), 4)

    def test_required_impl_types_count(self):
        self.assertEqual(len(mod.REQUIRED_IMPL_TYPES), 9)

    def test_required_impl_functions_count(self):
        self.assertEqual(len(mod.REQUIRED_IMPL_FUNCTIONS), 5)

    def test_all_checks_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 34)


# ---------------------------------------------------------------------------
# Test: JSON output
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-f2y")

    def test_json_flag_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_incident_bundles.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-f2y")
        self.assertEqual(data["verdict"], "PASS")


# ---------------------------------------------------------------------------
# Test: safe_rel with mock paths
# ---------------------------------------------------------------------------

class TestSafeRel(unittest.TestCase):
    def test_safe_rel_with_root_path(self):
        p = mod.ROOT / "some" / "file.txt"
        result = mod._safe_rel(p)
        self.assertFalse(result.startswith("/"))

    def test_safe_rel_with_non_root_path(self):
        p = Path("/tmp/fakepath/file.txt")
        result = mod._safe_rel(p)
        self.assertEqual(result, "/tmp/fakepath/file.txt")


if __name__ == "__main__":
    unittest.main()
