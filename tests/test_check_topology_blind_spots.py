"""Unit tests for scripts/check_topology_blind_spots.py (bd-1n1t)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "check_topology_blind_spots",
    ROOT / "scripts" / "check_topology_blind_spots.py",
)
mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mod
_spec.loader.exec_module(mod)


class TestSelfTest(unittest.TestCase):
    """self_test() must not raise."""

    def test_self_test(self) -> None:
        mod.self_test()


class TestRunAllStructure(unittest.TestCase):
    """run_all() returns a well-formed result dict."""

    def test_structure(self) -> None:
        result = mod.run_all()
        for key in [
            "bead_id",
            "section",
            "title",
            "verdict",
            "passed",
            "failed",
            "total",
            "checks",
            "all_passed",
            "status",
        ]:
            self.assertIn(key, result)

    def test_bead_id(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1n1t")

    def test_section(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["section"], "12")

    def test_verdict_pass(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_passed_lte_total(self) -> None:
        result = mod.run_all()
        self.assertLessEqual(result["passed"], result["total"])

    def test_failed_consistency(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    def test_check_names_unique(self) -> None:
        result = mod.run_all()
        names = [c["name"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names")

    def test_all_passed_consistency(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["all_passed"], result["passed"] == result["total"])

    def test_status_field(self) -> None:
        result = mod.run_all()
        self.assertIn(result["status"], ("pass", "fail"))


class TestIndividualChecks(unittest.TestCase):
    """Each individual check function populates RESULTS correctly."""

    def _run_check(self, fn):
        mod.RESULTS.clear()
        fn()
        self.assertGreaterEqual(len(mod.RESULTS), 1)
        return mod.RESULTS[-1]

    def test_check_spec_exists(self) -> None:
        r = self._run_check(mod.check_spec_exists)
        self.assertEqual(r["name"], "spec_exists")
        self.assertTrue(r["passed"])

    def test_check_policy_exists(self) -> None:
        r = self._run_check(mod.check_policy_exists)
        self.assertEqual(r["name"], "policy_exists")
        self.assertTrue(r["passed"])

    def test_check_spec_event_codes(self) -> None:
        r = self._run_check(mod.check_spec_event_codes)
        self.assertEqual(r["name"], "spec_event_codes")
        self.assertTrue(r["passed"])

    def test_check_spec_invariants(self) -> None:
        r = self._run_check(mod.check_spec_invariants)
        self.assertEqual(r["name"], "spec_invariants")
        self.assertTrue(r["passed"])

    def test_check_spec_countermeasures(self) -> None:
        r = self._run_check(mod.check_spec_countermeasures)
        self.assertEqual(r["name"], "spec_countermeasures")
        self.assertTrue(r["passed"])

    def test_check_spec_threshold_drift(self) -> None:
        r = self._run_check(mod.check_spec_threshold_drift)
        self.assertEqual(r["name"], "spec_threshold_drift")
        self.assertTrue(r["passed"])

    def test_check_spec_threshold_chokepoint(self) -> None:
        r = self._run_check(mod.check_spec_threshold_chokepoint)
        self.assertEqual(r["name"], "spec_threshold_chokepoint")
        self.assertTrue(r["passed"])

    def test_check_spec_keywords(self) -> None:
        r = self._run_check(mod.check_spec_keywords)
        self.assertEqual(r["name"], "spec_keywords")
        self.assertTrue(r["passed"])

    def test_check_spec_scenarios(self) -> None:
        r = self._run_check(mod.check_spec_scenarios)
        self.assertEqual(r["name"], "spec_scenarios")
        self.assertTrue(r["passed"])

    def test_check_policy_event_codes(self) -> None:
        r = self._run_check(mod.check_policy_event_codes)
        self.assertEqual(r["name"], "policy_event_codes")
        self.assertTrue(r["passed"])

    def test_check_policy_invariants(self) -> None:
        r = self._run_check(mod.check_policy_invariants)
        self.assertEqual(r["name"], "policy_invariants")
        self.assertTrue(r["passed"])

    def test_check_policy_sections(self) -> None:
        r = self._run_check(mod.check_policy_sections)
        self.assertEqual(r["name"], "policy_sections")
        self.assertTrue(r["passed"])

    def test_check_policy_allowlist(self) -> None:
        r = self._run_check(mod.check_policy_allowlist)
        self.assertEqual(r["name"], "policy_allowlist")
        self.assertTrue(r["passed"])

    def test_check_policy_remediation_register(self) -> None:
        r = self._run_check(mod.check_policy_remediation_register)
        self.assertEqual(r["name"], "policy_remediation_register")
        self.assertTrue(r["passed"])

    def test_check_policy_risk_description(self) -> None:
        r = self._run_check(mod.check_policy_risk_description)
        self.assertEqual(r["name"], "policy_risk_description")
        self.assertTrue(r["passed"])

    def test_check_policy_dead_zone_detection(self) -> None:
        r = self._run_check(mod.check_policy_dead_zone_detection)
        self.assertEqual(r["name"], "policy_dead_zone_detection")
        self.assertTrue(r["passed"])

    def test_check_policy_escalation(self) -> None:
        r = self._run_check(mod.check_policy_escalation)
        self.assertEqual(r["name"], "policy_escalation")
        self.assertTrue(r["passed"])

    def test_check_policy_countermeasures(self) -> None:
        r = self._run_check(mod.check_policy_countermeasures)
        self.assertEqual(r["name"], "policy_countermeasures")
        self.assertTrue(r["passed"])

    def test_check_verification_evidence(self) -> None:
        r = self._run_check(mod.check_verification_evidence)
        self.assertEqual(r["name"], "verification_evidence")
        self.assertTrue(r["passed"])

    def test_check_verification_summary(self) -> None:
        r = self._run_check(mod.check_verification_summary)
        self.assertEqual(r["name"], "verification_summary")
        self.assertTrue(r["passed"])


class TestMissingFileDetection(unittest.TestCase):
    """Checks fail gracefully when files are missing."""

    def _run_with_missing(self, fn, attr_name):
        """Run a check with a path patched to a non-existent file."""
        fake = Path("/tmp/nonexistent_bd1n1t_test_file.md")
        original = getattr(mod, attr_name)
        try:
            setattr(mod, attr_name, fake)
            mod.RESULTS.clear()
            fn()
            self.assertGreaterEqual(len(mod.RESULTS), 1)
            return mod.RESULTS[-1]
        finally:
            setattr(mod, attr_name, original)

    def test_spec_missing_event_codes(self) -> None:
        r = self._run_with_missing(mod.check_spec_event_codes, "SPEC")
        self.assertFalse(r["passed"])

    def test_spec_missing_invariants(self) -> None:
        r = self._run_with_missing(mod.check_spec_invariants, "SPEC")
        self.assertFalse(r["passed"])

    def test_spec_missing_countermeasures(self) -> None:
        r = self._run_with_missing(mod.check_spec_countermeasures, "SPEC")
        self.assertFalse(r["passed"])

    def test_spec_missing_threshold_drift(self) -> None:
        r = self._run_with_missing(mod.check_spec_threshold_drift, "SPEC")
        self.assertFalse(r["passed"])

    def test_spec_missing_keywords(self) -> None:
        r = self._run_with_missing(mod.check_spec_keywords, "SPEC")
        self.assertFalse(r["passed"])

    def test_spec_missing_scenarios(self) -> None:
        r = self._run_with_missing(mod.check_spec_scenarios, "SPEC")
        self.assertFalse(r["passed"])

    def test_policy_missing_event_codes(self) -> None:
        r = self._run_with_missing(mod.check_policy_event_codes, "POLICY")
        self.assertFalse(r["passed"])

    def test_policy_missing_invariants(self) -> None:
        r = self._run_with_missing(mod.check_policy_invariants, "POLICY")
        self.assertFalse(r["passed"])

    def test_policy_missing_sections(self) -> None:
        r = self._run_with_missing(mod.check_policy_sections, "POLICY")
        self.assertFalse(r["passed"])

    def test_policy_missing_allowlist(self) -> None:
        r = self._run_with_missing(mod.check_policy_allowlist, "POLICY")
        self.assertFalse(r["passed"])

    def test_evidence_missing(self) -> None:
        r = self._run_with_missing(mod.check_verification_evidence, "EVIDENCE")
        self.assertFalse(r["passed"])
        self.assertIn("MISSING", r["detail"])


class TestConstants(unittest.TestCase):
    """Module-level constants are correct."""

    def test_spec_event_codes_count(self) -> None:
        self.assertEqual(len(mod.SPEC_EVENT_CODES), 5)

    def test_policy_event_codes_count(self) -> None:
        self.assertEqual(len(mod.POLICY_EVENT_CODES), 4)

    def test_spec_invariants_count(self) -> None:
        self.assertEqual(len(mod.SPEC_INVARIANTS), 5)

    def test_policy_invariants_count(self) -> None:
        self.assertEqual(len(mod.POLICY_INVARIANTS), 4)

    def test_all_checks_count(self) -> None:
        self.assertEqual(len(mod.ALL_CHECKS), 20)

    def test_spec_event_code_prefix(self) -> None:
        for code in mod.SPEC_EVENT_CODES:
            self.assertTrue(code.startswith("TBS-"))

    def test_policy_event_code_prefix(self) -> None:
        for code in mod.POLICY_EVENT_CODES:
            self.assertTrue(code.startswith("TBS-"))

    def test_spec_invariant_prefix(self) -> None:
        for inv in mod.SPEC_INVARIANTS:
            self.assertTrue(inv.startswith("INV-TBS-"))

    def test_policy_invariant_prefix(self) -> None:
        for inv in mod.POLICY_INVARIANTS:
            self.assertTrue(inv.startswith("INV-TBS-"))

    def test_thresholds_keys(self) -> None:
        expected = {"coverage", "event_latency_s", "dead_zone_window_h", "remediation_sla_h"}
        self.assertEqual(set(mod.THRESHOLDS.keys()), expected)

    def test_countermeasures_count(self) -> None:
        self.assertEqual(len(mod.COUNTERMEASURES), 4)


class TestJsonOutput(unittest.TestCase):
    """--json flag produces valid JSON."""

    def test_json_roundtrip(self) -> None:
        result = mod.run_all()
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        self.assertEqual(parsed["bead_id"], "bd-1n1t")

    def test_json_subprocess(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_topology_blind_spots.py"),
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-1n1t")
        self.assertEqual(parsed["verdict"], "PASS")


class TestSafeRel(unittest.TestCase):
    """_safe_rel handles both ROOT-based and non-ROOT paths."""

    def test_root_based_path(self) -> None:
        p = ROOT / "docs" / "test.md"
        result = mod._safe_rel(p)
        self.assertNotIn(str(ROOT), result)
        self.assertIn("docs", result)

    def test_non_root_path(self) -> None:
        p = Path("/tmp/fake/test.md")
        result = mod._safe_rel(p)
        self.assertEqual(result, str(p))


class TestValidateTopologyAudit(unittest.TestCase):
    """validate_topology_audit() validates audit dicts correctly."""

    def test_valid_audit(self) -> None:
        audit = {
            "timestamp": "2026-02-20T00:00:00Z",
            "total_nodes": 100,
            "monitored_nodes": 96,
            "coverage_percent": 96.0,
            "unmonitored": ["nodeA", "nodeB"],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertEqual(errors, [])

    def test_missing_fields(self) -> None:
        errors = mod.validate_topology_audit({})
        self.assertEqual(len(errors), 5)
        self.assertTrue(all("missing field" in e for e in errors))

    def test_negative_total_nodes(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": -1,
            "monitored_nodes": 0,
            "coverage_percent": 0,
            "unmonitored": [],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertTrue(any("total_nodes" in e for e in errors))

    def test_negative_monitored_nodes(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": 10,
            "monitored_nodes": -1,
            "coverage_percent": 0,
            "unmonitored": [],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertTrue(any("monitored_nodes" in e for e in errors))

    def test_monitored_exceeds_total(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": 10,
            "monitored_nodes": 20,
            "coverage_percent": 50,
            "unmonitored": [],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertTrue(any("exceeds" in e for e in errors))

    def test_coverage_out_of_range_high(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": 10,
            "monitored_nodes": 10,
            "coverage_percent": 150.0,
            "unmonitored": [],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertTrue(any("coverage_percent" in e for e in errors))

    def test_coverage_out_of_range_low(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": 10,
            "monitored_nodes": 10,
            "coverage_percent": -5.0,
            "unmonitored": [],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertTrue(any("coverage_percent" in e for e in errors))

    def test_unmonitored_not_list(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": 10,
            "monitored_nodes": 10,
            "coverage_percent": 100.0,
            "unmonitored": "not a list",
        }
        errors = mod.validate_topology_audit(audit)
        self.assertTrue(any("unmonitored" in e for e in errors))

    def test_total_nodes_not_int(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": 10.5,
            "monitored_nodes": 10,
            "coverage_percent": 100.0,
            "unmonitored": [],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertTrue(any("total_nodes" in e for e in errors))

    def test_partial_fields(self) -> None:
        audit = {"timestamp": "t", "total_nodes": 10}
        errors = mod.validate_topology_audit(audit)
        missing_count = sum(1 for e in errors if "missing field" in e)
        self.assertEqual(missing_count, 3)

    def test_zero_coverage_valid(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": 10,
            "monitored_nodes": 0,
            "coverage_percent": 0,
            "unmonitored": [],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertEqual(errors, [])

    def test_100_coverage_valid(self) -> None:
        audit = {
            "timestamp": "t",
            "total_nodes": 10,
            "monitored_nodes": 10,
            "coverage_percent": 100,
            "unmonitored": [],
        }
        errors = mod.validate_topology_audit(audit)
        self.assertEqual(errors, [])


class TestCheckHelper(unittest.TestCase):
    """_check() appends to RESULTS correctly."""

    def setUp(self) -> None:
        mod.RESULTS.clear()

    def test_check_pass(self) -> None:
        mod._check("test_pass", True, "it passed")
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["passed"])
        self.assertEqual(mod.RESULTS[0]["name"], "test_pass")
        self.assertEqual(mod.RESULTS[0]["detail"], "it passed")

    def test_check_fail(self) -> None:
        mod._check("test_fail", False, "it failed")
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["passed"])


if __name__ == "__main__":
    unittest.main()
