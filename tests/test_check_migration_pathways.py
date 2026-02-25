#!/usr/bin/env python3
"""Unit tests for scripts/check_migration_pathways.py (bd-2f43)."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the verification script as a module
# ---------------------------------------------------------------------------
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
spec = importlib.util.spec_from_file_location(
    "check_migration_pathways", SCRIPTS_DIR / "check_migration_pathways.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest(unittest.TestCase):
    """The self_test() function must pass without error."""

    def test_self_test(self) -> None:
        mod.self_test()


class TestCheckHelper(unittest.TestCase):
    """Low-level _check() accumulator works correctly."""

    def setUp(self) -> None:
        mod.RESULTS.clear()

    def tearDown(self) -> None:
        mod.RESULTS.clear()

    def test_check_appends(self) -> None:
        mod._check("t1", True, "ok")
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_fail(self) -> None:
        mod._check("t2", False, "bad")
        self.assertFalse(mod.RESULTS[0]["passed"])


class TestRunAll(unittest.TestCase):
    """run_all() returns a well-formed result dict."""

    def test_structure(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-2f43")
        self.assertEqual(result["section"], "13")
        self.assertIn("total_checks", result)
        self.assertIn("passed", result)
        self.assertIn("failed", result)
        self.assertIn("overall_passed", result)
        self.assertIn("checks", result)
        self.assertEqual(
            result["passed"] + result["failed"], result["total_checks"]
        )

    def test_checks_have_required_keys(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_all_check_names_unique(self) -> None:
        result = mod.run_all()
        names = [c["name"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names found")


class TestSpecExists(unittest.TestCase):
    """check_spec_exists passes when spec file is present."""

    def test_spec_present(self) -> None:
        mod.RESULTS.clear()
        mod.check_spec_exists()
        spec_path = mod.ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
        if spec_path.is_file():
            self.assertTrue(mod.RESULTS[0]["passed"])
        else:
            self.assertFalse(mod.RESULTS[0]["passed"])
        mod.RESULTS.clear()


class TestPolicyExists(unittest.TestCase):
    """check_policy_exists passes when policy file is present."""

    def test_policy_present(self) -> None:
        mod.RESULTS.clear()
        mod.check_policy_exists()
        pol_path = mod.ROOT / "docs" / "policy" / "migration_pathways.md"
        if pol_path.is_file():
            self.assertTrue(mod.RESULTS[0]["passed"])
        else:
            self.assertFalse(mod.RESULTS[0]["passed"])
        mod.RESULTS.clear()


class TestQuantitativeTargets(unittest.TestCase):
    """check_quantitative_targets validates all four thresholds."""

    def test_targets_in_spec(self) -> None:
        mod.RESULTS.clear()
        mod.check_quantitative_targets()
        spec_path = mod.ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
        if spec_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"Targets check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestPathwayRequirements(unittest.TestCase):
    """check_pathway_requirements validates all four requirement sections."""

    def test_requirements_in_spec(self) -> None:
        mod.RESULTS.clear()
        mod.check_pathway_requirements()
        spec_path = mod.ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
        if spec_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"Requirements check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestRiskScoring(unittest.TestCase):
    """check_risk_scoring validates three dimensions and weights."""

    def test_scoring_in_policy(self) -> None:
        mod.RESULTS.clear()
        mod.check_risk_scoring()
        pol_path = mod.ROOT / "docs" / "policy" / "migration_pathways.md"
        if pol_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"Risk scoring check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestRolloutStages(unittest.TestCase):
    """check_rollout_stages validates canary, progressive, full."""

    def test_stages_in_policy(self) -> None:
        mod.RESULTS.clear()
        mod.check_rollout_stages()
        pol_path = mod.ROOT / "docs" / "policy" / "migration_pathways.md"
        if pol_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"Rollout stages check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestRollbackRequirements(unittest.TestCase):
    """check_rollback_requirements validates time and data-loss constraints."""

    def test_rollback_in_policy(self) -> None:
        mod.RESULTS.clear()
        mod.check_rollback_requirements()
        pol_path = mod.ROOT / "docs" / "policy" / "migration_pathways.md"
        if pol_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"Rollback check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestEventCodes(unittest.TestCase):
    """check_event_codes validates MIG-001 through MIG-004."""

    def test_codes_in_spec(self) -> None:
        mod.RESULTS.clear()
        mod.check_event_codes()
        spec_path = mod.ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
        if spec_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"Event codes check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestInvariants(unittest.TestCase):
    """check_invariants validates all four INV-MIG-* invariants."""

    def test_invariants_in_spec(self) -> None:
        mod.RESULTS.clear()
        mod.check_invariants()
        spec_path = mod.ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
        if spec_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"Invariants check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestEvidenceArtifacts(unittest.TestCase):
    """check_evidence_artifacts validates evidence files exist."""

    def test_evidence_present(self) -> None:
        mod.RESULTS.clear()
        mod.check_evidence_artifacts()
        ev_json = mod.ROOT / "artifacts" / "section_13" / "bd-2f43" / "verification_evidence.json"
        ev_md = mod.ROOT / "artifacts" / "section_13" / "bd-2f43" / "verification_summary.md"
        expected = ev_json.is_file() and ev_md.is_file()
        self.assertEqual(mod.RESULTS[0]["passed"], expected)
        mod.RESULTS.clear()


class TestCohortStrategy(unittest.TestCase):
    """check_cohort_strategy validates Node/Bun references."""

    def test_cohorts_in_policy(self) -> None:
        mod.RESULTS.clear()
        mod.check_cohort_strategy()
        pol_path = mod.ROOT / "docs" / "policy" / "migration_pathways.md"
        if pol_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"Cohort strategy check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestCIGate(unittest.TestCase):
    """check_ci_gate validates CI gate definition in policy."""

    def test_gate_in_policy(self) -> None:
        mod.RESULTS.clear()
        mod.check_ci_gate()
        pol_path = mod.ROOT / "docs" / "policy" / "migration_pathways.md"
        if pol_path.is_file():
            self.assertTrue(
                mod.RESULTS[0]["passed"],
                f"CI gate check failed: {mod.RESULTS[0]['detail']}",
            )
        mod.RESULTS.clear()


class TestOverallPassWhenAllFilesPresent(unittest.TestCase):
    """When all deliverables exist, overall_passed should be True."""

    def test_overall(self) -> None:
        result = mod.run_all()
        # If any check failed, report which ones
        failures = [c for c in result["checks"] if not c["passed"]]
        if failures:
            names = [f["name"] for f in failures]
            self.fail(f"Checks failed: {names}")
        self.assertTrue(result["overall_passed"])


class TestJsonOutput(unittest.TestCase):
    """JSON output must be valid and contain required keys."""

    def test_json_serializable(self) -> None:
        result = mod.run_all()
        text = json.dumps(result, indent=2)
        parsed = json.loads(text)
        self.assertEqual(parsed["bead_id"], "bd-2f43")
        self.assertIsInstance(parsed["checks"], list)


if __name__ == "__main__":
    unittest.main()
