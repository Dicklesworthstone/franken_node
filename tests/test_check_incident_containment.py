"""Unit tests for scripts/check_incident_containment.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_incident_containment",
    ROOT / "scripts" / "check_incident_containment.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants(TestCase):
    def test_event_codes_count(self) -> None:
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_event_codes_prefix(self) -> None:
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("DIC-"), f"{code} missing DIC- prefix")

    def test_event_codes_values(self) -> None:
        self.assertIn("DIC-001", mod.EVENT_CODES)
        self.assertIn("DIC-002", mod.EVENT_CODES)
        self.assertIn("DIC-003", mod.EVENT_CODES)
        self.assertIn("DIC-004", mod.EVENT_CODES)

    def test_invariants_count(self) -> None:
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_prefix(self) -> None:
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-DIC-"), f"{inv} missing INV-DIC- prefix")

    def test_invariants_values(self) -> None:
        self.assertIn("INV-DIC-CONTAIN", mod.INVARIANTS)
        self.assertIn("INV-DIC-EXPLAIN", mod.INVARIANTS)
        self.assertIn("INV-DIC-BOUND", mod.INVARIANTS)
        self.assertIn("INV-DIC-COMPLETE", mod.INVARIANTS)

    def test_containment_actions_minimum(self) -> None:
        self.assertGreaterEqual(len(mod.CONTAINMENT_ACTIONS), 5)

    def test_containment_actions_values(self) -> None:
        self.assertIn("isolate_component", mod.CONTAINMENT_ACTIONS)
        self.assertIn("shed_load", mod.CONTAINMENT_ACTIONS)
        self.assertIn("revoke_credentials", mod.CONTAINMENT_ACTIONS)

    def test_quantitative_targets_keys(self) -> None:
        expected = {"blast_radius", "time_to_contain", "evidence_completeness", "explanation_reproducibility"}
        self.assertEqual(set(mod.QUANTITATIVE_TARGETS.keys()), expected)

    def test_quantitative_target_blast_radius(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["blast_radius"]
        self.assertEqual(t["operator"], "<=")
        self.assertEqual(t["value"], 3)

    def test_quantitative_target_time_to_contain(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["time_to_contain"]
        self.assertEqual(t["operator"], "<=")
        self.assertEqual(t["value"], 60)

    def test_quantitative_target_evidence_completeness(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["evidence_completeness"]
        self.assertEqual(t["operator"], ">=")
        self.assertEqual(t["value"], 95)

    def test_quantitative_target_explanation_reproducibility(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["explanation_reproducibility"]
        self.assertEqual(t["operator"], "==")
        self.assertEqual(t["value"], 100)

    def test_explanation_dimensions_count(self) -> None:
        self.assertEqual(len(mod.EXPLANATION_DIMENSIONS), 3)

    def test_containment_dimensions_count(self) -> None:
        self.assertEqual(len(mod.CONTAINMENT_DIMENSIONS), 3)


# ---------------------------------------------------------------------------
# File existence checks
# ---------------------------------------------------------------------------


class TestFileChecks(TestCase):
    def test_spec_exists(self) -> None:
        result = mod.check_spec_exists()
        self.assertTrue(result["pass"], result["detail"])

    def test_policy_exists(self) -> None:
        result = mod.check_policy_exists()
        self.assertTrue(result["pass"], result["detail"])

    def test_spec_missing_detected(self) -> None:
        with patch.object(mod, "SPEC", ROOT / "nonexistent" / "file.md"):
            result = mod.check_spec_exists()
        self.assertFalse(result["pass"])
        self.assertIn("missing", result["detail"])

    def test_policy_missing_detected(self) -> None:
        with patch.object(mod, "POLICY", ROOT / "nonexistent" / "file.md"):
            result = mod.check_policy_exists()
        self.assertFalse(result["pass"])
        self.assertIn("missing", result["detail"])


# ---------------------------------------------------------------------------
# Containment and explanation documentation
# ---------------------------------------------------------------------------


class TestContainmentDocumented(TestCase):
    def test_containment_dimensions_found(self) -> None:
        results = mod.check_containment_documented()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_explanation_dimensions_found(self) -> None:
        results = mod.check_explanation_documented()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")


# ---------------------------------------------------------------------------
# Quantitative threshold checks
# ---------------------------------------------------------------------------


class TestQuantitativeChecks(TestCase):
    def test_blast_radius(self) -> None:
        result = mod.check_blast_radius()
        self.assertTrue(result["pass"], result["detail"])

    def test_time_to_contain(self) -> None:
        result = mod.check_time_to_contain()
        self.assertTrue(result["pass"], result["detail"])

    def test_evidence_completeness(self) -> None:
        result = mod.check_evidence_completeness()
        self.assertTrue(result["pass"], result["detail"])


# ---------------------------------------------------------------------------
# Event codes and invariants
# ---------------------------------------------------------------------------


class TestEventCodesAndInvariants(TestCase):
    def test_event_codes_in_docs(self) -> None:
        results = mod.check_event_codes()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_invariants_in_spec(self) -> None:
        results = mod.check_invariants()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")


# ---------------------------------------------------------------------------
# Policy sub-checks
# ---------------------------------------------------------------------------


class TestPolicyChecks(TestCase):
    def test_policy_containment_contract(self) -> None:
        results = mod.check_policy_containment_contract()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_policy_explanation_contract(self) -> None:
        results = mod.check_policy_explanation_contract()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_policy_escalation(self) -> None:
        results = mod.check_policy_escalation()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_policy_monitoring(self) -> None:
        results = mod.check_policy_monitoring()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_policy_evidence_requirements(self) -> None:
        result = mod.check_policy_evidence_requirements()
        self.assertTrue(result["pass"], result["detail"])


# ---------------------------------------------------------------------------
# Determinism contracts
# ---------------------------------------------------------------------------


class TestDeterminismContracts(TestCase):
    def test_determinism_contracts_documented(self) -> None:
        results = mod.check_determinism_contracts()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")


# ---------------------------------------------------------------------------
# Acceptance criteria and quantitative targets table
# ---------------------------------------------------------------------------


class TestAcceptanceCriteria(TestCase):
    def test_acceptance_criteria_section(self) -> None:
        results = mod.check_acceptance_criteria()
        section_check = results[0]
        self.assertTrue(section_check["pass"], section_check["detail"])

    def test_quantitative_targets_table(self) -> None:
        results = mod.check_quantitative_targets()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")


# ---------------------------------------------------------------------------
# Verification artifacts
# ---------------------------------------------------------------------------


class TestVerificationArtifacts(TestCase):
    def test_evidence_exists_and_valid(self) -> None:
        result = mod.check_verification_evidence()
        self.assertTrue(result["pass"], result["detail"])

    def test_summary_exists_and_valid(self) -> None:
        result = mod.check_verification_summary()
        self.assertTrue(result["pass"], result["detail"])

    def test_evidence_missing_detected(self) -> None:
        with patch.object(mod, "EVIDENCE", ROOT / "nonexistent" / "file.json"):
            result = mod.check_verification_evidence()
        self.assertFalse(result["pass"])

    def test_summary_missing_detected(self) -> None:
        with patch.object(mod, "SUMMARY", ROOT / "nonexistent" / "file.md"):
            result = mod.check_verification_summary()
        self.assertFalse(result["pass"])


# ---------------------------------------------------------------------------
# run_all and self_test
# ---------------------------------------------------------------------------


class TestRunAll(TestCase):
    def test_run_all_returns_dict(self) -> None:
        report = mod.run_all()
        self.assertIsInstance(report, dict)

    def test_run_all_bead_id(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["bead_id"], "bd-pga7")

    def test_run_all_section(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["section"], "13")

    def test_run_all_verdict_pass(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["verdict"], "PASS")

    def test_run_all_overall_pass(self) -> None:
        report = mod.run_all()
        self.assertTrue(report["overall_pass"])

    def test_run_all_has_summary(self) -> None:
        report = mod.run_all()
        self.assertIn("summary", report)
        self.assertIn("passing", report["summary"])
        self.assertIn("failing", report["summary"])
        self.assertIn("total", report["summary"])

    def test_run_all_no_failures(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["summary"]["failing"], 0)

    def test_run_all_checks_nonempty(self) -> None:
        report = mod.run_all()
        self.assertGreater(len(report["checks"]), 20)


class TestSelfTest(TestCase):
    def test_self_test_passes(self) -> None:
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)

    def test_self_test_message(self) -> None:
        ok, msg = mod.self_test()
        self.assertIn("pass", msg.lower())


class TestJsonOutput(TestCase):
    def test_run_all_json_serializable(self) -> None:
        report = mod.run_all()
        serialized = json.dumps(report)
        self.assertIsInstance(serialized, str)

    def test_all_checks_have_required_keys(self) -> None:
        report = mod.run_all()
        for check in report["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)


if __name__ == "__main__":
    main()
