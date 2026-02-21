"""Unit tests for scripts/check_impossible_adoption.py."""

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
    "check_impossible_adoption",
    ROOT / "scripts" / "check_impossible_adoption.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# TestRunAllStructure
# ---------------------------------------------------------------------------


class TestRunAllStructure(unittest.TestCase):
    """Verify that run_all returns a properly structured report."""

    def setUp(self) -> None:
        self.report = mod.run_all()

    def test_returns_dict(self) -> None:
        self.assertIsInstance(self.report, dict)

    def test_has_bead_id(self) -> None:
        self.assertEqual(self.report["bead_id"], "bd-1xao")

    def test_has_section(self) -> None:
        self.assertEqual(self.report["section"], "13")

    def test_has_title(self) -> None:
        self.assertIn("title", self.report)
        self.assertIsInstance(self.report["title"], str)
        self.assertTrue(len(self.report["title"]) > 0)

    def test_has_verdict(self) -> None:
        self.assertIn(self.report["verdict"], ("PASS", "FAIL"))

    def test_has_total(self) -> None:
        self.assertIsInstance(self.report["total"], int)
        self.assertGreater(self.report["total"], 0)

    def test_has_passed(self) -> None:
        self.assertIsInstance(self.report["passed"], int)

    def test_has_failed(self) -> None:
        self.assertIsInstance(self.report["failed"], int)

    def test_passed_plus_failed_equals_total(self) -> None:
        self.assertEqual(
            self.report["passed"] + self.report["failed"],
            self.report["total"],
        )

    def test_has_checks_list(self) -> None:
        self.assertIsInstance(self.report["checks"], list)
        self.assertGreater(len(self.report["checks"]), 0)

    def test_checks_count_matches_total(self) -> None:
        self.assertEqual(len(self.report["checks"]), self.report["total"])

    def test_verdict_pass(self) -> None:
        self.assertEqual(self.report["verdict"], "PASS")

    def test_no_failures(self) -> None:
        self.assertEqual(self.report["failed"], 0)

    def test_minimum_check_count(self) -> None:
        """Must have at least 50 checks for a thorough verification."""
        self.assertGreaterEqual(self.report["total"], 50)


# ---------------------------------------------------------------------------
# TestSelfTest
# ---------------------------------------------------------------------------


class TestSelfTest(unittest.TestCase):
    """Verify the self_test function."""

    def test_self_test_passes(self) -> None:
        ok = mod.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_bool(self) -> None:
        result = mod.self_test()
        self.assertIsInstance(result, bool)


# ---------------------------------------------------------------------------
# TestIndividualChecks
# ---------------------------------------------------------------------------


class TestIndividualChecks(unittest.TestCase):
    """Verify individual check functions return proper results."""

    def test_check_spec_exists(self) -> None:
        result = mod.check_spec_exists()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_policy_exists(self) -> None:
        result = mod.check_policy_exists()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_event_codes_in_spec(self) -> None:
        results = mod.check_event_codes_in_spec()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_event_codes_in_policy(self) -> None:
        results = mod.check_event_codes_in_policy()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_invariants_in_spec(self) -> None:
        results = mod.check_invariants_in_spec()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_invariants_in_policy(self) -> None:
        results = mod.check_invariants_in_policy()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_capability_states_in_spec(self) -> None:
        results = mod.check_capability_states_in_spec()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_capability_states_in_policy(self) -> None:
        results = mod.check_capability_states_in_policy()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_adoption_tiers_in_spec(self) -> None:
        results = mod.check_adoption_tiers_in_spec()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_adoption_tiers_in_policy(self) -> None:
        results = mod.check_adoption_tiers_in_policy()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_dangerous_op_categories(self) -> None:
        results = mod.check_dangerous_op_categories()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_quantitative_targets_in_spec(self) -> None:
        results = mod.check_quantitative_targets_in_spec()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_coverage_threshold(self) -> None:
        result = mod.check_coverage_threshold()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_bypass_detection_target(self) -> None:
        result = mod.check_bypass_detection_target()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_audit_completeness_target(self) -> None:
        result = mod.check_audit_completeness_target()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_release_gate_threshold(self) -> None:
        result = mod.check_release_gate_threshold()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_state_machine_in_spec(self) -> None:
        result = mod.check_state_machine_in_spec()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_authorization_workflow(self) -> None:
        result = mod.check_authorization_workflow()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_acceptance_criteria(self) -> None:
        result = mod.check_acceptance_criteria()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_artifacts_table(self) -> None:
        result = mod.check_artifacts_table()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_policy_risk_description(self) -> None:
        result = mod.check_policy_risk_description()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_policy_impact(self) -> None:
        result = mod.check_policy_impact()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_policy_monitoring(self) -> None:
        results = mod.check_policy_monitoring()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_policy_escalation(self) -> None:
        results = mod.check_policy_escalation()
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")

    def test_check_policy_evidence_requirements(self) -> None:
        result = mod.check_policy_evidence_requirements()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_verification_evidence(self) -> None:
        result = mod.check_verification_evidence()
        self.assertTrue(result["pass"], result["detail"])

    def test_check_verification_summary(self) -> None:
        result = mod.check_verification_summary()
        self.assertTrue(result["pass"], result["detail"])


# ---------------------------------------------------------------------------
# TestMissingFileDetection
# ---------------------------------------------------------------------------


class TestMissingFileDetection(unittest.TestCase):
    """Verify that missing files are properly detected."""

    def test_spec_missing_detected(self) -> None:
        fake_path = ROOT / "nonexistent" / "spec.md"
        with patch.object(mod, "SPEC", fake_path):
            result = mod.check_spec_exists()
        self.assertFalse(result["pass"])
        self.assertIn("missing", result["detail"])

    def test_policy_missing_detected(self) -> None:
        fake_path = ROOT / "nonexistent" / "policy.md"
        with patch.object(mod, "POLICY", fake_path):
            result = mod.check_policy_exists()
        self.assertFalse(result["pass"])
        self.assertIn("missing", result["detail"])

    def test_evidence_missing_detected(self) -> None:
        fake_path = ROOT / "nonexistent" / "evidence.json"
        with patch.object(mod, "EVIDENCE", fake_path):
            result = mod.check_verification_evidence()
        self.assertFalse(result["pass"])
        self.assertIn("missing", result["detail"])

    def test_summary_missing_detected(self) -> None:
        fake_path = ROOT / "nonexistent" / "summary.md"
        with patch.object(mod, "SUMMARY", fake_path):
            result = mod.check_verification_summary()
        self.assertFalse(result["pass"])
        self.assertIn("missing", result["detail"])

    def test_event_codes_with_missing_spec(self) -> None:
        fake_path = ROOT / "nonexistent" / "spec.md"
        with patch.object(mod, "SPEC", fake_path):
            results = mod.check_event_codes_in_spec()
        for r in results:
            self.assertFalse(r["pass"])

    def test_event_codes_with_missing_policy(self) -> None:
        fake_path = ROOT / "nonexistent" / "policy.md"
        with patch.object(mod, "POLICY", fake_path):
            results = mod.check_event_codes_in_policy()
        for r in results:
            self.assertFalse(r["pass"])

    def test_invariants_with_missing_spec(self) -> None:
        fake_path = ROOT / "nonexistent" / "spec.md"
        with patch.object(mod, "SPEC", fake_path):
            results = mod.check_invariants_in_spec()
        for r in results:
            self.assertFalse(r["pass"])

    def test_coverage_threshold_with_missing_spec(self) -> None:
        fake_path = ROOT / "nonexistent" / "spec.md"
        with patch.object(mod, "SPEC", fake_path):
            result = mod.check_coverage_threshold()
        self.assertFalse(result["pass"])

    def test_bypass_detection_with_missing_spec(self) -> None:
        fake_path = ROOT / "nonexistent" / "spec.md"
        with patch.object(mod, "SPEC", fake_path):
            result = mod.check_bypass_detection_target()
        self.assertFalse(result["pass"])

    def test_audit_completeness_with_missing_spec(self) -> None:
        fake_path = ROOT / "nonexistent" / "spec.md"
        with patch.object(mod, "SPEC", fake_path):
            result = mod.check_audit_completeness_target()
        self.assertFalse(result["pass"])

    def test_release_gate_with_missing_spec(self) -> None:
        fake_path = ROOT / "nonexistent" / "spec.md"
        with patch.object(mod, "SPEC", fake_path):
            result = mod.check_release_gate_threshold()
        self.assertFalse(result["pass"])

    def test_state_machine_with_missing_spec(self) -> None:
        fake_path = ROOT / "nonexistent" / "spec.md"
        with patch.object(mod, "SPEC", fake_path):
            result = mod.check_state_machine_in_spec()
        self.assertFalse(result["pass"])


# ---------------------------------------------------------------------------
# TestConstants
# ---------------------------------------------------------------------------


class TestConstants(unittest.TestCase):
    """Verify module-level constants are correct."""

    def test_event_codes_count(self) -> None:
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_event_codes_prefix(self) -> None:
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("IBD-"), f"{code} missing IBD- prefix")

    def test_event_codes_values(self) -> None:
        self.assertIn("IBD-001", mod.EVENT_CODES)
        self.assertIn("IBD-002", mod.EVENT_CODES)
        self.assertIn("IBD-003", mod.EVENT_CODES)
        self.assertIn("IBD-004", mod.EVENT_CODES)

    def test_invariants_count(self) -> None:
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_prefix(self) -> None:
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-IBD-"), f"{inv} missing INV-IBD- prefix")

    def test_invariants_values(self) -> None:
        self.assertIn("INV-IBD-DEFAULT", mod.INVARIANTS)
        self.assertIn("INV-IBD-AUTH", mod.INVARIANTS)
        self.assertIn("INV-IBD-AUDIT", mod.INVARIANTS)
        self.assertIn("INV-IBD-COVERAGE", mod.INVARIANTS)

    def test_adoption_tiers_count(self) -> None:
        self.assertEqual(len(mod.ADOPTION_TIERS), 5)

    def test_adoption_tiers_values(self) -> None:
        for tier in ["A0", "A1", "A2", "A3", "A4"]:
            self.assertIn(tier, mod.ADOPTION_TIERS)

    def test_capability_states_count(self) -> None:
        self.assertEqual(len(mod.CAPABILITY_STATES), 4)

    def test_capability_states_values(self) -> None:
        for state in ["BLOCKED", "AUTHORIZED", "ACTIVE", "REVOKED"]:
            self.assertIn(state, mod.CAPABILITY_STATES)

    def test_dangerous_op_categories_minimum(self) -> None:
        self.assertGreaterEqual(len(mod.DANGEROUS_OP_CATEGORIES), 5)

    def test_quantitative_targets_keys(self) -> None:
        expected = {
            "capability_coverage",
            "bypass_detection_rate",
            "authorization_audit_completeness",
            "operator_adoption_rate",
            "mean_time_to_authorize",
            "revocation_latency",
        }
        self.assertEqual(set(mod.QUANTITATIVE_TARGETS.keys()), expected)

    def test_quantitative_target_coverage(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["capability_coverage"]
        self.assertEqual(t["operator"], ">=")
        self.assertEqual(t["value"], 95)

    def test_quantitative_target_bypass(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["bypass_detection_rate"]
        self.assertEqual(t["operator"], "==")
        self.assertEqual(t["value"], 100)

    def test_quantitative_target_audit(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["authorization_audit_completeness"]
        self.assertEqual(t["operator"], "==")
        self.assertEqual(t["value"], 100)

    def test_quantitative_target_operator(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["operator_adoption_rate"]
        self.assertEqual(t["operator"], ">=")
        self.assertEqual(t["value"], 90)

    def test_quantitative_target_time_to_auth(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["mean_time_to_authorize"]
        self.assertEqual(t["operator"], "<=")
        self.assertEqual(t["value"], 24)

    def test_quantitative_target_revocation(self) -> None:
        t = mod.QUANTITATIVE_TARGETS["revocation_latency"]
        self.assertEqual(t["operator"], "<=")
        self.assertEqual(t["value"], 1)

    def test_all_checks_nonempty(self) -> None:
        self.assertGreater(len(mod.ALL_CHECKS), 0)

    def test_all_checks_are_callable(self) -> None:
        for fn in mod.ALL_CHECKS:
            self.assertTrue(callable(fn), f"{fn} is not callable")


# ---------------------------------------------------------------------------
# TestJsonOutput
# ---------------------------------------------------------------------------


class TestJsonOutput(unittest.TestCase):
    """Verify that the report is JSON-serializable."""

    def test_json_serializable(self) -> None:
        report = mod.run_all()
        serialized = json.dumps(report)
        self.assertIsInstance(serialized, str)

    def test_json_roundtrip(self) -> None:
        report = mod.run_all()
        serialized = json.dumps(report)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["bead_id"], "bd-1xao")
        self.assertEqual(deserialized["section"], "13")

    def test_all_checks_have_required_keys(self) -> None:
        report = mod.run_all()
        for check in report["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)

    def test_check_pass_is_bool(self) -> None:
        report = mod.run_all()
        for check in report["checks"]:
            self.assertIsInstance(check["pass"], bool)

    def test_check_name_is_str(self) -> None:
        report = mod.run_all()
        for check in report["checks"]:
            self.assertIsInstance(check["check"], str)

    def test_check_detail_is_str(self) -> None:
        report = mod.run_all()
        for check in report["checks"]:
            self.assertIsInstance(check["detail"], str)


# ---------------------------------------------------------------------------
# TestSafeRel
# ---------------------------------------------------------------------------


class TestSafeRel(unittest.TestCase):
    """Verify the _safe_rel utility function."""

    def test_path_under_root(self) -> None:
        p = mod.ROOT / "docs" / "test.md"
        result = mod._safe_rel(p)
        self.assertEqual(result, "docs/test.md")

    def test_path_outside_root(self) -> None:
        p = Path("/tmp/some/other/path.md")
        result = mod._safe_rel(p)
        self.assertEqual(result, "/tmp/some/other/path.md")

    def test_root_itself(self) -> None:
        result = mod._safe_rel(mod.ROOT)
        self.assertEqual(result, ".")

    def test_deeply_nested(self) -> None:
        p = mod.ROOT / "a" / "b" / "c" / "d.txt"
        result = mod._safe_rel(p)
        self.assertEqual(result, "a/b/c/d.txt")


# ---------------------------------------------------------------------------
# TestValidateAdoptionMetrics
# ---------------------------------------------------------------------------


class TestValidateAdoptionMetrics(unittest.TestCase):
    """Verify the validate_adoption_metrics helper."""

    def test_valid_metrics_accepted(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertEqual(errors, [])

    def test_missing_coverage_pct(self) -> None:
        metrics = {
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("coverage_pct" in e for e in errors))

    def test_coverage_pct_out_of_range(self) -> None:
        metrics = {
            "coverage_pct": 150.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("out of range" in e for e in errors))

    def test_coverage_pct_negative(self) -> None:
        metrics = {
            "coverage_pct": -5.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("out of range" in e for e in errors))

    def test_coverage_pct_non_numeric(self) -> None:
        metrics = {
            "coverage_pct": "high",
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("numeric" in e for e in errors))

    def test_missing_bypass_attempts(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("bypass_attempts" in e for e in errors))

    def test_bypass_attempts_negative(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "bypass_attempts": -1,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("negative" in e for e in errors))

    def test_invalid_tier(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "X9",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("invalid tier" in e for e in errors))

    def test_missing_tier(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("tier" in e for e in errors))

    def test_gated_exceeds_total(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 60,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("exceeds" in e for e in errors))

    def test_total_operations_zero(self) -> None:
        metrics = {
            "coverage_pct": 0.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A0",
            "gated_operations": 0,
            "total_operations": 0,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("total_operations" in e for e in errors))

    def test_tier_mismatch_detected(self) -> None:
        metrics = {
            "coverage_pct": 50.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 25,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("mismatch" in e for e in errors))

    def test_tier_matches_coverage(self) -> None:
        test_cases = [
            (45.0, "A0"), (50.0, "A1"), (75.0, "A2"),
            (90.0, "A3"), (95.0, "A4"), (100.0, "A4"),
        ]
        for pct, tier in test_cases:
            metrics = {
                "coverage_pct": pct,
                "bypass_attempts": 0,
                "audit_completeness_pct": 100.0,
                "tier": tier,
                "gated_operations": int(pct),
                "total_operations": 100,
            }
            errors = mod.validate_adoption_metrics(metrics)
            self.assertEqual(errors, [], f"pct={pct}, tier={tier}: {errors}")

    def test_empty_metrics(self) -> None:
        errors = mod.validate_adoption_metrics({})
        self.assertGreater(len(errors), 0)

    def test_audit_completeness_out_of_range(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 110.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("audit_completeness_pct" in e for e in errors))

    def test_gated_operations_non_int(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "bypass_attempts": 0,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48.5,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("gated_operations" in e for e in errors))

    def test_bypass_attempts_non_int(self) -> None:
        metrics = {
            "coverage_pct": 96.0,
            "bypass_attempts": 1.5,
            "audit_completeness_pct": 100.0,
            "tier": "A4",
            "gated_operations": 48,
            "total_operations": 50,
        }
        errors = mod.validate_adoption_metrics(metrics)
        self.assertTrue(any("bypass_attempts" in e for e in errors))


# ---------------------------------------------------------------------------
# TestCoverageToTier
# ---------------------------------------------------------------------------


class TestCoverageToTier(unittest.TestCase):
    """Verify the coverage_to_tier helper."""

    def test_a0_below_50(self) -> None:
        self.assertEqual(mod.coverage_to_tier(0), "A0")
        self.assertEqual(mod.coverage_to_tier(25), "A0")
        self.assertEqual(mod.coverage_to_tier(49.9), "A0")

    def test_a1_50_to_74(self) -> None:
        self.assertEqual(mod.coverage_to_tier(50), "A1")
        self.assertEqual(mod.coverage_to_tier(60), "A1")
        self.assertEqual(mod.coverage_to_tier(74.9), "A1")

    def test_a2_75_to_89(self) -> None:
        self.assertEqual(mod.coverage_to_tier(75), "A2")
        self.assertEqual(mod.coverage_to_tier(80), "A2")
        self.assertEqual(mod.coverage_to_tier(89.9), "A2")

    def test_a3_90_to_94(self) -> None:
        self.assertEqual(mod.coverage_to_tier(90), "A3")
        self.assertEqual(mod.coverage_to_tier(92), "A3")
        self.assertEqual(mod.coverage_to_tier(94.9), "A3")

    def test_a4_95_and_above(self) -> None:
        self.assertEqual(mod.coverage_to_tier(95), "A4")
        self.assertEqual(mod.coverage_to_tier(97.5), "A4")
        self.assertEqual(mod.coverage_to_tier(100), "A4")

    def test_exact_boundaries(self) -> None:
        self.assertEqual(mod.coverage_to_tier(50), "A1")
        self.assertEqual(mod.coverage_to_tier(75), "A2")
        self.assertEqual(mod.coverage_to_tier(90), "A3")
        self.assertEqual(mod.coverage_to_tier(95), "A4")

    def test_return_type(self) -> None:
        result = mod.coverage_to_tier(50)
        self.assertIsInstance(result, str)

    def test_zero(self) -> None:
        self.assertEqual(mod.coverage_to_tier(0), "A0")


# ---------------------------------------------------------------------------
# TestAdoptionTiers
# ---------------------------------------------------------------------------


class TestAdoptionTiers(unittest.TestCase):
    """Verify adoption tier constants and their relationship to coverage."""

    def test_tiers_ordered(self) -> None:
        self.assertEqual(mod.ADOPTION_TIERS, ["A0", "A1", "A2", "A3", "A4"])

    def test_release_gate_is_a3(self) -> None:
        """A3 is the minimum for release gate."""
        self.assertIn("A3", mod.ADOPTION_TIERS)

    def test_highest_tier_is_a4(self) -> None:
        self.assertEqual(mod.ADOPTION_TIERS[-1], "A4")

    def test_lowest_tier_is_a0(self) -> None:
        self.assertEqual(mod.ADOPTION_TIERS[0], "A0")

    def test_coverage_to_tier_covers_all_tiers(self) -> None:
        """Every tier must be reachable from some coverage value."""
        reached = set()
        for pct in [0, 25, 50, 60, 75, 85, 90, 93, 95, 100]:
            reached.add(mod.coverage_to_tier(pct))
        self.assertEqual(reached, set(mod.ADOPTION_TIERS))


# ---------------------------------------------------------------------------
# TestCliExecution
# ---------------------------------------------------------------------------


class TestCliExecution(unittest.TestCase):
    """Verify the script works when invoked as a subprocess."""

    def test_json_flag(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_impossible_adoption.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["bead_id"], "bd-1xao")
        self.assertEqual(data["verdict"], "PASS")

    def test_self_test_flag(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_impossible_adoption.py"), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)

    def test_plain_output(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_impossible_adoption.py")],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("verdict=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
