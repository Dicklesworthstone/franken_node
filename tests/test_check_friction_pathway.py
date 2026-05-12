#!/usr/bin/env python3
"""Unit tests for scripts/check_friction_pathway.py (bd-34d5)."""

import contextlib
import io
import json
import sys
import unittest
from importlib import util as importlib_util
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def load_check_friction_pathway():
    spec = importlib_util.spec_from_file_location(
        "check_friction_pathway",
        ROOT / "scripts" / "check_friction_pathway.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load check_friction_pathway.py")
    module = importlib_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cfp = load_check_friction_pathway()


class TestCheckFrictionPathway(unittest.TestCase):
    """Tests for each verification check."""

    def parse_json_output(self, payload: str):
        decoder = json.JSONDecoder()
        try:
            return decoder.decode(payload)
        except json.JSONDecodeError as exc:
            self.fail(f"Expected valid JSON output, got: {exc}: {payload!r}")

    def run_cli(self, *args: str):
        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = ["check_friction_pathway.py", *args]
        with patch.object(sys, "argv", argv):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exit_info:
                    cfp.main()
        self.assertEqual(exit_info.exception.code, 0, f"Script failed: {stderr.getvalue()}")
        return stdout.getvalue()

    # ------------------------------------------------------------------
    # Structural self-test
    # ------------------------------------------------------------------
    def test_self_test(self):
        """self_test() must not raise."""
        cfp.self_test()

    # ------------------------------------------------------------------
    # File-existence checks
    # ------------------------------------------------------------------
    def test_spec_exists(self):
        result = cfp.check_spec_exists()
        self.assertIn("check", result)
        self.assertEqual(result["check"], "spec_exists")
        self.assertIsInstance(result["passed"], bool)
        self.assertTrue(result["passed"], "Spec file should exist")

    def test_policy_exists(self):
        result = cfp.check_policy_exists()
        self.assertEqual(result["check"], "policy_exists")
        self.assertTrue(result["passed"], "Policy file should exist")

    # ------------------------------------------------------------------
    # Archetype checks
    # ------------------------------------------------------------------
    def test_archetypes_defined(self):
        result = cfp.check_archetypes()
        self.assertEqual(result["check"], "archetypes_defined")
        self.assertTrue(result["passed"], result["detail"])

    def test_archetype_scores(self):
        result = cfp.check_archetype_scores()
        self.assertEqual(result["check"], "archetype_scores")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Time budget
    # ------------------------------------------------------------------
    def test_time_budget(self):
        result = cfp.check_time_budget()
        self.assertEqual(result["check"], "time_budget")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Zero-edit requirement
    # ------------------------------------------------------------------
    def test_zero_edit(self):
        result = cfp.check_zero_edit()
        self.assertEqual(result["check"], "zero_edit_requirement")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Event codes
    # ------------------------------------------------------------------
    def test_event_codes(self):
        result = cfp.check_event_codes()
        self.assertEqual(result["check"], "event_codes")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Invariants
    # ------------------------------------------------------------------
    def test_invariants(self):
        result = cfp.check_invariants()
        self.assertEqual(result["check"], "invariants")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Policy content checks
    # ------------------------------------------------------------------
    def test_telemetry_in_policy(self):
        result = cfp.check_telemetry_in_policy()
        self.assertEqual(result["check"], "telemetry_policy")
        self.assertTrue(result["passed"], result["detail"])

    def test_error_handling_policy(self):
        result = cfp.check_error_handling_policy()
        self.assertEqual(result["check"], "error_handling_policy")
        self.assertTrue(result["passed"], result["detail"])

    def test_ci_gate_policy(self):
        result = cfp.check_ci_gate_policy()
        self.assertEqual(result["check"], "ci_gate_policy")
        self.assertTrue(result["passed"], result["detail"])

    def test_spec_sections(self):
        result = cfp.check_spec_sections()
        self.assertEqual(result["check"], "spec_sections")
        self.assertTrue(result["passed"], result["detail"])

    def test_policy_pathway_steps(self):
        result = cfp.check_policy_pathway_steps()
        self.assertEqual(result["check"], "policy_pathway_steps")
        self.assertTrue(result["passed"], result["detail"])

    def test_current_surface_reality(self):
        result = cfp.check_current_surface_reality()
        self.assertEqual(result["check"], "current_surface_reality")
        self.assertTrue(result["passed"], result["detail"])

    def test_current_reporting_surface(self):
        result = cfp.check_current_reporting_surface()
        self.assertEqual(result["check"], "current_reporting_surface")
        self.assertTrue(result["passed"], result["detail"])

    def test_named_pathway_artifacts(self):
        result = cfp.check_named_pathway_artifacts()
        self.assertEqual(result["check"], "named_pathway_artifacts")
        self.assertTrue(result["passed"], result["detail"])

    def test_onboarding_timing_report(self):
        result = cfp.check_onboarding_timing_report()
        self.assertEqual(result["check"], "onboarding_timing_report")
        self.assertTrue(result["passed"], result["detail"])

    def test_completion_debt_citations(self):
        result = cfp.check_completion_debt_citations()
        self.assertEqual(result["check"], "completion_debt_citations")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Aggregate run
    # ------------------------------------------------------------------
    def test_run_all_checks_count(self):
        results = cfp.run_all_checks()
        self.assertEqual(len(results), len(cfp.ALL_CHECKS))

    def test_run_all_checks_pass(self):
        results = cfp.run_all_checks()
        for r in results:
            self.assertTrue(r["passed"], f"Check '{r['check']}' failed: {r['detail']}")

    # ------------------------------------------------------------------
    # Evidence and summary generation
    # ------------------------------------------------------------------
    def test_write_evidence(self):
        results = cfp.run_all_checks()
        cfp.write_evidence(results)
        self.assertTrue(cfp.EVIDENCE_PATH.is_file(), "Evidence file should be written")
        data = self.parse_json_output(cfp.EVIDENCE_PATH.read_text())
        self.assertEqual(data["bead_id"], "bd-34d5")
        self.assertEqual(data["total_checks"], len(results))
        self.assertIn("checks", data)

    def test_write_summary(self):
        results = cfp.run_all_checks()
        cfp.write_summary(results)
        self.assertTrue(cfp.SUMMARY_PATH.is_file(), "Summary file should be written")
        content = cfp.SUMMARY_PATH.read_text()
        self.assertIn("bd-34d5", content)
        self.assertIn("PASS", content)

    # ------------------------------------------------------------------
    # CLI --json output
    # ------------------------------------------------------------------
    def test_cli_json_output(self):
        data = self.parse_json_output(self.run_cli("--json"))
        self.assertEqual(data["bead_id"], "bd-34d5")
        self.assertTrue(data["all_passed"])

    def test_cli_human_output(self):
        output = self.run_cli()
        self.assertIn("bd-34d5", output)
        self.assertIn("PASS", output)

    # ------------------------------------------------------------------
    # Missing-file edge cases (mock Path.is_file to return False)
    # ------------------------------------------------------------------
    def test_spec_missing_graceful(self):
        with patch.object(cfp, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = cfp.check_spec_exists()
            self.assertFalse(result["passed"])

    def test_policy_missing_graceful(self):
        with patch.object(cfp, "POLICY_PATH", Path("/nonexistent/policy.md")):
            result = cfp.check_policy_exists()
            self.assertFalse(result["passed"])

    def test_archetypes_missing_spec_graceful(self):
        with patch.object(cfp, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = cfp.check_archetypes()
            self.assertFalse(result["passed"])
            self.assertIn("missing", result["detail"].lower())

    def test_event_codes_missing_spec_graceful(self):
        with patch.object(cfp, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = cfp.check_event_codes()
            self.assertFalse(result["passed"])

    def test_invariants_missing_spec_graceful(self):
        with patch.object(cfp, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = cfp.check_invariants()
            self.assertFalse(result["passed"])

    def test_telemetry_missing_policy_graceful(self):
        with patch.object(cfp, "POLICY_PATH", Path("/nonexistent/policy.md")):
            result = cfp.check_telemetry_in_policy()
            self.assertFalse(result["passed"])

    def test_current_reporting_missing_policy_graceful(self):
        with patch.object(cfp, "POLICY_PATH", Path("/nonexistent/policy.md")):
            result = cfp.check_current_reporting_surface()
            self.assertFalse(result["passed"])

    def test_error_handling_missing_policy_graceful(self):
        with patch.object(cfp, "POLICY_PATH", Path("/nonexistent/policy.md")):
            result = cfp.check_error_handling_policy()
            self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
