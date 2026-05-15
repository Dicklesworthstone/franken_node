"""Unit tests for check_execution_scorer.py verification logic."""

import contextlib
import importlib.util
import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = Path(ROOT) / "scripts" / "check_execution_scorer.py"

spec = importlib.util.spec_from_file_location("check_execution_scorer", str(SCRIPT))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class TestExecutionScorerCheckerCli(unittest.TestCase):

    def test_help_does_not_run_rust_tests(self):
        stdout = io.StringIO()
        with mock.patch.object(checker.subprocess, "run", side_effect=AssertionError("unexpected rust test")):
            with self.assertRaises(SystemExit) as raised:
                with contextlib.redirect_stdout(stdout):
                    checker.main(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--json", stdout.getvalue())
        self.assertIn("--skip-rust", stdout.getvalue())

    def test_json_mode_is_structural_without_rust_or_artifact_write(self):
        stdout = io.StringIO()
        with mock.patch.object(checker.subprocess, "run", side_effect=AssertionError("unexpected rust test")):
            with mock.patch.object(checker, "write_evidence", side_effect=AssertionError("unexpected evidence write")):
                with contextlib.redirect_stdout(stdout):
                    exit_code = checker.main(["--json"])

        self.assertEqual(exit_code, 1)
        evidence = json.loads(stdout.getvalue())
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        test_check = next(check for check in evidence["checks"] if check["id"] == "EPS-TESTS")
        self.assertEqual(test_check["status"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)

    def test_skip_rust_alias_sets_structural_mode(self):
        args = checker.parse_args(["--skip-rust"])
        self.assertTrue(args.structural_only)


class TestExecutionScorerFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-jxgt/planner_decision_explanations.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixtures_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-jxgt/planner_decision_explanations.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(len(data["scenarios"]), 3)

    def test_fixtures_have_tiebreak(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-jxgt/planner_decision_explanations.json")
        with open(path) as f:
            data = json.load(f)
        tiebreak = [s for s in data["scenarios"] if "tiebreak" in s.get("id", "")]
        self.assertGreater(len(tiebreak), 0)


class TestExecutionScorerImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/execution_scorer.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_scoring_weights(self):
        self.assertIn("struct ScoringWeights", self.content)

    def test_has_candidate_input(self):
        self.assertIn("struct CandidateInput", self.content)

    def test_has_scored_candidate(self):
        self.assertIn("struct ScoredCandidate", self.content)

    def test_has_planner_decision(self):
        self.assertIn("struct PlannerDecision", self.content)

    def test_has_factor_breakdown(self):
        self.assertIn("struct FactorBreakdown", self.content)

    def test_has_score_candidates(self):
        self.assertIn("fn score_candidates", self.content)

    def test_has_validate_weights(self):
        self.assertIn("fn validate_weights", self.content)

    def test_has_all_error_codes(self):
        for code in ["EPS_INVALID_WEIGHTS", "EPS_NO_CANDIDATES",
                     "EPS_INVALID_INPUT", "EPS_SCORE_OVERFLOW"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestExecutionScorerSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-jxgt_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-EPS-DETERMINISTIC", "INV-EPS-TIEBREAK",
                    "INV-EPS-EXPLAINABLE", "INV-EPS-REJECT-INVALID"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["EPS_INVALID_WEIGHTS", "EPS_NO_CANDIDATES",
                     "EPS_INVALID_INPUT", "EPS_SCORE_OVERFLOW"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestExecutionScorerIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/execution_planner_determinism.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_deterministic(self):
        self.assertIn("inv_eps_deterministic", self.content)

    def test_covers_tiebreak(self):
        self.assertIn("inv_eps_tiebreak", self.content)

    def test_covers_explainable(self):
        self.assertIn("inv_eps_explainable", self.content)

    def test_covers_reject_invalid(self):
        self.assertIn("inv_eps_reject_invalid", self.content)


if __name__ == "__main__":
    unittest.main()
