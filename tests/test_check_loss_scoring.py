#!/usr/bin/env python3
"""Unit tests for scripts/check_loss_scoring.py."""

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check_loss_scoring as scorer


class TestProbabilityValidation(unittest.TestCase):
    def test_probability_sum_must_be_one(self):
        with self.assertRaises(ValueError):
            scorer.validate_probabilities([0.5, 0.2], expected_len=2)

    def test_probability_length_mismatch(self):
        with self.assertRaises(ValueError):
            scorer.validate_probabilities([1.0], expected_len=2)

    def test_probability_range_violation(self):
        with self.assertRaises(ValueError):
            scorer.validate_probabilities([1.2, -0.2], expected_len=2)


class TestDegenerateMatrix(unittest.TestCase):
    def test_single_action_single_outcome(self):
        actions = ["do_nothing"]
        outcomes = ["single"]
        matrix = [[3.0]]
        probabilities = [1.0]
        result = scorer.score_action(
            "do_nothing",
            actions,
            outcomes,
            matrix,
            probabilities,
        )
        self.assertEqual(result["action"], "do_nothing")
        self.assertAlmostEqual(result["expected_loss"], 3.0)
        self.assertEqual(result["dominant_outcome"], "single")
        self.assertEqual(len(result["breakdown"]), 1)


class TestSensitivityAnalysis(unittest.TestCase):
    def test_reports_rank_changes(self):
        actions = ["do_nothing", "monitor", "block"]
        outcomes = ["false_alarm", "active_attack"]
        matrix = [[1.0, 100.0], [5.0, 60.0], [20.0, 20.0]]
        probabilities = [0.8, 0.2]

        records = scorer.sensitivity_analysis(
            actions, actions, outcomes, matrix, probabilities, delta=0.3
        )
        self.assertGreater(len(records), 0)
        self.assertTrue(any(record["action"] == "block" for record in records))
        for record in records:
            self.assertIn("parameter_name", record)
            self.assertIn("delta", record)
            self.assertIn("original_rank", record)
            self.assertIn("perturbed_rank", record)

    def test_invalid_delta_rejected(self):
        actions, outcomes, matrix, probabilities = scorer.build_reference_matrix()
        with self.assertRaises(ValueError):
            scorer.sensitivity_analysis(
                actions, actions, outcomes, matrix, probabilities, delta=0.0
            )


class TestVerificationAssets(unittest.TestCase):
    def test_script_file_exists(self):
        script_path = ROOT / "scripts" / "check_loss_scoring.py"
        self.assertTrue(script_path.is_file())

    def test_spec_exists(self):
        spec_path = ROOT / "docs" / "specs" / "section_10_5" / "bd-33b_contract.md"
        self.assertTrue(spec_path.is_file())

    def test_self_test_passes(self):
        result = scorer.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["summary"]["failing_checks"], 0)


if __name__ == "__main__":
    unittest.main()
