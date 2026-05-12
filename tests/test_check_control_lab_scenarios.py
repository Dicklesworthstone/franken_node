#!/usr/bin/env python3
"""Unit tests for check_control_lab_scenarios.py (bd-145n)."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_control_lab_scenarios as cls_mod


class TestCheckScenariosDocExists(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_scenarios_doc_exists()
        self.assertEqual(r["status"], "PASS")


class TestCheckSeedMatrixExists(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_seed_matrix_exists()
        self.assertEqual(r["status"], "PASS")

    def test_has_bead(self):
        data = json.loads(cls_mod.SEED_MATRIX.read_text())
        self.assertEqual(data["bead"], "bd-145n")


class TestCheckScenariosDocumented(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_scenarios_documented()
        self.assertEqual(r["status"], "PASS")

    def test_no_missing(self):
        r = cls_mod.check_scenarios_documented()
        self.assertEqual(r["details"]["missing"], [])


class TestCheckSeedControlledModel(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_seed_controlled_model()
        self.assertEqual(r["status"], "PASS")


class TestCheckInvariantsPerScenario(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_invariants_per_scenario()
        self.assertEqual(r["status"], "PASS")


class TestCheckFailureArtifactFormat(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_failure_artifact_format()
        self.assertEqual(r["status"], "PASS")


class TestCheckMatrixCoverage(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_matrix_all_scenarios_covered()
        self.assertEqual(r["status"], "PASS")

    def test_five_scenarios(self):
        r = cls_mod.check_matrix_all_scenarios_covered()
        self.assertEqual(r["details"]["covered"], 5)


class TestCheckMatrixAllPass(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_matrix_all_pass()
        self.assertEqual(r["status"], "PASS")


class TestCheckMatrixBoundarySeeds(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_matrix_boundary_seeds()
        self.assertEqual(r["status"], "PASS")


class TestCheckSpecContractExists(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_spec_contract_exists()
        self.assertEqual(r["status"], "PASS")


class TestCheckScenarioIndexExists(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_scenario_index_exists()
        self.assertEqual(r["status"], "PASS")

    def test_named_control_protocol_scenarios_present(self):
        r = cls_mod.check_scenario_index_exists()
        self.assertEqual(r["details"]["missing"], [])


class TestCheckTestFileExists(unittest.TestCase):
    def test_passes(self):
        r = cls_mod.check_test_file_exists()
        self.assertEqual(r["status"], "PASS")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        r = cls_mod.self_test()
        self.assertEqual(r["verdict"], "PASS")

    def test_all_checks_present(self):
        r = cls_mod.self_test()
        self.assertGreaterEqual(r["summary"]["total_checks"], 11)

    def test_no_failures(self):
        r = cls_mod.self_test()
        self.assertEqual(r["summary"]["failing_checks"], 0)

    def test_bead_field(self):
        r = cls_mod.self_test()
        self.assertEqual(r["bead"], "bd-145n")


if __name__ == "__main__":
    unittest.main()
