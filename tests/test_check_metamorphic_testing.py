#!/usr/bin/env python3
"""Unit tests for check_metamorphic_testing.py verification script."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_metamorphic_testing as checker


class TestCheckFilesExist(unittest.TestCase):
    def test_spec_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        spec_check = [r for r in checker.RESULTS if r["name"] == "file_exists:spec"]
        self.assertEqual(len(spec_check), 1)
        self.assertTrue(spec_check[0]["pass"])

    def test_policy_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        pol_check = [r for r in checker.RESULTS if r["name"] == "file_exists:policy"]
        self.assertEqual(len(pol_check), 1)
        self.assertTrue(pol_check[0]["pass"])

    def test_returns_count(self):
        checker.RESULTS.clear()
        count = checker.check_files_exist()
        self.assertEqual(count, 2)


class TestSafeRel(unittest.TestCase):
    def test_relative_within_root(self):
        p = checker.ROOT / "some" / "file.md"
        self.assertEqual(checker._safe_rel(p), "some/file.md")

    def test_absolute_outside_root(self):
        p = Path("/tmp/other/file.md")
        self.assertEqual(checker._safe_rel(p), "/tmp/other/file.md")


class TestCheckMetamorphicRelations(unittest.TestCase):
    def test_all_relations_found(self):
        checker.RESULTS.clear()
        count = checker.check_metamorphic_relations()
        self.assertEqual(count, 4)

    def test_equiv_found(self):
        checker.RESULTS.clear()
        checker.check_metamorphic_relations()
        equiv = [r for r in checker.RESULTS if "MR-EQUIV" in r["name"]]
        self.assertTrue(equiv[0]["pass"])

    def test_mono_found(self):
        checker.RESULTS.clear()
        checker.check_metamorphic_relations()
        mono = [r for r in checker.RESULTS if "MR-MONO" in r["name"]]
        self.assertTrue(mono[0]["pass"])

    def test_idem_found(self):
        checker.RESULTS.clear()
        checker.check_metamorphic_relations()
        idem = [r for r in checker.RESULTS if "MR-IDEM" in r["name"]]
        self.assertTrue(idem[0]["pass"])

    def test_comm_found(self):
        checker.RESULTS.clear()
        checker.check_metamorphic_relations()
        comm = [r for r in checker.RESULTS if "MR-COMM" in r["name"]]
        self.assertTrue(comm[0]["pass"])


class TestCheckEventCodes(unittest.TestCase):
    def test_all_event_codes_found(self):
        checker.RESULTS.clear()
        count = checker.check_event_codes()
        self.assertEqual(count, 4)

    def test_mmt001(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        c = [r for r in checker.RESULTS if "MMT-001" in r["name"]]
        self.assertTrue(c[0]["pass"])


class TestCheckInvariants(unittest.TestCase):
    def test_all_invariants_found(self):
        checker.RESULTS.clear()
        count = checker.check_invariants()
        self.assertEqual(count, 4)

    def test_relations_invariant(self):
        checker.RESULTS.clear()
        checker.check_invariants()
        inv = [r for r in checker.RESULTS if "INV-MMT-RELATIONS" in r["name"]]
        self.assertTrue(inv[0]["pass"])

    def test_corpus_invariant(self):
        checker.RESULTS.clear()
        checker.check_invariants()
        inv = [r for r in checker.RESULTS if "INV-MMT-CORPUS" in r["name"]]
        self.assertTrue(inv[0]["pass"])


class TestCheckErrorCodes(unittest.TestCase):
    def test_all_error_codes_found(self):
        checker.RESULTS.clear()
        count = checker.check_error_codes()
        self.assertEqual(count, 4)


class TestCheckOracleDesign(unittest.TestCase):
    def test_oracle_free_present(self):
        checker.RESULTS.clear()
        checker.check_oracle_design()
        orc = [r for r in checker.RESULTS if "oracle-free" in r["name"]]
        self.assertTrue(orc[0]["pass"])

    def test_all_oracle_keywords(self):
        checker.RESULTS.clear()
        count = checker.check_oracle_design()
        self.assertEqual(count, 4)


class TestCheckGenerationStrategy(unittest.TestCase):
    def test_all_generation_keywords(self):
        checker.RESULTS.clear()
        count = checker.check_generation_strategy()
        self.assertEqual(count, 4)


class TestCheckViolationReporting(unittest.TestCase):
    def test_all_violation_fields(self):
        checker.RESULTS.clear()
        count = checker.check_violation_reporting()
        self.assertEqual(count, 7)

    def test_divergence_point_present(self):
        checker.RESULTS.clear()
        checker.check_violation_reporting()
        dp = [r for r in checker.RESULTS if "divergence_point" in r["name"]]
        self.assertTrue(dp[0]["pass"])


class TestCheckCIIntegration(unittest.TestCase):
    def test_all_ci_keywords(self):
        checker.RESULTS.clear()
        count = checker.check_ci_integration()
        self.assertEqual(count, 4)


class TestCheckCorpusRequirements(unittest.TestCase):
    def test_all_corpus_keywords(self):
        checker.RESULTS.clear()
        count = checker.check_corpus_requirements()
        self.assertEqual(count, 5)


class TestCheckComparisonModes(unittest.TestCase):
    def test_all_comparison_modes(self):
        checker.RESULTS.clear()
        count = checker.check_comparison_modes()
        self.assertEqual(count, 4)


class TestCheckAcceptanceCriteria(unittest.TestCase):
    def test_all_acceptance_keywords(self):
        checker.RESULTS.clear()
        count = checker.check_acceptance_criteria()
        self.assertEqual(count, 4)


class TestCheckRelationDescriptions(unittest.TestCase):
    def test_all_relation_descriptions(self):
        checker.RESULTS.clear()
        count = checker.check_relation_descriptions()
        self.assertEqual(count, 4)


class TestCheckSeverityClassification(unittest.TestCase):
    def test_all_severity_keywords(self):
        checker.RESULTS.clear()
        count = checker.check_severity_classification()
        self.assertEqual(count, 3)


class TestCheckPluggableInterface(unittest.TestCase):
    def test_all_pluggable_keywords(self):
        checker.RESULTS.clear()
        count = checker.check_pluggable_interface()
        self.assertEqual(count, 3)


class TestRunAll(unittest.TestCase):
    def test_full_run(self):
        result = checker.run_all()
        self.assertIn("checks", result)
        self.assertIn("total", result)
        self.assertIn("passed", result)
        self.assertIn("failed", result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-1u4")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.7")

    def test_verdict_pass(self):
        result = checker.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_pass(self):
        result = checker.run_all()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}",
        )

    def test_check_count_reasonable(self):
        result = checker.run_all()
        self.assertGreaterEqual(result["total"], 50)

    def test_no_failures(self):
        result = checker.run_all()
        self.assertEqual(result["failed"], 0)

    def test_title_field(self):
        result = checker.run_all()
        self.assertIn("Metamorphic", result["title"])


class TestSelfTest(unittest.TestCase):
    def test_self_test_runs(self):
        # self_test() calls run_all() internally, just verify it doesn't raise
        checker.self_test()


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_metamorphic_testing.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_metamorphic_testing.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_metamorphic_testing.py"), "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test: OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
