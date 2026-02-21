#!/usr/bin/env python3
"""Unit tests for scripts/check_migration_demo.py"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT / "scripts"))
import check_migration_demo as checker


class TestFilesExist(unittest.TestCase):
    def test_spec_exists(self):
        self.assertTrue(checker.SPEC_PATH.is_file(),
                        f"Missing: {checker._safe_rel(checker.SPEC_PATH)}")

    def test_policy_exists(self):
        self.assertTrue(checker.POLICY_PATH.is_file(),
                        f"Missing: {checker._safe_rel(checker.POLICY_PATH)}")

    def test_fixtures_dir_exists(self):
        self.assertTrue(checker.FIXTURES_DIR.is_dir(),
                        f"Missing: {checker._safe_rel(checker.FIXTURES_DIR)}")

    def test_check_files_exist_count(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 3)
        for r in checks:
            self.assertTrue(r["pass"], f"Failed: {r['name']}: {r['detail']}")


class TestFlagshipConfigs(unittest.TestCase):
    def test_at_least_three_configs(self):
        configs = sorted(checker.FIXTURES_DIR.glob("*.json"))
        self.assertGreaterEqual(len(configs), 3)

    def test_configs_valid_json(self):
        for cfg_path in checker.FIXTURES_DIR.glob("*.json"):
            with self.subTest(cfg=cfg_path.stem):
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
                self.assertIn("name", data)
                self.assertIn("category", data)
                self.assertIn("repository_url", data)
                self.assertIn("pinned_version", data)

    def test_distinct_categories(self):
        cats = set()
        for cfg_path in checker.FIXTURES_DIR.glob("*.json"):
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            cats.add(data.get("category", ""))
        self.assertGreaterEqual(len(cats), 3)

    def test_check_flagship_configs(self):
        checker.RESULTS.clear()
        count = checker.check_flagship_configs()
        self.assertGreater(count, 0)


class TestPipelineStages(unittest.TestCase):
    def test_six_stages(self):
        checker.RESULTS.clear()
        checker.check_pipeline_stages()
        checks = [r for r in checker.RESULTS if r["name"].startswith("stage:")]
        self.assertEqual(len(checks), 6)

    def test_all_stages_pass(self):
        checker.RESULTS.clear()
        checker.check_pipeline_stages()
        for r in checker.RESULTS:
            if r["name"].startswith("stage:"):
                self.assertTrue(r["pass"], r["name"])


class TestStageOutputs(unittest.TestCase):
    def test_six_outputs(self):
        checker.RESULTS.clear()
        checker.check_stage_outputs()
        checks = [r for r in checker.RESULTS if r["name"].startswith("output:")]
        self.assertEqual(len(checks), 6)

    def test_all_outputs_pass(self):
        checker.RESULTS.clear()
        checker.check_stage_outputs()
        for r in checker.RESULTS:
            if r["name"].startswith("output:"):
                self.assertTrue(r["pass"], r["name"])


class TestEventCodes(unittest.TestCase):
    def test_four_codes(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("event_code:")]
        self.assertEqual(len(checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestInvariants(unittest.TestCase):
    def test_four_invariants(self):
        checker.RESULTS.clear()
        checker.check_invariants()
        checks = [r for r in checker.RESULTS if r["name"].startswith("invariant:")]
        self.assertEqual(len(checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_invariants()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestErrorCodes(unittest.TestCase):
    def test_five_error_codes(self):
        checker.RESULTS.clear()
        checker.check_error_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("error_code:")]
        self.assertEqual(len(checks), 5)


class TestConfidenceGrades(unittest.TestCase):
    def test_grades_in_both_docs(self):
        checker.RESULTS.clear()
        checker.check_confidence_grades()
        checks = [r for r in checker.RESULTS if r["name"].startswith("confidence:")]
        self.assertGreaterEqual(len(checks), 6)  # 3 grades x 2 docs


class TestRollbackPolicy(unittest.TestCase):
    def test_rollback_keywords(self):
        checker.RESULTS.clear()
        checker.check_rollback_policy()
        checks = [r for r in checker.RESULTS if r["name"].startswith("rollback:")]
        self.assertEqual(len(checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_rollback_policy()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestReproducibility(unittest.TestCase):
    def test_reproducibility_keywords(self):
        checker.RESULTS.clear()
        checker.check_reproducibility()
        checks = [r for r in checker.RESULTS if r["name"].startswith("reproducibility:")]
        self.assertGreaterEqual(len(checks), 6)  # 3 keywords x 2 docs


class TestEvidenceIntegrity(unittest.TestCase):
    def test_integrity_keywords(self):
        checker.RESULTS.clear()
        checker.check_evidence_integrity()
        checks = [r for r in checker.RESULTS if r["name"].startswith("integrity:")]
        self.assertGreaterEqual(len(checks), 6)  # 3 keywords x 2 docs


class TestBeforeAfter(unittest.TestCase):
    def test_five_dimensions(self):
        checker.RESULTS.clear()
        checker.check_before_after_evidence()
        checks = [r for r in checker.RESULTS if r["name"].startswith("before_after:")]
        self.assertEqual(len(checks), 5)


class TestTimeline(unittest.TestCase):
    def test_timeline_targets(self):
        checker.RESULTS.clear()
        checker.check_timeline()
        checks = [r for r in checker.RESULTS if r["name"].startswith("timeline:")]
        self.assertEqual(len(checks), 4)


class TestAcceptanceCriteria(unittest.TestCase):
    def test_acceptance_keywords(self):
        checker.RESULTS.clear()
        checker.check_acceptance_criteria()
        checks = [r for r in checker.RESULTS if r["name"].startswith("acceptance:")]
        self.assertEqual(len(checks), 7)


class TestPolicyEventLogging(unittest.TestCase):
    def test_four_codes_in_policy(self):
        checker.RESULTS.clear()
        checker.check_policy_event_logging()
        checks = [r for r in checker.RESULTS if r["name"].startswith("logging:")]
        self.assertEqual(len(checks), 4)


class TestPolicyInvariants(unittest.TestCase):
    def test_four_invariants_in_policy(self):
        checker.RESULTS.clear()
        checker.check_policy_invariants()
        checks = [r for r in checker.RESULTS if r["name"].startswith("policy_inv:")]
        self.assertEqual(len(checks), 4)


class TestFlagshipCriteria(unittest.TestCase):
    def test_criteria_keywords(self):
        checker.RESULTS.clear()
        checker.check_flagship_criteria()
        checks = [r for r in checker.RESULTS if r["name"].startswith("criteria:")]
        self.assertEqual(len(checks), 4)


class TestCompatibilityReport(unittest.TestCase):
    def test_report_keywords(self):
        checker.RESULTS.clear()
        checker.check_compatibility_report()
        checks = [r for r in checker.RESULTS if r["name"].startswith("report:")]
        self.assertEqual(len(checks), 4)


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = checker.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-1e0")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.9")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_verdict_pass(self):
        result = checker.run_all()
        self.assertEqual(result["verdict"], "PASS",
                         f"Failing: {[r for r in result['checks'] if not r['pass']]}")

    def test_check_count_reasonable(self):
        result = checker.run_all()
        self.assertGreaterEqual(result["total"], 80)

    def test_all_checks_pass(self):
        result = checker.run_all()
        failing = [r for r in result["checks"] if not r["pass"]]
        self.assertEqual(len(failing), 0,
                         f"Failing checks: {json.dumps(failing, indent=2)}")


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


class TestSafeRel(unittest.TestCase):
    def test_under_root(self):
        p = checker.ROOT / "docs" / "specs" / "foo.md"
        self.assertEqual(checker._safe_rel(p), "docs/specs/foo.md")

    def test_outside_root(self):
        p = Path("/tmp/unrelated/file.txt")
        self.assertEqual(checker._safe_rel(p), "/tmp/unrelated/file.txt")


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_migration_demo.py"),
             "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["bead_id"], "bd-1e0")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_migration_demo.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PASS", proc.stdout)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_migration_demo.py"),
             "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("self_test: OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
