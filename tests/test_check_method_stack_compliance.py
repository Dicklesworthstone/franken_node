#!/usr/bin/env python3
"""Unit tests for scripts/check_method_stack_compliance.py"""

import sys
import unittest
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_method_stack_compliance as checker


class TestFilesExist(unittest.TestCase):
    def test_returns_count(self):
        n = checker.check_files_exist()
        self.assertIsInstance(n, int)
        self.assertGreaterEqual(n, 0)

    def test_checks_three_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        file_checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(file_checks), 3)


class TestMethodStacksDocumented(unittest.TestCase):
    def test_returns_count(self):
        n = checker.check_method_stacks_documented()
        self.assertIsInstance(n, int)

    def test_checks_four_stacks(self):
        checker.RESULTS.clear()
        checker.check_method_stacks_documented()
        stack_checks = [r for r in checker.RESULTS if r["name"].startswith("stack_documented:")]
        self.assertEqual(len(stack_checks), 4)

    def test_all_stacks_found(self):
        checker.RESULTS.clear()
        checker.check_method_stacks_documented()
        for r in checker.RESULTS:
            if r["name"].startswith("stack_documented:"):
                self.assertTrue(r["pass"], f"{r['name']} should pass")


class TestStackDomains(unittest.TestCase):
    def test_four_domains(self):
        checker.RESULTS.clear()
        checker.check_stack_domains()
        domain_checks = [r for r in checker.RESULTS if r["name"].startswith("stack_domain:")]
        self.assertEqual(len(domain_checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_stack_domains()
        for r in checker.RESULTS:
            if r["name"].startswith("stack_domain:"):
                self.assertTrue(r["pass"], f"{r['name']} should pass")


class TestRequiredArtifacts(unittest.TestCase):
    def test_artifact_keywords(self):
        checker.RESULTS.clear()
        checker.check_required_artifacts_per_stack()
        artifact_checks = [r for r in checker.RESULTS if r["name"].startswith("artifact_keyword:")]
        # MS-01: 3, MS-02: 2, MS-03: 3, MS-04: 3 = 11
        self.assertEqual(len(artifact_checks), 11)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_required_artifacts_per_stack()
        for r in checker.RESULTS:
            if r["name"].startswith("artifact_keyword:"):
                self.assertTrue(r["pass"], f"{r['name']} should pass")


class TestComplianceChecks(unittest.TestCase):
    def test_four_checks(self):
        checker.RESULTS.clear()
        checker.check_compliance_checks()
        cc_checks = [r for r in checker.RESULTS if r["name"].startswith("compliance_check:")]
        self.assertEqual(len(cc_checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_compliance_checks()
        for r in checker.RESULTS:
            if r["name"].startswith("compliance_check:"):
                self.assertTrue(r["pass"], f"{r['name']} should pass")


class TestEventCodes(unittest.TestCase):
    def test_four_codes(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        code_checks = [r for r in checker.RESULTS if r["name"].startswith("event_code:")]
        self.assertEqual(len(code_checks), 4)


class TestInvariants(unittest.TestCase):
    def test_four_invariants(self):
        checker.RESULTS.clear()
        checker.check_invariants()
        inv_checks = [r for r in checker.RESULTS if r["name"].startswith("invariant:")]
        self.assertEqual(len(inv_checks), 4)


class TestComplianceMatrixJson(unittest.TestCase):
    def test_json_valid(self):
        checker.RESULTS.clear()
        checker.check_compliance_matrix_json()
        json_check = [r for r in checker.RESULTS if r["name"] == "matrix:valid_json"]
        self.assertEqual(len(json_check), 1)
        self.assertTrue(json_check[0]["pass"])

    def test_four_stacks_in_matrix(self):
        checker.RESULTS.clear()
        checker.check_compliance_matrix_json()
        stack_check = [r for r in checker.RESULTS if r["name"] == "matrix:four_stacks"]
        self.assertTrue(stack_check[0]["pass"])

    def test_section_mappings(self):
        checker.RESULTS.clear()
        checker.check_compliance_matrix_json()
        map_checks = [r for r in checker.RESULTS if r["name"].startswith("matrix:section_map:")]
        self.assertGreaterEqual(len(map_checks), 5)
        for r in map_checks:
            self.assertTrue(r["pass"], f"{r['name']}: {r['detail']}")


class TestComplianceTable(unittest.TestCase):
    def test_table_header(self):
        checker.RESULTS.clear()
        checker.check_compliance_table()
        header = [r for r in checker.RESULTS if r["name"] == "table:header"]
        self.assertTrue(header[0]["pass"])

    def test_section_rows(self):
        checker.RESULTS.clear()
        checker.check_compliance_table()
        rows = [r for r in checker.RESULTS if r["name"].startswith("table:section_row:")]
        self.assertGreaterEqual(len(rows), 8)


class TestPrChecklist(unittest.TestCase):
    def test_checklist_keywords(self):
        checker.RESULTS.clear()
        checker.check_pr_checklist()
        pr_checks = [r for r in checker.RESULTS if r["name"].startswith("pr_checklist:")]
        self.assertEqual(len(pr_checks), 4)


class TestSpecContract(unittest.TestCase):
    def test_spec_keywords(self):
        checker.RESULTS.clear()
        checker.check_spec_contract()
        spec_checks = [r for r in checker.RESULTS if r["name"].startswith("spec:")]
        self.assertEqual(len(spec_checks), 8)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_spec_contract()
        for r in checker.RESULTS:
            if r["name"].startswith("spec:"):
                self.assertTrue(r["pass"], f"{r['name']} should pass")


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = checker.run_all()
        self.assertIsInstance(result, dict)

    def test_has_required_keys(self):
        result = checker.run_all()
        for key in ["bead_id", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-22e7")

    def test_positive_total(self):
        result = checker.run_all()
        self.assertGreater(result["total"], 0)

    def test_math_consistent(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])
        self.assertEqual(result["total"], len(result["checks"]))


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


if __name__ == "__main__":
    unittest.main()
