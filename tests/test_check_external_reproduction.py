#!/usr/bin/env python3
"""Unit tests for scripts/check_external_reproduction.py"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_external_reproduction as checker


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


class TestSafeRel(unittest.TestCase):
    def test_relative_path(self):
        p = checker.ROOT / "foo" / "bar.md"
        self.assertEqual(checker._safe_rel(p), "foo/bar.md")

    def test_nonrelative_path(self):
        p = Path("/nonexistent/foo.md")
        self.assertEqual(checker._safe_rel(p), "/nonexistent/foo.md")


class TestFilesExist(unittest.TestCase):
    def test_five_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 5)

    def test_spec_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        spec_check = [r for r in checker.RESULTS if r["name"] == "file_exists:spec"][0]
        self.assertTrue(spec_check["pass"])

    def test_policy_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        policy_check = [r for r in checker.RESULTS if r["name"] == "file_exists:policy"][0]
        self.assertTrue(policy_check["pass"])

    def test_playbook_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        playbook_check = [r for r in checker.RESULTS if r["name"] == "file_exists:playbook"][0]
        self.assertTrue(playbook_check["pass"])

    def test_claims_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        claims_check = [r for r in checker.RESULTS if r["name"] == "file_exists:claims_registry"][0]
        self.assertTrue(claims_check["pass"])

    def test_script_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        script_check = [r for r in checker.RESULTS if r["name"] == "file_exists:automation_script"][0]
        self.assertTrue(script_check["pass"])


class TestMissingFiles(unittest.TestCase):
    def test_spec_missing(self):
        with patch.object(checker, "SPEC_PATH", Path("/nonexistent/spec.md")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            spec_check = [r for r in checker.RESULTS if r["name"] == "file_exists:spec"][0]
            self.assertFalse(spec_check["pass"])

    def test_policy_missing(self):
        with patch.object(checker, "POLICY_PATH", Path("/nonexistent/policy.md")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            policy_check = [r for r in checker.RESULTS if r["name"] == "file_exists:policy"][0]
            self.assertFalse(policy_check["pass"])

    def test_playbook_missing(self):
        with patch.object(checker, "PLAYBOOK_PATH", Path("/nonexistent/playbook.md")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            pb_check = [r for r in checker.RESULTS if r["name"] == "file_exists:playbook"][0]
            self.assertFalse(pb_check["pass"])

    def test_claims_missing(self):
        with patch.object(checker, "CLAIMS_PATH", Path("/nonexistent/claims.toml")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            cl_check = [r for r in checker.RESULTS if r["name"] == "file_exists:claims_registry"][0]
            self.assertFalse(cl_check["pass"])

    def test_script_missing(self):
        with patch.object(checker, "SCRIPT_PATH", Path("/nonexistent/reproduce.py")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            sc_check = [r for r in checker.RESULTS if r["name"] == "file_exists:automation_script"][0]
            self.assertFalse(sc_check["pass"])

    def test_missing_spec_cascades(self):
        """When spec is missing, spec content checks also fail."""
        with patch.object(checker, "SPEC_PATH", Path("/nonexistent/spec.md")):
            checker.RESULTS.clear()
            checker.check_spec_event_codes()
            for r in checker.RESULTS:
                self.assertFalse(r["pass"])


class TestSpecEventCodes(unittest.TestCase):
    def test_four_codes(self):
        checker.RESULTS.clear()
        checker.check_spec_event_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("spec_event_code:")]
        self.assertEqual(len(checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_spec_event_codes()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestSpecInvariants(unittest.TestCase):
    def test_four_invariants(self):
        checker.RESULTS.clear()
        checker.check_spec_invariants()
        checks = [r for r in checker.RESULTS if r["name"].startswith("spec_invariant:")]
        self.assertEqual(len(checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_spec_invariants()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestSpecSections(unittest.TestCase):
    def test_five_sections(self):
        checker.RESULTS.clear()
        checker.check_spec_sections()
        checks = [r for r in checker.RESULTS if r["name"].startswith("spec_section:")]
        self.assertEqual(len(checks), 5)


class TestSpecErrorCodes(unittest.TestCase):
    def test_four_error_codes(self):
        checker.RESULTS.clear()
        checker.check_spec_error_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("spec_error_code:")]
        self.assertEqual(len(checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_spec_error_codes()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestPolicySections(unittest.TestCase):
    def test_eight_sections(self):
        checker.RESULTS.clear()
        checker.check_policy_sections()
        checks = [r for r in checker.RESULTS if r["name"].startswith("policy_section:")]
        self.assertEqual(len(checks), 8)


class TestPolicyEventCodes(unittest.TestCase):
    def test_four_codes(self):
        checker.RESULTS.clear()
        checker.check_policy_event_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("policy_event_code:")]
        self.assertEqual(len(checks), 4)


class TestPolicyGovernance(unittest.TestCase):
    def test_six_keywords(self):
        checker.RESULTS.clear()
        checker.check_policy_governance()
        checks = [r for r in checker.RESULTS if r["name"].startswith("policy_governance:")]
        self.assertEqual(len(checks), 6)


class TestPlaybookSections(unittest.TestCase):
    def test_five_sections(self):
        checker.RESULTS.clear()
        checker.check_playbook_sections()
        checks = [r for r in checker.RESULTS if r["name"].startswith("playbook_section:")]
        self.assertEqual(len(checks), 5)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_playbook_sections()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestPlaybookEnvironment(unittest.TestCase):
    def test_six_env_keywords(self):
        checker.RESULTS.clear()
        checker.check_playbook_environment()
        checks = [r for r in checker.RESULTS if r["name"].startswith("playbook_env:")]
        self.assertEqual(len(checks), 6)


class TestPlaybookCommands(unittest.TestCase):
    def test_three_commands(self):
        checker.RESULTS.clear()
        checker.check_playbook_commands()
        checks = [r for r in checker.RESULTS if r["name"].startswith("playbook_command:")]
        self.assertEqual(len(checks), 3)


class TestPlaybookVariance(unittest.TestCase):
    def test_three_keywords(self):
        checker.RESULTS.clear()
        checker.check_playbook_variance()
        checks = [r for r in checker.RESULTS if r["name"].startswith("playbook_variance:")]
        self.assertEqual(len(checks), 3)


class TestClaimsFormat(unittest.TestCase):
    def test_five_fields(self):
        checker.RESULTS.clear()
        checker.check_claims_format()
        checks = [r for r in checker.RESULTS if r["name"].startswith("claims_field:")]
        self.assertEqual(len(checks), 5)


class TestClaimsEntries(unittest.TestCase):
    def test_count(self):
        checker.RESULTS.clear()
        checker.check_claims_entries()
        check = [r for r in checker.RESULTS if r["name"] == "claims_entries:count"][0]
        self.assertTrue(check["pass"])


class TestClaimsCategories(unittest.TestCase):
    def test_five_categories(self):
        checker.RESULTS.clear()
        checker.check_claims_categories()
        checks = [r for r in checker.RESULTS if r["name"].startswith("claims_category:")]
        self.assertEqual(len(checks), 5)


class TestClaimsIds(unittest.TestCase):
    def test_five_ids(self):
        checker.RESULTS.clear()
        checker.check_claims_ids()
        checks = [r for r in checker.RESULTS if r["name"].startswith("claims_id:")]
        self.assertEqual(len(checks), 5)


class TestScriptFeatures(unittest.TestCase):
    def test_eight_features(self):
        checker.RESULTS.clear()
        checker.check_script_features()
        checks = [r for r in checker.RESULTS if r["name"].startswith("script_feature:")]
        self.assertEqual(len(checks), 8)


class TestScriptReportFields(unittest.TestCase):
    def test_five_fields(self):
        checker.RESULTS.clear()
        checker.check_script_report_fields()
        checks = [r for r in checker.RESULTS if r["name"].startswith("script_report_field:")]
        self.assertEqual(len(checks), 5)


class TestScriptEnvFingerprint(unittest.TestCase):
    def test_five_fields(self):
        checker.RESULTS.clear()
        checker.check_script_env_fingerprint()
        checks = [r for r in checker.RESULTS if r["name"].startswith("script_fingerprint:")]
        self.assertEqual(len(checks), 5)


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = checker.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-2pu")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.7")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_verdict_pass(self):
        result = checker.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_check_count(self):
        result = checker.run_all()
        self.assertGreaterEqual(result["total"], 80)

    def test_checks_is_list(self):
        result = checker.run_all()
        self.assertIsInstance(result["checks"], list)
        self.assertGreater(len(result["checks"]), 0)


class TestJsonOutput(unittest.TestCase):
    def test_json_flag(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_external_reproduction.py", "--json"],
            capture_output=True, text=True, cwd=str(checker.ROOT),
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["bead_id"], "bd-2pu")
        self.assertEqual(data["verdict"], "PASS")

    def test_human_output(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_external_reproduction.py"],
            capture_output=True, text=True, cwd=str(checker.ROOT),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("bd-2pu", result.stdout)
        self.assertIn("PASS", result.stdout)

    def test_self_test_flag(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_external_reproduction.py", "--self-test"],
            capture_output=True, text=True, cwd=str(checker.ROOT),
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("self_test: OK", result.stdout)

    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)
        roundtrip = json.loads(json_str)
        self.assertEqual(roundtrip["bead_id"], "bd-2pu")


if __name__ == "__main__":
    unittest.main()
