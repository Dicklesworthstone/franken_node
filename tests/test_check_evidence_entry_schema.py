"""Unit tests for check_evidence_entry_schema.py."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_evidence_entry_schema.py"
SCHEMA = ROOT / "spec" / "evidence_entry_v1.json"
REPORT = ROOT / "artifacts" / "10.14" / "evidence_schema_validation_report.json"

sys.path.insert(0, str(ROOT / "scripts"))
import check_evidence_entry_schema as cees


class TestEvidenceEntrySchemaFiles(unittest.TestCase):
    def test_schema_exists(self):
        self.assertTrue(SCHEMA.is_file())

    def test_report_exists(self):
        self.assertTrue(REPORT.is_file())

    def test_schema_has_required_fields(self):
        schema = json.loads(SCHEMA.read_text())
        required = set(schema.get("required", []))
        for field in cees.CANONICAL_ROOT_FIELDS:
            self.assertIn(field, required)


class TestValidationSemantics(unittest.TestCase):
    def test_valid_entry_passes(self):
        entry = cees.make_valid_entry()
        errors = cees.validate_entry(entry)
        self.assertEqual(errors, [])

    def test_candidate_order_violation_fails(self):
        entry = cees.make_valid_entry()
        entry["candidates"][0], entry["candidates"][1] = entry["candidates"][1], entry["candidates"][0]
        errors = cees.validate_entry(entry)
        self.assertIn(cees.ERROR_CODES["candidate_order"], errors)

    def test_missing_witness_fails(self):
        entry = cees.make_valid_entry()
        del entry["witness_refs"]
        errors = cees.validate_entry(entry)
        self.assertIn(cees.ERROR_CODES["missing"], errors)

    def test_unknown_chosen_candidate_fails(self):
        entry = cees.make_valid_entry()
        entry["chosen_action"]["candidate_id"] = "cand-missing"
        errors = cees.validate_entry(entry)
        self.assertIn(cees.ERROR_CODES["chosen"], errors)


class TestReportContent(unittest.TestCase):
    def test_report_has_expected_cases(self):
        report = json.loads(REPORT.read_text())
        case_ids = {case["id"] for case in report["cases"]}
        expected = {
            "valid-canonical-entry",
            "missing-witness-refs",
            "candidate-order-violation",
            "chosen-candidate-missing",
        }
        self.assertTrue(expected.issubset(case_ids))

    def test_report_verdict_pass(self):
        report = json.loads(REPORT.read_text())
        self.assertEqual(report["summary"]["verdict"], "PASS")


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test_passes(self):
        result = cees.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_cli_json_output(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(ROOT),
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["verdict"], "PASS")
        check_ids = {check["id"] for check in payload["checks"]}
        self.assertIn("EE-SCHEMA", check_ids)
        self.assertIn("EE-E2E", check_ids)
        self.assertIn("EE-LOGS", check_ids)


if __name__ == "__main__":
    unittest.main()
