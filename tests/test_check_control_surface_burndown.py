#!/usr/bin/env python3
"""Unit tests for check_control_surface_burndown.py (bd-2h2s)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_control_surface_burndown as csb


class TestConstants(unittest.TestCase):
    """Verify module-level constants are properly defined."""

    def test_required_columns_count(self):
        self.assertEqual(len(csb.REQUIRED_COLUMNS), 8)

    def test_required_columns_include_module_path(self):
        self.assertIn("module_path", csb.REQUIRED_COLUMNS)

    def test_required_columns_include_exception_expiry(self):
        self.assertIn("exception_expiry", csb.REQUIRED_COLUMNS)

    def test_allowed_statuses(self):
        self.assertEqual(
            csb.ALLOWED_STATUSES,
            {"not_started", "in_progress", "completed", "excepted"},
        )

    def test_min_surface_count(self):
        self.assertGreaterEqual(csb.MIN_SURFACE_COUNT, 12)


class TestCheckCsvExists(unittest.TestCase):
    def test_passes(self):
        result = csb.check_csv_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-CSV-EXISTS")

    def test_event_code_on_pass(self):
        result = csb.check_csv_exists()
        self.assertEqual(result["event"], "MIG-001")


class TestCheckMigrationDocExists(unittest.TestCase):
    def test_passes(self):
        result = csb.check_migration_doc_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-DOC-EXISTS")


class TestCheckSpecContractExists(unittest.TestCase):
    def test_passes(self):
        result = csb.check_spec_contract_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-SPEC-EXISTS")


class TestCheckTestFileExists(unittest.TestCase):
    def test_passes(self):
        result = csb.check_test_file_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-TESTS-EXISTS")


class TestCheckCsvRequiredColumns(unittest.TestCase):
    def test_passes(self):
        result = csb.check_csv_required_columns()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-CSV-COLUMNS")

    def test_no_missing_columns(self):
        result = csb.check_csv_required_columns()
        self.assertEqual(result["details"]["missing_columns"], [])


class TestCheckCsvMinSurfaces(unittest.TestCase):
    def test_passes(self):
        result = csb.check_csv_min_surfaces()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-CSV-MIN")

    def test_at_least_12_surfaces(self):
        result = csb.check_csv_min_surfaces()
        self.assertGreaterEqual(result["details"]["total_surfaces"], 12)


class TestCheckCsvStatusValues(unittest.TestCase):
    def test_passes(self):
        result = csb.check_csv_status_values()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-CSV-STATUS")

    def test_no_invalid_statuses(self):
        result = csb.check_csv_status_values()
        self.assertEqual(result["details"]["invalid_statuses"], [])


class TestCheckCsvStatusDistribution(unittest.TestCase):
    def test_passes(self):
        result = csb.check_csv_status_distribution()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-CSV-DIST")

    def test_has_completed_count(self):
        result = csb.check_csv_status_distribution()
        self.assertGreater(result["details"]["completed"], 0)

    def test_has_in_progress_count(self):
        result = csb.check_csv_status_distribution()
        self.assertGreater(result["details"]["in_progress"], 0)

    def test_has_not_started_count(self):
        result = csb.check_csv_status_distribution()
        self.assertGreater(result["details"]["not_started"], 0)

    def test_has_excepted_count(self):
        result = csb.check_csv_status_distribution()
        self.assertGreater(result["details"]["excepted"], 0)

    def test_event_code(self):
        result = csb.check_csv_status_distribution()
        self.assertEqual(result["event"], "MIG-002")


class TestCheckNoExpiredExceptions(unittest.TestCase):
    def test_passes(self):
        result = csb.check_no_expired_exceptions()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-NO-EXPIRED")

    def test_no_expired(self):
        result = csb.check_no_expired_exceptions()
        self.assertEqual(result["details"]["expired_exceptions"], [])


class TestCheckExceptionHasReason(unittest.TestCase):
    def test_passes(self):
        result = csb.check_exception_has_reason()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-EXC-REASON")


class TestCheckExceptionHasExpiry(unittest.TestCase):
    def test_passes(self):
        result = csb.check_exception_has_expiry()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-EXC-EXPIRY")


class TestCheckMigrationDocSections(unittest.TestCase):
    def test_passes(self):
        result = csb.check_migration_doc_sections()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-DOC-SECTIONS")

    def test_no_missing_sections(self):
        result = csb.check_migration_doc_sections()
        self.assertEqual(result["details"]["missing_sections"], [])


class TestCheckClosureCriteria(unittest.TestCase):
    def test_passes(self):
        result = csb.check_closure_criteria_nonempty()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "MIG-CLOSURE")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        result = csb.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_present(self):
        result = csb.self_test()
        self.assertGreaterEqual(result["summary"]["total_checks"], 13)

    def test_no_failures(self):
        result = csb.self_test()
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_bead_field(self):
        result = csb.self_test()
        self.assertEqual(result["bead"], "bd-2h2s")

    def test_section_field(self):
        result = csb.self_test()
        self.assertEqual(result["section"], "10.15")

    def test_gate_name(self):
        result = csb.self_test()
        self.assertEqual(result["gate"], "control_surface_burndown_verification")

    def test_events_list(self):
        result = csb.self_test()
        self.assertIn("MIG-005", result["events"])
        self.assertIn("MIG-001", result["events"])
        self.assertIn("MIG-002", result["events"])

    def test_checks_are_list(self):
        result = csb.self_test()
        self.assertIsInstance(result["checks"], list)

    def test_verdict_field_present(self):
        result = csb.self_test()
        self.assertIn("verdict", result)


# --- Mutation tests ---

class TestMutationExpiredExceptionDetected(unittest.TestCase):
    """Mutation: inject an expired exception and verify detection."""

    def test_expired_exception_causes_fail(self):
        expired_csv = (
            "module_path,function_name,invariant_violated,target_bead,"
            "migration_status,closure_criteria,exception_reason,exception_expiry\n"
            "connector/lifecycle.rs,transition,INV-MIG-EPOCH-SCOPED,bd-1cs7,"
            "excepted,test closure,Legacy reason,2020-01-01\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write(expired_csv)
            tmp_path = Path(f.name)

        original = csb.BURNDOWN_CSV
        try:
            csb.BURNDOWN_CSV = tmp_path
            result = csb.check_no_expired_exceptions()
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(len(result["details"]["expired_exceptions"]), 1)
            self.assertEqual(result["event"], "MIG-004")
        finally:
            csb.BURNDOWN_CSV = original
            tmp_path.unlink()


class TestMutationMissingColumnDetected(unittest.TestCase):
    """Mutation: CSV with missing column should be detected."""

    def test_missing_column_causes_fail(self):
        bad_csv = (
            "module_path,function_name,invariant_violated,target_bead,"
            "migration_status,closure_criteria,exception_reason\n"
            "connector/lifecycle.rs,transition,INV-MIG-EPOCH-SCOPED,bd-1cs7,"
            "completed,test closure,\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write(bad_csv)
            tmp_path = Path(f.name)

        original = csb.BURNDOWN_CSV
        try:
            csb.BURNDOWN_CSV = tmp_path
            result = csb.check_csv_required_columns()
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("exception_expiry", result["details"]["missing_columns"])
        finally:
            csb.BURNDOWN_CSV = original
            tmp_path.unlink()


class TestMutationInvalidStatusDetected(unittest.TestCase):
    """Mutation: invalid status value should be detected."""

    def test_invalid_status_causes_fail(self):
        bad_csv = (
            "module_path,function_name,invariant_violated,target_bead,"
            "migration_status,closure_criteria,exception_reason,exception_expiry\n"
            "connector/lifecycle.rs,transition,INV-MIG-EPOCH-SCOPED,bd-1cs7,"
            "bogus_status,test closure,,\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write(bad_csv)
            tmp_path = Path(f.name)

        original = csb.BURNDOWN_CSV
        try:
            csb.BURNDOWN_CSV = tmp_path
            result = csb.check_csv_status_values()
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(len(result["details"]["invalid_statuses"]), 1)
        finally:
            csb.BURNDOWN_CSV = original
            tmp_path.unlink()


# --- CLI integration tests ---

class TestCliJsonOutput(unittest.TestCase):
    """Verify CLI --json produces valid PASS verdict."""

    def test_json_output_pass_verdict(self):
        result = subprocess.run(
            [sys.executable, str(csb.ROOT / "scripts" / "check_control_surface_burndown.py"), "--json"],
            capture_output=True,
            text=True,
            cwd=str(csb.ROOT),
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertIn("checks", data)
        self.assertIn("events", data)


class TestCliSelfTest(unittest.TestCase):
    """Verify CLI --self-test exits 0."""

    def test_self_test_succeeds(self):
        result = subprocess.run(
            [sys.executable, str(csb.ROOT / "scripts" / "check_control_surface_burndown.py"), "--self-test"],
            capture_output=True,
            text=True,
            cwd=str(csb.ROOT),
        )
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
