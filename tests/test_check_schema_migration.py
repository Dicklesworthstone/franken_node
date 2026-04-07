"""Unit tests for check_schema_migration.py verification logic."""

import json
import os
import unittest
from unittest import mock

from scripts import check_schema_migration

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestMigrationFixtures(unittest.TestCase):
    """Test fixture files."""

    def _load_fixture(self, name):
        path = os.path.join(ROOT, "fixtures/schema_migration", name)
        self.assertTrue(os.path.isfile(path), f"Fixture {name} must exist")
        with open(path) as f:
            return json.load(f)

    def test_migration_paths_exist(self):
        data = self._load_fixture("migration_paths.json")
        self.assertIn("cases", data)
        self.assertGreater(len(data["cases"]), 0)

    def test_idempotency_scenarios_exist(self):
        data = self._load_fixture("idempotency_scenarios.json")
        self.assertIn("cases", data)
        self.assertGreater(len(data["cases"]), 0)

    def test_path_cases_have_fields(self):
        data = self._load_fixture("migration_paths.json")
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("from", case)
            self.assertIn("to", case)
            self.assertIn("expected_result", case)

    def test_idempotency_cases_have_fields(self):
        data = self._load_fixture("idempotency_scenarios.json")
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("current_version", case)
            self.assertIn("expected_outcome", case)

    def test_paths_cover_success_and_failure(self):
        data = self._load_fixture("migration_paths.json")
        results = [c["expected_result"] for c in data["cases"]]
        self.assertIn("ok", results)
        has_error = any(r != "ok" for r in results)
        self.assertTrue(has_error)

    def test_idempotency_covers_all_outcomes(self):
        data = self._load_fixture("idempotency_scenarios.json")
        outcomes = [c["expected_outcome"] for c in data["cases"]]
        self.assertIn("already_applied", outcomes)
        self.assertIn("applied", outcomes)
        self.assertIn("failed", outcomes)


class TestMigrationReceipts(unittest.TestCase):
    """Test migration receipts artifact."""

    def test_receipts_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-b44/state_migration_receipts.json")
        self.assertTrue(os.path.isfile(path))

    def test_receipts_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-b44/state_migration_receipts.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("receipts", data)
        self.assertGreater(len(data["receipts"]), 0)

    def test_receipts_have_outcomes(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-b44/state_migration_receipts.json")
        with open(path) as f:
            data = json.load(f)
        for r in data["receipts"]:
            self.assertIn("outcome", r)
            self.assertIn("connector_id", r)


class TestMigrationImplementation(unittest.TestCase):
    """Test implementation file structure."""

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/schema_migration.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_schema_version(self):
        self.assertIn("struct SchemaVersion", self.content)

    def test_has_migration_hint(self):
        self.assertIn("struct MigrationHint", self.content)

    def test_has_migration_registry(self):
        self.assertIn("struct MigrationRegistry", self.content)

    def test_has_find_path(self):
        self.assertIn("fn find_path", self.content)

    def test_has_execute_plan(self):
        self.assertIn("fn execute_plan", self.content)

    def test_has_check_idempotency(self):
        self.assertIn("fn check_idempotency", self.content)

    def test_has_all_hint_types(self):
        for t in ["AddField", "RemoveField", "RenameField", "Transform"]:
            self.assertIn(t, self.content, f"Missing hint type {t}")

    def test_has_all_error_codes(self):
        for code in ["MIGRATION_PATH_MISSING", "MIGRATION_ALREADY_APPLIED",
                     "MIGRATION_ROLLBACK_FAILED", "SCHEMA_VERSION_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestMigrationCheckerLogic(unittest.TestCase):
    """Test checker-specific regression paths."""

    def test_cargo_harness_wires_integration_test(self):
        harness_path = os.path.join(ROOT, "crates/franken-node/tests/state_migration_contract.rs")
        self.assertTrue(os.path.isfile(harness_path))
        with open(harness_path) as f:
            content = f.read()
        self.assertIn("../../../tests/integration/state_migration_contract.rs", content)

    def test_parse_rust_test_summary_handles_singular_and_plural(self):
        output = """
running 1 test
test smoke ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 4 tests
test alpha ... ok
test beta ... ok
test gamma ... ok
test delta ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out
"""
        summary = check_schema_migration.parse_rust_test_summary(output)
        self.assertEqual(summary["running"], 5)
        self.assertEqual(summary["passed"], 5)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["filtered"], 2)

    def test_summarize_failure_output_strips_ansi_and_focuses_error(self):
        output = (
            "\x1b[32mCompiling\x1b[0m frankenengine-engine\n"
            "\x1b[31merror[E0753]\x1b[0m: expected outer doc comment\n"
            " --> /data/projects/franken_engine/crates/franken-engine/src/parser.rs:2:1\n"
            "help: you might have meant to write a regular comment\n"
        )
        summary = check_schema_migration.summarize_failure_output(output, max_lines=3)
        self.assertIn("error[E0753]: expected outer doc comment", summary)
        self.assertIn("--> /data/projects/franken_engine/crates/franken-engine/src/parser.rs:2:1", summary)
        self.assertNotIn("\x1b", summary)

    @mock.patch("scripts.check_schema_migration.subprocess.run")
    def test_run_schema_migration_tests_targets_named_integration_test(self, run_mock):
        run_mock.return_value = mock.Mock(
            stdout="running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
            stderr="",
            returncode=0,
        )

        summary, _ = check_schema_migration.run_schema_migration_tests()

        run_mock.assert_called_once_with(
            [
                "rch",
                "exec",
                "--",
                "cargo",
                "test",
                "-p",
                "frankenengine-node",
                "--test",
                check_schema_migration.SCHEMA_MIGRATION_TEST_TARGET,
            ],
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=check_schema_migration.ROOT,
        )
        self.assertEqual(summary["returncode"], 0)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["running"], 1)


class TestMigrationSpec(unittest.TestCase):
    """Test spec contract."""

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-b44_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-MIGRATE-PATH", "INV-MIGRATE-IDEMPOTENT",
                    "INV-MIGRATE-ROLLBACK", "INV-MIGRATE-MONOTONIC"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_hint_types(self):
        for t in ["add_field", "remove_field", "rename_field", "transform"]:
            self.assertIn(t, self.content, f"Missing hint type {t}")

    def test_has_error_codes(self):
        for code in ["MIGRATION_PATH_MISSING", "MIGRATION_ALREADY_APPLIED",
                     "MIGRATION_ROLLBACK_FAILED", "SCHEMA_VERSION_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


if __name__ == "__main__":
    unittest.main()
