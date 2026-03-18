"""Tests for scripts/check_migration_kit.py (bd-wpck)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_migration_kit.py")

# Dynamic import
spec = importlib.util.spec_from_file_location("check_migration_kit", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-wpck"
        assert data["section"] == "15"
        assert "checks_passed" in data
        assert "checks_total" in data
        assert "verdict" in data
        assert isinstance(data["checks"], list)


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results):
        assert results["source_exists"]["passed"]

    def test_module_wiring(self, results):
        assert results["module_wiring"]["passed"]

    def test_archetypes(self, results):
        assert results["archetypes"]["passed"]

    def test_migration_phases(self, results):
        assert results["migration_phases"]["passed"]

    def test_struct_migration_step(self, results):
        assert results["struct_MigrationStep"]["passed"]

    def test_struct_compatibility_mapping(self, results):
        assert results["struct_CompatibilityMapping"]["passed"]

    def test_struct_migration_kit(self, results):
        assert results["struct_MigrationKit"]["passed"]

    def test_struct_migration_report(self, results):
        assert results["struct_MigrationReport"]["passed"]

    def test_struct_mke_audit_record(self, results):
        assert results["struct_MkeAuditRecord"]["passed"]

    def test_struct_migration_kit_ecosystem(self, results):
        assert results["struct_MigrationKitEcosystem"]["passed"]

    def test_compatibility_gating(self, results):
        assert results["compatibility_gating"]["passed"]

    def test_step_management(self, results):
        assert results["step_management"]["passed"]

    def test_deterministic_hashing(self, results):
        assert results["deterministic_hashing"]["passed"]

    def test_kit_versioning(self, results):
        assert results["kit_versioning"]["passed"]

    def test_report_generation(self, results):
        assert results["report_generation"]["passed"]

    def test_event_codes(self, results):
        assert results["event_codes"]["passed"]

    def test_invariants(self, results):
        assert results["invariants"]["passed"]

    def test_audit_log(self, results):
        assert results["audit_log"]["passed"]

    def test_spec_alignment(self, results):
        assert results["spec_alignment"]["passed"]

    def test_test_coverage(self, results):
        assert results["test_coverage"]["passed"]

    def test_content_hash_surface(self, results):
        assert results["content_hash_surface"]["passed"]

    def test_nan_inf_guard(self, results):
        assert results["nan_inf_guard"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        results = mod._checks()
        failed = [r for r in results if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"

    def test_human_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT],
            capture_output=True, text=True,
        )
        assert "bd-wpck" in result.stdout
        assert "PASS" in result.stdout
