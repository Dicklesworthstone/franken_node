#!/usr/bin/env python3
"""Tests for bd-sxt5: Migration validation cohorts gate."""
import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_migration_validation_cohorts.py")

def _load():
    spec = importlib.util.spec_from_file_location("chk", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

mod = _load()

class TestSelfTest:
    def test_self_test_passes(self): assert mod.self_test() is True

class TestJsonOutput:
    def test_json_has_required_keys(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        d = json.loads(r.stdout)
        for k in ("bead_id", "section", "gate_script", "checks_passed", "checks_total", "verdict", "checks"): assert k in d

    def test_bead_id(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        d = json.loads(r.stdout)
        assert d["bead_id"] == "bd-sxt5" and d["section"] == "15"

    def test_verdict_field(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert json.loads(r.stdout)["verdict"] in ("PASS", "FAIL")

    def test_checks_is_list(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        d = json.loads(r.stdout)
        assert isinstance(d["checks"], list) and len(d["checks"]) >= 16

    def test_each_check_has_fields(self):
        r = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        for c in json.loads(r.stdout)["checks"]: assert "check" in c and "passed" in c

class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self): return {x["check"]: x for x in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_cohort_categories(self, results): assert results["cohort_categories"]["passed"]
    def test_struct_project_cohort(self, results): assert results["struct_ProjectCohort"]["passed"]
    def test_struct_validation_run(self, results): assert results["struct_ValidationRun"]["passed"]
    def test_struct_cohort_report(self, results): assert results["struct_CohortReport"]["passed"]
    def test_struct_migration_validation_cohorts(self, results): assert results["struct_MigrationValidationCohorts"]["passed"]
    def test_determinism_check(self, results): assert results["determinism_check"]["passed"]
    def test_reproduction_command(self, results): assert results["reproduction_command"]["passed"]
    def test_drift_detection(self, results): assert results["drift_detection"]["passed"]
    def test_coverage_analysis(self, results): assert results["coverage_analysis"]["passed"]
    def test_content_hash(self, results): assert results["content_hash"]["passed"]
    def test_event_codes(self, results): assert results["event_codes"]["passed"]
    def test_invariants(self, results): assert results["invariants"]["passed"]
    def test_audit_log(self, results): assert results["audit_log"]["passed"]
    def test_schema_version(self, results): assert results["schema_version"]["passed"]
    def test_spec_alignment(self, results): assert results["spec_alignment"]["passed"]
    def test_test_coverage(self, results): assert results["test_coverage"]["passed"]

class TestOverall:
    def test_all_pass(self):
        failed = [x["check"] for x in mod._checks() if not x["passed"]]
        assert not failed, f"Failed: {failed}"
    def test_minimum_check_count(self): assert len(mod._checks()) >= 16
