"""Tests for scripts/check_transparent_reports.py (bd-10ee)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_transparent_reports.py")

spec = importlib.util.spec_from_file_location("check_tr", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-10ee"
        assert data["section"] == "16"
        assert isinstance(data["checks"], list)


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_report_categories(self, results): assert results["report_categories"]["passed"]
    def test_required_sections(self, results): assert results["required_sections"]["passed"]
    def test_action_statuses(self, results): assert results["action_statuses"]["passed"]
    def test_status_transitions(self, results): assert results["status_transitions"]["passed"]
    def test_struct_report(self, results): assert results["struct_TransparentReport"]["passed"]
    def test_struct_timeline(self, results): assert results["struct_TimelineEntry"]["passed"]
    def test_struct_action(self, results): assert results["struct_CorrectiveAction"]["passed"]
    def test_struct_catalog(self, results): assert results["struct_ReportCatalog"]["passed"]
    def test_struct_engine(self, results): assert results["struct_TransparentReports"]["passed"]
    def test_timeline_validation(self, results): assert results["timeline_validation"]["passed"]
    def test_root_cause(self, results): assert results["root_cause_analysis"]["passed"]
    def test_lessons(self, results): assert results["lessons_learned"]["passed"]
    def test_hashing(self, results): assert results["content_hashing"]["passed"]
    def test_catalog(self, results): assert results["catalog_generation"]["passed"]
    def test_event_codes(self, results): assert results["event_codes"]["passed"]
    def test_invariants(self, results): assert results["invariants"]["passed"]
    def test_audit_log(self, results): assert results["audit_log"]["passed"]
    def test_version(self, results): assert results["report_version"]["passed"]
    def test_spec(self, results): assert results["spec_alignment"]["passed"]
    def test_coverage(self, results): assert results["test_coverage"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [r for r in mod._checks() if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert json.loads(result.stdout)["verdict"] == "PASS"

    def test_human_output(self):
        result = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
        assert "bd-10ee" in result.stdout and "PASS" in result.stdout
