"""Tests for scripts/check_redteam_evaluations.py (bd-3id1)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_redteam_evaluations.py")

spec = importlib.util.spec_from_file_location("check_rte", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-3id1"
        assert data["section"] == "16"
        assert isinstance(data["checks"], list)


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_severity_levels(self, results): assert results["severity_levels"]["passed"]
    def test_evaluation_types(self, results): assert results["evaluation_types"]["passed"]
    def test_remediation_statuses(self, results): assert results["remediation_statuses"]["passed"]
    def test_status_transitions(self, results): assert results["status_transitions"]["passed"]
    def test_struct_engagement(self, results): assert results["struct_Engagement"]["passed"]
    def test_struct_finding(self, results): assert results["struct_Finding"]["passed"]
    def test_struct_catalog(self, results): assert results["struct_EvaluationCatalog"]["passed"]
    def test_struct_engine(self, results): assert results["struct_RedTeamEvaluations"]["passed"]
    def test_scope_validation(self, results): assert results["scope_validation"]["passed"]
    def test_confidence_scoring(self, results): assert results["confidence_scoring"]["passed"]
    def test_remediation_tracking(self, results): assert results["remediation_tracking"]["passed"]
    def test_catalog_generation(self, results): assert results["catalog_generation"]["passed"]
    def test_event_codes(self, results): assert results["event_codes"]["passed"]
    def test_invariants(self, results): assert results["invariants"]["passed"]
    def test_audit_log(self, results): assert results["audit_log"]["passed"]
    def test_schema_version(self, results): assert results["schema_version"]["passed"]
    def test_spec_alignment(self, results): assert results["spec_alignment"]["passed"]
    def test_test_coverage(self, results): assert results["test_coverage"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [r for r in mod._checks() if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert json.loads(result.stdout)["verdict"] == "PASS"

    def test_human_output(self):
        result = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
        assert "bd-3id1" in result.stdout and "PASS" in result.stdout
