"""Tests for scripts/check_enterprise_governance.py (bd-3mj9)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_enterprise_governance.py")

spec = importlib.util.spec_from_file_location("check_egi", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-3mj9"
        assert data["section"] == "15"
        assert isinstance(data["checks"], list)


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_rule_categories(self, results): assert results["rule_categories"]["passed"]
    def test_enforcement_levels(self, results): assert results["enforcement_levels"]["passed"]
    def test_compliance_statuses(self, results): assert results["compliance_statuses"]["passed"]
    def test_struct_rule(self, results): assert results["struct_GovernanceRule"]["passed"]
    def test_struct_assessment(self, results): assert results["struct_ComplianceAssessment"]["passed"]
    def test_struct_category(self, results): assert results["struct_CategoryCompliance"]["passed"]
    def test_struct_report(self, results): assert results["struct_ComplianceReport"]["passed"]
    def test_struct_engine(self, results): assert results["struct_EnterpriseGovernance"]["passed"]
    def test_gate_actions(self, results): assert results["gate_actions"]["passed"]
    def test_compliance_rate(self, results): assert results["compliance_rate"]["passed"]
    def test_evidence_capture(self, results): assert results["evidence_capture"]["passed"]
    def test_blocked_rules(self, results): assert results["blocked_rules"]["passed"]
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
        assert "bd-3mj9" in result.stdout and "PASS" in result.stdout
