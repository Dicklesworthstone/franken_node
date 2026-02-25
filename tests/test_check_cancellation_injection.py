"""Tests for scripts/check_cancellation_injection.py (bd-876n)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_cancellation_injection.py")

spec = importlib.util.spec_from_file_location("check_ci", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-876n"
        assert data["section"] == "10.14"
        assert isinstance(data["checks"], list)

    def test_verdict_field(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["verdict"] in ("PASS", "FAIL")

    def test_checks_have_fields(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        for c in data["checks"]:
            assert "check" in c and "passed" in c and "detail" in c

    def test_minimum_check_count(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert len(data["checks"]) >= 30


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_struct_workflow_id(self, results): assert results["struct_WorkflowId"]["passed"]
    def test_struct_await_point(self, results): assert results["struct_AwaitPoint"]["passed"]
    def test_struct_resource_snapshot(self, results): assert results["struct_ResourceSnapshot"]["passed"]
    def test_struct_resource_delta(self, results): assert results["struct_ResourceDelta"]["passed"]
    def test_struct_state_snapshot(self, results): assert results["struct_StateSnapshot"]["passed"]
    def test_struct_halfcommit(self, results): assert results["struct_HalfCommitDetection"]["passed"]
    def test_struct_outcome(self, results): assert results["struct_CancelTestOutcome"]["passed"]
    def test_struct_matrix_entry(self, results): assert results["struct_CancelMatrixEntry"]["passed"]
    def test_struct_matrix(self, results): assert results["struct_CancelInjectionMatrix"]["passed"]
    def test_struct_audit_record(self, results): assert results["struct_CancelAuditRecord"]["passed"]
    def test_struct_error(self, results): assert results["struct_CancelError"]["passed"]
    def test_struct_workflow_reg(self, results): assert results["struct_WorkflowRegistration"]["passed"]
    def test_struct_framework(self, results): assert results["struct_CancellationInjectionFramework"]["passed"]
    def test_workflow_coverage(self, results): assert results["workflow_coverage"]["passed"]
    def test_fn_register_workflow(self, results): assert results["fn_register_workflow"]["passed"]
    def test_fn_run_cancel_case(self, results): assert results["fn_run_cancel_case"]["passed"]
    def test_fn_register_default(self, results): assert results["fn_register_default_workflows"]["passed"]
    def test_fn_detect_halfcommit(self, results): assert results["fn_detect_halfcommit"]["passed"]
    def test_fn_has_leaks(self, results): assert results["fn_has_leaks"]["passed"]
    def test_fn_delta(self, results): assert results["fn_delta"]["passed"]
    def test_matrix_coverage(self, results): assert results["matrix_coverage"]["passed"]
    def test_matrix_verdict(self, results): assert results["matrix_verdict"]["passed"]
    def test_matrix_record_case(self, results): assert results["matrix_record_case"]["passed"]
    def test_min_matrix_cases(self, results): assert results["min_matrix_cases"]["passed"]
    def test_audit_log(self, results): assert results["audit_log"]["passed"]
    def test_event_codes(self, results): assert results["event_codes"]["passed"]
    def test_error_codes(self, results): assert results["error_codes"]["passed"]
    def test_invariants(self, results): assert results["invariants"]["passed"]
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
        assert "bd-876n" in result.stdout and "PASS" in result.stdout
