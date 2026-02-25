"""Tests for scripts/check_dpor_exploration.py (bd-22yy)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_dpor_exploration.py")

spec = importlib.util.spec_from_file_location("check_dpor", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-22yy"
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
        assert len(data["checks"]) >= 28


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_struct_model_id(self, results): assert results["struct_ProtocolModelId"]["passed"]
    def test_struct_operation(self, results): assert results["struct_Operation"]["passed"]
    def test_struct_safety_property(self, results): assert results["struct_SafetyProperty"]["passed"]
    def test_struct_protocol_model(self, results): assert results["struct_ProtocolModel"]["passed"]
    def test_struct_budget(self, results): assert results["struct_ExplorationBudget"]["passed"]
    def test_struct_step(self, results): assert results["struct_CounterexampleStep"]["passed"]
    def test_struct_counterexample(self, results): assert results["struct_Counterexample"]["passed"]
    def test_struct_schedule_result(self, results): assert results["struct_ScheduleResult"]["passed"]
    def test_struct_exploration_result(self, results): assert results["struct_ExplorationResult"]["passed"]
    def test_struct_audit_record(self, results): assert results["struct_DporAuditRecord"]["passed"]
    def test_struct_error(self, results): assert results["struct_DporError"]["passed"]
    def test_struct_explorer(self, results): assert results["struct_DporExplorer"]["passed"]
    def test_model_coverage(self, results): assert results["model_coverage"]["passed"]
    def test_fn_register_model(self, results): assert results["fn_register_model"]["passed"]
    def test_fn_explore(self, results): assert results["fn_explore"]["passed"]
    def test_fn_register_defaults(self, results): assert results["fn_register_default_models"]["passed"]
    def test_fn_validate(self, results): assert results["fn_validate"]["passed"]
    def test_fn_estimated(self, results): assert results["fn_estimated_schedules"]["passed"]
    def test_fn_linearizations(self, results): assert results["fn_generate_linearizations"]["passed"]
    def test_safety_properties(self, results): assert results["safety_properties"]["passed"]
    def test_counterexample_trace(self, results): assert results["counterexample_trace"]["passed"]
    def test_budget_config(self, results): assert results["budget_config"]["passed"]
    def test_memory_budget(self, results): assert results["memory_budget"]["passed"]
    def test_coverage_pct(self, results): assert results["coverage_pct"]["passed"]
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
        assert "bd-22yy" in result.stdout and "PASS" in result.stdout
