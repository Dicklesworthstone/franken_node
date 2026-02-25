"""Tests for scripts/check_transition_abort.py (bd-1vsr)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_transition_abort.py")

spec = importlib.util.spec_from_file_location("check_ta", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-1vsr"
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
        assert len(data["checks"]) >= 25


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_struct_abort_reason(self, results): assert results["struct_TransitionAbortReason"]["passed"]
    def test_struct_participant_state(self, results): assert results["struct_ParticipantAbortState"]["passed"]
    def test_struct_abort_event(self, results): assert results["struct_TransitionAbortEvent"]["passed"]
    def test_struct_force_policy(self, results): assert results["struct_ForceTransitionPolicy"]["passed"]
    def test_struct_abort_error(self, results): assert results["struct_AbortError"]["passed"]
    def test_struct_force_event(self, results): assert results["struct_ForceTransitionEvent"]["passed"]
    def test_struct_audit_record(self, results): assert results["struct_AbortAuditRecord"]["passed"]
    def test_struct_manager(self, results): assert results["struct_TransitionAbortManager"]["passed"]
    def test_reason_timeout(self, results): assert results["reason_timeout"]["passed"]
    def test_reason_cancellation(self, results): assert results["reason_cancellation"]["passed"]
    def test_reason_participant_failure(self, results): assert results["reason_participant_failure"]["passed"]
    def test_fn_validate_force_policy(self, results): assert results["fn_validate_force_policy"]["passed"]
    def test_fn_record_abort(self, results): assert results["fn_record_abort"]["passed"]
    def test_fn_record_force_transition(self, results): assert results["fn_record_force_transition"]["passed"]
    def test_fn_verify_no_partial_state(self, results): assert results["fn_verify_no_partial_state"]["passed"]
    def test_fn_policy_hash(self, results): assert results["fn_policy_hash"]["passed"]
    def test_force_skippable(self, results): assert results["force_skippable"]["passed"]
    def test_force_max_skippable(self, results): assert results["force_max_skippable"]["passed"]
    def test_force_operator_id(self, results): assert results["force_operator_id"]["passed"]
    def test_force_audit_reason(self, results): assert results["force_audit_reason"]["passed"]
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
        assert "bd-1vsr" in result.stdout and "PASS" in result.stdout
