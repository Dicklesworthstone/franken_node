"""Tests for scripts/check_epoch_transition_barrier.py (bd-2wsm)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_epoch_transition_barrier.py")

spec = importlib.util.spec_from_file_location("check_etb", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-2wsm"
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
    def test_struct_barrier_phase(self, results): assert results["struct_BarrierPhase"]["passed"]
    def test_struct_drain_ack(self, results): assert results["struct_DrainAck"]["passed"]
    def test_struct_abort_reason(self, results): assert results["struct_AbortReason"]["passed"]
    def test_struct_barrier_error(self, results): assert results["struct_BarrierError"]["passed"]
    def test_struct_barrier_config(self, results): assert results["struct_BarrierConfig"]["passed"]
    def test_struct_transcript_entry(self, results): assert results["struct_TranscriptEntry"]["passed"]
    def test_struct_barrier_transcript(self, results): assert results["struct_BarrierTranscript"]["passed"]
    def test_struct_barrier_audit_record(self, results): assert results["struct_BarrierAuditRecord"]["passed"]
    def test_struct_barrier_instance(self, results): assert results["struct_BarrierInstance"]["passed"]
    def test_struct_epoch_transition_barrier(self, results): assert results["struct_EpochTransitionBarrier"]["passed"]
    def test_phase_proposed(self, results): assert results["phase_proposed"]["passed"]
    def test_phase_draining(self, results): assert results["phase_draining"]["passed"]
    def test_phase_committed(self, results): assert results["phase_committed"]["passed"]
    def test_phase_aborted(self, results): assert results["phase_aborted"]["passed"]
    def test_fn_propose(self, results): assert results["fn_propose"]["passed"]
    def test_fn_record_drain_ack(self, results): assert results["fn_record_drain_ack"]["passed"]
    def test_fn_try_commit(self, results): assert results["fn_try_commit"]["passed"]
    def test_fn_abort(self, results): assert results["fn_abort"]["passed"]
    def test_fn_record_drain_failure(self, results): assert results["fn_record_drain_failure"]["passed"]
    def test_fn_check_participant_timeouts(self, results): assert results["fn_check_participant_timeouts"]["passed"]
    def test_fn_register_participant(self, results): assert results["fn_register_participant"]["passed"]
    def test_all_acked(self, results): assert results["all_acked"]["passed"]
    def test_missing_acks(self, results): assert results["missing_acks"]["passed"]
    def test_is_terminal(self, results): assert results["is_terminal"]["passed"]
    def test_is_barrier_active(self, results): assert results["is_barrier_active"]["passed"]
    def test_configurable_timeout(self, results): assert results["configurable_timeout"]["passed"]
    def test_transcript_export(self, results): assert results["transcript_export"]["passed"]
    def test_audit_log(self, results): assert results["audit_log"]["passed"]
    def test_event_codes(self, results): assert results["event_codes"]["passed"]
    def test_error_codes(self, results): assert results["error_codes"]["passed"]
    def test_invariants(self, results): assert results["invariants"]["passed"]
    def test_config_validation(self, results): assert results["config_validation"]["passed"]
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
        assert "bd-2wsm" in result.stdout and "PASS" in result.stdout
