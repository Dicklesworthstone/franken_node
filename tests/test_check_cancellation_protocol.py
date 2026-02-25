"""Tests for scripts/check_cancellation_protocol.py (bd-1cs7)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_cancellation_protocol.py")

spec = importlib.util.spec_from_file_location("check_cp", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-1cs7"
        assert data["section"] == "10.15"
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
        assert len(data["checks"]) >= 40


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    # ── File existence ────────────────────────────────────────────────
    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_spec_contract_exists(self, results): assert results["spec_contract_exists"]["passed"]
    def test_conformance_test_exists(self, results): assert results["conformance_test_exists"]["passed"]
    def test_timing_csv_exists(self, results): assert results["timing_csv_exists"]["passed"]
    def test_evidence_exists(self, results): assert results["evidence_exists"]["passed"]
    def test_summary_exists(self, results): assert results["summary_exists"]["passed"]

    # ── Phase enum ────────────────────────────────────────────────────
    def test_phase_Idle(self, results): assert results["phase_Idle"]["passed"]
    def test_phase_Requested(self, results): assert results["phase_Requested"]["passed"]
    def test_phase_Draining(self, results): assert results["phase_Draining"]["passed"]
    def test_phase_Finalizing(self, results): assert results["phase_Finalizing"]["passed"]
    def test_phase_Completed(self, results): assert results["phase_Completed"]["passed"]

    # ── Core types ────────────────────────────────────────────────────
    def test_type_CancellationPhase(self, results): assert results["type_CancellationPhase"]["passed"]
    def test_type_CancellationBudget(self, results): assert results["type_CancellationBudget"]["passed"]
    def test_type_CancellationProtocol(self, results): assert results["type_CancellationProtocol"]["passed"]
    def test_type_CancellationAuditEvent(self, results): assert results["type_CancellationAuditEvent"]["passed"]
    def test_type_ResourceTracker(self, results): assert results["type_ResourceTracker"]["passed"]
    def test_type_ResourceGuard(self, results): assert results["type_ResourceGuard"]["passed"]
    def test_type_PhaseTransitionResult(self, results): assert results["type_PhaseTransitionResult"]["passed"]
    def test_type_TimingRow(self, results): assert results["type_TimingRow"]["passed"]
    def test_type_WorkflowKind(self, results): assert results["type_WorkflowKind"]["passed"]

    # ── Workflow coverage ─────────────────────────────────────────────
    def test_workflow_coverage(self, results): assert results["workflow_coverage"]["passed"]

    # ── Core operations ───────────────────────────────────────────────
    def test_fn_request(self, results): assert results["fn_request"]["passed"]
    def test_fn_drain(self, results): assert results["fn_drain"]["passed"]
    def test_fn_finalize(self, results): assert results["fn_finalize"]["passed"]
    def test_fn_run_full(self, results): assert results["fn_run_full"]["passed"]
    def test_fn_force_finalize(self, results): assert results["fn_force_finalize"]["passed"]

    # ── Budget features ───────────────────────────────────────────────
    def test_budget_timeout_ms(self, results): assert results["budget_timeout_ms"]["passed"]
    def test_budget_is_exceeded(self, results): assert results["budget_is_exceeded"]["passed"]
    def test_budget_from_kind(self, results): assert results["budget_from_kind"]["passed"]

    # ── Resource tracking ─────────────────────────────────────────────
    def test_resource_acquire(self, results): assert results["resource_acquire"]["passed"]
    def test_resource_release(self, results): assert results["resource_release"]["passed"]
    def test_resource_has_leaks(self, results): assert results["resource_has_leaks"]["passed"]
    def test_resource_release_all(self, results): assert results["resource_release_all"]["passed"]

    # ── Drop safety ───────────────────────────────────────────────────
    def test_drop_safety(self, results): assert results["drop_safety"]["passed"]

    # ── Child propagation ─────────────────────────────────────────────
    def test_fn_register_child(self, results): assert results["fn_register_child"]["passed"]
    def test_fn_complete_child(self, results): assert results["fn_complete_child"]["passed"]

    # ── Audit features ────────────────────────────────────────────────
    def test_audit_log(self, results): assert results["audit_log"]["passed"]

    # ── Timing CSV ────────────────────────────────────────────────────
    def test_fn_generate_timing_csv(self, results): assert results["fn_generate_timing_csv"]["passed"]

    # ── Codes and invariants ──────────────────────────────────────────
    def test_event_codes(self, results): assert results["event_codes"]["passed"]
    def test_error_codes(self, results): assert results["error_codes"]["passed"]
    def test_invariants(self, results): assert results["invariants"]["passed"]
    def test_schema_version(self, results): assert results["schema_version"]["passed"]
    def test_bead_id(self, results): assert results["bead_id"]["passed"]

    # ── Integration: lifecycle ────────────────────────────────────────
    def test_lifecycle_cancelling_state(self, results): assert results["lifecycle_cancelling_state"]["passed"]
    def test_lifecycle_cancel_transition(self, results): assert results["lifecycle_cancel_transition"]["passed"]

    # ── Integration: rollout_state ────────────────────────────────────
    def test_rollout_cancel_phase(self, results): assert results["rollout_cancel_phase"]["passed"]
    def test_rollout_set_cancel(self, results): assert results["rollout_set_cancel"]["passed"]
    def test_rollout_is_cancelling(self, results): assert results["rollout_is_cancelling"]["passed"]
    def test_rollout_imports_cancel(self, results): assert results["rollout_imports_cancel"]["passed"]

    # ── Test coverage ─────────────────────────────────────────────────
    def test_test_coverage(self, results): assert results["test_coverage"]["passed"]

    # ── Timing CSV content ────────────────────────────────────────────
    def test_timing_csv_header(self, results): assert results["timing_csv_header"]["passed"]
    def test_timing_csv_has_rows(self, results): assert results["timing_csv_has_rows"]["passed"]

    # ── Spec contract sections ────────────────────────────────────────
    def test_spec_invariants(self, results): assert results["spec_invariants"]["passed"]
    def test_spec_event_codes(self, results): assert results["spec_event_codes"]["passed"]
    def test_spec_error_codes(self, results): assert results["spec_error_codes"]["passed"]
    def test_spec_acceptance_criteria(self, results): assert results["spec_acceptance_criteria"]["passed"]
    def test_spec_three_phase_protocol(self, results): assert results["spec_three_phase_protocol"]["passed"]
    def test_spec_gate_behavior(self, results): assert results["spec_gate_behavior"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [r for r in mod._checks() if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert json.loads(result.stdout)["verdict"] == "PASS"

    def test_human_output(self):
        result = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
        assert "bd-1cs7" in result.stdout and "PASS" in result.stdout
