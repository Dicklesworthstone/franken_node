"""Unit tests for scripts/check_vef_degraded_mode.py (bd-4jh9)."""

import importlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

mod = importlib.import_module("check_vef_degraded_mode")


# ── Helpers ────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_safe_rel_returns_string(self):
        result = mod._safe_rel(ROOT / "crates")
        assert isinstance(result, str)

    def test_safe_rel_temp_path(self):
        result = mod._safe_rel(Path("/tmp/no_such_path"))
        assert isinstance(result, str)

    def test_read_existing_file(self):
        content = mod._read(ROOT / "scripts" / "check_vef_degraded_mode.py")
        assert "bd-4jh9" in content

    def test_read_missing_file(self):
        content = mod._read(ROOT / "no_such_file.xyz")
        assert content == ""

    def test_check_pass(self):
        result = mod._check("test", True, "ok")
        assert result["pass"] is True
        assert result["check"] == "test"

    def test_check_fail(self):
        result = mod._check("fail-test", False, "bad")
        assert result["pass"] is False


# ── Constants ──────────────────────────────────────────────────────────────


class TestConstants:
    def test_required_types_count(self):
        assert len(mod.REQUIRED_TYPES) >= 13

    def test_required_event_codes_count(self):
        assert len(mod.REQUIRED_EVENT_CODES) == 5

    def test_required_modes_count(self):
        assert len(mod.REQUIRED_MODES) == 4

    def test_required_functions_count(self):
        assert len(mod.REQUIRED_FUNCTIONS) >= 6

    def test_required_metrics_count(self):
        assert len(mod.REQUIRED_METRICS) == 4

    def test_required_invariants_count(self):
        assert len(mod.REQUIRED_INVARIANTS_SPEC) == 5

    def test_event_codes_prefixed(self):
        for code in mod.REQUIRED_EVENT_CODES:
            assert code.startswith("VEF-DEGRADE-"), f"{code} missing VEF-DEGRADE- prefix"

    def test_modes_expected(self):
        assert "Normal" in mod.REQUIRED_MODES
        assert "Restricted" in mod.REQUIRED_MODES
        assert "Quarantine" in mod.REQUIRED_MODES
        assert "Halt" in mod.REQUIRED_MODES


# ── Simulation helpers ─────────────────────────────────────────────────────


class TestSimulationHelpers:
    def test_default_config(self):
        cfg = mod._default_config()
        assert cfg["restricted_slo"]["max_proof_lag_secs"] == 300
        assert cfg["quarantine_slo"]["max_proof_lag_secs"] == 900
        assert cfg["halt_multiplier"] == 2.0
        assert cfg["stabilization_window_secs"] == 120

    def test_halt_slo(self):
        cfg = mod._default_config()
        h = mod._halt_slo(cfg)
        assert h["max_proof_lag_secs"] == 1800
        assert h["max_backlog_depth"] == 1000
        assert h["max_error_rate"] == 0.50

    def test_slo_breached_true(self):
        slo = {"max_proof_lag_secs": 300, "max_backlog_depth": 100, "max_error_rate": 0.10}
        assert mod._slo_breached(slo, {"proof_lag_secs": 301, "backlog_depth": 0, "error_rate": 0.0})

    def test_slo_breached_false(self):
        slo = {"max_proof_lag_secs": 300, "max_backlog_depth": 100, "max_error_rate": 0.10}
        assert not mod._slo_breached(slo, {"proof_lag_secs": 300, "backlog_depth": 100, "error_rate": 0.10})

    def test_slo_breached_backlog(self):
        slo = {"max_proof_lag_secs": 300, "max_backlog_depth": 100, "max_error_rate": 0.10}
        assert mod._slo_breached(slo, {"proof_lag_secs": 0, "backlog_depth": 101, "error_rate": 0.0})

    def test_slo_breached_error_rate(self):
        slo = {"max_proof_lag_secs": 300, "max_backlog_depth": 100, "max_error_rate": 0.10}
        assert mod._slo_breached(slo, {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.11})

    def test_first_breach_proof_lag(self):
        slo = {"max_proof_lag_secs": 300, "max_backlog_depth": 100, "max_error_rate": 0.10}
        assert mod._first_breach(slo, {"proof_lag_secs": 301, "backlog_depth": 0, "error_rate": 0.0}) == "proof_lag_secs"

    def test_first_breach_backlog(self):
        slo = {"max_proof_lag_secs": 300, "max_backlog_depth": 100, "max_error_rate": 0.10}
        assert mod._first_breach(slo, {"proof_lag_secs": 0, "backlog_depth": 101, "error_rate": 0.0}) == "backlog_depth"

    def test_first_breach_none(self):
        slo = {"max_proof_lag_secs": 300, "max_backlog_depth": 100, "max_error_rate": 0.10}
        assert mod._first_breach(slo, {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0}) is None


# ── Target mode function ──────────────────────────────────────────────────


class TestTargetMode:
    def setup_method(self):
        self.cfg = mod._default_config()

    def test_normal(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "normal"

    def test_restricted_proof_lag(self):
        m = {"proof_lag_secs": 301, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "restricted"

    def test_restricted_backlog(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 101, "error_rate": 0.0, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "restricted"

    def test_restricted_error_rate(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.11, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "restricted"

    def test_quarantine_proof_lag(self):
        m = {"proof_lag_secs": 901, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "quarantine"

    def test_quarantine_backlog(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 501, "error_rate": 0.0, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "quarantine"

    def test_quarantine_error_rate(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.31, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "quarantine"

    def test_halt_proof_lag(self):
        m = {"proof_lag_secs": 1801, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "halt"

    def test_halt_backlog(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 1001, "error_rate": 0.0, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "halt"

    def test_halt_error_rate(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.51, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "halt"

    def test_halt_heartbeat(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 61}
        assert mod._target_mode(self.cfg, m) == "halt"

    def test_boundary_restricted_not_breached(self):
        m = {"proof_lag_secs": 300, "backlog_depth": 100, "error_rate": 0.10, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "normal"

    def test_boundary_quarantine_not_breached(self):
        m = {"proof_lag_secs": 900, "backlog_depth": 500, "error_rate": 0.30, "heartbeat_age_secs": 0}
        assert mod._target_mode(self.cfg, m) == "restricted"

    def test_boundary_heartbeat_not_breached(self):
        m = {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 60}
        assert mod._target_mode(self.cfg, m) == "normal"


# ── Lifecycle simulation ──────────────────────────────────────────────────


class TestLifecycleSimulation:
    def test_final_mode_normal(self):
        sim = mod.simulate_lifecycle()
        assert sim["final_mode"] == "normal"

    def test_events_non_empty(self):
        sim = mod.simulate_lifecycle()
        assert len(sim["events"]) > 0

    def test_slo_breach_events(self):
        sim = mod.simulate_lifecycle()
        codes = [e["event_code"] for e in sim["events"]]
        assert codes.count("VEF-DEGRADE-002") >= 3

    def test_transition_events(self):
        sim = mod.simulate_lifecycle()
        codes = [e["event_code"] for e in sim["events"]]
        assert codes.count("VEF-DEGRADE-001") >= 6

    def test_recovery_initiated(self):
        sim = mod.simulate_lifecycle()
        codes = [e["event_code"] for e in sim["events"]]
        assert codes.count("VEF-DEGRADE-003") >= 3

    def test_recovery_receipts(self):
        sim = mod.simulate_lifecycle()
        codes = [e["event_code"] for e in sim["events"]]
        assert codes.count("VEF-DEGRADE-004") >= 3

    def test_high_risk_blocked(self):
        sim = mod.simulate_lifecycle()
        assert sim["high_risk_blocked"] is True

    def test_low_risk_permitted(self):
        sim = mod.simulate_lifecycle()
        assert sim["low_risk_permitted"] is True

    def test_actions_affected(self):
        sim = mod.simulate_lifecycle()
        assert sim["actions_affected"] >= 2


# ── Determinism ────────────────────────────────────────────────────────────


class TestDeterminism:
    def test_deterministic(self):
        assert mod.simulate_determinism() is True

    def test_target_mode_same_twice(self):
        cfg = mod._default_config()
        m = {"proof_lag_secs": 500, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
        assert mod._target_mode(cfg, m) == mod._target_mode(cfg, m)


# ── Severity and step-down ─────────────────────────────────────────────────


class TestSeverityAndStepDown:
    def test_severity_ordering(self):
        assert mod.MODE_SEVERITY["normal"] < mod.MODE_SEVERITY["restricted"]
        assert mod.MODE_SEVERITY["restricted"] < mod.MODE_SEVERITY["quarantine"]
        assert mod.MODE_SEVERITY["quarantine"] < mod.MODE_SEVERITY["halt"]

    def test_step_down_halt(self):
        assert mod.STEP_DOWN["halt"] == "quarantine"

    def test_step_down_quarantine(self):
        assert mod.STEP_DOWN["quarantine"] == "restricted"

    def test_step_down_restricted(self):
        assert mod.STEP_DOWN["restricted"] == "normal"


# ── Self-test ──────────────────────────────────────────────────────────────


class TestSelfTest:
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        assert ok is True
        assert len(checks) >= 20

    def test_self_test_all_pass(self):
        ok, checks = mod.self_test()
        for c in checks:
            assert c["pass"], f"self-test check failed: {c['check']}"


# ── run_all ────────────────────────────────────────────────────────────────


class TestRunAll:
    def test_run_all_returns_dict(self):
        result = mod.run_all()
        assert isinstance(result, dict)

    def test_run_all_bead_id(self):
        result = mod.run_all()
        assert result["bead_id"] == "bd-4jh9"

    def test_run_all_section(self):
        result = mod.run_all()
        assert result["section"] == "10.18"

    def test_run_all_has_verdict(self):
        result = mod.run_all()
        assert result["verdict"] in ("PASS", "FAIL")

    def test_run_all_has_checks(self):
        result = mod.run_all()
        assert isinstance(result["checks"], list)
        assert len(result["checks"]) > 50

    def test_run_all_total_matches(self):
        result = mod.run_all()
        assert result["total"] == len(result["checks"])

    def test_run_all_passed_plus_failed(self):
        result = mod.run_all()
        assert result["passed"] + result["failed"] == result["total"]

    def test_run_all_json_serializable(self):
        result = mod.run_all()
        s = json.dumps(result)
        assert isinstance(s, str)
