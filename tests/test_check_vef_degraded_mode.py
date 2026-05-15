"""Unit tests for scripts/check_vef_degraded_mode.py (bd-4jh9)."""

import importlib
import json
import sys
from pathlib import Path
from unittest.mock import patch


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
        assert result["pass"]
        assert result["check"] == "test"

    def test_check_fail(self):
        result = mod._check("fail-test", False, "bad")
        assert not result["pass"]


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


# ── Real Rust evidence ─────────────────────────────────────────────────────


class TestRealRustEvidence:
    def test_real_evidence_requirements_count(self):
        assert len(mod.REAL_EVIDENCE_REQUIREMENTS) >= 6

    def test_real_evidence_checks_pass(self):
        mod.ALL_CHECKS.clear()
        mod.check_real_vef_evidence()
        checks = list(mod.ALL_CHECKS)
        assert checks
        assert all(check["pass"] for check in checks)

    def test_run_all_has_real_evidence_not_legacy_simulation(self):
        result = mod.run_all()
        checks = [check["check"] for check in result["checks"]]
        legacy_prefix = "s" + "im:"
        assert sum(check.startswith("real evidence:") for check in checks) >= 6
        assert not any(check.startswith(legacy_prefix) for check in checks)

    def test_legacy_python_lifecycle_helpers_absent(self):
        source = (ROOT / "scripts" / "check_vef_degraded_mode.py").read_text(encoding="utf-8")
        legacy_names = [
            "simulate_" + "lifecycle",
            "simulate_" + "determinism",
            "_target_" + "mode",
            "_slo_" + "breached",
            "_default_" + "config",
            "MODE_" + "SEVERITY",
            "STEP_" + "DOWN",
        ]
        for name in legacy_names:
            assert name not in source
            assert not hasattr(mod, name)


# ── Comment-only regressions ───────────────────────────────────────────────


class TestCommentOnlyRegressions:
    def test_comment_only_impl_markers_fail_closed(self):
        comment_only_impl = "\n".join(
            [
                "// pub enum VefMode { Normal, Restricted, Quarantine, Halt }",
                "// pub struct ProofLagSlo { pub max_proof_lag_secs: u64 }",
                "// pub struct VefDegradedModeConfig { pub restricted_slo: ProofLagSlo }",
                "// pub struct ProofLagMetrics { pub proof_lag_secs: u64, pub backlog_depth: u64, pub error_rate: f64, pub heartbeat_age_secs: u64 }",
                "// pub enum ActionRisk { HighRisk, LowRisk, HealthCheck }",
                "// pub struct VefActionDecision { pub permitted: bool }",
                "// pub struct VefModeTransitionEvent { pub correlation_id: String }",
                "// pub struct VefSloBreachEvent { pub correlation_id: String }",
                "// pub struct VefRecoveryInitiatedEvent { pub correlation_id: String }",
                "// pub struct VefRecoveryReceipt { pub degraded_mode_duration_secs: u64, pub actions_affected: u64, pub recovery_trigger: String, pub pipeline_health_at_recovery: ProofLagMetrics, pub from_mode: VefMode, pub to_mode: VefMode, pub correlation_id: String }",
                "// pub enum VefDegradedModeEvent { RecoveryComplete(VefRecoveryReceipt) }",
                "// pub struct VefTransitionErrorEvent { pub correlation_id: String }",
                "// pub struct VefDegradedModeEngine {}",
                '// pub const VEF_DEGRADE_001: &str = "VEF-DEGRADE-001";',
                '// pub const VEF_DEGRADE_002: &str = "VEF-DEGRADE-002";',
                '// pub const VEF_DEGRADE_003: &str = "VEF-DEGRADE-003";',
                '// pub const VEF_DEGRADE_004: &str = "VEF-DEGRADE-004";',
                '// pub const VEF_DEGRADE_ERR_001: &str = "VEF-DEGRADE-ERR-001";',
                "// pub fn observe_metrics(",
                "// pub fn evaluate_action(",
                "// pub fn target_mode_for_metrics(",
                "// fn escalate(",
                "// fn maybe_deescalate(",
                "// fn find_breach_details(",
                "// fn restricted_on_proof_lag_breach",
                "// fn quarantine_on_slo_breach",
                "// fn halt_on_critical_lag",
                "// fn halt_on_heartbeat_timeout",
                "// fn normal_to_restricted_to_quarantine_escalation",
                "// fn skip_to_halt_directly",
                "// fn deterministic_identical_metric_sequences",
                "// run1.observe_metrics(m, *t, \"det-1\")",
                "// assert_eq!(run1.mode(), run2.mode())",
                "// fn normal_permits_all",
                "// fn quarantine_blocks_high_risk",
                "// fn halt_blocks_all_except_health_check",
                "// VefDegradedModeEvent::RecoveryComplete",
                "// VEF_DEGRADE_003",
                "// VEF_DEGRADE_004",
            ]
            + ["// #[test]\n// fn normal_mode_by_default() {}" for _ in range(20)]
        )

        def fake_read(path: Path) -> str:
            if path == mod.IMPL_FILE:
                return comment_only_impl
            return ""

        mod.ALL_CHECKS.clear()
        with patch.object(mod, "_read", side_effect=fake_read):
            mod.check_types()
            mod.check_event_codes()
            mod.check_modes()
            mod.check_functions()
            mod.check_metrics()
            mod.check_tests()
            mod.check_determinism_invariant()
            mod.check_action_evaluation()
            mod.check_recovery_receipt_fields()
            mod.check_real_vef_evidence()

        checks = {check["check"]: check for check in mod.ALL_CHECKS}
        assert not checks["type: pub enum VefMode"]["pass"]
        assert not checks["event code: VEF-DEGRADE-001"]["pass"]
        assert not checks["mode variant: Normal"]["pass"]
        assert not checks["function: fn observe_metrics"]["pass"]
        assert not checks["metric field: proof_lag_secs"]["pass"]
        assert not checks["test: normal default"]["pass"]
        assert not checks["INV: deterministic function/test coverage"]["pass"]
        assert not checks["action: HighRisk variant"]["pass"]
        assert not checks["receipt: correlation_id"]["pass"]
        assert not checks["real evidence: tier escalation paths"]["pass"]

    def test_comment_only_mod_wiring_fails_closed(self):
        original_read = mod._read

        def fake_read(path: Path) -> str:
            if path == mod.MOD_FILE:
                return "// pub mod vef_degraded_mode;"
            return original_read(path)

        mod.ALL_CHECKS.clear()
        with patch.object(mod, "_read", side_effect=fake_read):
            mod.check_file_existence()

        checks = {check["check"]: check for check in mod.ALL_CHECKS}
        assert not checks["module wired in mod.rs"]["pass"]


# ── Self-test ──────────────────────────────────────────────────────────────


class TestSelfTest:
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        assert ok
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
