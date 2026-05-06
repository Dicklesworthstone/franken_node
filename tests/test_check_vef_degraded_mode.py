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
