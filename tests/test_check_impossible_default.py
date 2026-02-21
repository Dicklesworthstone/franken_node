"""Unit tests for check_impossible_default.py verification script (bd-1xao)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

spec = importlib.util.spec_from_file_location(
    "check_impossible_default",
    os.path.join(ROOT, "scripts/check_impossible_default.py"),
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ── run_all() shape ───────────────────────────────────────────────────────────


class TestRunAll:
    def test_returns_dict(self):
        result = mod.run_all()
        assert isinstance(result, dict)

    def test_has_required_keys(self):
        result = mod.run_all()
        for key in ("bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"):
            assert key in result, f"Missing key: {key}"

    def test_bead_id(self):
        assert mod.run_all()["bead_id"] == "bd-1xao"

    def test_section(self):
        assert mod.run_all()["section"] == "13"

    def test_checks_is_list(self):
        assert isinstance(mod.run_all()["checks"], list)

    def test_all_entries_have_required_keys(self):
        for entry in mod.run_all()["checks"]:
            assert "check" in entry
            assert "pass" in entry
            assert "detail" in entry

    def test_pass_values_are_bool(self):
        for entry in mod.run_all()["checks"]:
            assert isinstance(entry["pass"], bool)

    def test_minimum_check_count(self):
        result = mod.run_all()
        assert result["total"] >= 90, f"Expected >= 90 checks, got {result['total']}"

    def test_total_equals_passed_plus_failed(self):
        result = mod.run_all()
        assert result["total"] == result["passed"] + result["failed"]

    def test_all_checks_pass(self):
        result = mod.run_all()
        failing = [c for c in result["checks"] if not c["pass"]]
        assert not failing, f"Failing checks: {failing}"

    def test_verdict_is_pass(self):
        result = mod.run_all()
        assert result["verdict"] == "PASS"


# ── File checks ───────────────────────────────────────────────────────────────


class TestFileChecks:
    def _get_check(self, name):
        return next(c for c in mod.run_all()["checks"] if c["check"] == name)

    def test_implementation_file(self):
        assert self._get_check("file: implementation")["pass"]

    def test_spec_file(self):
        assert self._get_check("file: spec contract")["pass"]

    def test_policy_file(self):
        assert self._get_check("file: policy document")["pass"]

    def test_evidence_file(self):
        assert self._get_check("file: evidence artifact")["pass"]

    def test_summary_file(self):
        assert self._get_check("file: verification summary")["pass"]


# ── Module registration ──────────────────────────────────────────────────────


class TestModuleRegistration:
    def test_module_registered(self):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == "module registered in mod.rs")
        assert check["pass"]


# ── Type checks ───────────────────────────────────────────────────────────────


class TestTypeChecks:
    TYPES = [
        "pub enum ImpossibleCapability",
        "pub struct CapabilityToken",
        "pub struct CapabilityEnforcer",
        "pub struct EnforcementReport",
        "pub struct EnforcementError",
        "pub struct EnforcementAuditEntry",
        "pub struct EnforcementMetrics",
        "pub enum EnforcementStatus",
        "pub struct CapabilityReportEntry",
    ]

    @pytest.mark.parametrize("ty", TYPES)
    def test_type_found(self, ty):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == f"type: {ty}")
        assert check["pass"], f"Type not found: {ty}"


# ── Capability variants ──────────────────────────────────────────────────────


class TestCapabilityVariants:
    VARIANTS = ["FsAccess", "OutboundNetwork", "ChildProcessSpawn", "UnsignedExtension", "DisableHardening"]

    @pytest.mark.parametrize("variant", VARIANTS)
    def test_variant_found(self, variant):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == f"capability_variant: {variant}")
        assert check["pass"]


# ── Event codes ───────────────────────────────────────────────────────────────


class TestEventCodes:
    CODES = ["IBD-001", "IBD-002", "IBD-003", "IBD-004"]

    @pytest.mark.parametrize("code", CODES)
    def test_event_code_in_impl(self, code):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == f"event_code_value: {code}")
        assert check["pass"]

    @pytest.mark.parametrize("code", CODES)
    def test_event_code_in_spec(self, code):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == f"event_code_in_spec: {code}")
        assert check["pass"]

    @pytest.mark.parametrize("code", CODES)
    def test_event_code_in_policy(self, code):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == f"event_code_in_policy: {code}")
        assert check["pass"]


# ── Error codes ───────────────────────────────────────────────────────────────


class TestErrorCodes:
    CODES = ["ERR_IBD_BLOCKED", "ERR_IBD_TOKEN_EXPIRED", "ERR_IBD_INVALID_SIGNATURE", "ERR_IBD_SILENT_DISABLE"]

    @pytest.mark.parametrize("code", CODES)
    def test_error_code_found(self, code):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == f"error_code: {code}")
        assert check["pass"]


# ── Invariants ────────────────────────────────────────────────────────────────


class TestInvariants:
    IMPL_INVARIANTS = ["INV-IBD-ENFORCE", "INV-IBD-TOKEN", "INV-IBD-AUDIT", "INV-IBD-ADOPTION"]
    SPEC_INVARIANTS = ["INV-IBD-DEFAULT", "INV-IBD-AUTH", "INV-IBD-AUDIT", "INV-IBD-COVERAGE"]

    @pytest.mark.parametrize("inv", IMPL_INVARIANTS)
    def test_invariant_in_impl(self, inv):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == f"invariant_in_impl: {inv}")
        assert check["pass"]

    @pytest.mark.parametrize("inv", SPEC_INVARIANTS)
    def test_invariant_in_spec(self, inv):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == f"invariant_in_spec: {inv}")
        assert check["pass"]


# ── Acceptance criteria ───────────────────────────────────────────────────────


class TestAcceptanceCriteria:
    def _get_check(self, name):
        return next(c for c in mod.run_all()["checks"] if c["check"] == name)

    def test_ac1_capabilities_enumerated(self):
        assert self._get_check("ac1: capabilities enumerated")["pass"]

    def test_ac2_blocked_by_default(self):
        assert self._get_check("ac2: blocked by default state")["pass"]

    def test_ac3_token_expiry(self):
        assert self._get_check("ac3: token expiry field")["pass"]

    def test_ac3_token_signature(self):
        assert self._get_check("ac3: token signature field")["pass"]

    def test_ac4_actionable_descriptions(self):
        assert self._get_check("ac4: actionable descriptions")["pass"]

    def test_ac5_adoption_rate(self):
        assert self._get_check("ac5: adoption rate computation")["pass"]

    def test_ac6_silent_disable(self):
        assert self._get_check("ac6: silent disable detection")["pass"]

    def test_ac7_report_generation(self):
        assert self._get_check("ac7: report generation")["pass"]


# ── Serde and SHA-256 ─────────────────────────────────────────────────────────


class TestInfrastructure:
    def _get_check(self, name):
        return next(c for c in mod.run_all()["checks"] if c["check"] == name)

    def test_serde_serialize(self):
        assert self._get_check("serde: Serialize")["pass"]

    def test_serde_deserialize(self):
        assert self._get_check("serde: Deserialize")["pass"]

    def test_sha256(self):
        assert self._get_check("sha256: audit chain integrity")["pass"]


# ── Unit test checks ─────────────────────────────────────────────────────────


class TestUnitTests:
    def test_count_passes(self):
        checks = mod.run_all()["checks"]
        check = next(c for c in checks if c["check"] == "unit test count")
        assert check["pass"], check["detail"]


# ── Spec content ──────────────────────────────────────────────────────────────


class TestSpecContent:
    def _get_check(self, name):
        return next(c for c in mod.run_all()["checks"] if c["check"] == name)

    def test_mentions_bead_id(self):
        assert self._get_check("spec: mentions bd-1xao")["pass"]

    def test_has_acceptance_criteria(self):
        assert self._get_check("spec: has acceptance criteria")["pass"]

    def test_has_state_machine(self):
        assert self._get_check("spec: has state machine")["pass"]

    def test_has_adoption_tiers(self):
        assert self._get_check("spec: has adoption tiers")["pass"]

    def test_has_quantitative_targets(self):
        assert self._get_check("spec: has quantitative targets")["pass"]


# ── Policy content ────────────────────────────────────────────────────────────


class TestPolicyContent:
    def _get_check(self, name):
        return next(c for c in mod.run_all()["checks"] if c["check"] == name)

    def test_has_risk(self):
        assert self._get_check("policy: has risk description")["pass"]

    def test_has_impact(self):
        assert self._get_check("policy: has impact")["pass"]

    def test_has_monitoring(self):
        assert self._get_check("policy: has monitoring")["pass"]

    def test_has_escalation(self):
        assert self._get_check("policy: has escalation")["pass"]

    def test_has_evidence(self):
        assert self._get_check("policy: has evidence requirements")["pass"]


# ── Evidence artifact ─────────────────────────────────────────────────────────


class TestEvidenceArtifact:
    def _get_check(self, name):
        return next(c for c in mod.run_all()["checks"] if c["check"] == name)

    def test_valid_json(self):
        assert self._get_check("evidence: valid JSON")["pass"]

    def test_bead_id(self):
        assert self._get_check("evidence: has bead_id")["pass"]

    def test_section(self):
        assert self._get_check("evidence: has section")["pass"]

    def test_event_codes(self):
        assert self._get_check("evidence: has event_codes")["pass"]

    def test_invariants(self):
        assert self._get_check("evidence: has invariants")["pass"]


# ── Self-test ─────────────────────────────────────────────────────────────────


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test()


# ── _check helper ─────────────────────────────────────────────────────────────


class TestCheckHelper:
    def test_pass_true(self):
        mod.RESULTS.clear()
        result = mod._check("t", True, "ok")
        assert result["pass"] is True
        assert result["detail"] == "ok"

    def test_pass_false_default_detail(self):
        mod.RESULTS.clear()
        result = mod._check("t", False)
        assert result["pass"] is False
        assert result["detail"] == "NOT FOUND"


# ── _safe_rel helper ──────────────────────────────────────────────────────────


class TestSafeRel:
    def test_relative_inside_root(self):
        p = os.path.join(mod.ROOT, "foo/bar.txt")
        assert mod._safe_rel(p) == "foo/bar.txt"

    def test_path_outside_root(self):
        p = "/tmp/some_random_path/file.txt"
        result = mod._safe_rel(p)
        # Should not crash; returns something
        assert isinstance(result, str)


# ── CLI JSON output ───────────────────────────────────────────────────────────


class TestJsonOutput:
    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts/check_impossible_default.py"), "--json"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"
        assert data["bead_id"] == "bd-1xao"

    def test_cli_self_test(self):
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts/check_impossible_default.py"), "--self-test"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Self-test failed: {result.stderr}"


# ── _file_exists helper ──────────────────────────────────────────────────────


class TestFileExists:
    def test_existing_file(self):
        mod.RESULTS.clear()
        result = mod._file_exists(mod.IMPL, "test-label")
        assert result["pass"] is True
        assert "exists" in result["detail"]

    def test_missing_file(self):
        mod.RESULTS.clear()
        result = mod._file_exists("/nonexistent/path/file.rs", "test-missing")
        assert result["pass"] is False
        assert "missing" in result["detail"]
