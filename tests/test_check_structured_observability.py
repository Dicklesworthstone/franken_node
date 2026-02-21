"""Unit tests for scripts/check_structured_observability.py (bd-3o6)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_structured_observability",
    ROOT / "scripts" / "check_structured_observability.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Test: run_all structure
# ---------------------------------------------------------------------------

class TestRunAllStructure(unittest.TestCase):
    def test_run_all_returns_dict(self):
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_run_all_has_required_keys(self):
        result = mod.run_all()
        for key in ["bead_id", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_bead_id(self):
        self.assertEqual(mod.run_all()["bead_id"], "bd-3o6")

    def test_section(self):
        self.assertEqual(mod.run_all()["section"], "10.8")

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_total_equals_passed_plus_failed(self):
        result = mod.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_checks_is_list(self):
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)

    def test_check_entry_structure(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


# ---------------------------------------------------------------------------
# Test: self_test
# ---------------------------------------------------------------------------

class TestSelfTest(unittest.TestCase):
    def test_self_test_returns_bool(self):
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


# ---------------------------------------------------------------------------
# Test: individual check functions
# ---------------------------------------------------------------------------

class TestIndividualChecks(unittest.TestCase):
    def _run_check(self, fn):
        mod.RESULTS.clear()
        fn()
        self.assertGreater(len(mod.RESULTS), 0)
        return mod.RESULTS[-1]

    def test_check_spec_exists(self):
        result = self._run_check(mod.check_spec_exists)
        self.assertTrue(result["pass"])

    def test_check_policy_exists(self):
        result = self._run_check(mod.check_policy_exists)
        self.assertTrue(result["pass"])

    def test_check_upstream_telemetry_ns(self):
        result = self._run_check(mod.check_upstream_telemetry_ns)
        self.assertTrue(result["pass"])

    def test_check_upstream_error_registry(self):
        result = self._run_check(mod.check_upstream_error_registry)
        self.assertTrue(result["pass"])

    def test_check_upstream_trace_context(self):
        result = self._run_check(mod.check_upstream_trace_context)
        self.assertTrue(result["pass"])

    def test_check_spec_event_codes(self):
        result = self._run_check(mod.check_spec_event_codes)
        self.assertTrue(result["pass"])

    def test_check_spec_invariants(self):
        result = self._run_check(mod.check_spec_invariants)
        self.assertTrue(result["pass"])

    def test_check_spec_operational_surfaces(self):
        result = self._run_check(mod.check_spec_operational_surfaces)
        self.assertTrue(result["pass"])

    def test_check_spec_recovery_hint_schema(self):
        result = self._run_check(mod.check_spec_recovery_hint_schema)
        self.assertTrue(result["pass"])

    def test_check_spec_backward_compatibility(self):
        result = self._run_check(mod.check_spec_backward_compatibility)
        self.assertTrue(result["pass"])

    def test_check_spec_adoption_checklist(self):
        result = self._run_check(mod.check_spec_adoption_checklist)
        self.assertTrue(result["pass"])

    def test_check_policy_canonical_log_format(self):
        result = self._run_check(mod.check_policy_canonical_log_format)
        self.assertTrue(result["pass"])

    def test_check_policy_error_taxonomy(self):
        result = self._run_check(mod.check_policy_error_taxonomy)
        self.assertTrue(result["pass"])

    def test_check_policy_severity_levels(self):
        result = self._run_check(mod.check_policy_severity_levels)
        self.assertTrue(result["pass"])

    def test_check_policy_trace_ids(self):
        result = self._run_check(mod.check_policy_trace_ids)
        self.assertTrue(result["pass"])

    def test_check_policy_recovery_hints(self):
        result = self._run_check(mod.check_policy_recovery_hints)
        self.assertTrue(result["pass"])

    def test_check_policy_surface_inventory(self):
        result = self._run_check(mod.check_policy_surface_inventory)
        self.assertTrue(result["pass"])

    def test_check_policy_enforcement_event_codes(self):
        result = self._run_check(mod.check_policy_enforcement_event_codes)
        self.assertTrue(result["pass"])

    def test_check_policy_invariants(self):
        result = self._run_check(mod.check_policy_invariants)
        self.assertTrue(result["pass"])

    def test_check_policy_deprecation_cycle(self):
        result = self._run_check(mod.check_policy_deprecation_cycle)
        self.assertTrue(result["pass"])

    def test_check_policy_governance(self):
        result = self._run_check(mod.check_policy_governance)
        self.assertTrue(result["pass"])

    def test_check_upstream_telemetry_ns_spec(self):
        result = self._run_check(mod.check_upstream_telemetry_ns_spec)
        self.assertTrue(result["pass"])

    def test_check_upstream_error_registry_spec(self):
        result = self._run_check(mod.check_upstream_error_registry_spec)
        self.assertTrue(result["pass"])

    def test_check_telemetry_ns_has_schema_registry(self):
        result = self._run_check(mod.check_telemetry_ns_has_schema_registry)
        self.assertTrue(result["pass"])

    def test_check_error_reg_has_recovery_info(self):
        result = self._run_check(mod.check_error_reg_has_recovery_info)
        self.assertTrue(result["pass"])

    def test_check_trace_ctx_has_trace_context(self):
        result = self._run_check(mod.check_trace_ctx_has_trace_context)
        self.assertTrue(result["pass"])

    def test_check_cli_has_json_flag(self):
        result = self._run_check(mod.check_cli_has_json_flag)
        self.assertTrue(result["pass"])

    def test_check_spec_canonical_prefixes(self):
        result = self._run_check(mod.check_spec_canonical_prefixes)
        self.assertTrue(result["pass"])

    def test_check_policy_canonical_prefixes(self):
        result = self._run_check(mod.check_policy_canonical_prefixes)
        self.assertTrue(result["pass"])

    def test_check_spec_dependencies_documented(self):
        result = self._run_check(mod.check_spec_dependencies_documented)
        self.assertTrue(result["pass"])


# ---------------------------------------------------------------------------
# Test: missing file detection
# ---------------------------------------------------------------------------

class TestMissingFileDetection(unittest.TestCase):
    def test_missing_spec_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "spec.md"
        with patch.object(mod, "SPEC", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("spec" in c["check"].lower() for c in failed))

    def test_missing_policy_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "policy.md"
        with patch.object(mod, "POLICY", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("policy" in c["check"].lower() for c in failed))

    def test_missing_telemetry_ns_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "telemetry.rs"
        with patch.object(mod, "TELEMETRY_NS_IMPL", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(any("telemetry" in c["check"].lower() for c in failed))

    def test_missing_error_reg_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "error_reg.rs"
        with patch.object(mod, "ERROR_REG_IMPL", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(any("error" in c["check"].lower() for c in failed))


# ---------------------------------------------------------------------------
# Test: validate_recovery_hint helper
# ---------------------------------------------------------------------------

class TestValidateRecoveryHint(unittest.TestCase):
    def _make_hint(self, **overrides):
        hint = {
            "action": "retry",
            "target": "franken.protocol.auth_service",
            "confidence": 0.85,
            "escalation_path": "on-call-sre",
        }
        hint.update(overrides)
        return hint

    def test_valid_hint(self):
        results = mod.validate_recovery_hint(self._make_hint())
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_valid_hint_without_escalation(self):
        hint = self._make_hint()
        del hint["escalation_path"]
        results = mod.validate_recovery_hint(hint)
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_invalid_action(self):
        results = mod.validate_recovery_hint(self._make_hint(action="unknown"))
        action_check = [r for r in results if r["name"] == "hint_action_valid"][0]
        self.assertFalse(action_check["passed"])

    def test_all_valid_actions(self):
        for action in mod.RECOVERY_HINT_ACTIONS:
            results = mod.validate_recovery_hint(self._make_hint(action=action))
            action_check = [r for r in results if r["name"] == "hint_action_valid"][0]
            self.assertTrue(action_check["passed"], f"Valid action '{action}' rejected")

    def test_empty_target(self):
        results = mod.validate_recovery_hint(self._make_hint(target=""))
        target_check = [r for r in results if r["name"] == "hint_target_present"][0]
        self.assertFalse(target_check["passed"])

    def test_confidence_out_of_range_high(self):
        results = mod.validate_recovery_hint(self._make_hint(confidence=1.5))
        conf_check = [r for r in results if r["name"] == "hint_confidence_range"][0]
        self.assertFalse(conf_check["passed"])

    def test_confidence_out_of_range_low(self):
        results = mod.validate_recovery_hint(self._make_hint(confidence=-0.1))
        conf_check = [r for r in results if r["name"] == "hint_confidence_range"][0]
        self.assertFalse(conf_check["passed"])

    def test_confidence_boundary_zero(self):
        results = mod.validate_recovery_hint(self._make_hint(confidence=0.0))
        conf_check = [r for r in results if r["name"] == "hint_confidence_range"][0]
        self.assertTrue(conf_check["passed"])

    def test_confidence_boundary_one(self):
        results = mod.validate_recovery_hint(self._make_hint(confidence=1.0))
        conf_check = [r for r in results if r["name"] == "hint_confidence_range"][0]
        self.assertTrue(conf_check["passed"])


# ---------------------------------------------------------------------------
# Test: validate_structured_log_entry helper
# ---------------------------------------------------------------------------

class TestValidateStructuredLogEntry(unittest.TestCase):
    def _make_entry(self, **overrides):
        entry = {
            "timestamp": "2026-02-20T12:00:00.000Z",
            "level": "error",
            "message": "Authentication failed",
            "trace_id": "a" * 32,
            "span_id": "b" * 16,
            "error_code": "FRANKEN_PROTOCOL_AUTH_FAILED",
            "surface": "OPS-API",
        }
        entry.update(overrides)
        return entry

    def test_valid_entry(self):
        results = mod.validate_structured_log_entry(self._make_entry())
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_missing_trace_id(self):
        entry = self._make_entry()
        del entry["trace_id"]
        results = mod.validate_structured_log_entry(entry)
        tid_check = [r for r in results if r["name"] == "log_trace_id"][0]
        self.assertFalse(tid_check["passed"])

    def test_short_trace_id(self):
        results = mod.validate_structured_log_entry(self._make_entry(trace_id="abc"))
        tid_check = [r for r in results if r["name"] == "log_trace_id"][0]
        self.assertFalse(tid_check["passed"])

    def test_missing_span_id(self):
        entry = self._make_entry()
        del entry["span_id"]
        results = mod.validate_structured_log_entry(entry)
        sid_check = [r for r in results if r["name"] == "log_span_id"][0]
        self.assertFalse(sid_check["passed"])

    def test_invalid_level(self):
        results = mod.validate_structured_log_entry(self._make_entry(level="critical"))
        level_check = [r for r in results if r["name"] == "log_level_valid"][0]
        self.assertFalse(level_check["passed"])

    def test_valid_levels(self):
        for level in ("error", "warn", "info", "debug"):
            results = mod.validate_structured_log_entry(self._make_entry(level=level))
            level_check = [r for r in results if r["name"] == "log_level_valid"][0]
            self.assertTrue(level_check["passed"], f"Valid level '{level}' rejected")

    def test_invalid_surface(self):
        results = mod.validate_structured_log_entry(self._make_entry(surface="OPS-UNKNOWN"))
        surface_check = [r for r in results if r["name"] == "log_surface_valid"][0]
        self.assertFalse(surface_check["passed"])

    def test_all_valid_surfaces(self):
        for surface in mod.OPERATIONAL_SURFACES:
            results = mod.validate_structured_log_entry(self._make_entry(surface=surface))
            surface_check = [r for r in results if r["name"] == "log_surface_valid"][0]
            self.assertTrue(surface_check["passed"], f"Valid surface '{surface}' rejected")

    def test_error_without_canonical_code(self):
        results = mod.validate_structured_log_entry(
            self._make_entry(error_code="INVALID_CODE")
        )
        code_check = [r for r in results if r["name"] == "log_error_code_canonical"][0]
        self.assertFalse(code_check["passed"])

    def test_info_level_no_error_code_required(self):
        entry = self._make_entry(level="info")
        del entry["error_code"]
        results = mod.validate_structured_log_entry(entry)
        # No error_code check should appear for info level
        code_checks = [r for r in results if r["name"] == "log_error_code_canonical"]
        self.assertEqual(len(code_checks), 0)


# ---------------------------------------------------------------------------
# Test: is_canonical_metric_name helper
# ---------------------------------------------------------------------------

class TestIsCanonicalMetricName(unittest.TestCase):
    def test_protocol_metric(self):
        self.assertTrue(mod.is_canonical_metric_name("franken.protocol.messages_received_total"))

    def test_capability_metric(self):
        self.assertTrue(mod.is_canonical_metric_name("franken.capability.invocations_total"))

    def test_egress_metric(self):
        self.assertTrue(mod.is_canonical_metric_name("franken.egress.bytes_sent_total"))

    def test_security_metric(self):
        self.assertTrue(mod.is_canonical_metric_name("franken.security.auth_failures_total"))

    def test_non_canonical_metric(self):
        self.assertFalse(mod.is_canonical_metric_name("custom.my_metric"))

    def test_empty_metric(self):
        self.assertFalse(mod.is_canonical_metric_name(""))

    def test_partial_prefix(self):
        self.assertFalse(mod.is_canonical_metric_name("franken.unknown.metric"))


# ---------------------------------------------------------------------------
# Test: constants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_operational_surfaces_count(self):
        self.assertEqual(len(mod.OPERATIONAL_SURFACES), 6)

    def test_recovery_hint_actions_count(self):
        self.assertEqual(len(mod.RECOVERY_HINT_ACTIONS), 5)

    def test_severity_levels_count(self):
        self.assertEqual(len(mod.SEVERITY_LEVELS), 3)

    def test_canonical_prefixes_count(self):
        self.assertEqual(len(mod.CANONICAL_PREFIXES), 4)

    def test_all_checks_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 30)


# ---------------------------------------------------------------------------
# Test: JSON output
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-3o6")

    def test_json_flag_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_structured_observability.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-3o6")
        self.assertEqual(data["verdict"], "PASS")


# ---------------------------------------------------------------------------
# Test: safe_rel with mock paths
# ---------------------------------------------------------------------------

class TestSafeRel(unittest.TestCase):
    def test_safe_rel_with_root_path(self):
        p = mod.ROOT / "some" / "file.txt"
        result = mod._safe_rel(p)
        self.assertFalse(result.startswith("/"))

    def test_safe_rel_with_non_root_path(self):
        p = Path("/tmp/fakepath/file.txt")
        result = mod._safe_rel(p)
        self.assertEqual(result, "/tmp/fakepath/file.txt")


if __name__ == "__main__":
    unittest.main()
