"""Tests for scripts/check_ambient_authority.py (bd-3vm)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_ambient_authority.py"

spec = importlib.util.spec_from_file_location("check_ambient_authority", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec is not None
assert spec.loader is not None
spec.loader.exec_module(module)


class TestSelfTest:
    def test_self_test_passes(self):
        result = module.self_test()
        assert result["verdict"] == "PASS"

    def test_self_test_bead_id(self):
        result = module.self_test()
        assert result["bead_id"] == "bd-3vm"

    def test_self_test_has_events(self):
        result = module.self_test()
        assert len(result["events"]) > 0

    def test_self_test_no_failures(self):
        result = module.self_test()
        assert result["checks_passed"] == result["checks_total"]


class TestChecks:
    def test_all_checks_have_shape(self):
        checks = module._checks()
        assert isinstance(checks, list)
        assert len(checks) >= 11
        for c in checks:
            assert set(c.keys()) == {"check", "passed", "detail"}
            assert isinstance(c["check"], str)
            assert isinstance(c["passed"], bool)
            assert isinstance(c["detail"], str)

    def test_all_checks_pass(self):
        checks = module._checks()
        failed = [c for c in checks if not c["passed"]]
        assert failed == [], f"failed checks: {[c['check'] for c in failed]}"

    def test_minimum_check_count(self):
        checks = module._checks()
        assert len(checks) >= 11

    def test_expected_checks_present(self):
        checks = module._checks()
        names = {c["check"] for c in checks}
        expected = {
            "rust_module_exists",
            "module_wired_into_mod_rs",
            "config_inventory_exists",
            "spec_contract_exists",
            "test_file_exists",
            "event_codes_defined",
            "error_codes_defined",
            "invariants_defined",
            "audit_report_generation",
            "capability_taxonomy_complete",
        }
        assert expected.issubset(names), f"missing: {expected - names}"


class TestCli:
    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["bead_id"] == "bd-3vm"
        assert payload["section"] == "10.11"
        assert payload["verdict"] == "PASS"
        assert payload["checks_passed"] == payload["checks_total"]

    def test_self_test_cli_exit_0(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "self_test:" in result.stderr


class TestRegressionCases:
    def test_missing_evidence_causes_fail(self):
        original = module.EVIDENCE
        try:
            module.EVIDENCE = str(ROOT / "artifacts" / "section_10_11" / "bd-3vm" / "_missing_.json")
            checks = module._checks()
        finally:
            module.EVIDENCE = original

        by_name = {c["check"]: c for c in checks}
        assert by_name["evidence_pass_verdict"]["passed"] is False

    def test_missing_rust_module_causes_fail(self):
        original = module.AUTHORITY_AUDIT_RS
        try:
            module.AUTHORITY_AUDIT_RS = str(
                ROOT / "crates" / "franken-node" / "src" / "runtime" / "_missing_.rs"
            )
            checks = module._checks()
        finally:
            module.AUTHORITY_AUDIT_RS = original

        by_name = {c["check"]: c for c in checks}
        assert by_name["rust_module_exists"]["passed"] is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
