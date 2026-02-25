"""Tests for scripts/check_effects_firewall.py (bd-3l2p)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_effects_firewall.py"

spec = importlib.util.spec_from_file_location("check_effects_firewall", SCRIPT)
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
        assert result["bead_id"] == "bd-3l2p"

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
        assert len(checks) >= 12
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
        assert len(checks) >= 12

    def test_expected_checks_present(self):
        checks = module._checks()
        names = {c["check"] for c in checks}
        expected = {
            "rust_module_exists",
            "module_wired_into_mod_rs",
            "spec_contract_exists",
            "test_file_exists",
            "event_codes_defined",
            "error_codes_defined",
            "invariants_defined",
            "core_types_present",
            "verdict_pathways_present",
            "schema_version",
            "btreemap_determinism",
            "test_count",
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
        assert payload["bead_id"] == "bd-3l2p"
        assert payload["section"] == "10.17"
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

    def test_self_test_json_cli(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["bead_id"] == "bd-3l2p"
        assert payload["verdict"] == "PASS"


class TestRegressionCases:
    def test_missing_evidence_causes_fail(self):
        original = module.EVIDENCE
        try:
            module.EVIDENCE = str(ROOT / "artifacts" / "section_10_17" / "bd-3l2p" / "_missing_.json")
            checks = module._checks()
        finally:
            module.EVIDENCE = original

        by_name = {c["check"]: c for c in checks}
        assert by_name["evidence_pass_verdict"]["passed"] is False

    def test_missing_rust_module_causes_fail(self):
        original = module.INTENT_FIREWALL_RS
        try:
            module.INTENT_FIREWALL_RS = str(
                ROOT / "crates" / "franken-node" / "src" / "security" / "_missing_.rs"
            )
            checks = module._checks()
        finally:
            module.INTENT_FIREWALL_RS = original

        by_name = {c["check"]: c for c in checks}
        assert by_name["rust_module_exists"]["passed"] is False

    def test_missing_spec_causes_fail(self):
        original = module.SPEC
        try:
            module.SPEC = str(ROOT / "docs" / "specs" / "section_10_17" / "_missing_.md")
            checks = module._checks()
        finally:
            module.SPEC = original

        by_name = {c["check"]: c for c in checks}
        assert by_name["spec_contract_exists"]["passed"] is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
