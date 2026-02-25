"""Unit tests for check_bpet_economic.py verification script."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_bpet_economic.py"


def run_script(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestSelfTest:
    def test_self_test_passes(self):
        result = run_script("--self-test")
        assert result.returncode == 0, f"self_test failed: {result.stdout}\n{result.stderr}"


class TestJsonOutput:
    def test_json_output_is_valid(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["gate"] == "bpet_economic_integration"
        assert data["bead"] == "bd-3cbi"
        assert data["section"] == "10.21"
        assert "verdict" in data
        assert "checks" in data
        assert len(data["checks"]) >= 10

    def test_all_checks_have_required_fields(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        for check in data["checks"]:
            assert "name" in check
            assert "passed" in check
            assert "message" in check


class TestIndividualChecks:
    def test_source_exists(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "source_exists")
        assert check["passed"] is True

    def test_module_wiring(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "module_wiring")
        assert check["passed"] is True

    def test_structs(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "structs")
        assert check["passed"] is True

    def test_event_codes(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "event_codes")
        assert check["passed"] is True

    def test_propensity_scoring(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "propensity_scoring")
        assert check["passed"] is True

    def test_economic_pricing(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "economic_pricing")
        assert check["passed"] is True

    def test_intervention_roi(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "intervention_roi")
        assert check["passed"] is True

    def test_motif_matching(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "motif_matching")
        assert check["passed"] is True

    def test_playbook(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "playbook")
        assert check["passed"] is True

    def test_test_coverage(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "test_coverage")
        assert check["passed"] is True

    def test_audit_logging(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["name"] == "audit_logging")
        assert check["passed"] is True


class TestOverallVerdict:
    def test_verdict_is_pass(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS", f"Failed: {[c for c in data['checks'] if not c['passed']]}"
        assert data["passed"] == data["total"]


class TestHumanOutput:
    def test_human_output_format(self):
        result = run_script()
        assert "[PASS]" in result.stdout or "[FAIL]" in result.stdout
        assert "checks passed" in result.stdout
