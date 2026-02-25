"""Unit tests for check_dgis_barrier.py verification script."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_dgis_barrier.py"
ROOT = Path(__file__).resolve().parent.parent


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
        assert "PASS" in result.stdout


class TestJsonOutput:
    def test_json_output_is_valid(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert "gate" in data
        assert data["gate"] == "dgis_barrier_primitives"
        assert data["bead"] == "bd-1tnu"
        assert data["section"] == "10.20"
        assert "verdict" in data
        assert "checks" in data
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) >= 10

    def test_json_checks_have_required_fields(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        for check in data["checks"]:
            assert "name" in check
            assert "passed" in check
            assert "message" in check
            assert isinstance(check["passed"], bool)


class TestSourceChecks:
    def test_source_exists_check(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        source_check = next(c for c in data["checks"] if c["name"] == "source_exists")
        assert source_check["passed"] is True

    def test_module_wiring_check(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        wiring_check = next(c for c in data["checks"] if c["name"] == "module_wiring")
        assert wiring_check["passed"] is True

    def test_barrier_types_check(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        types_check = next(c for c in data["checks"] if c["name"] == "barrier_types")
        assert types_check["passed"] is True

    def test_event_codes_check(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        codes_check = next(c for c in data["checks"] if c["name"] == "event_codes")
        assert codes_check["passed"] is True
        assert len(codes_check.get("details", {}).get("codes", [])) >= 10

    def test_structs_check(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        structs_check = next(c for c in data["checks"] if c["name"] == "structs")
        assert structs_check["passed"] is True

    def test_test_coverage_check(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        tests_check = next(c for c in data["checks"] if c["name"] == "test_coverage")
        assert tests_check["passed"] is True

    def test_override_mechanism_check(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        override_check = next(c for c in data["checks"] if c["name"] == "override_mechanism")
        assert override_check["passed"] is True

    def test_composition_check(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        comp_check = next(c for c in data["checks"] if c["name"] == "composition")
        assert comp_check["passed"] is True


class TestHumanOutput:
    def test_human_output_format(self):
        result = run_script()
        assert "[PASS]" in result.stdout or "[FAIL]" in result.stdout
        assert "checks passed" in result.stdout


class TestOverallVerdict:
    def test_overall_verdict_pass(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        # All checks should pass if implementation is complete
        assert data["verdict"] == "PASS", f"Failed checks: {[c for c in data['checks'] if not c['passed']]}"
        assert data["passed"] == data["total"]
