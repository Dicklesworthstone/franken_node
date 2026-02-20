#!/usr/bin/env python3
"""Unit tests for check_correctness_envelope.py verification script."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_correctness_envelope.py"


def run_check(*extra_args: str) -> subprocess.CompletedProcess:
    """Run the verification script."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *extra_args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


def test_human_output_passes():
    """Human-readable output succeeds and mentions PASS."""
    result = run_check()
    assert result.returncode == 0, f"script failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS" in result.stdout


def test_json_output_is_valid():
    """JSON output is valid and has expected structure."""
    result = run_check("--json")
    assert result.returncode == 0, f"script failed:\n{result.stdout}\n{result.stderr}"
    data = json.loads(result.stdout)
    assert data["bead_id"] == "bd-sddz"
    assert data["overall_pass"] is True
    assert isinstance(data["checks"], list)
    assert data["invariant_count"] >= 10


def test_json_all_checks_pass():
    """Every individual check passes."""
    result = run_check("--json")
    data = json.loads(result.stdout)
    for check in data["checks"]:
        assert check["pass"], f"check '{check['check']}' failed: {check['detail']}"


def test_json_has_artifact_paths():
    """JSON output includes artifact path references."""
    result = run_check("--json")
    data = json.loads(result.stdout)
    assert "implementation" in data["artifacts"]
    assert "spec" in data["artifacts"]
    assert "manifest" in data["artifacts"]


def test_invariant_count_at_least_10():
    """At least 10 invariants are verified."""
    result = run_check("--json")
    data = json.loads(result.stdout)
    assert data["invariant_count"] >= 10


def test_self_test_function():
    """Import and run self_test directly."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import check_correctness_envelope as mod
    all_pass, results = mod.self_test()
    assert all_pass
    check_names = {r["check"] for r in results}
    expected = {
        "impl_exists", "mod_rs", "invariant_count", "unique_ids",
        "no_enforcement_none", "is_within_envelope", "log_codes",
        "spec_exists", "manifest", "test_coverage",
    }
    assert expected <= check_names, f"missing checks: {expected - check_names}"
    sys.path.pop(0)


if __name__ == "__main__":
    test_human_output_passes()
    test_json_output_is_valid()
    test_json_all_checks_pass()
    test_json_has_artifact_paths()
    test_invariant_count_at_least_10()
    test_self_test_function()
    print("All tests passed.")
