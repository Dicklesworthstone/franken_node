#!/usr/bin/env python3
"""Unit tests for check_hardening_state_machine.py verification script."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_hardening_state_machine.py"


def run_check(*extra_args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *extra_args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


def test_human_output_passes():
    result = run_check()
    assert result.returncode == 0, f"script failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS" in result.stdout


def test_json_output_is_valid():
    result = run_check("--json")
    assert result.returncode == 0, f"script failed:\n{result.stdout}\n{result.stderr}"
    data = json.loads(result.stdout)
    assert data["bead_id"] == "bd-3rya"
    assert data["overall_pass"] is True


def test_json_all_checks_pass():
    result = run_check("--json")
    data = json.loads(result.stdout)
    for check in data["checks"]:
        assert check["pass"], f"check '{check['check']}' failed: {check['detail']}"


def test_test_count_at_least_20():
    result = run_check("--json")
    data = json.loads(result.stdout)
    assert data["test_count"] >= 20


def test_self_test_function():
    sys.path.insert(0, str(ROOT / "scripts"))
    import check_hardening_state_machine as mod
    all_pass, results = mod.self_test()
    assert all_pass
    check_names = {r["check"] for r in results}
    expected = {
        "impl_exists", "hardening_levels", "escalate_fn",
        "governance_rollback_fn", "replay_fn", "log_codes",
        "governance_artifact", "error_types", "test_count",
        "history_artifact",
    }
    assert expected <= check_names
    sys.path.pop(0)


if __name__ == "__main__":
    test_human_output_passes()
    test_json_output_is_valid()
    test_json_all_checks_pass()
    test_test_count_at_least_20()
    test_self_test_function()
    print("All tests passed.")
