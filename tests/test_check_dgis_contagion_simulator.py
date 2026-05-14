"""Unit tests for scripts/check_dgis_contagion_simulator.py."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_dgis_contagion_simulator.py"


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )


def static_json() -> dict:
    result = run_script("--json", "--skip-cargo")
    assert result.returncode == 0, f"checker failed: {result.stdout}\n{result.stderr}"
    try:
        return json.JSONDecoder().decode(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"checker emitted invalid JSON: {result.stdout}") from exc


def test_self_test_passes():
    result = run_script("--self-test")
    assert result.returncode == 0, f"self-test failed: {result.stdout}\n{result.stderr}"


def test_static_json_contract_passes_without_cargo():
    data = static_json()
    assert data["schema_version"] == "franken-node/verification-evidence/v1"
    assert data["gate"] == "dgis_contagion_simulator"
    assert data["bead_id"] == "bd-1q38"
    assert data["completion_debt_bead_id"] == "bd-1q38.1"
    assert data["section"] == "10.20"
    assert data["verdict"] == "PASS_STATIC_ONLY"
    assert data["cargo_skipped"]
    assert data["passed"] == data["total"] == 6


def test_required_checks_are_present_and_green():
    data = static_json()
    checks = {check["name"]: check for check in data["checks"]}
    assert set(checks) == {
        "paths_exist",
        "cargo_registration",
        "rust_symbols",
        "integration_tests",
        "profile_fixtures",
        "cargo_dgis_contagion_simulator",
    }
    assert all(check["passed"] for check in checks.values())


def test_profile_fixture_invariants_are_exact_and_nontrivial():
    data = static_json()
    fixture_check = next(check for check in data["checks"] if check["name"] == "profile_fixtures")
    profiles = fixture_check["details"]["profiles"]
    assert profiles["xz_style"] == {
        "nodes": 20,
        "edges": 18,
        "initial_infected": 1,
        "termination_reason": "Converged",
        "min_infected_count": 18,
        "max_infected_count": 19,
        "terminated_by_step": 50,
    }
    assert profiles["dependency_confusion"] == {
        "nodes": 15,
        "edges": 12,
        "initial_infected": 1,
        "termination_reason": "Converged",
        "min_infected_count": 8,
        "max_infected_count": 10,
        "terminated_by_step": 20,
    }
    assert profiles["typosquat"] == {
        "nodes": 30,
        "edges": 16,
        "initial_infected": 5,
        "termination_reason": "Converged",
        "min_infected_count": 9,
        "max_infected_count": 11,
        "terminated_by_step": 30,
    }


def test_profile_fixture_aggregate_invariants_are_realistic():
    data = static_json()
    fixture_check = next(check for check in data["checks"] if check["name"] == "profile_fixtures")
    aggregate = fixture_check["details"]["aggregate"]
    assert aggregate["profile_count"] == 3
    assert aggregate["total_nodes"] == 65
    assert aggregate["total_edges"] == 46
    assert aggregate["total_initial_infected"] == 7
    assert aggregate["total_expected_min_infected"] == 35
    assert aggregate["total_expected_max_infected"] == 40
    assert aggregate["edge_kinds"] == {
        "DependencyImport": 35,
        "MaintainerOverlap": 2,
        "NamespaceShadow": 9,
    }


def test_integration_test_inventory_names_all_8_required_tests():
    data = static_json()
    integration_check = next(check for check in data["checks"] if check["name"] == "integration_tests")
    assert integration_check["details"]["total_tests"] == 8


def test_full_gate_command_uses_rch_for_cargo():
    data = static_json()
    cargo_check = next(check for check in data["checks"] if check["name"] == "cargo_dgis_contagion_simulator")
    command = cargo_check["details"]["command"]
    assert command[:3] == ["rch", "exec", "--"]
    assert "cargo" in command
    assert "test" in command
    assert "dgis_contagion_simulator" in command


def test_source_paths_cite_real_profiles_and_test_surface():
    data = static_json()
    paths = set(data["source_paths"])
    assert "tests/security/dgis_contagion_simulator.rs" in paths
    assert "tests/security/contagion_profiles/xz_style.json" in paths
    assert "tests/security/contagion_profiles/dependency_confusion.json" in paths
    assert "tests/security/contagion_profiles/typosquat.json" in paths


def test_human_output_reports_static_only_status():
    result = run_script("--skip-cargo")
    assert result.returncode == 0
    assert "PASS_STATIC_ONLY" in result.stdout
    assert "cargo_dgis_contagion_simulator" in result.stdout
