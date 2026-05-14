"""Unit tests for scripts/check_dgis_graph_ingestion.py."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_dgis_graph_ingestion.py"


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def static_json() -> dict:
    result = run_script("--json", "--skip-cargo")
    assert result.returncode == 0, f"checker failed: {result.stdout}\n{result.stderr}"
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"checker emitted invalid JSON: {result.stdout}") from exc


def test_self_test_passes():
    result = run_script("--self-test")
    assert result.returncode == 0, f"self-test failed: {result.stdout}\n{result.stderr}"


def test_static_json_contract_passes_without_cargo():
    data = static_json()
    assert data["schema_version"] == "franken-node/verification-evidence/v1"
    assert data["gate"] == "dgis_graph_ingestion"
    assert data["bead_id"] == "bd-2bj4"
    assert data["completion_debt_bead_id"] == "bd-2bj4.1"
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
        "seed_fixture",
        "cargo_dgis_graph_ingestion",
    }
    assert all(check["passed"] for check in checks.values())


def test_seed_fixture_invariants_are_realistic_and_nontrivial():
    data = static_json()
    seed_check = next(check for check in data["checks"] if check["name"] == "seed_fixture")
    invariants = seed_check["details"]["invariants"]
    assert invariants["total_observations"] == 51
    assert invariants["expected_unique_package_versions"] == 20
    assert invariants["expected_unique_maintainers"] == 6
    assert invariants["expected_unique_dependency_targets"] == 8
    assert invariants["min_total_nodes"] == 34
    assert invariants["min_total_edges"] == 56


def test_integration_test_inventory_names_all_12_required_tests():
    data = static_json()
    integration_check = next(check for check in data["checks"] if check["name"] == "integration_tests")
    assert integration_check["details"]["total_tests"] == 12


def test_full_gate_command_uses_rch_for_cargo():
    data = static_json()
    cargo_check = next(check for check in data["checks"] if check["name"] == "cargo_dgis_graph_ingestion")
    command = cargo_check["details"]["command"]
    assert command[:3] == ["rch", "exec", "--"]
    assert "cargo" in command
    assert "test" in command
    assert "dgis_graph_ingestion" in command


def test_human_output_reports_static_only_status():
    result = run_script("--skip-cargo")
    assert result.returncode == 0
    assert "PASS_STATIC_ONLY" in result.stdout
    assert "cargo_dgis_graph_ingestion" in result.stdout
