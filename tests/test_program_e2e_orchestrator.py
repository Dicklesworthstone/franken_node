"""Regression tests for cross-section journey fixture orchestration."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts import program_e2e_orchestrator as orchestrator


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs" / "verification" / "journey_matrix.json"
FIXTURE_SUITE_PATH = ROOT / "docs" / "verification" / "cross_section_fixture_suite.json"
ORCHESTRATOR = ROOT / "scripts" / "program_e2e_orchestrator.py"


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{path} is not valid JSON: {exc}") from exc


def _decode_report(stdout: str) -> dict:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"orchestrator did not emit JSON: {stdout}") from exc


def test_fixture_catalog_covers_every_matrix_phase() -> None:
    matrix = _load_json(MATRIX_PATH)
    fixture_suite = _load_json(FIXTURE_SUITE_PATH)
    fixture_ids = {fixture["id"] for fixture in fixture_suite["fixtures"]}
    referenced = {
        phase["fixture"]
        for journey in matrix["journeys"]
        for phase in journey["phases"]
    }

    assert referenced == fixture_ids

    for journey in matrix["journeys"]:
        result = orchestrator.validate_journey_structural(journey, fixture_suite)
        assert result["status"] == "PASS", result["errors"]
        assert result["fixtures_validated"] == result["phases_validated"]


def test_structural_cli_executes_all_cataloged_fixtures() -> None:
    result = subprocess.run(
        [sys.executable, str(ORCHESTRATOR), "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    report = _decode_report(result.stdout)

    fixture_count = len(_load_json(FIXTURE_SUITE_PATH)["fixtures"])
    assert report["verdict"] == "PASS"
    assert report["journeys_executed"] == 7
    assert sum(r["fixtures_validated"] for r in report["journey_results"]) == fixture_count


def test_live_cli_replays_target_cross_section_fixture_journey() -> None:
    result = subprocess.run(
        [sys.executable, str(ORCHESTRATOR), "--json", "--live", "--journey", "J-001"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    report = _decode_report(result.stdout)

    assert report["verdict"] == "PASS"
    assert report["live_scenarios_executed"] >= 6
    assert report["fixture_scenarios_executed"] == 1
    assert report["fixture_scenarios_passed"] == 1
    assert report["fixture_results"][0]["journey_id"] == "J-001"
    assert report["fixture_results"][0]["fixture_count"] == 5
