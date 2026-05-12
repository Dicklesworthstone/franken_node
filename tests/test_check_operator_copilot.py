#!/usr/bin/env python3
"""Tests for the bd-2yc.1 operator copilot named verification gate."""

from __future__ import annotations

import json
import subprocess  # nosec B404
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_operator_copilot as checker  # noqa: E402


def _json_from_stdout(stdout: str) -> dict:
    try:
        payload = json.JSONDecoder().decode(stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON output: {stdout[:200]}") from exc
    if not isinstance(payload, dict):
        raise AssertionError(f"expected JSON object, got {type(payload).__name__}")
    return payload


def test_self_test_passes() -> None:
    assert checker.self_test()


def test_required_files_include_named_checker_and_tests() -> None:
    results = {check["name"]: check for check in checker.check_required_files()}

    assert results["file:operator_checker"]["passed"]
    assert results["file:operator_checker_tests"]["passed"]
    assert results["file:core_checker"]["passed"]
    assert results["file:core_checker_tests"]["passed"]


def test_self_binding_links_completion_bead_to_parent_gate() -> None:
    result = checker.check_self_binding()[0]

    assert result["passed"]
    assert checker.COMPLETION_BEAD_ID in result["found"]
    assert checker.PARENT_BEAD_ID in result["found"]


def test_core_gate_uses_real_operator_copilot_checks() -> None:
    results = {check["name"]: check for check in checker.check_core_gate()}

    assert results["core_gate:bead_id"]["passed"]
    assert results["core_gate:overall_pass"]["passed"]
    assert results["core_gate:summary_counts"]["passed"]
    assert results["core_check:rust_symbols"]["passed"]
    assert results["core_check:engine_methods"]["passed"]
    assert results["core_check:tests"]["passed"]


def test_run_all_checks_returns_passing_completion_evidence() -> None:
    evidence = checker.run_all_checks()

    assert evidence["bead_id"] == checker.COMPLETION_BEAD_ID
    assert evidence["parent_bead_id"] == checker.PARENT_BEAD_ID
    assert evidence["overall_pass"]
    assert evidence["summary"]["failed"] == 0
    assert evidence["summary"]["passed"] == evidence["summary"]["total_checks"]


def test_run_all_checks_json_serializable() -> None:
    evidence = checker.run_all_checks()

    payload = _json_from_stdout(json.dumps(evidence))
    assert payload["bead_id"] == checker.COMPLETION_BEAD_ID
    assert payload["overall_pass"]


def test_json_cli_outputs_completion_bead_evidence() -> None:
    completed = subprocess.run(  # nosec B603
        [sys.executable, str(checker.OPERATOR_CHECKER_PATH), "--json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    evidence = _json_from_stdout(completed.stdout)
    assert evidence["bead_id"] == checker.COMPLETION_BEAD_ID
    assert evidence["overall_pass"]


def test_self_test_cli_passes() -> None:
    completed = subprocess.run(  # nosec B603
        [sys.executable, str(checker.OPERATOR_CHECKER_PATH), "--self-test"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert "self_test passed" in completed.stdout
