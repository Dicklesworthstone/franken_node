#!/usr/bin/env python3
"""Tests for the bd-1vier.1 replay bundle golden artifact gate."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_replay_bundle_golden_artifacts.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_replay_bundle_golden_artifacts", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


checker = _load()


def _json_output() -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON: {result.stdout}\nstderr: {result.stderr}") from exc


class TestSelfTest:
    def test_self_test_passes(self):
        assert checker.self_test()


class TestJsonOutput:
    def test_json_has_required_keys(self):
        data = _json_output()
        for key in (
            "bead_id",
            "parent_bead_id",
            "gate_script",
            "checks_passed",
            "checks_total",
            "verdict",
            "checks",
        ):
            assert key in data

    def test_bead_ids(self):
        data = _json_output()
        assert data["bead_id"] == "bd-1vier.1"
        assert data["parent_bead_id"] == "bd-1vier"

    def test_checks_are_structured(self):
        data = _json_output()
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) >= 14
        for check in data["checks"]:
            assert "check" in check
            assert "passed" in check
            assert "detail" in check


class TestIndividualChecks:
    def _results(self) -> dict:
        return {result["check"]: result for result in checker._checks()}

    def test_cargo_target_registered(self):
        assert self._results()["cargo_target_registered"]["passed"]

    def test_test_file_exists(self):
        assert self._results()["test_file_exists"]["passed"]

    def test_test_file_tracked(self):
        assert self._results()["test_file_tracked"]["passed"]

    def test_golden_file_exists(self):
        assert self._results()["golden_file_exists"]["passed"]

    def test_golden_file_tracked(self):
        assert self._results()["golden_file_tracked"]["passed"]

    def test_golden_file_non_empty(self):
        assert self._results()["golden_file_non_empty"]["passed"]

    def test_test_includes_checked_in_golden(self):
        assert self._results()["test_includes_checked_in_golden"]["passed"]

    def test_canonical_test_compares_actual_to_golden(self):
        assert self._results()["canonical_test_compares_actual_to_golden"]["passed"]

    def test_canonical_test_not_inline_empty_snapshot(self):
        assert self._results()["canonical_test_not_inline_empty_snapshot"]["passed"]

    def test_required_tests_present(self):
        assert self._results()["required_tests_present"]["passed"]

    def test_golden_has_replay_bundle_shape(self):
        assert self._results()["golden_has_replay_bundle_shape"]["passed"]

    def test_bead_record_present(self):
        assert self._results()["bead_record_present"]["passed"]

    def test_bead_closed(self):
        assert self._results()["bead_closed"]["passed"]

    def test_close_reason_documents_artifacts(self):
        assert self._results()["close_reason_documents_artifacts"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [result["check"] for result in checker._checks() if not result["passed"]]
        assert not failed

    def test_json_verdict_passes(self):
        data = _json_output()
        assert data["verdict"] == "PASS"
        assert data["checks_passed"] == data["checks_total"]
