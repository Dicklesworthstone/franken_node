#!/usr/bin/env python3
"""Tests for the bd-2mt88.1 API test-support migration gate."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_api_test_support_migration.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_api_test_support_migration", SCRIPT)
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
        assert data["bead_id"] == "bd-2mt88.1"
        assert data["parent_bead_id"] == "bd-2mt88"

    def test_checks_are_structured(self):
        data = _json_output()
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) >= 15
        for check in data["checks"]:
            assert "check" in check
            assert "passed" in check
            assert "detail" in check


class TestIndividualChecks:
    def _results(self) -> dict:
        return {result["check"]: result for result in checker._checks()}

    def test_doc_exists(self):
        assert self._results()["doc_exists"]["passed"]

    def test_doc_required_terms(self):
        assert self._results()["doc_required_terms"]["passed"]

    def test_cargo_test_support_composes_control_plane(self):
        assert self._results()["cargo_test_support_composes_control_plane"]["passed"]

    def test_api_namespace_owned_by_control_plane(self):
        assert self._results()["api_namespace_owned_by_control_plane"]["passed"]

    def test_api_mod_wiring_is_not_test_support_gated(self):
        assert self._results()["api_mod_wiring_is_not_test_support_gated"]["passed"]

    def test_middleware_has_no_direct_test_support_gate(self):
        assert self._results()["middleware_has_no_direct_test_support_gate"]["passed"]

    def test_fleet_mutating_requests_are_control_plane_owned(self):
        assert self._results()["fleet_mutating_requests_are_control_plane_owned"]["passed"]

    def test_fleet_route_metadata_is_control_plane_owned(self):
        assert self._results()["fleet_route_metadata_is_control_plane_owned"]["passed"]

    def test_direct_api_test_support_refs_limited(self):
        assert self._results()["direct_api_test_support_refs_limited"]["passed"]

    def test_remaining_direct_ref_is_status_request(self):
        assert self._results()["remaining_direct_ref_is_status_request"]["passed"]

    def test_doc_explains_remaining_status_request(self):
        assert self._results()["doc_explains_remaining_status_request"]["passed"]

    def test_doc_has_downstream_migration_rules(self):
        assert self._results()["doc_has_downstream_migration_rules"]["passed"]

    def test_bead_record_present(self):
        assert self._results()["bead_record_present"]["passed"]

    def test_bead_closed(self):
        assert self._results()["bead_closed"]["passed"]

    def test_close_reason_documents_migration_path(self):
        assert self._results()["close_reason_documents_migration_path"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [result["check"] for result in checker._checks() if not result["passed"]]
        assert not failed

    def test_json_verdict_passes(self):
        data = _json_output()
        assert data["verdict"] == "PASS"
        assert data["checks_passed"] == data["checks_total"]
