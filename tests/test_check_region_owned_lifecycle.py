"""Tests for scripts/check_region_owned_lifecycle.py (bd-2tdi)."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_region_owned_lifecycle.py"

spec = importlib.util.spec_from_file_location("check_region", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules["check_region"] = mod
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test(self):
        assert mod.self_test() is True


class TestValidPasses:
    def test_all_checks_pass(self):
        results = mod._checks()
        failed = [r for r in results if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-2tdi"
        assert data["section"] == "10.15"
        assert data["verdict"] == "PASS"
        assert data["checks_passed"] == data["checks_total"]

    def test_human_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True,
        )
        assert "bd-2tdi" in result.stdout
        assert "PASS" in result.stdout


class TestMissingImplFails:
    def test_missing_impl(self, tmp_path):
        missing = tmp_path / "nonexistent.rs"
        with mock.patch.object(mod, "IMPL_PATH", missing):
            results = mod._checks()
            impl_check = next(r for r in results if r["check"] == "impl_exists")
            assert not impl_check["passed"]


class TestMissingSpecFails:
    def test_missing_spec(self, tmp_path):
        missing = tmp_path / "nonexistent.md"
        with mock.patch.object(mod, "SPEC_PATH", missing):
            results = mod._checks()
            spec_check = next(r for r in results if r["check"] == "spec_exists")
            assert not spec_check["passed"]


class TestMissingEvidenceFails:
    def test_missing_evidence(self, tmp_path):
        missing = tmp_path / "nonexistent.json"
        with mock.patch.object(mod, "EVIDENCE_PATH", missing):
            results = mod._checks()
            ev_check = next(r for r in results if r["check"] == "evidence_exists")
            assert not ev_check["passed"]


class TestCheckStructure:
    def test_all_checks_have_keys(self):
        results = mod._checks()
        for r in results:
            assert "check" in r
            assert "passed" in r
            assert "detail" in r
            assert isinstance(r["passed"], bool)

    def test_minimum_check_count(self):
        results = mod._checks()
        assert len(results) >= 20


class TestEventCodeChecks:
    def test_all_event_codes_checked(self):
        results = mod._checks()
        for code in mod.EVENT_CODES:
            check = next(r for r in results if r["check"] == f"event_code:{code}")
            assert check["passed"], f"{code} should pass"


class TestInvariantChecks:
    def test_all_invariants_checked(self):
        results = mod._checks()
        for inv in mod.INVARIANTS:
            check = next(r for r in results if r["check"] == f"spec_invariant:{inv}")
            assert check["passed"], f"{inv} should pass"
