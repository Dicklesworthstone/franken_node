"""Tests for scripts/check_section_10_13_gate.py (section 10.13 verification gate)."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_section_10_13_gate.py"

spec = importlib.util.spec_from_file_location("check_section_10_13_gate", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# _check() helper
# ---------------------------------------------------------------------------

class TestCheckHelper:
    def setup_method(self):
        mod.CHECKS.clear()
        mod._json_mode = False

    def test_passing_check(self):
        result = mod._check("TEST-001", "test check", True, "all good")
        assert result is True
        assert len(mod.CHECKS) == 1
        assert mod.CHECKS[0]["id"] == "TEST-001"
        assert mod.CHECKS[0]["status"] == "PASS"
        assert mod.CHECKS[0]["details"] == "all good"

    def test_failing_check(self):
        result = mod._check("TEST-002", "test fail", False, "broken")
        assert result is False
        assert len(mod.CHECKS) == 1
        assert mod.CHECKS[0]["status"] == "FAIL"

    def test_check_without_details(self):
        mod._check("TEST-003", "no details", True)
        assert "details" not in mod.CHECKS[0]

    def test_multiple_checks_accumulate(self):
        mod._check("A", "first", True)
        mod._check("B", "second", False)
        mod._check("C", "third", True)
        assert len(mod.CHECKS) == 3
        ids = [c["id"] for c in mod.CHECKS]
        assert ids == ["A", "B", "C"]

    def test_check_entry_structure(self):
        mod._check("STRUCT", "structure test", True, "details here")
        entry = mod.CHECKS[0]
        assert set(entry.keys()) == {"id", "description", "status", "details"}

    def test_json_mode_suppresses_output(self, capsys):
        mod._json_mode = True
        mod._check("QUIET", "should not print", True)
        captured = capsys.readouterr()
        assert captured.out == ""
        mod._json_mode = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_beads_list_not_empty():
    assert len(mod.BEADS_10_13) >= 40

def test_beads_all_prefixed():
    assert all(b.startswith("bd-") for b in mod.BEADS_10_13)

def test_bead_id():
    assert mod.BEAD_ID == "bd-3uoo"

def test_section():
    assert mod.SECTION == "10.13"

def test_known_beads_present():
    known = ["bd-2gh", "bd-1rk", "bd-3ua7", "bd-3n2u"]
    for b in known:
        assert b in mod.BEADS_10_13, f"Missing bead: {b}"


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def test_self_test_passes():
    ok, checks = mod.self_test()
    assert ok is True
    assert len(checks) >= 4
    assert all(c["pass"] for c in checks)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_self_test_json():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--self-test", "--json"],
        capture_output=True, text=True, timeout=30, cwd=ROOT,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["self_test_passed"] is True

def test_cli_no_execution_json():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--no-exec", "--json"],
        capture_output=True, text=True, timeout=60, cwd=ROOT,
    )
    data = json.loads(result.stdout)
    assert "verdict" in data
    assert "checks" in data
    assert data["bead_id"] == "bd-3uoo"


# ---------------------------------------------------------------------------
# Evidence structure
# ---------------------------------------------------------------------------

def test_evidence_artifact_paths():
    source = SCRIPT.read_text()
    assert "section_10_13" in source
    assert "verification_evidence.json" in source

def test_build_report_no_execution():
    mod.CHECKS.clear()
    mod._json_mode = True
    report = mod.build_report(execute=False)
    assert "verdict" in report
    assert "checks" in report
    assert report["bead_id"] == "bd-3uoo"
    assert report["section"] == "10.13"
    assert isinstance(report["summary"], dict)
    mod._json_mode = False


# ---------------------------------------------------------------------------
# Thresholds (source-based checks)
# ---------------------------------------------------------------------------

def test_evidence_threshold():
    source = SCRIPT.read_text()
    assert "evidence_pass >= 40" in source

def test_module_threshold():
    source = SCRIPT.read_text()
    assert "modules >= 30" in source

def test_spec_threshold():
    source = SCRIPT.read_text()
    assert "len(specs) >= 40" in source

def test_integration_threshold():
    source = SCRIPT.read_text()
    assert "len(integ_files) >= 25" in source
