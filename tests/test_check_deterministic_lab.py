#!/usr/bin/env python3
"""Tests for scripts/check_deterministic_lab.py (bd-2ko, Section 10.11).

Verifies that the deterministic lab runtime verification gate script
operates correctly: self-test passes, JSON output has the required
structure, and evidence validation rejects invalid or incomplete data.
"""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_project_root() -> str:
    """Walk upward from this file until a directory containing Cargo.toml is found."""
    current = os.path.dirname(os.path.abspath(__file__))
    while True:
        if os.path.isfile(os.path.join(current, "Cargo.toml")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            raise RuntimeError("Could not find project root (no Cargo.toml found)")
        current = parent


ROOT = _find_project_root()
SCRIPT = os.path.join(ROOT, "scripts", "check_deterministic_lab.py")


def _load_module():
    """Import the check script as a Python module."""
    spec = importlib.util.spec_from_file_location("check_deterministic_lab", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_script(*args):
    """Run the check script as a subprocess and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, SCRIPT, *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def _make_valid_evidence():
    """Return a complete, valid verification_evidence.json dict."""
    return {
        "bead_id": "bd-2ko",
        "section": "10.11",
        "title": "Deterministic Lab Runtime for Control-Plane Protocol Testing",
        "timestamp": "2026-02-22T00:00:00Z",
        "scenarios_executed": 4,
        "interleavings_explored": 128,
        "bugs_found": 0,
        "repro_bundles_generated": 0,
        "determinism_verified": True,
        "modules_implemented": [
            "crates/franken-node/src/testing/lab_runtime.rs",
            "crates/franken-node/src/testing/virtual_transport.rs",
            "crates/franken-node/src/testing/scenario_builder.rs",
        ],
        "invariants_enforced": [
            "INV-LB-DETERMINISTIC",
            "INV-LB-TIMER-ORDER",
            "INV-LB-FAULT-APPLIED",
            "INV-LB-REPLAY",
            "INV-LB-COVERAGE",
            "INV-LB-NO-WALLCLOCK",
        ],
        "event_codes": [
            "FN-LB-001", "FN-LB-002", "FN-LB-003", "FN-LB-004",
            "FN-LB-005", "FN-LB-006", "FN-LB-007", "FN-LB-008",
            "FN-LB-009", "FN-LB-010",
        ],
        "gate_script": "scripts/check_deterministic_lab.py",
        "verdict": "PASS",
    }


LAB_EVENT_CODES = [
    "FN-LB-001", "FN-LB-002", "FN-LB-003", "FN-LB-004", "FN-LB-005",
    "FN-LB-006", "FN-LB-007", "FN-LB-008", "FN-LB-009", "FN-LB-010",
]

VT_EVENT_CODES = [
    "VT-001", "VT-002", "VT-003", "VT-004",
    "VT-005", "VT-006", "VT-007", "VT-008",
]

SB_EVENT_CODES = ["SB-001", "SB-002", "SB-003", "SB-004"]


def _scaffold_fixtures(tmp_path, *, include_lab=True, include_vt=True,
                        include_sb=True, include_spec=True, evidence=None):
    """Create synthetic fixture files and monkey-patch module paths."""
    mod = _load_module()

    # lab_runtime.rs
    if include_lab:
        lab_rs = tmp_path / "lab_runtime.rs"
        src = "// synthetic\n"
        for code in LAB_EVENT_CODES:
            src += f'pub const EVT: &str = "{code}";\n'
        lab_rs.write_text(src, encoding="utf-8")
        mod.LAB_RUNTIME_RS = lab_rs
    else:
        mod.LAB_RUNTIME_RS = tmp_path / "nonexistent.rs"

    # virtual_transport.rs
    if include_vt:
        vt_rs = tmp_path / "virtual_transport.rs"
        src = "// synthetic\n"
        for code in VT_EVENT_CODES:
            src += f'pub const EVT: &str = "{code}";\n'
        vt_rs.write_text(src, encoding="utf-8")
        mod.VIRTUAL_TRANSPORT_RS = vt_rs
    else:
        mod.VIRTUAL_TRANSPORT_RS = tmp_path / "nonexistent.rs"

    # scenario_builder.rs
    if include_sb:
        sb_rs = tmp_path / "scenario_builder.rs"
        src = "// synthetic\n"
        for code in SB_EVENT_CODES:
            src += f'pub const EVT: &str = "{code}";\n'
        sb_rs.write_text(src, encoding="utf-8")
        mod.SCENARIO_BUILDER_RS = sb_rs
    else:
        mod.SCENARIO_BUILDER_RS = tmp_path / "nonexistent.rs"

    # spec contract
    if include_spec:
        spec = tmp_path / "bd-2ko_contract.md"
        spec.write_text("# bd-2ko contract\n", encoding="utf-8")
        mod.SPEC_CONTRACT = spec
    else:
        mod.SPEC_CONTRACT = tmp_path / "nonexistent.md"

    # evidence
    if evidence is not None:
        ev_path = tmp_path / "verification_evidence.json"
        ev_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        mod.EVIDENCE_JSON = ev_path
    else:
        ev = _make_valid_evidence()
        ev_path = tmp_path / "verification_evidence.json"
        ev_path.write_text(json.dumps(ev, indent=2), encoding="utf-8")
        mod.EVIDENCE_JSON = ev_path

    return mod


def _restore_paths(mod):
    """Restore module-level paths to their original values."""
    # Re-import to reset paths.
    spec = importlib.util.spec_from_file_location("check_deterministic_lab", SCRIPT)
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    mod.LAB_RUNTIME_RS = fresh.LAB_RUNTIME_RS
    mod.VIRTUAL_TRANSPORT_RS = fresh.VIRTUAL_TRANSPORT_RS
    mod.SCENARIO_BUILDER_RS = fresh.SCENARIO_BUILDER_RS
    mod.SPEC_CONTRACT = fresh.SPEC_CONTRACT
    mod.EVIDENCE_JSON = fresh.EVIDENCE_JSON


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSelfTest:
    """Verify that importing the module and calling self_test() succeeds."""

    def test_self_test(self):
        mod = _load_module()
        # Register module so self_test() can find it via sys.modules[__name__]
        sys.modules["check_deterministic_lab"] = mod
        result = mod.self_test()
        assert result is True

    def test_self_test_via_subprocess(self):
        result = _run_script("--self-test", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"


class TestJsonOutputStructure:
    """Run the script with --json and validate the output schema."""

    def test_json_output_structure(self):
        result = _run_script("--json")
        assert result.returncode == 0, (
            f"Script exited with code {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        data = json.loads(result.stdout)

        assert data.get("bead_id") == "bd-2ko"
        assert data.get("section") == "10.11"
        assert data.get("verdict") in ("PASS", "FAIL")
        assert isinstance(data.get("checks"), list)
        assert len(data["checks"]) > 0

    def test_checks_have_required_keys(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        for entry in data["checks"]:
            assert isinstance(entry, dict)
            assert "check" in entry, f"Entry missing 'check' key: {entry}"
            assert "pass" in entry, f"Entry missing 'pass' key: {entry}"

    def test_total_and_passed_counts(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        assert "total" in data
        assert "passed" in data
        assert "failed" in data
        assert data["total"] == data["passed"] + data["failed"]

    def test_overall_pass_field(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        assert "overall_pass" in data
        assert data["overall_pass"] == (data["verdict"] == "PASS")


class TestMissingSourceFile:
    """When lab_runtime.rs is absent the gate must fail."""

    def test_missing_lab_runtime(self, tmp_path):
        mod = _scaffold_fixtures(tmp_path, include_lab=False)
        result = mod.run_checks()
        assert result["verdict"] == "FAIL"
        failing = [c for c in result["checks"] if not c["pass"]]
        names = [c["check"] for c in failing]
        assert any("lab_runtime" in n for n in names)
        _restore_paths(mod)

    def test_missing_virtual_transport(self, tmp_path):
        mod = _scaffold_fixtures(tmp_path, include_vt=False)
        result = mod.run_checks()
        assert result["verdict"] == "FAIL"
        failing = [c for c in result["checks"] if not c["pass"]]
        names = [c["check"] for c in failing]
        assert any("virtual_transport" in n for n in names)
        _restore_paths(mod)

    def test_missing_scenario_builder(self, tmp_path):
        mod = _scaffold_fixtures(tmp_path, include_sb=False)
        result = mod.run_checks()
        assert result["verdict"] == "FAIL"
        failing = [c for c in result["checks"] if not c["pass"]]
        names = [c["check"] for c in failing]
        assert any("scenario_builder" in n for n in names)
        _restore_paths(mod)

    def test_missing_spec_contract(self, tmp_path):
        mod = _scaffold_fixtures(tmp_path, include_spec=False)
        result = mod.run_checks()
        assert result["verdict"] == "FAIL"
        failing = [c for c in result["checks"] if not c["pass"]]
        names = [c["check"] for c in failing]
        assert any("spec" in n.lower() or "contract" in n.lower() for n in names)
        _restore_paths(mod)


class TestInvalidEvidenceJson:
    """Evidence JSON with missing required fields must cause a gate failure."""

    def test_missing_fields(self, tmp_path):
        invalid_evidence = {"bead_id": "bd-2ko"}
        mod = _scaffold_fixtures(tmp_path, evidence=invalid_evidence)
        result = mod.run_checks()
        assert result["verdict"] == "FAIL"
        failing = [c for c in result["checks"] if not c["pass"]]
        assert len(failing) > 0
        _restore_paths(mod)

    def test_malformed_json(self, tmp_path):
        mod = _scaffold_fixtures(tmp_path)
        ev_path = tmp_path / "verification_evidence.json"
        ev_path.write_text("{invalid json", encoding="utf-8")
        mod.EVIDENCE_JSON = ev_path
        result = mod.run_checks()
        assert result["verdict"] == "FAIL"
        _restore_paths(mod)


class TestDeterminismNotVerified:
    """Evidence with determinism_verified=false must cause a gate failure."""

    def test_determinism_false(self, tmp_path):
        evidence = _make_valid_evidence()
        evidence["determinism_verified"] = False
        mod = _scaffold_fixtures(tmp_path, evidence=evidence)
        result = mod.run_checks()
        assert result["verdict"] == "FAIL"
        failing = [c for c in result["checks"] if not c["pass"]]
        names = [c["check"] for c in failing]
        assert any("determinism" in n.lower() for n in names)
        _restore_paths(mod)


class TestValidEvidencePasses:
    """Complete valid evidence together with all required files must pass."""

    def test_valid_evidence_passes(self, tmp_path):
        mod = _scaffold_fixtures(tmp_path)
        result = mod.run_checks()
        assert result["verdict"] == "PASS", (
            f"Gate should pass with valid fixtures. "
            f"Failing: {[c for c in result['checks'] if not c['pass']]}"
        )
        assert result["overall_pass"] is True
        _restore_paths(mod)


class TestEventCodes:
    """Verify event code constants and coverage."""

    def test_lab_event_code_count(self):
        assert len(LAB_EVENT_CODES) == 10

    def test_vt_event_code_count(self):
        assert len(VT_EVENT_CODES) == 8

    def test_sb_event_code_count(self):
        assert len(SB_EVENT_CODES) == 4

    def test_event_codes_unique(self):
        all_codes = LAB_EVENT_CODES + VT_EVENT_CODES + SB_EVENT_CODES
        assert len(all_codes) == len(set(all_codes))

    def test_lab_event_codes_prefixed(self):
        for code in LAB_EVENT_CODES:
            assert code.startswith("FN-LB-")

    def test_vt_event_codes_prefixed(self):
        for code in VT_EVENT_CODES:
            assert code.startswith("VT-")

    def test_sb_event_codes_prefixed(self):
        for code in SB_EVENT_CODES:
            assert code.startswith("SB-")


class TestEvidenceSchema:
    """Verify the evidence JSON schema structure."""

    def test_valid_evidence_has_required_fields(self):
        ev = _make_valid_evidence()
        required = {"bead_id", "section", "scenarios_executed",
                     "interleavings_explored", "determinism_verified", "bugs_found"}
        assert required.issubset(set(ev.keys()))

    def test_evidence_bead_id(self):
        ev = _make_valid_evidence()
        assert ev["bead_id"] == "bd-2ko"

    def test_evidence_section(self):
        ev = _make_valid_evidence()
        assert ev["section"] == "10.11"

    def test_evidence_determinism_true(self):
        ev = _make_valid_evidence()
        assert ev["determinism_verified"] is True

    def test_evidence_modules_list(self):
        ev = _make_valid_evidence()
        assert isinstance(ev["modules_implemented"], list)
        assert len(ev["modules_implemented"]) >= 2

    def test_evidence_invariants_list(self):
        ev = _make_valid_evidence()
        assert isinstance(ev["invariants_enforced"], list)
        assert len(ev["invariants_enforced"]) >= 4


class TestHumanReadableOutput:
    """Verify the human-readable (non-JSON) output format."""

    def test_human_readable_output(self):
        result = _run_script()
        assert result.returncode == 0
        assert "PASS" in result.stdout or "FAIL" in result.stdout
        assert "bd-2ko" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
