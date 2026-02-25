"""Tests for scripts/check_section_14_gate.py (bd-2l4i)."""

import importlib.util
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_section_14_gate.py")

spec = importlib.util.spec_from_file_location("check_s14", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestConfiguration:
    def test_ten_beads(self):
        assert len(mod.SECTION_BEADS) == 10

    def test_six_metric_families(self):
        metric = [b for b in mod.SECTION_BEADS if b["title"].startswith("Metric family:")]
        assert len(metric) == 6

    def test_four_publication_beads(self):
        pub = [b for b in mod.SECTION_BEADS if not b["title"].startswith("Metric family:")]
        assert len(pub) == 4

    def test_all_scripts_exist(self):
        from pathlib import Path
        for entry in mod.SECTION_BEADS:
            assert (Path(ROOT) / entry["script"]).exists(), f"Missing: {entry['script']}"

    def test_all_tests_exist(self):
        from pathlib import Path
        for entry in mod.SECTION_BEADS:
            assert (Path(ROOT) / entry["test"]).exists(), f"Missing: {entry['test']}"

    def test_all_evidence_exists(self):
        from pathlib import Path
        for entry in mod.SECTION_BEADS:
            ev = Path(ROOT) / "artifacts" / "section_14" / entry["bead"] / "verification_evidence.json"
            assert ev.exists(), f"Missing: {ev}"


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=300,
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-2l4i"
        assert data["section"] == "14"
        assert isinstance(data["per_bead_results"], list)

    def test_verdict_field(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=300,
        )
        data = json.loads(result.stdout)
        assert data["verdict"] in ("PASS", "FAIL")

    def test_gate_checks_present(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=300,
        )
        data = json.loads(result.stdout)
        gate_ids = [g["id"] for g in data["gate_checks"]]
        assert "GATE-14-ALL-BEADS" in gate_ids


class TestNoExec:
    def test_no_execution_runs(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json", "--no-exec"],
            capture_output=True, text=True, cwd=ROOT, timeout=60,
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-2l4i"
        assert data["beads_expected"] == 10


class TestOverall:
    def test_all_beads_pass(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=300,
        )
        data = json.loads(result.stdout)
        for b in data["per_bead_results"]:
            assert b["overall_pass"], f"{b['bead_id']} failed"

    def test_gate_verdict_pass(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=300,
        )
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"

    def test_content_hash_present(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=300,
        )
        data = json.loads(result.stdout)
        assert len(data["content_hash"]) == 64
