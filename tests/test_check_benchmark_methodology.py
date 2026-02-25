"""Tests for scripts/check_benchmark_methodology.py (bd-nbh7)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_benchmark_methodology.py")

spec = importlib.util.spec_from_file_location("check_bmp", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-nbh7"
        assert data["section"] == "16"
        assert "checks_passed" in data
        assert isinstance(data["checks"], list)


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results):
        assert results["source_exists"]["passed"]

    def test_module_wiring(self, results):
        assert results["module_wiring"]["passed"]

    def test_methodology_topics(self, results):
        assert results["methodology_topics"]["passed"]

    def test_pub_statuses(self, results):
        assert results["pub_statuses"]["passed"]

    def test_status_transitions(self, results):
        assert results["status_transitions"]["passed"]

    def test_required_sections(self, results):
        assert results["required_sections"]["passed"]

    def test_struct_publication(self, results):
        assert results["struct_Publication"]["passed"]

    def test_struct_citation(self, results):
        assert results["struct_Citation"]["passed"]

    def test_struct_checklist_item(self, results):
        assert results["struct_ChecklistItem"]["passed"]

    def test_struct_catalog(self, results):
        assert results["struct_PublicationCatalog"]["passed"]

    def test_struct_engine(self, results):
        assert results["struct_BenchmarkMethodology"]["passed"]

    def test_content_hashing(self, results):
        assert results["content_hashing"]["passed"]

    def test_reproducibility_checklist(self, results):
        assert results["reproducibility_checklist"]["passed"]

    def test_catalog_generation(self, results):
        assert results["catalog_generation"]["passed"]

    def test_search_by_topic(self, results):
        assert results["search_by_topic"]["passed"]

    def test_event_codes(self, results):
        assert results["event_codes"]["passed"]

    def test_invariants(self, results):
        assert results["invariants"]["passed"]

    def test_audit_log(self, results):
        assert results["audit_log"]["passed"]

    def test_pub_version(self, results):
        assert results["pub_version"]["passed"]

    def test_spec_alignment(self, results):
        assert results["spec_alignment"]["passed"]

    def test_test_coverage(self, results):
        assert results["test_coverage"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        results = mod._checks()
        failed = [r for r in results if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"

    def test_human_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT],
            capture_output=True, text=True,
        )
        assert "bd-nbh7" in result.stdout
        assert "PASS" in result.stdout
