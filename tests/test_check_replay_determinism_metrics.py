"""Tests for scripts/check_replay_determinism_metrics.py (bd-jbp1)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_replay_determinism_metrics.py")

spec = importlib.util.spec_from_file_location("check_replay_determinism_metrics", SCRIPT)
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
        assert data["bead_id"] == "bd-jbp1"
        assert data["section"] == "14"
        assert isinstance(data["checks"], list)


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results):
        assert results["source_exists"]["passed"]

    def test_module_wiring(self, results):
        assert results["module_wiring"]["passed"]

    def test_artifact_categories(self, results):
        assert results["artifact_categories"]["passed"]

    def test_struct_replay_run(self, results):
        assert results["struct_ReplayRun"]["passed"]

    def test_struct_comparison_result(self, results):
        assert results["struct_ComparisonResult"]["passed"]

    def test_struct_artifact_completeness(self, results):
        assert results["struct_ArtifactCompleteness"]["passed"]

    def test_struct_determinism_report(self, results):
        assert results["struct_DeterminismReport"]["passed"]

    def test_struct_rdm_audit_record(self, results):
        assert results["struct_RdmAuditRecord"]["passed"]

    def test_struct_replay_determinism_metrics(self, results):
        assert results["struct_ReplayDeterminismMetrics"]["passed"]

    def test_hash_comparison(self, results):
        assert results["hash_comparison"]["passed"]

    def test_divergence_detection(self, results):
        assert results["divergence_detection"]["passed"]

    def test_artifact_tracking(self, results):
        assert results["artifact_tracking"]["passed"]

    def test_report_generation(self, results):
        assert results["report_generation"]["passed"]

    def test_artifact_completeness_hash_surface(self, results):
        assert results["artifact_completeness_hash_surface"]["passed"]

    def test_metric_versioning(self, results):
        assert results["metric_versioning"]["passed"]

    def test_event_codes(self, results):
        assert results["event_codes"]["passed"]

    def test_invariants(self, results):
        assert results["invariants"]["passed"]

    def test_audit_log(self, results):
        assert results["audit_log"]["passed"]

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
        assert "bd-jbp1" in result.stdout
        assert "PASS" in result.stdout
