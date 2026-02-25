"""Tests for scripts/check_compatibility_correctness_metrics.py (bd-18ie)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_compatibility_correctness_metrics.py")

spec = importlib.util.spec_from_file_location("check_ccm", SCRIPT)
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
        assert data["bead_id"] == "bd-18ie"
        assert data["section"] == "14"
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

    def test_api_families(self, results):
        assert results["api_families"]["passed"]

    def test_risk_bands(self, results):
        assert results["risk_bands"]["passed"]

    def test_thresholds_defined(self, results):
        assert results["thresholds_defined"]["passed"]

    def test_struct_correctness_metric(self, results):
        assert results["struct_CorrectnessMetric"]["passed"]

    def test_struct_segment_key(self, results):
        assert results["struct_SegmentKey"]["passed"]

    def test_struct_segment_stats(self, results):
        assert results["struct_SegmentStats"]["passed"]

    def test_struct_correctness_report(self, results):
        assert results["struct_CorrectnessReport"]["passed"]

    def test_struct_engine(self, results):
        assert results["struct_CompatibilityCorrectnessMetrics"]["passed"]

    def test_correctness_rate(self, results):
        assert results["correctness_rate"]["passed"]

    def test_regression_detection(self, results):
        assert results["regression_detection"]["passed"]

    def test_report_generation(self, results):
        assert results["report_generation"]["passed"]

    def test_flagged_segments(self, results):
        assert results["flagged_segments"]["passed"]

    def test_event_codes(self, results):
        assert results["event_codes"]["passed"]

    def test_invariants(self, results):
        assert results["invariants"]["passed"]

    def test_audit_log(self, results):
        assert results["audit_log"]["passed"]

    def test_metric_version(self, results):
        assert results["metric_version"]["passed"]

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
        assert "bd-18ie" in result.stdout
        assert "PASS" in result.stdout
