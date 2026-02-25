"""Tests for scripts/check_performance_hardening_metrics.py (bd-ka0n)."""

import importlib.util
import json
import os
import subprocess
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_performance_hardening_metrics.py")

spec = importlib.util.spec_from_file_location("check_phm", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-ka0n"
        assert data["section"] == "14"
        assert isinstance(data["checks"], list)


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results): assert results["source_exists"]["passed"]
    def test_module_wiring(self, results): assert results["module_wiring"]["passed"]
    def test_operation_categories(self, results): assert results["operation_categories"]["passed"]
    def test_percentiles(self, results): assert results["percentiles"]["passed"]
    def test_percentile_ordering(self, results): assert results["percentile_ordering"]["passed"]
    def test_struct_metric(self, results): assert results["struct_PerformanceMetric"]["passed"]
    def test_struct_percentiles(self, results): assert results["struct_Percentiles"]["passed"]
    def test_struct_stats(self, results): assert results["struct_CategoryStats"]["passed"]
    def test_struct_report(self, results): assert results["struct_PerformanceReport"]["passed"]
    def test_struct_engine(self, results): assert results["struct_PerformanceHardeningMetrics"]["passed"]
    def test_overhead_ratio(self, results): assert results["overhead_ratio"]["passed"]
    def test_cold_start_ratio(self, results): assert results["cold_start_ratio"]["passed"]
    def test_budget_enforcement(self, results): assert results["budget_enforcement"]["passed"]
    def test_flagged_categories(self, results): assert results["flagged_categories"]["passed"]
    def test_event_codes(self, results): assert results["event_codes"]["passed"]
    def test_invariants(self, results): assert results["invariants"]["passed"]
    def test_audit_log(self, results): assert results["audit_log"]["passed"]
    def test_metric_version(self, results): assert results["metric_version"]["passed"]
    def test_spec_alignment(self, results): assert results["spec_alignment"]["passed"]
    def test_test_coverage(self, results): assert results["test_coverage"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [r for r in mod._checks() if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert json.loads(result.stdout)["verdict"] == "PASS"

    def test_human_output(self):
        result = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
        assert "bd-ka0n" in result.stdout and "PASS" in result.stdout
