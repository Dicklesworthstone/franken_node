"""Unit tests for scripts/check_benchmark_suite.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SCRIPT = ROOT / "scripts" / "check_benchmark_suite.py"

from scripts import check_benchmark_suite as checker


def run_script(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


class TestSelfTest:
    def test_self_test_passes(self):
        result = run_script("--self-test")
        assert result.returncode == 0
        assert "SELF-TEST OK" in result.stderr


class TestJsonOutput:
    def test_json_output_is_valid(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-k4s"
        assert data["section"] == "10.6"
        assert isinstance(data["total"], int)
        assert isinstance(data["passed"], int)
        assert isinstance(data["checks"], list)

    def test_json_has_verdict(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["verdict"] in ("PASS", "FAIL")
        assert isinstance(data["overall_pass"], bool)

    def test_json_check_structure(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        for check in data["checks"]:
            assert "check" in check
            assert "pass" in check
            assert "detail" in check
            assert isinstance(check["pass"], bool)


class TestSpecChecks:
    def test_spec_exists(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        spec_check = next(c for c in data["checks"] if c["check"] == "spec_exists")
        assert spec_check["pass"] is True

    def test_policy_exists(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        policy_check = next(c for c in data["checks"] if c["check"] == "policy_exists")
        assert policy_check["pass"] is True


class TestKeywordChecks:
    @pytest.mark.parametrize(
        "keyword",
        [
            "spec_keyword_benchmark",
            "spec_keyword_scoring",
            "spec_keyword_confidence",
            "spec_keyword_deterministic",
            "spec_keyword_sandbox",
            "spec_keyword_provenance",
            "spec_keyword_variance_5pct",
        ],
    )
    def test_spec_keyword_present(self, keyword: str):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == keyword)
        assert check["pass"] is True, f"{keyword} should be found in spec"


class TestEventCodes:
    def test_event_codes_in_spec(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "event_codes_in_spec")
        assert check["pass"] is True, f"Event codes should be in spec: {check['detail']}"


class TestDimensionCoverage:
    def test_dimensions_in_spec(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "dimensions_in_spec")
        assert check["pass"] is True, f"All 6 dimensions should be in spec: {check['detail']}"


class TestRustImplementation:
    def test_rust_impl_exists(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "rust_impl_exists")
        assert check["pass"] is True

    def test_rust_module_registered(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "rust_module_registered")
        assert check["pass"] is True

    def test_rust_event_codes(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "rust_event_codes")
        assert check["pass"] is True

    def test_rust_invariant_constants(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "rust_invariant_constants")
        assert check["pass"] is True

    def test_rust_scoring_formula(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "rust_scoring_formula")
        assert check["pass"] is True

    def test_rust_test_count_sufficient(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "rust_test_count")
        assert check["pass"] is True, f"Should have >= 15 tests: {check['detail']}"

    def test_measured_boundary_check_passes(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "rust_measured_evidence_boundary")
        assert check["pass"] is True

    def test_default_cli_measured_provider_check_passes(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "rust_default_cli_uses_measured_provider")
        assert check["pass"] is True, check["detail"]

    def test_bench_run_e2e_real_and_failure_coverage_passes(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "bench_run_e2e_real_and_failure_coverage")
        assert check["pass"] is True, check["detail"]

    def test_default_cli_measured_provider_check_rejects_fixture_default(self, tmp_path, monkeypatch):
        impl = tmp_path / "benchmark_suite.rs"
        impl.write_text(
            """
pub fn run_default_suite_for_cli(
    scenario_filter: Option<&str>,
    fixture_mode: bool,
) -> Result<BenchmarkReport, BenchRunError> {
    let evidence_mode = if fixture_mode {
        BenchmarkEvidenceMode::FixtureOnly
    } else {
        BenchmarkEvidenceMode::FixtureOnly
    };
    run_default_suite_with_config_and_mode(SuiteConfig::for_cli(), scenario_filter, evidence_mode)
}

fn measured_sample_map() {
    BenchmarkSecurityControls::from_env(false);
    let _ = "measured_product_workload";
    let _ = "fixture_only_deterministic";
    let _ = "FRANKEN_NODE_BENCH_FAIL_SCENARIO";
}
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(checker, "RUST_IMPL_PATH", impl)
        checker.RESULTS.clear()

        check = checker.check_rust_default_cli_uses_measured_provider()

        assert check["pass"] is False
        assert "default_cli_measured_else_branch" in check["detail"]

    def test_bench_run_e2e_coverage_check_rejects_missing_forced_failure(self, tmp_path, monkeypatch):
        e2e = tmp_path / "bench_run_e2e.rs"
        e2e.write_text(
            """
fn bench_run_default_path_emits_measured_evidence() {
    let _ = "--fixture-mode";
    let _ = "fixture_only_deterministic";
    let _ = "raw_samples";
    let _ = "security_controls";
}

fn bench_run_invalid_scenario_returns_structured_error() {}
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(checker, "BENCH_E2E_PATH", e2e)
        checker.RESULTS.clear()

        check = checker.check_bench_run_e2e_real_and_failure_coverage()

        assert check["pass"] is False
        assert "forced_runner_failure_test" in check["detail"]


class TestPolicyDocument:
    def test_policy_scoring_formula(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "policy_scoring_formula")
        assert check["pass"] is True

    def test_policy_dimensions(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "policy_dimensions")
        assert check["pass"] is True


class TestOverallVerdict:
    def test_all_checks_pass(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["overall_pass"] is True, (
            f"Expected all checks to pass. Failed: "
            f"{[c['check'] for c in data['checks'] if not c['pass']]}"
        )

    def test_human_readable_output(self):
        result = run_script()
        assert "bd-k4s verification" in result.stdout
