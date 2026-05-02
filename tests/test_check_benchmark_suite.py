"""Unit tests for scripts/check_benchmark_suite.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SCRIPT = ROOT / "scripts" / "check_benchmark_suite.py"

from scripts import check_benchmark_suite as checker  # noqa: E402


_JSON_CACHE: dict[str, object] | None = None


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        text=True,
        cwd=str(ROOT),
        timeout=30,
    )


def run_json() -> dict[str, object]:
    global _JSON_CACHE
    if _JSON_CACHE is None:
        result = run_script("--json")
        if result.returncode != 0:
            msg = f"{SCRIPT.name} --json failed: {result.stderr}"
            raise AssertionError(msg)
        _JSON_CACHE = json.JSONDecoder().decode(result.stdout)
    return _JSON_CACHE


def check_named(name: str) -> dict[str, object]:
    return next(check for check in run_json()["checks"] if check["check"] == name)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        result = run_script("--self-test")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SELF-TEST OK", result.stderr)


class TestJsonOutput(unittest.TestCase):
    def test_json_output_is_valid(self):
        data = run_json()
        self.assertEqual(data["bead_id"], "bd-k4s")
        self.assertEqual(data["section"], "10.6")
        self.assertIsInstance(data["total"], int)
        self.assertIsInstance(data["passed"], int)
        self.assertIsInstance(data["checks"], list)

    def test_json_has_verdict(self):
        data = run_json()
        self.assertIn(data["verdict"], ("PASS", "FAIL"))
        self.assertIsInstance(data["overall_pass"], bool)

    def test_json_check_structure(self):
        for check in run_json()["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)
            self.assertIsInstance(check["pass"], bool)


class TestSpecChecks(unittest.TestCase):
    def test_spec_exists(self):
        self.assertTrue(check_named("spec_exists")["pass"])

    def test_policy_exists(self):
        self.assertTrue(check_named("policy_exists")["pass"])


class TestKeywordChecks(unittest.TestCase):
    def assertKeywordPresent(self, keyword: str) -> None:
        self.assertTrue(check_named(keyword)["pass"], f"{keyword} should be found in spec")

    def test_spec_keyword_benchmark_present(self):
        self.assertKeywordPresent("spec_keyword_benchmark")

    def test_spec_keyword_scoring_present(self):
        self.assertKeywordPresent("spec_keyword_scoring")

    def test_spec_keyword_confidence_present(self):
        self.assertKeywordPresent("spec_keyword_confidence")

    def test_spec_keyword_deterministic_present(self):
        self.assertKeywordPresent("spec_keyword_deterministic")

    def test_spec_keyword_sandbox_present(self):
        self.assertKeywordPresent("spec_keyword_sandbox")

    def test_spec_keyword_provenance_present(self):
        self.assertKeywordPresent("spec_keyword_provenance")

    def test_spec_keyword_variance_present(self):
        self.assertKeywordPresent("spec_keyword_variance_5pct")


class TestEventCodes(unittest.TestCase):
    def test_event_codes_in_spec(self):
        check = check_named("event_codes_in_spec")
        self.assertTrue(check["pass"], f"Event codes should be in spec: {check['detail']}")


class TestDimensionCoverage(unittest.TestCase):
    def test_dimensions_in_spec(self):
        check = check_named("dimensions_in_spec")
        self.assertTrue(check["pass"], f"All 6 dimensions should be in spec: {check['detail']}")


class TestRustImplementation(unittest.TestCase):
    def test_rust_impl_exists(self):
        self.assertTrue(check_named("rust_impl_exists")["pass"])

    def test_rust_module_registered(self):
        self.assertTrue(check_named("rust_module_registered")["pass"])

    def test_rust_event_codes(self):
        self.assertTrue(check_named("rust_event_codes")["pass"])

    def test_rust_invariant_constants(self):
        self.assertTrue(check_named("rust_invariant_constants")["pass"])

    def test_rust_scoring_formula(self):
        self.assertTrue(check_named("rust_scoring_formula")["pass"])

    def test_rust_test_count_sufficient(self):
        check = check_named("rust_test_count")
        self.assertTrue(check["pass"], f"Should have >= 15 tests: {check['detail']}")

    def test_measured_boundary_check_passes(self):
        self.assertTrue(check_named("rust_measured_evidence_boundary")["pass"])

    def test_default_cli_measured_provider_check_passes(self):
        check = check_named("rust_default_cli_uses_measured_provider")
        self.assertTrue(check["pass"], check["detail"])

    def test_bench_run_e2e_real_and_failure_coverage_passes(self):
        check = check_named("bench_run_e2e_real_and_failure_coverage")
        self.assertTrue(check["pass"], check["detail"])

    def test_default_cli_measured_provider_check_rejects_fixture_default(self):
        with tempfile.TemporaryDirectory(prefix="bench-check-") as temp_dir:
            impl = Path(temp_dir) / "benchmark_suite.rs"
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
            checker.RESULTS.clear()

            with patch.object(checker, "RUST_IMPL_PATH", impl):
                check = checker.check_rust_default_cli_uses_measured_provider()

        self.assertFalse(check["pass"])
        self.assertIn("default_cli_measured_else_branch", check["detail"])

    def test_bench_run_e2e_coverage_check_rejects_missing_forced_failure(self):
        with tempfile.TemporaryDirectory(prefix="bench-e2e-check-") as temp_dir:
            e2e = Path(temp_dir) / "bench_run_e2e.rs"
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
            checker.RESULTS.clear()

            with patch.object(checker, "BENCH_E2E_PATH", e2e):
                check = checker.check_bench_run_e2e_real_and_failure_coverage()

        self.assertFalse(check["pass"])
        self.assertIn("forced_runner_failure_test", check["detail"])


class TestPolicyDocument(unittest.TestCase):
    def test_policy_scoring_formula(self):
        self.assertTrue(check_named("policy_scoring_formula")["pass"])

    def test_policy_dimensions(self):
        self.assertTrue(check_named("policy_dimensions")["pass"])


class TestOverallVerdict(unittest.TestCase):
    def test_all_checks_pass(self):
        data = run_json()
        failed = [check["check"] for check in data["checks"] if not check["pass"]]
        self.assertTrue(data["overall_pass"], f"Expected all checks to pass. Failed: {failed}")

    def test_human_readable_output(self):
        result = run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bd-k4s verification", result.stdout)


if __name__ == "__main__":
    unittest.main()
