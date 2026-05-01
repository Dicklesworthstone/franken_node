#!/usr/bin/env python3
"""Verification script for bd-k4s: product-level benchmark suite.

Usage:
    python scripts/check_benchmark_suite.py          # human-readable
    python scripts/check_benchmark_suite.py --json    # machine-readable
    python scripts/check_benchmark_suite.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from typing import Any


SPEC_PATH = ROOT / "docs" / "specs" / "section_10_6" / "bd-k4s_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "benchmark_suite.md"
RUST_IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "tools" / "benchmark_suite.rs"
TOOLS_MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
BENCH_E2E_PATH = ROOT / "crates" / "franken-node" / "tests" / "bench_run_e2e.rs"
FRANKEN_NODE_CARGO_TOML = ROOT / "crates" / "franken-node" / "Cargo.toml"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_relative(path: Path) -> str:
    """Return a relative path string, guarding against paths outside ROOT."""
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Spec checks
# ---------------------------------------------------------------------------


def check_spec_exists() -> dict[str, Any]:
    exists = SPEC_PATH.is_file()
    return _check(
        "spec_exists",
        exists,
        f"exists: {_safe_relative(SPEC_PATH)}" if exists else f"missing: {_safe_relative(SPEC_PATH)}",
    )


def check_policy_exists() -> dict[str, Any]:
    exists = POLICY_PATH.is_file()
    return _check(
        "policy_exists",
        exists,
        f"exists: {_safe_relative(POLICY_PATH)}" if exists else f"missing: {_safe_relative(POLICY_PATH)}",
    )


# ---------------------------------------------------------------------------
# Spec keyword checks
# ---------------------------------------------------------------------------


def check_spec_keyword_benchmark() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_benchmark", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "benchmark" in text.lower()
    return _check("spec_keyword_benchmark", found)


def check_spec_keyword_scoring() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_scoring", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "scoring" in text.lower()
    return _check("spec_keyword_scoring", found)


def check_spec_keyword_confidence() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_confidence", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "confidence" in text.lower()
    return _check("spec_keyword_confidence", found)


def check_spec_keyword_deterministic() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_deterministic", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "deterministic" in text.lower()
    return _check("spec_keyword_deterministic", found)


def check_spec_keyword_sandbox() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_sandbox", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "sandbox" in text.lower()
    return _check("spec_keyword_sandbox", found)


def check_spec_keyword_provenance() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_provenance", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "provenance" in text.lower()
    return _check("spec_keyword_provenance", found)


def check_spec_keyword_variance() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_variance_5pct", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "5%" in text or "< 5%" in text or "variance" in text.lower()
    return _check("spec_keyword_variance_5pct", found)


# ---------------------------------------------------------------------------
# Event code checks in spec
# ---------------------------------------------------------------------------


def check_event_codes_in_spec() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("event_codes_in_spec", False, "spec file missing")
    text = SPEC_PATH.read_text()
    required = [
        "BS-001",
        "BS-002",
        "BS-003",
        "BS-004",
        "BS-005",
        "BS-006",
        "BS-007",
        "BS-008",
        "BS-009",
        "BS-010",
    ]
    missing = [code for code in required if code not in text]
    passed = len(missing) == 0
    detail = "all present" if passed else f"missing: {', '.join(missing)}"
    return _check("event_codes_in_spec", passed, detail)


# ---------------------------------------------------------------------------
# Dimension coverage in spec
# ---------------------------------------------------------------------------


def check_dimensions_in_spec() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("dimensions_in_spec", False, "spec file missing")
    text = SPEC_PATH.read_text().lower()
    dimensions = [
        "compatibility_correctness",
        "performance_under_hardening",
        "containment_latency",
        "replay_determinism",
        "adversarial_resilience",
        "migration_speed",
    ]
    missing = [d for d in dimensions if d not in text]
    passed = len(missing) == 0
    detail = "all 6 dimensions present" if passed else f"missing: {', '.join(missing)}"
    return _check("dimensions_in_spec", passed, detail)


# ---------------------------------------------------------------------------
# Rust implementation checks
# ---------------------------------------------------------------------------


def check_rust_impl_exists() -> dict[str, Any]:
    exists = RUST_IMPL_PATH.is_file()
    return _check(
        "rust_impl_exists",
        exists,
        f"exists: {_safe_relative(RUST_IMPL_PATH)}" if exists else f"missing: {_safe_relative(RUST_IMPL_PATH)}",
    )


def check_rust_module_registered() -> dict[str, Any]:
    if not TOOLS_MOD_PATH.is_file():
        return _check("rust_module_registered", False, "tools/mod.rs missing")
    text = TOOLS_MOD_PATH.read_text()
    found = "pub mod benchmark_suite" in text
    return _check("rust_module_registered", found, "registered in tools/mod.rs" if found else "NOT registered")


def check_rust_event_codes() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_event_codes", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    required = [
        "BS-001",
        "BS-002",
        "BS-003",
        "BS-004",
        "BS-005",
        "BS-006",
        "BS-007",
        "BS-008",
        "BS-009",
        "BS-010",
    ]
    missing = [code for code in required if code not in text]
    passed = len(missing) == 0
    detail = "all present" if passed else f"missing: {', '.join(missing)}"
    return _check("rust_event_codes", passed, detail)


def check_rust_invariant_constants() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_invariant_constants", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    required = [
        "INV-BS-DETERMINISTIC",
        "INV-BS-SECURE",
        "INV-BS-CONFIDENCE",
        "INV-BS-SCORING",
        "INV-BS-MACHINE-READABLE",
        "INV-BS-COVERAGE",
    ]
    missing = [inv for inv in required if inv not in text]
    passed = len(missing) == 0
    detail = "all 6 invariants present" if passed else f"missing: {', '.join(missing)}"
    return _check("rust_invariant_constants", passed, detail)


def check_rust_scoring_formula() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_scoring_formula", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    found = "fn score(" in text and "clamp" in text
    return _check("rust_scoring_formula", found, "scoring formula with clamp found" if found else "NOT FOUND")


def check_rust_confidence_interval() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_confidence_interval", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    found = "confidence_interval_95" in text and "ConfidenceInterval" in text
    return _check("rust_confidence_interval", found)


def check_rust_regression_detection() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_regression_detection", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    found = "detect_regressions" in text and "RegressionFinding" in text
    return _check("rust_regression_detection", found)


def check_rust_measured_evidence_boundary() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_measured_evidence_boundary", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    required = [
        "BenchmarkEvidenceMode",
        "Measured",
        "FixtureOnly",
        "measured_samples_for_scenario",
        "fixture_measurement_sample_map",
        "FRANKEN_NODE_BENCH_SECURITY_DISABLED",
        "raw_samples",
        "trace_id",
        "evidence_path",
        "sample_policy",
        "events",
        "BenchmarkSamplePolicy",
        "BS_FIXTURE_MODE_USED",
    ]
    missing = [item for item in required if item not in text]
    passed = not missing
    detail = "measured/fixture boundary present" if passed else f"missing: {', '.join(missing)}"
    return _check("rust_measured_evidence_boundary", passed, detail)


def check_rust_default_cli_uses_measured_provider() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_default_cli_uses_measured_provider", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    default_cli_pattern = re.compile(
        r"pub fn run_default_suite_for_cli\([\s\S]*?"
        r"let evidence_mode = if fixture_mode \{[\s\S]*?"
        r"BenchmarkEvidenceMode::FixtureOnly[\s\S]*?"
        r"\} else \{[\s\S]*?"
        r"BenchmarkEvidenceMode::Measured[\s\S]*?"
        r"run_default_suite_with_config_and_mode\(SuiteConfig::for_cli\(\), scenario_filter, evidence_mode\)",
        re.MULTILINE,
    )
    required = {
        "default_cli_measured_else_branch": bool(default_cli_pattern.search(text)),
        "measured_security_from_env": "BenchmarkSecurityControls::from_env(false)" in text,
        "measured_source_marker": '"measured_product_workload"' in text,
        "fixture_source_marker": '"fixture_only_deterministic"' in text,
        "forced_failure_hook": "FRANKEN_NODE_BENCH_FAIL_SCENARIO" in text,
    }
    missing = [name for name, present in required.items() if not present]
    passed = not missing
    detail = (
        "default CLI path uses measured provider; fixture provider requires --fixture-mode"
        if passed
        else f"missing: {', '.join(missing)}"
    )
    return _check("rust_default_cli_uses_measured_provider", passed, detail)


def check_bench_run_e2e_real_and_failure_coverage() -> dict[str, Any]:
    if not BENCH_E2E_PATH.is_file():
        return _check("bench_run_e2e_real_and_failure_coverage", False, "bench_run_e2e.rs missing")
    text = BENCH_E2E_PATH.read_text()
    manifest_text = FRANKEN_NODE_CARGO_TOML.read_text() if FRANKEN_NODE_CARGO_TOML.is_file() else ""
    required = {
        "registered_cargo_test_target": 'name = "bench_run_e2e"' in manifest_text
        and 'path = "tests/bench_run_e2e.rs"' in manifest_text,
        "measured_default_test": "bench_run_default_path_emits_measured_evidence" in text,
        "fixture_mode_test": "--fixture-mode" in text and "fixture_only_deterministic" in text,
        "invalid_scenario_test": "bench_run_invalid_scenario_returns_structured_error" in text,
        "forced_runner_failure_test": "FRANKEN_NODE_BENCH_FAIL_SCENARIO" in text,
        "raw_samples_assertion": "raw_samples" in text,
        "security_metadata_assertion": "security_controls" in text,
        "trace_metadata_assertion": "trace_id" in text,
        "sample_policy_assertion": "sample_policy" in text,
        "event_log_assertion": "BS-008" in text and "BS-010" in text,
    }
    missing = [name for name, present in required.items() if not present]
    passed = not missing
    detail = (
        "bench_run_e2e covers measured default, fixture quarantine, invalid scenario, forced runner failure, raw samples, security metadata, sample policy, and event logs"
        if passed
        else f"missing: {', '.join(missing)}"
    )
    return _check("bench_run_e2e_real_and_failure_coverage", passed, detail)


def check_rust_json_roundtrip_test() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_json_roundtrip_test", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    found = "test_report_json_roundtrip" in text
    return _check("rust_json_roundtrip_test", found)


def check_rust_dimension_coverage_test() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_dimension_coverage_test", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    found = "test_report_dimension_coverage" in text or "test_suite_default_scenarios_coverage" in text
    return _check("rust_dimension_coverage_test", found)


def check_rust_test_count() -> dict[str, Any]:
    if not RUST_IMPL_PATH.is_file():
        return _check("rust_test_count", False, "impl file missing")
    text = RUST_IMPL_PATH.read_text()
    test_count = text.count("#[test]")
    passed = test_count >= 15
    return _check("rust_test_count", passed, f"{test_count} tests (>= 15 required)")


# ---------------------------------------------------------------------------
# Policy document checks
# ---------------------------------------------------------------------------


def check_policy_scoring_formula() -> dict[str, Any]:
    if not POLICY_PATH.is_file():
        return _check("policy_scoring_formula", False, "policy file missing")
    text = POLICY_PATH.read_text()
    found = "sf-v1" in text and "clamp" in text.lower()
    return _check("policy_scoring_formula", found, "sf-v1 and clamp found" if found else "NOT FOUND")


def check_policy_dimensions() -> dict[str, Any]:
    if not POLICY_PATH.is_file():
        return _check("policy_dimensions", False, "policy file missing")
    text = POLICY_PATH.read_text().lower()
    required = ["cold_start", "p99", "extension_overhead", "quarantine"]
    missing = [d for d in required if d not in text]
    passed = len(missing) == 0
    return _check("policy_dimensions", passed, "key metrics present" if passed else f"missing: {', '.join(missing)}")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()
    check_spec_exists()
    check_policy_exists()
    check_spec_keyword_benchmark()
    check_spec_keyword_scoring()
    check_spec_keyword_confidence()
    check_spec_keyword_deterministic()
    check_spec_keyword_sandbox()
    check_spec_keyword_provenance()
    check_spec_keyword_variance()
    check_event_codes_in_spec()
    check_dimensions_in_spec()
    check_rust_impl_exists()
    check_rust_module_registered()
    check_rust_event_codes()
    check_rust_invariant_constants()
    check_rust_scoring_formula()
    check_rust_confidence_interval()
    check_rust_regression_detection()
    check_rust_measured_evidence_boundary()
    check_rust_default_cli_uses_measured_provider()
    check_bench_run_e2e_real_and_failure_coverage()
    check_rust_json_roundtrip_test()
    check_rust_dimension_coverage_test()
    check_rust_test_count()
    check_policy_scoring_formula()
    check_policy_dimensions()
    return RESULTS


def self_test() -> bool:
    """Validate that the check script itself works correctly."""
    results = run_all_checks()
    if not results:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False

    for r in results:
        if not isinstance(r, dict):
            print(f"SELF-TEST FAIL: bad result type: {type(r)}", file=sys.stderr)
            return False
        for key in ("check", "pass", "detail"):
            if key not in r:
                print(f"SELF-TEST FAIL: missing key '{key}' in {r}", file=sys.stderr)
                return False

    print(f"SELF-TEST OK: {len(results)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_benchmark_suite")
    parser = argparse.ArgumentParser(description="Verify bd-k4s benchmark suite")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0

    if args.json:
        output = {
            "bead_id": "bd-k4s",
            "title": "Product-level benchmark suite with secure-extension scenarios",
            "section": "10.6",
            "verdict": "PASS" if overall else "FAIL",
            "overall_pass": overall,
            "total": total,
            "passed": passed,
            "failed": failed,
            "checks": results,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n  bd-k4s verification: {'PASS' if overall else 'FAIL'} ({passed}/{total})\n")
        for r in results:
            mark = "+" if r["pass"] else "x"
            print(f"  [{mark}] {r['check']}: {r['detail']}")

    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
