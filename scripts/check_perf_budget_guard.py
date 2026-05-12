#!/usr/bin/env python3
"""Verification script for bd-1xwz: performance budget guard.

Usage:
    python scripts/check_perf_budget_guard.py          # human-readable
    python scripts/check_perf_budget_guard.py --json    # machine-readable
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "perf_budget_guard.rs"
CONFORMANCE_TEST = ROOT / "tests" / "conformance" / "perf_budget_guard.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_15" / "bd-1xwz_contract.md"
OVERHEAD_CSV = ROOT / "artifacts" / "10.15" / "integration_overhead_report.csv"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"

REQUIRED_TYPES = [
    "pub enum HotPath",
    "pub struct HotPathBudget",
    "pub struct BudgetPolicy",
    "pub struct MeasurementResult",
    "pub enum GateDecision",
    "pub struct OverheadEvent",
    "pub struct OverheadGateSummary",
    "pub struct OverheadGate",
]

REQUIRED_METHODS = [
    "fn evaluate(",
    "fn evaluate_batch(",
    "fn gate_pass(",
    "fn summary(",
    "fn to_csv(",
    "fn to_report(",
    "fn to_csv_row(",
    "fn events(",
    "fn take_events(",
    "fn results(",
    "fn policy(",
    "fn from_measurements(",
    "fn budget_for(",
    "fn default_policy(",
    "fn to_json(",
    "fn label(",
    "fn all(",
    "fn is_pass(",
    "fn is_fail(",
    "fn with_default_policy(",
]

EVENT_CODES = [
    "PRF-001",
    "PRF-002",
    "PRF-003",
    "PRF-004",
    "PRF-005",
]

INVARIANTS = [
    "INV-PBG-BUDGET",
    "INV-PBG-GATE",
    "INV-PBG-FLAMEGRAPH",
    "INV-PBG-COLD-START",
]

HOT_PATHS = [
    "LifecycleTransition",
    "HealthGateEvaluation",
    "RolloutStateChange",
    "FencingTokenOp",
]

REQUIRED_IMPL_TESTS = [
    "test_hot_path_all",
    "test_hot_path_labels",
    "test_hot_path_display",
    "test_hot_path_serde_roundtrip",
    "test_default_policy_has_all_paths",
    "test_budget_for_health_gate",
    "test_budget_for_missing",
    "test_policy_to_json",
    "test_policy_serde_roundtrip",
    "test_measurement_within_budget",
    "test_measurement_over_budget",
    "test_measurement_overhead_calculation",
    "test_measurement_zero_baseline",
    "test_measurement_csv_row",
    "test_measurement_serde_roundtrip",
    "test_measurement_cold_start_over_budget",
    "test_gate_decision_pass",
    "test_gate_decision_fail",
    "test_gate_decision_display",
    "test_gate_decision_serde_roundtrip",
    "test_summary_gate_pass",
    "test_summary_gate_fail",
    "test_summary_gate_fail_empty",
    "test_summary_display",
    "test_gate_evaluate_within_budget",
    "test_gate_evaluate_over_budget",
    "test_gate_pass_all_within",
    "test_gate_fail_one_over",
    "test_gate_evaluate_batch",
    "test_gate_evaluate_batch_mixed",
    "test_evaluate_emits_prf001",
    "test_evaluate_within_emits_prf002",
    "test_evaluate_over_emits_prf003",
    "test_evaluate_emits_prf004_with_flamegraph",
    "test_evaluate_no_prf004_without_flamegraph",
    "test_evaluate_emits_prf005",
    "test_take_events_drains",
    "test_csv_header",
    "test_csv_with_results",
    "test_report_structure",
    "test_report_results",
    "test_default_gate",
    "test_adversarial_zero_budgets",
    "test_adversarial_infinity_budgets",
    "test_adversarial_no_flamegraph",
    "test_summary_all_within",
    "test_summary_mixed",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_overhead_event_serde",
    "test_determinism_identical_policy",
    "test_fail_has_violation_details",
]

REQUIRED_CONFORMANCE_TESTS = [
    "test_lifecycle_transition_within_budget",
    "test_health_gate_evaluation_within_budget",
    "test_rollout_state_change_within_budget",
    "test_fencing_token_op_within_budget",
    "test_over_budget_fails_gate",
    "test_over_budget_has_violations",
    "test_cold_start_over_budget_fails",
    "test_batch_all_hot_paths_within",
    "test_batch_mixed_results",
    "test_event_codes_emitted",
    "test_over_budget_emits_prf003",
    "test_flamegraph_emits_prf004",
    "test_invariant_budget_machine_readable",
    "test_invariant_gate_blocks_violations",
    "test_invariant_flamegraph_tracked",
    "test_invariant_cold_start_separate",
    "test_summary_after_batch",
    "test_csv_report_format",
    "test_json_report_structure",
    "test_deterministic_overhead_calculation",
]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.exists():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.exists():
        return {"check": "module registered in mod.rs", "pass": False, "detail": "mod.rs missing"}
    text = MOD_RS.read_text()
    found = "pub mod perf_budget_guard;" in text
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_impl_test_count():
    if not IMPL.exists():
        return {"check": "impl unit test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 40
    return {
        "check": "impl unit test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 40)",
    }


def check_conformance_test_count():
    if not CONFORMANCE_TEST.exists():
        return {"check": "conformance test count", "pass": False, "detail": "test file missing"}
    text = CONFORMANCE_TEST.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 15
    return {
        "check": "conformance test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 15)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_overhead_csv():
    results = []
    if not OVERHEAD_CSV.exists():
        results.append({"check": "overhead CSV: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "overhead CSV: exists", "pass": True, "detail": "found"})
    text = OVERHEAD_CSV.read_text()
    lines = text.strip().split("\n")
    has_header = lines[0].startswith("hot_path,")
    results.append({
        "check": "overhead CSV: valid header",
        "pass": has_header,
        "detail": "header present" if has_header else "bad header",
    })
    data_rows = len(lines) - 1
    has_all = data_rows >= 4
    results.append({
        "check": "overhead CSV: all hot paths",
        "pass": has_all,
        "detail": f"{data_rows} data rows (need 4)",
    })
    for hp in HOT_PATHS:
        label = hp[0].lower() + hp[1:]
        # Convert CamelCase to snake_case
        snake = re.sub(r'(?<!^)(?=[A-Z])', '_', hp).lower()
        found = snake in text
        results.append({
            "check": f"overhead CSV: {snake} row",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    all_within = all("true" in line for line in lines[1:] if line.strip())
    results.append({
        "check": "overhead CSV: all within budget",
        "pass": all_within,
        "detail": "all within budget" if all_within else "some over budget",
    })
    return results


def check_spec_content():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec: exists", "pass": False, "detail": "spec missing"})
        return results
    text = SPEC.read_text()
    for hp in HOT_PATHS:
        found = hp in text
        results.append({
            "check": f"spec: {hp} documented",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    for ec in EVENT_CODES:
        found = ec in text
        results.append({
            "check": f"spec: event code {ec}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    for inv in INVARIANTS:
        found = inv in text
        results.append({
            "check": f"spec: invariant {inv}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(CONFORMANCE_TEST, "conformance test"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(OVERHEAD_CSV, "overhead CSV report"))

    # Module registration
    checks.append(check_module_registered())

    # Test counts
    checks.append(check_impl_test_count())
    checks.append(check_conformance_test_count())

    # Serde derives
    checks.append(check_serde_derives())

    # Implementation content: types, methods, events, invariants, tests
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, HOT_PATHS, "hot_path"))
    checks.extend(check_content(IMPL, REQUIRED_IMPL_TESTS, "impl_test"))

    # Conformance test content
    checks.extend(check_content(CONFORMANCE_TEST, REQUIRED_CONFORMANCE_TESTS, "conformance_test"))

    # Overhead CSV
    checks.extend(check_overhead_csv())

    # Spec content
    checks.extend(check_spec_content())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-1xwz",
        "title": "Performance budget guard for asupersync integration overhead",
        "section": "10.15",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": check_impl_test_count()["detail"].split()[0] if IMPL.exists() else 0,
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    logger = configure_test_logging("check_perf_budget_guard")
    logger.info("starting %s verification", "check_perf_budget_guard")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-1xwz verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
