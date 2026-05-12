#!/usr/bin/env python3
"""Verification script for bd-35l5: adjacent substrate overhead guardrails.

Usage:
    python scripts/check_substrate_overhead.py          # human-readable
    python scripts/check_substrate_overhead.py --json    # machine-readable
"""

import csv
import json
import os
import re
import sys
from io import StringIO
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

IMPL = ROOT / "tests" / "perf" / "adjacent_substrate_overhead_gate.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_16" / "bd-35l5_contract.md"
OVERHEAD_CSV = ROOT / "artifacts" / "10.16" / "adjacent_substrate_overhead_report.csv"

SUBSTRATES = ["frankentui", "frankensqlite", "sqlmodel_rust", "fastapi_rust"]

OPERATIONS = [
    ("frankentui", "render_status_panel"),
    ("frankentui", "render_tree_view"),
    ("frankensqlite", "fencing_token_write"),
    ("frankensqlite", "config_read"),
    ("sqlmodel_rust", "typed_model_serialize"),
    ("sqlmodel_rust", "typed_model_deserialize"),
    ("fastapi_rust", "middleware_pipeline"),
    ("fastapi_rust", "health_check_endpoint"),
]

EVENT_CODES = [
    "PERF_BENCHMARK_START",
    "PERF_BENCHMARK_COMPLETE",
    "PERF_BUDGET_PASS",
    "PERF_BUDGET_FAIL",
    "PERF_REGRESSION_DETECTED",
]

INVARIANTS = [
    "INV-ASO-BUDGET",
    "INV-ASO-GATE",
    "INV-ASO-EVIDENCE",
    "INV-ASO-REGRESSION",
]

REQUIRED_TYPES = [
    "pub enum Substrate",
    "pub struct Operation",
    "pub struct MeasurementRecord",
    "pub enum GateDecision",
    "pub struct PerfEvent",
    "pub struct OverheadGateSummary",
    "pub struct SubstrateOverheadGate",
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
    "fn records(",
    "fn operations(",
    "fn from_benchmark(",
    "fn is_hard_regression(",
    "fn with_defaults(",
    "fn label(",
    "fn all(",
    "fn is_pass(",
    "fn is_fail(",
    "fn default_operations(",
]

REQUIRED_TESTS = [
    "test_substrate_all",
    "test_substrate_labels",
    "test_substrate_display",
    "test_substrate_serde_roundtrip",
    "test_default_operations_count",
    "test_default_operations_all_substrates",
    "test_default_operations_budgets_positive",
    "test_measurement_within_budget",
    "test_measurement_over_budget",
    "test_measurement_regression_detected",
    "test_measurement_hard_regression",
    "test_measurement_zero_baseline",
    "test_measurement_csv_row",
    "test_measurement_serde_roundtrip",
    "test_gate_decision_pass",
    "test_gate_decision_fail",
    "test_gate_decision_display",
    "test_gate_decision_serde_roundtrip",
    "test_summary_gate_pass",
    "test_summary_gate_fail_over_budget",
    "test_summary_gate_fail_hard_regression",
    "test_summary_gate_fail_empty",
    "test_summary_display",
    "test_gate_evaluate_within_budget",
    "test_gate_evaluate_over_budget",
    "test_gate_pass_all_within",
    "test_gate_fail_one_over",
    "test_gate_evaluate_batch",
    "test_gate_evaluate_batch_mixed",
    "test_evaluate_emits_benchmark_start",
    "test_evaluate_emits_benchmark_complete",
    "test_evaluate_within_emits_budget_pass",
    "test_evaluate_over_emits_budget_fail",
    "test_evaluate_regression_emits_event",
    "test_event_has_run_id",
    "test_take_events_drains",
    "test_csv_header",
    "test_csv_with_results",
    "test_report_structure",
    "test_report_records",
    "test_default_gate",
    "test_summary_all_within",
    "test_summary_mixed",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_perf_event_serde",
    "test_determinism_identical_measurements",
    "test_fail_has_violation_details",
    "test_hard_regression_fails_gate",
    "test_soft_regression_passes_gate",
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


def check_impl_test_count():
    if not IMPL.exists():
        return {"check": "impl unit test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 35
    return {
        "check": "impl unit test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 35)",
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

    # Valid header
    lines = text.strip().split("\n")
    has_header = lines[0].startswith("substrate,operation,budget_ms")
    results.append({
        "check": "overhead CSV: valid header",
        "pass": has_header,
        "detail": "header present" if has_header else "bad header",
    })

    # Parse CSV
    reader = csv.DictReader(StringIO(text))
    rows = list(reader)

    # All operations covered
    has_all = len(rows) >= 8
    results.append({
        "check": "overhead CSV: all operations covered",
        "pass": has_all,
        "detail": f"{len(rows)} data rows (need 8)",
    })

    # Each operation present
    csv_ops = {(r["substrate"], r["operation"]) for r in rows}
    for substrate, operation in OPERATIONS:
        found = (substrate, operation) in csv_ops
        results.append({
            "check": f"overhead CSV: {substrate}/{operation}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # All pass at p95
    all_pass = all(r.get("status") == "pass" for r in rows)
    results.append({
        "check": "overhead CSV: all pass at p95",
        "pass": all_pass,
        "detail": "all pass" if all_pass else "some fail",
    })

    # No regressions
    no_regressions = all(r.get("regression_detected") == "false" for r in rows)
    results.append({
        "check": "overhead CSV: no regressions",
        "pass": no_regressions,
        "detail": "no regressions" if no_regressions else "regressions detected",
    })

    # Baseline data present
    has_baselines = all(float(r.get("baseline_p50_ms", "0")) > 0 for r in rows)
    results.append({
        "check": "overhead CSV: baseline data present",
        "pass": has_baselines,
        "detail": "all baselines present" if has_baselines else "missing baselines",
    })

    return results


def check_spec_content():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec: exists", "pass": False, "detail": "spec missing"})
        return results
    text = SPEC.read_text()

    for substrate in SUBSTRATES:
        found = substrate in text
        results.append({
            "check": f"spec: substrate {substrate}",
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
    checks.append(check_file(IMPL, "perf test"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(OVERHEAD_CSV, "overhead CSV report"))

    # Test count
    checks.append(check_impl_test_count())

    # Serde derives
    checks.append(check_serde_derives())

    # Implementation content
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, [s.capitalize().replace("_", "") if "_" not in s else s for s in SUBSTRATES], "substrate_variant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "impl_test"))

    # Overhead CSV
    checks.extend(check_overhead_csv())

    # Spec content
    checks.extend(check_spec_content())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-35l5",
        "title": "Performance overhead guardrails for adjacent substrate integrations",
        "section": "10.16",
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
    logger = configure_test_logging("check_substrate_overhead")
    logger.info("starting substrate overhead verification")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-35l5 verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
