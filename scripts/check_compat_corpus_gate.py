#!/usr/bin/env python3
"""Verification script for bd-28sz: compatibility corpus gate (>= 95%).

Usage:
    python3 scripts/check_compat_corpus_gate.py              # human-readable
    python3 scripts/check_compat_corpus_gate.py --json        # machine-readable JSON
    python3 scripts/check_compat_corpus_gate.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-28sz_contract.md"
POLICY = ROOT / "docs" / "policy" / "compat_corpus_gate.md"

EVENT_CODES = ["CCG-001", "CCG-002", "CCG-003", "CCG-004"]

INVARIANTS = ["INV-CCG-OVERALL", "INV-CCG-FAMILY-FLOOR", "INV-CCG-RATCHET", "INV-CCG-REPRODUCIBILITY"]

GATE_TIERS = ["G0", "G1", "G2", "G3", "G4"]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    """Return a relative path string, guarding against non-ROOT paths."""
    s_path = str(path)
    s_root = str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file_exists: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _file_contains(path: Path, keyword: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: '{keyword}'", False, "file missing")
    content = path.read_text(encoding="utf-8")
    found = keyword in content
    return _check(
        f"{label}: '{keyword}'",
        found,
        "found" if found else "not found in file",
    )


# ---------------------------------------------------------------------------
# Corpus result validation helpers
# ---------------------------------------------------------------------------

def validate_corpus_result(result: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a corpus run result object. Returns (valid, errors)."""
    errors: list[str] = []
    required = [
        "run_id", "timestamp", "total_tests", "passed_tests", "failed_tests",
        "skipped_tests", "errored_tests", "aggregate_rate", "module_results",
        "duration_seconds",
    ]
    for f in required:
        if f not in result:
            errors.append(f"missing field: {f}")

    # total_tests == passed + failed + skipped + errored
    count_fields = ["total_tests", "passed_tests", "failed_tests", "skipped_tests", "errored_tests"]
    if all(f in result for f in count_fields):
        computed = result["passed_tests"] + result["failed_tests"] + result["skipped_tests"] + result["errored_tests"]
        if computed != result["total_tests"]:
            errors.append(f"total_tests mismatch: {result['total_tests']} != {computed}")

    # aggregate_rate matches (within 0.01 tolerance)
    if "aggregate_rate" in result and "passed_tests" in result and "total_tests" in result:
        if result["total_tests"] > 0:
            expected = (result["passed_tests"] / result["total_tests"]) * 100
            if abs(result["aggregate_rate"] - expected) > 0.01:
                errors.append(f"aggregate_rate mismatch: {result['aggregate_rate']} vs {expected:.2f}")

    # module_results non-empty list with required fields
    if "module_results" in result:
        if not isinstance(result["module_results"], list) or len(result["module_results"]) == 0:
            errors.append("module_results must be non-empty list")
        else:
            for i, m in enumerate(result["module_results"]):
                for mf in ["module_name", "total", "passed", "failed", "pass_rate"]:
                    if mf not in m:
                        errors.append(f"module_results[{i}] missing {mf}")
                if "pass_rate" in m and (m["pass_rate"] < 0 or m["pass_rate"] > 100):
                    errors.append(f"module_results[{i}] pass_rate out of range")

    # duration_seconds >= 0
    if "duration_seconds" in result and result["duration_seconds"] < 0:
        errors.append("duration_seconds must be >= 0")

    return (len(errors) == 0, errors)


def pass_rate_to_tier(rate: float) -> str:
    """Map a pass rate (0-100) to a gate tier string."""
    if rate < 80:
        return "G0"
    if rate < 90:
        return "G1"
    if rate < 95:
        return "G2"
    if rate < 100:
        return "G3"
    return "G4"


def check_regression(current_rate: float, previous_rate: float) -> tuple[bool, float]:
    """Check whether the current pass rate represents a regression."""
    if current_rate < previous_rate:
        return (True, previous_rate - current_rate)
    return (False, 0.0)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_spec_exists() -> dict[str, Any]:
    """C01: Spec contract file exists."""
    return _file_exists(SPEC, "spec contract")


def check_policy_exists() -> dict[str, Any]:
    """C02: Policy document exists."""
    return _file_exists(POLICY, "policy document")


def check_spec_aggregate_threshold() -> dict[str, Any]:
    """C03: Spec defines aggregate >= 95% threshold."""
    return _file_contains(SPEC, ">= 95%", "spec_threshold")


def check_spec_module_floor() -> dict[str, Any]:
    """C04: Spec defines per-module >= 80% floor."""
    return _file_contains(SPEC, ">= 80%", "spec_floor")


def check_spec_gate_tiers() -> dict[str, Any]:
    """C05: Spec defines all five gate tiers G0 through G4."""
    if not SPEC.is_file():
        return _check("spec_gate_tiers", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [t for t in GATE_TIERS if t not in content]
    passed = len(missing) == 0
    detail = "all 5 gate tiers present" if passed else f"missing: {missing}"
    return _check("spec_gate_tiers", passed, detail)


def check_spec_event_codes() -> dict[str, Any]:
    """C06: Spec defines all four event codes CCG-001 through CCG-004."""
    if not SPEC.is_file():
        return _check("spec_event_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes present" if passed else f"missing: {missing}"
    return _check("spec_event_codes", passed, detail)


def check_spec_invariants() -> dict[str, Any]:
    """C07: Spec defines all four INV-CCG invariants."""
    if not SPEC.is_file():
        return _check("spec_invariants", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants present" if passed else f"missing: {missing}"
    return _check("spec_invariants", passed, detail)


def check_spec_ratchet() -> dict[str, Any]:
    """C08: Spec documents 0% regression tolerance / ratchet."""
    return _file_contains(SPEC, "0%", "spec_ratchet")


def check_spec_max_run_time() -> dict[str, Any]:
    """C09: Spec documents <= 30 min max corpus run time."""
    return _file_contains(SPEC, "30 min", "spec_run_time")


def check_spec_corpus_schema() -> dict[str, Any]:
    """C10: Spec defines corpus result schema fields."""
    if not SPEC.is_file():
        return _check("spec_corpus_schema", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    schema_fields = ["run_id", "timestamp", "total_tests", "passed_tests",
                     "aggregate_rate", "module_results", "duration_seconds"]
    missing = [f for f in schema_fields if f not in content]
    passed = len(missing) == 0
    detail = "all schema fields documented" if passed else f"missing: {missing}"
    return _check("spec_corpus_schema", passed, detail)


def check_spec_module_schema() -> dict[str, Any]:
    """C11: Spec defines module result sub-schema fields."""
    if not SPEC.is_file():
        return _check("spec_module_schema", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    module_fields = ["module_name", "pass_rate"]
    missing = [f for f in module_fields if f not in content]
    passed = len(missing) == 0
    detail = "module sub-schema fields documented" if passed else f"missing: {missing}"
    return _check("spec_module_schema", passed, detail)


def check_spec_decision_flow() -> dict[str, Any]:
    """C12: Spec documents gate decision flow."""
    return _file_contains(SPEC, "Gate Decision Flow", "spec_section")


def check_spec_pass_rate_formula() -> dict[str, Any]:
    """C13: Spec documents pass rate formula."""
    return _file_contains(SPEC, "pass_rate", "spec_formula")


def check_policy_gate_tiers() -> dict[str, Any]:
    """C14: Policy defines all five gate tiers."""
    if not POLICY.is_file():
        return _check("policy_gate_tiers", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [t for t in GATE_TIERS if t not in content]
    passed = len(missing) == 0
    detail = "all 5 gate tiers in policy" if passed else f"missing: {missing}"
    return _check("policy_gate_tiers", passed, detail)


def check_policy_event_codes() -> dict[str, Any]:
    """C15: Policy references all four event codes."""
    if not POLICY.is_file():
        return _check("policy_event_codes", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes in policy" if passed else f"missing: {missing}"
    return _check("policy_event_codes", passed, detail)


def check_policy_invariants() -> dict[str, Any]:
    """C16: Policy references all four invariants."""
    if not POLICY.is_file():
        return _check("policy_invariants", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants in policy" if passed else f"missing: {missing}"
    return _check("policy_invariants", passed, detail)


def check_policy_governance() -> dict[str, Any]:
    """C17: Policy defines governance section."""
    return _file_contains(POLICY, "Governance", "policy_section")


def check_policy_appeal_process() -> dict[str, Any]:
    """C18: Policy defines appeal/waiver process."""
    return _file_contains(POLICY, "Appeal Process", "policy_section")


def check_policy_thresholds() -> dict[str, Any]:
    """C19: Policy documents the same thresholds as spec."""
    if not POLICY.is_file():
        return _check("policy_thresholds", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    found_95 = ">= 95%" in content
    found_80 = ">= 80%" in content
    passed = found_95 and found_80
    detail = "both thresholds present" if passed else "threshold(s) missing"
    return _check("policy_thresholds", passed, detail)


def check_policy_decision_flow() -> dict[str, Any]:
    """C20: Policy documents gate decision flow."""
    return _file_contains(POLICY, "Gate Decision Flow", "policy_section")


# ---------------------------------------------------------------------------
# All check functions
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_spec_aggregate_threshold,
    check_spec_module_floor,
    check_spec_gate_tiers,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_ratchet,
    check_spec_max_run_time,
    check_spec_corpus_schema,
    check_spec_module_schema,
    check_spec_decision_flow,
    check_spec_pass_rate_formula,
    check_policy_gate_tiers,
    check_policy_event_codes,
    check_policy_invariants,
    check_policy_governance,
    check_policy_appeal_process,
    check_policy_thresholds,
    check_policy_decision_flow,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    """Run all checks and return structured result."""
    global RESULTS
    RESULTS = []

    for fn in ALL_CHECKS:
        fn()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-28sz",
        "title": "Compatibility corpus gate (>= 95%)",
        "section": "13",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    """Run self-test: execute all checks and report pass/fail."""
    report = run_all()
    total = report["total"]
    passed = report["passed"]
    failed = report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-28sz: compatibility corpus gate (>= 95%)"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    report = run_all()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{report['passed']}/{report['total']} checks pass (verdict={report['verdict']})")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
