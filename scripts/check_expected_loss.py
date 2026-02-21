#!/usr/bin/env python3
"""Verification script for bd-2fpj: expected-loss model contract field.

Usage:
    python3 scripts/check_expected_loss.py              # human-readable
    python3 scripts/check_expected_loss.py --json        # machine-readable JSON
    python3 scripts/check_expected_loss.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_11" / "bd-2fpj_contract.md"
EVIDENCE = ROOT / "artifacts" / "section_11" / "bd-2fpj" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_11" / "bd-2fpj" / "verification_summary.md"

EVENT_CODES = [
    "CONTRACT_ELM_VALIDATED",
    "CONTRACT_ELM_MISSING",
    "CONTRACT_ELM_INVALID",
    "CONTRACT_ELM_THRESHOLD_EXCEEDED",
]

INVARIANTS = [
    "INV-ELM-SCENARIOS",
    "INV-ELM-AGGREGATE",
    "INV-ELM-CATEGORY",
    "INV-ELM-CONFIDENCE",
]

LOSS_CATEGORIES = ["negligible", "minor", "moderate", "major", "catastrophic"]

VALID_IMPACT_UNITS = ["dollars", "hours", "severity_units"]

# Thresholds: category -> (lower_bound_inclusive, upper_bound_exclusive)
# catastrophic has no upper bound (use float('inf'))
CATEGORY_THRESHOLDS = {
    "negligible": (0, 100),
    "minor": (100, 1_000),
    "moderate": (1_000, 10_000),
    "major": (10_000, 100_000),
    "catastrophic": (100_000, float("inf")),
}

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "name": name,
        "passed": bool(passed),
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
# Expected-loss model validation helper
# ---------------------------------------------------------------------------

def classify_loss(aggregate: float) -> str:
    """Map an aggregate expected loss value to its loss category."""
    if aggregate >= 100_000:
        return "catastrophic"
    elif aggregate >= 10_000:
        return "major"
    elif aggregate >= 1_000:
        return "moderate"
    elif aggregate >= 100:
        return "minor"
    else:
        return "negligible"


def compute_aggregate(scenarios: list[dict[str, Any]]) -> float:
    """Compute aggregate expected loss from a list of scenarios."""
    return sum(s.get("probability", 0) * s.get("impact_value", 0) for s in scenarios)


def validate_elm_object(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate an expected-loss model object. Returns list of check results."""
    results: list[dict[str, Any]] = []

    # --- Scenarios ---
    scenarios = obj.get("scenarios", [])
    ok_count = isinstance(scenarios, list) and len(scenarios) >= 3
    results.append({
        "name": "scenarios_min_count",
        "passed": ok_count,
        "detail": f"{len(scenarios) if isinstance(scenarios, list) else 0} scenarios (need >= 3)",
    })

    all_scenarios_valid = True
    for i, s in enumerate(scenarios if isinstance(scenarios, list) else []):
        # name
        name_ok = isinstance(s.get("name"), str) and len(s.get("name", "")) > 0
        if not name_ok:
            all_scenarios_valid = False

        # probability
        prob = s.get("probability")
        prob_ok = isinstance(prob, (int, float)) and 0.0 <= prob <= 1.0
        if not prob_ok:
            all_scenarios_valid = False

        # impact_value
        iv = s.get("impact_value")
        iv_ok = isinstance(iv, (int, float)) and iv >= 0
        if not iv_ok:
            all_scenarios_valid = False

        # impact_unit
        iu = s.get("impact_unit")
        iu_ok = iu in VALID_IMPACT_UNITS
        if not iu_ok:
            all_scenarios_valid = False

        # mitigation
        mit = s.get("mitigation")
        mit_ok = isinstance(mit, str) and len(mit) > 0
        if not mit_ok:
            all_scenarios_valid = False

    results.append({
        "name": "scenarios_schema_valid",
        "passed": all_scenarios_valid and ok_count,
        "detail": "all scenarios have valid fields" if (all_scenarios_valid and ok_count) else "one or more scenarios have invalid fields",
    })

    # --- Aggregate ---
    agg = obj.get("aggregate_expected_loss")
    agg_is_num = isinstance(agg, (int, float)) and agg >= 0
    results.append({
        "name": "aggregate_non_negative",
        "passed": agg_is_num,
        "detail": f"aggregate={agg}",
    })

    if isinstance(scenarios, list) and len(scenarios) > 0 and agg_is_num:
        expected_agg = compute_aggregate(scenarios)
        agg_match = abs(agg - expected_agg) < 1e-6
        results.append({
            "name": "aggregate_formula_correct",
            "passed": agg_match,
            "detail": f"aggregate={agg} expected={expected_agg}",
        })
    else:
        results.append({
            "name": "aggregate_formula_correct",
            "passed": False,
            "detail": "cannot verify aggregate formula",
        })

    # --- Loss category ---
    cat = obj.get("loss_category")
    cat_valid = cat in LOSS_CATEGORIES
    results.append({
        "name": "loss_category_valid",
        "passed": cat_valid,
        "detail": f"loss_category={cat}",
    })

    if agg_is_num and cat_valid:
        expected_cat = classify_loss(agg)
        cat_match = cat == expected_cat
        results.append({
            "name": "category_matches_thresholds",
            "passed": cat_match,
            "detail": f"category={cat} expected={expected_cat} for aggregate={agg}",
        })
    else:
        results.append({
            "name": "category_matches_thresholds",
            "passed": False,
            "detail": "cannot verify category match",
        })

    # --- Confidence interval ---
    ci = obj.get("confidence_interval", {})
    if not isinstance(ci, dict):
        ci = {}
    lower = ci.get("lower")
    upper = ci.get("upper")
    cl = ci.get("confidence_level")

    lower_ok = isinstance(lower, (int, float)) and lower >= 0
    upper_ok = isinstance(upper, (int, float)) and upper >= 0
    cl_ok = isinstance(cl, (int, float)) and 0.0 < cl < 1.0

    bounds_ok = lower_ok and upper_ok and (lower <= upper)
    results.append({
        "name": "confidence_bounds_valid",
        "passed": bounds_ok,
        "detail": f"lower={lower} upper={upper}" if bounds_ok else f"invalid bounds: lower={lower} upper={upper}",
    })

    results.append({
        "name": "confidence_level_valid",
        "passed": cl_ok,
        "detail": f"confidence_level={cl}" if cl_ok else f"invalid confidence_level={cl}",
    })

    if bounds_ok and agg_is_num:
        agg_in_range = lower <= agg <= upper
        results.append({
            "name": "aggregate_within_confidence",
            "passed": agg_in_range,
            "detail": f"lower={lower} <= aggregate={agg} <= upper={upper}" if agg_in_range else f"aggregate={agg} outside [{lower}, {upper}]",
        })
    else:
        results.append({
            "name": "aggregate_within_confidence",
            "passed": False,
            "detail": "cannot verify aggregate within confidence interval",
        })

    return results


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_spec_exists() -> dict[str, Any]:
    """C01: Spec contract file exists."""
    return _file_exists(SPEC, "spec contract")


def check_contract_field() -> dict[str, Any]:
    """C02: Spec defines the contract field path."""
    return _file_contains(SPEC, "change_summary.expected_loss_model", "contract_field")


def check_scenarios_schema() -> dict[str, Any]:
    """C03: Spec defines scenarios sub-field with required properties."""
    if not SPEC.is_file():
        return _check("scenarios_schema", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    keywords = ["scenarios", "probability", "impact_value", "impact_unit", "mitigation", "name"]
    missing = [k for k in keywords if k not in content]
    passed = len(missing) == 0
    detail = "all scenario fields documented" if passed else f"missing: {missing}"
    return _check("scenarios_schema", passed, detail)


def check_loss_categories() -> dict[str, Any]:
    """C04: Spec defines all five loss categories."""
    if not SPEC.is_file():
        return _check("loss_categories", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in LOSS_CATEGORIES if c not in content]
    passed = len(missing) == 0
    detail = "all 5 loss categories present" if passed else f"missing: {missing}"
    return _check("loss_categories", passed, detail)


def check_category_thresholds() -> dict[str, Any]:
    """C05: Spec defines category threshold boundaries."""
    if not SPEC.is_file():
        return _check("category_thresholds", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    # Check for key threshold values
    markers = ["100", "1000", "10000", "100000"]
    found = [m for m in markers if m in content]
    passed = len(found) == len(markers)
    detail = f"{len(found)}/{len(markers)} threshold values present" if not passed else "all threshold values present"
    return _check("category_thresholds", passed, detail)


def check_aggregate_formula() -> dict[str, Any]:
    """C06: Spec documents the aggregate expected loss formula."""
    if not SPEC.is_file():
        return _check("aggregate_formula", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    has_formula = "aggregate_expected_loss" in content and "probability" in content and "impact_value" in content
    return _check(
        "aggregate_formula",
        has_formula,
        "formula documented" if has_formula else "formula not found",
    )


def check_confidence_interval() -> dict[str, Any]:
    """C07: Spec documents confidence interval requirements."""
    if not SPEC.is_file():
        return _check("confidence_interval", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    keywords = ["confidence_interval", "lower", "upper", "confidence_level"]
    missing = [k for k in keywords if k not in content]
    passed = len(missing) == 0
    detail = "confidence interval fully documented" if passed else f"missing: {missing}"
    return _check("confidence_interval", passed, detail)


def check_event_codes() -> dict[str, Any]:
    """C08: Spec defines all four event codes."""
    if not SPEC.is_file():
        return _check("event_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes present" if passed else f"missing: {missing}"
    return _check("event_codes", passed, detail)


def check_invariants() -> dict[str, Any]:
    """C09: Spec defines all four INV-ELM invariants."""
    if not SPEC.is_file():
        return _check("invariants", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants present" if passed else f"missing: {missing}"
    return _check("invariants", passed, detail)


def check_acceptance_criteria() -> dict[str, Any]:
    """C10: Spec defines acceptance criteria (at least 8 items)."""
    if not SPEC.is_file():
        return _check("acceptance_criteria", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    has_section = "Acceptance Criteria" in content
    # Count numbered criteria lines (e.g., "1. ", "2. ")
    import re
    criteria_lines = re.findall(r"^\d+\.\s+", content, re.MULTILINE)
    count = len(criteria_lines)
    passed = has_section and count >= 8
    detail = f"section present with {count} criteria" if passed else f"{'section missing' if not has_section else f'only {count} criteria (need >= 8)'}"
    return _check("acceptance_criteria", passed, detail)


def check_enforcement() -> dict[str, Any]:
    """C11: Spec references enforcement validator."""
    if not SPEC.is_file():
        return _check("enforcement", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    has_validator = "check_expected_loss.py" in content
    has_tests = "test_check_expected_loss.py" in content
    passed = has_validator and has_tests
    detail = "validator and tests referenced" if passed else "enforcement references incomplete"
    return _check("enforcement", passed, detail)


def check_verification_evidence() -> dict[str, Any]:
    """C12: Verification evidence JSON exists and is valid."""
    if not EVIDENCE.is_file():
        return _check("verification_evidence", False, f"missing: {_safe_rel(EVIDENCE)}")
    try:
        data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        ok = (
            data.get("bead_id") == "bd-2fpj"
            and data.get("section") == "11"
            and data.get("status") == "pass"
        )
        detail = "valid evidence file" if ok else "evidence file has wrong content"
        return _check("verification_evidence", ok, detail)
    except (json.JSONDecodeError, KeyError) as exc:
        return _check("verification_evidence", False, f"parse error: {exc}")


def check_verification_summary() -> dict[str, Any]:
    """C13: Verification summary markdown exists."""
    return _file_exists(SUMMARY, "verification summary")


ALL_CHECKS = [
    check_spec_exists,
    check_contract_field,
    check_scenarios_schema,
    check_loss_categories,
    check_category_thresholds,
    check_aggregate_formula,
    check_confidence_interval,
    check_event_codes,
    check_invariants,
    check_acceptance_criteria,
    check_enforcement,
    check_verification_evidence,
    check_verification_summary,
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
    passed = sum(1 for r in RESULTS if r["passed"])

    return {
        "bead_id": "bd-2fpj",
        "section": "11",
        "title": "Contract field: expected-loss model",
        "status": "pass" if passed == total else "fail",
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
        "checks": list(RESULTS),
    }


def self_test() -> tuple[bool, str]:
    """Run self-test: execute all checks and report pass/fail."""
    report = run_all()
    total = report["total"]
    passed = report["passed"]
    failed = total - passed
    msg = f"self_test: {passed}/{total} checks pass, {failed} failing"
    if failed:
        for c in report["checks"]:
            if not c["passed"]:
                msg += f"\n  FAIL: {c['name']} -- {c['detail']}"
    return failed == 0, msg


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-2fpj: expected-loss model contract field"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok, msg = self_test()
        print(msg)
        sys.exit(0 if ok else 1)

    report = run_all()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"[{status}] {c['name']}: {c['detail']}")
        print(f"\n{report['passed']}/{report['total']} checks pass (status={report['status']})")

    sys.exit(0 if report["all_passed"] else 1)


if __name__ == "__main__":
    main()
