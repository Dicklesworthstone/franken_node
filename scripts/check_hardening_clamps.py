#!/usr/bin/env python3
"""bd-1ayu: Verify the hardening clamp policy implementation.

Checks:
  1. hardening_clamps.rs exists and contains HardeningClampPolicy.
  2. EscalationBudget struct with required fields.
  3. ClampResult enum with Allowed/Clamped/Denied variants.
  4. check_escalation function exists.
  5. ClampEvent struct with CSV support.
  6. EVD-CLAMP event codes (001-004) present.
  7. Determinism test (1000 runs).
  8. Rate limit, overhead limit, and min/max bound logic.
  9. Unit test count >= 25.
  10. Spec document exists.
  11. Metrics CSV artifact exists and is valid.

Usage:
  python3 scripts/check_hardening_clamps.py          # human-readable
  python3 scripts/check_hardening_clamps.py --json    # machine-readable
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "policy" / "hardening_clamps.rs"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_14" / "bd-1ayu_contract.md"
METRICS_PATH = ROOT / "artifacts" / "10.14" / "hardening_clamp_metrics.csv"


def _read_impl() -> str:
    return IMPL_PATH.read_text()


def check_impl_exists() -> tuple[bool, str]:
    if not IMPL_PATH.exists():
        return False, f"missing: {IMPL_PATH}"
    content = _read_impl()
    if "pub struct HardeningClampPolicy" not in content:
        return False, "HardeningClampPolicy struct not found"
    return True, "HardeningClampPolicy struct found"


def check_escalation_budget() -> tuple[bool, str]:
    content = _read_impl()
    if "pub struct EscalationBudget" not in content:
        return False, "EscalationBudget struct not found"
    required_fields = [
        "max_escalations_per_window",
        "window_duration_ms",
        "max_overhead_pct",
        "min_level",
        "max_level",
    ]
    missing = [f for f in required_fields if f not in content]
    if missing:
        return False, f"EscalationBudget missing fields: {missing}"
    return True, "EscalationBudget with all required fields"


def check_clamp_result() -> tuple[bool, str]:
    content = _read_impl()
    if "pub enum ClampResult" not in content:
        return False, "ClampResult enum not found"
    variants = ["Allowed", "Clamped", "Denied"]
    missing = [v for v in variants if v not in content]
    if missing:
        return False, f"ClampResult missing variants: {missing}"
    return True, "ClampResult with Allowed/Clamped/Denied"


def check_check_escalation_fn() -> tuple[bool, str]:
    content = _read_impl()
    if "fn check_escalation(" not in content:
        return False, "check_escalation function not found"
    return True, "check_escalation function present"


def check_clamp_event() -> tuple[bool, str]:
    content = _read_impl()
    if "pub struct ClampEvent" not in content:
        return False, "ClampEvent struct not found"
    required = ["timestamp", "proposed_level", "effective_level", "reason", "budget_utilization_pct"]
    missing = [f for f in required if f not in content]
    if missing:
        return False, f"ClampEvent missing fields: {missing}"
    if "fn csv_header" not in content or "fn to_csv_row" not in content:
        return False, "ClampEvent missing CSV methods"
    return True, "ClampEvent with required fields and CSV support"


def check_event_codes() -> tuple[bool, str]:
    content = _read_impl()
    codes = ["EVD-CLAMP-001", "EVD-CLAMP-002", "EVD-CLAMP-003", "EVD-CLAMP-004"]
    missing = [c for c in codes if c not in content]
    if missing:
        return False, f"missing event codes: {missing}"
    return True, "all EVD-CLAMP event codes present"


def check_rate_limit_logic() -> tuple[bool, str]:
    content = _read_impl()
    if "count_in_window" not in content:
        return False, "rate limit window counting not found"
    if "rate_count" not in content:
        return False, "rate count tracking not found"
    if "max_escalations_per_window" not in content:
        return False, "rate limit threshold not found"
    return True, "rate limit logic with window counting"


def check_overhead_limit_logic() -> tuple[bool, str]:
    content = _read_impl()
    if "estimated_overhead_pct" not in content:
        return False, "overhead estimation function not found"
    if "max_overhead_pct" not in content:
        return False, "overhead threshold not found"
    if "highest_level_within_overhead" not in content:
        return False, "overhead clamp fallback not found"
    return True, "overhead limit logic with estimation and fallback"


def check_determinism_test() -> tuple[bool, str]:
    content = _read_impl()
    if "deterministic_across_1000_runs" not in content:
        return False, "determinism test not found"
    return True, "determinism test (1000 runs) present"


def check_min_max_bounds() -> tuple[bool, str]:
    content = _read_impl()
    if "min_level" not in content or "max_level" not in content:
        return False, "min/max level bounds not found"
    if "budget.max_level" not in content or "budget.min_level" not in content:
        return False, "bound enforcement in check_escalation not found"
    return True, "min/max level bound enforcement present"


def count_tests() -> tuple[bool, str, int]:
    content = _read_impl()
    test_fns = re.findall(r"#\[test\]", content)
    count = len(test_fns)
    if count < 25:
        return False, f"only {count} tests (need >= 25)", count
    return True, f"{count} unit tests", count


def check_spec_exists() -> tuple[bool, str]:
    if not SPEC_PATH.exists():
        return False, f"missing: {SPEC_PATH}"
    content = SPEC_PATH.read_text()
    required = ["EscalationBudget", "ClampResult", "EVD-CLAMP"]
    missing = [r for r in required if r not in content]
    if missing:
        return False, f"spec missing content: {missing}"
    return True, "spec document with required content"


def check_metrics_csv() -> tuple[bool, str]:
    if not METRICS_PATH.exists():
        return False, f"missing: {METRICS_PATH}"
    try:
        text = METRICS_PATH.read_text().strip()
        lines = text.split("\n")
        if len(lines) < 2:
            return False, "metrics CSV has fewer than 2 lines"
        reader = csv.reader(lines)
        header = next(reader)
        required_cols = ["timestamp", "proposed_level", "effective_level", "clamp_reason",
                         "budget_utilization_pct", "rate_count"]
        missing = [c for c in required_cols if c not in header]
        if missing:
            return False, f"metrics CSV missing columns: {missing}"
        rows = list(reader)
        if len(rows) < 3:
            return False, f"metrics CSV has only {len(rows)} data rows (need >= 3)"
        return True, f"metrics CSV valid with {len(rows)} rows"
    except Exception as e:
        return False, f"metrics CSV parse error: {e}"


def self_test() -> tuple[bool, list]:
    checks = [
        ("impl_exists", check_impl_exists),
        ("escalation_budget", check_escalation_budget),
        ("clamp_result", check_clamp_result),
        ("check_escalation_fn", check_check_escalation_fn),
        ("clamp_event", check_clamp_event),
        ("event_codes", check_event_codes),
        ("rate_limit_logic", check_rate_limit_logic),
        ("overhead_limit_logic", check_overhead_limit_logic),
        ("determinism_test", check_determinism_test),
        ("min_max_bounds", check_min_max_bounds),
        ("test_count", lambda: count_tests()[:2]),
        ("spec_exists", check_spec_exists),
        ("metrics_csv", check_metrics_csv),
    ]
    results = []
    all_pass = True
    for name, fn in checks:
        ok, msg = fn()
        results.append({"check": name, "pass": ok, "detail": msg})
        if not ok:
            all_pass = False
    return all_pass, results


def main():
    parser = argparse.ArgumentParser(description="Verify hardening clamp policy (bd-1ayu)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    all_pass, results = self_test()
    test_count = count_tests()[2]

    if args.json:
        evidence = {
            "bead_id": "bd-1ayu",
            "title": "Overhead/rate clamp policy for hardening escalations",
            "overall_pass": all_pass,
            "checks": results,
            "test_count": test_count,
            "artifacts": {
                "implementation": str(IMPL_PATH.relative_to(ROOT)),
                "spec": str(SPEC_PATH.relative_to(ROOT)),
                "metrics": str(METRICS_PATH.relative_to(ROOT)),
            },
        }
        print(json.dumps(evidence, indent=2))
    else:
        for r in results:
            status = "PASS" if r["pass"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
        print()
        print("All checks PASSED." if all_pass else "Some checks FAILED.")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
