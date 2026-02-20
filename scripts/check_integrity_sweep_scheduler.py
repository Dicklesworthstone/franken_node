#!/usr/bin/env python3
"""Verification script for bd-1fp4: integrity sweep scheduler."""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates/franken-node/src/policy/integrity_sweep_scheduler.rs")
MOD_RS = os.path.join(ROOT, "crates/franken-node/src/policy/mod.rs")
SPEC = os.path.join(ROOT, "docs/specs/section_10_14/bd-1fp4_contract.md")
TRAJECTORY = os.path.join(ROOT, "artifacts/10.14/sweep_policy_trajectory.csv")


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "NOT FOUND")}


def _file_exists(path: str, label: str) -> dict:
    exists = os.path.isfile(path)
    return _check(f"file: {label}", exists, f"exists: {os.path.relpath(path, ROOT)}" if exists else f"missing: {os.path.relpath(path, ROOT)}")


def run_checks() -> list[dict]:
    checks = []

    # File existence
    checks.append(_file_exists(IMPL, "implementation"))
    checks.append(_file_exists(SPEC, "spec contract"))
    checks.append(_file_exists(TRAJECTORY, "trajectory artifact"))

    # Module registered
    with open(MOD_RS) as f:
        mod_src = f.read()
    checks.append(_check("module registered in mod.rs", "pub mod integrity_sweep_scheduler;" in mod_src))

    with open(IMPL) as f:
        src = f.read()

    # Types
    for ty in ["pub enum Trend", "pub struct EvidenceTrajectory", "pub enum PolicyBand",
               "pub enum SweepDepth", "pub struct SweepScheduleDecision",
               "pub struct BandThresholds", "pub struct SweepIntervals",
               "pub struct IntegritySweepScheduler"]:
        checks.append(_check(f"type: {ty}", ty in src))

    # Trend variants
    for variant in ["Improving", "Stable", "Degrading"]:
        checks.append(_check(f"trend: {variant}", variant in src))

    # PolicyBand variants
    for variant in ["Green", "Yellow", "Red"]:
        checks.append(_check(f"band: {variant}", variant in src))

    # SweepDepth variants
    for variant in ["Quick", "Standard", "Deep", "Full"]:
        checks.append(_check(f"depth: {variant}", variant in src))

    # Methods
    for method in ["fn update_trajectory(", "fn next_sweep_interval(",
                   "fn current_sweep_depth(", "fn classify_band(",
                   "fn with_hysteresis(", "fn with_thresholds(", "fn with_intervals(",
                   "fn current_band(", "fn hysteresis_counter(", "fn decisions("]:
        checks.append(_check(f"method: {method}", method in src))

    # Event codes
    for code in ["EVD-SWEEP-001", "EVD-SWEEP-002", "EVD-SWEEP-003", "EVD-SWEEP-004"]:
        checks.append(_check(f"event_code: {code}", code in src))

    # Invariants
    for inv in ["INV-SWEEP-ESCALATE-IMMEDIATE", "INV-SWEEP-DEESCALATE-HYSTERESIS",
                "INV-SWEEP-DETERMINISTIC", "INV-SWEEP-BOUNDED"]:
        checks.append(_check(f"invariant: {inv}", inv in src))

    # Tests
    test_names = [
        "trend_labels", "trend_display",
        "policy_band_labels", "policy_band_ordering", "policy_band_display",
        "sweep_depth_labels", "sweep_depth_ordering",
        "evidence_trajectory_stable", "evidence_trajectory_clamps_repairability",
        "classify_green_band", "classify_yellow_band_rejections",
        "classify_yellow_band_repairability", "classify_yellow_band_escalations",
        "classify_red_band_rejections", "classify_red_band_repairability",
        "classify_red_band_escalations", "classify_red_band_degrading_trend",
        "scheduler_defaults", "green_band_long_interval", "sweep_depth_per_band",
        "immediate_escalation_green_to_red", "immediate_escalation_green_to_yellow",
        "immediate_escalation_yellow_to_red",
        "deescalation_requires_hysteresis", "hysteresis_resets_on_escalation",
        "hysteresis_threshold_zero_allows_immediate_deescalation",
        "oscillation_prevention_1000_updates",
        "decisions_recorded", "decision_contains_band_and_depth",
        "decision_trajectory_summary_non_empty", "update_count_increments",
        "cadence_increases_with_degradation",
        "sustained_improvement_deescalates", "sustained_degradation_escalates",
        "first_update_no_history", "trajectory_all_zeroes", "decisions_bounded",
        "custom_hysteresis", "custom_intervals", "custom_thresholds",
        "event_codes_defined", "default_is_new",
    ]
    for test in test_names:
        checks.append(_check(f"test: {test}", f"fn {test}(" in src))

    # Unit test count
    test_count = len(re.findall(r"#\[test\]", src))
    checks.append(_check("unit test count", test_count >= 30,
                          f"{test_count} tests (minimum 30)"))

    # Trajectory artifact validity
    if os.path.isfile(TRAJECTORY):
        with open(TRAJECTORY) as f:
            lines = f.readlines()
        checks.append(_check("trajectory has header", len(lines) >= 1 and "band" in lines[0]))
        checks.append(_check("trajectory has data rows", len(lines) >= 5))
    else:
        checks.append(_check("trajectory has header", False, "file missing"))
        checks.append(_check("trajectory has data rows", False, "file missing"))

    return checks


def self_test():
    checks = run_checks()
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing
    print(f"self_test: {passing}/{total} checks pass, {failing} failing")
    if failing:
        for c in checks:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} — {c['detail']}")
    return failing == 0


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    checks = run_checks()
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing

    if args.json:
        result = {
            "bead_id": "bd-1fp4",
            "title": "Integrity sweep escalation/de-escalation policy",
            "section": "10.14",
            "overall_pass": failing == 0,
            "verdict": "PASS" if failing == 0 else "FAIL",
            "test_count": 42,
            "summary": {"passing": passing, "failing": failing, "total": total},
            "checks": checks,
        }
        print(json.dumps(result, indent=2))
    else:
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{passing}/{total} checks pass")

    sys.exit(0 if failing == 0 else 1)


if __name__ == "__main__":
    main()
