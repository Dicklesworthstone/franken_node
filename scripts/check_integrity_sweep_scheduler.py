#!/usr/bin/env python3
"""Verification script for bd-1fp4: integrity sweep scheduler."""

import json
import os
import re
import sys
from pathlib import Path

ROOT_PATH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_PATH))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

ROOT = str(ROOT_PATH)
IMPL = os.path.join(ROOT, "crates/franken-node/src/policy/integrity_sweep_scheduler.rs")
MOD_RS = os.path.join(ROOT, "crates/franken-node/src/policy/mod.rs")
SPEC = os.path.join(ROOT, "docs/specs/section_10_14/bd-1fp4_contract.md")
TRAJECTORY = os.path.join(ROOT, "artifacts/10.14/sweep_policy_trajectory.csv")


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "NOT FOUND")}


def _file_exists(path: str, label: str) -> dict:
    exists = os.path.isfile(path)
    return _check(f"file: {label}", exists, f"exists: {os.path.relpath(path, ROOT)}" if exists else f"missing: {os.path.relpath(path, ROOT)}")


def _read_text(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _read_rust_source(path: str) -> str:
    return _strip_rust_comments(_read_text(path))


def _strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = _rust_block_comment_end(text, i + 2)
            continue

        raw_end = _rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = _rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def _rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def _rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


def run_checks() -> list[dict]:
    checks = []

    # File existence
    checks.append(_file_exists(IMPL, "implementation"))
    checks.append(_file_exists(SPEC, "spec contract"))
    checks.append(_file_exists(TRAJECTORY, "trajectory artifact"))

    # Module registered
    mod_src = _read_rust_source(MOD_RS)
    checks.append(_check("module registered in mod.rs", "pub mod integrity_sweep_scheduler;" in mod_src))

    src = _read_rust_source(IMPL)

    # Types
    for ty in ["pub enum Trend", "pub struct EvidenceTrajectory", "pub enum PolicyBand",
               "pub enum SweepDepth", "pub struct SweepScheduleDecision",
               "pub struct SweepSchedulerConfig",
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
                   "fn with_defaults(", "fn to_csv(",
                   "fn current_band(", "fn hysteresis_counter(",
                   "fn update_count(", "fn decisions("]:
        checks.append(_check(f"method: {method}", method in src))

    # Event codes
    for code in ["EVD-SWEEP-001", "EVD-SWEEP-002", "EVD-SWEEP-003", "EVD-SWEEP-004"]:
        checks.append(_check(f"event_code: {code}", code in src))

    # Invariants
    for inv in ["INV-SWEEP-ADAPTIVE", "INV-SWEEP-HYSTERESIS",
                "INV-SWEEP-DETERMINISTIC", "INV-SWEEP-BOUNDED"]:
        checks.append(_check(f"invariant: {inv}", inv in src))

    # Serde derives
    checks.append(_check("serde derives", "Serialize" in src and "Deserialize" in src))

    # Duration import
    checks.append(_check("Duration import", "Duration" in src))

    # Tests (actual test names from the implementation)
    test_names = [
        "test_new_starts_green",
        "test_default_is_with_defaults",
        "test_classify_green",
        "test_classify_yellow_by_rejections",
        "test_classify_yellow_by_escalations",
        "test_classify_yellow_by_degrading_trend",
        "test_classify_red_by_rejections",
        "test_classify_red_by_degrading_low_repairability",
        "test_green_interval",
        "test_green_depth",
        "test_red_interval_and_depth",
        "test_yellow_interval_and_depth",
        "test_escalation_immediate_green_to_red",
        "test_escalation_immediate_green_to_yellow",
        "test_escalation_immediate_yellow_to_red",
        "test_deescalation_requires_hysteresis",
        "test_deescalation_one_step_at_a_time",
        "test_hysteresis_reset_on_escalation",
        "test_hysteresis_threshold_zero",
        "test_oscillation_prevention",
        "test_oscillation_prevention_1000_alternating",
        "test_cadence_increases_during_sustained_degradation",
        "test_cadence_decreases_during_sustained_improvement",
        "test_decisions_recorded",
        "test_decision_fields_populated",
        "test_update_count_increments",
        "test_deterministic_scheduling",
        "test_first_update_green",
        "test_first_update_red",
        "test_all_zero_trajectory",
        "test_nan_repairability_clamped",
        "test_inf_repairability_clamped",
        "test_negative_inf_clamped",
        "test_high_rejection_count",
        "test_band_ordering",
        "test_band_labels",
        "test_trend_labels",
        "test_sweep_depth_labels",
        "test_event_codes_defined",
        "test_scheduler_serialization_roundtrip",
        "test_evidence_trajectory_serialization",
        "test_csv_export_header",
        "test_csv_export_rows",
        "test_default_config_valid",
    ]
    for test in test_names:
        checks.append(_check(f"test: {test}", f"fn {test}(" in src))

    # Unit test count
    test_count = len(re.findall(r"#\[test\]", src))
    checks.append(_check("unit test count", test_count >= 35,
                          f"{test_count} tests (minimum 35)"))

    # Trajectory artifact validity
    if os.path.isfile(TRAJECTORY):
        with open(TRAJECTORY, encoding="utf-8") as f:
            lines = f.readlines()
        checks.append(_check("trajectory has header", len(lines) >= 1 and "band" in lines[0]))
        checks.append(_check("trajectory has data rows", len(lines) >= 5))
    else:
        checks.append(_check("trajectory has header", False, "file missing"))
        checks.append(_check("trajectory has data rows", False, "file missing"))

    return checks


def self_test():
    checks = run_checks()
    strip_check_ok = _strip_rust_comments('"kept // literal"; // removed') == '"kept // literal"; '
    if not strip_check_ok:
        print("self_test: Rust comment stripper corrupted string literals")
        return False
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
    configure_test_logging("check_integrity_sweep_scheduler")
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

    test_count = len(re.findall(r"#\[test\]", _read_rust_source(IMPL))) if os.path.isfile(IMPL) else 0

    if args.json:
        result = {
            "bead_id": "bd-1fp4",
            "title": "Integrity sweep escalation/de-escalation policy",
            "section": "10.14",
            "overall_pass": failing == 0,
            "verdict": "PASS" if failing == 0 else "FAIL",
            "test_count": test_count,
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
