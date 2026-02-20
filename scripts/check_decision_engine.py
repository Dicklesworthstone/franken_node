#!/usr/bin/env python3
"""Verification script for bd-15u3: Guardrail precedence enforcement (decision engine).

Usage:
    python3 scripts/check_decision_engine.py          # human-readable
    python3 scripts/check_decision_engine.py --json    # machine-readable
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "decision_engine.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-15u3_contract.md"

REQUIRED_TYPES = [
    "pub struct DecisionEngine",
    "pub struct DecisionOutcome",
    "pub struct BlockedCandidate",
    "pub enum DecisionReason",
    "pub struct GuardrailId",
]

REQUIRED_METHODS = [
    "fn new(",
    "fn decide(",
    "fn as_str(",
]

EVENT_CODES = [
    "EVD-DECIDE-001",
    "EVD-DECIDE-002",
    "EVD-DECIDE-003",
    "EVD-DECIDE-004",
]

INVARIANTS = [
    "INV-DECIDE-PRECEDENCE",
    "INV-DECIDE-DETERMINISTIC",
    "INV-DECIDE-NO-PANIC",
]

REQUIRED_TESTS = [
    "test_decide_empty_candidates",
    "test_decide_single_candidate_passes",
    "test_decide_single_candidate_blocked_per_candidate",
    "test_decide_top_blocked_fallback_to_second",
    "test_decide_all_blocked",
    "test_decide_system_level_block",
    "test_decide_system_plus_per_candidate_block",
    "test_decide_preserves_bayesian_rank_order",
    "test_decide_memory_budget_blocks_all",
    "test_decide_durability_blocks_all",
    "test_decide_hardening_regression_blocks_all",
    "test_decide_epoch_id_propagated",
    "test_decide_multiple_candidates_all_pass",
    "test_decide_no_monitors_allows_all",
    "test_decide_per_candidate_no_monitors",
    "test_blocked_candidate_has_reasons",
    "test_decide_deterministic",
    "test_decide_warn_does_not_block",
    "test_decide_tie_with_guardrail",
    "test_decision_outcome_serialization",
    "test_guardrail_id_display",
    "test_event_codes_defined",
    "test_decision_reason_top_accepted",
    "test_decision_reason_fallback",
    "test_decision_reason_all_blocked",
    "test_decision_reason_no_candidates",
    "test_decide_multiple_system_blocks_accumulate",
    "test_decide_fallback_picks_first_passing",
    "test_decide_middle_and_first_blocked",
    "test_decide_large_candidate_set",
    "test_blocked_candidate_serialization",
    "test_decide_single_monitor_blocks",
    "test_engine_different_epochs",
    "test_decide_all_filtered_empty_monitors",
]


def check_file(path, label):
    return {
        "check": f"file: {label}",
        "pass": path.exists(),
        "detail": f"exists: {path.relative_to(ROOT)}" if path.exists() else f"missing: {path}",
    }


def check_content(path, patterns, category):
    results = []
    try:
        text = path.read_text()
    except FileNotFoundError:
        for p in patterns:
            results.append({
                "check": f"{category}: {p}",
                "pass": False,
                "detail": f"file not found: {path}",
            })
        return results
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else f"not found in {path.name}",
        })
    return results


def check_module_registered():
    try:
        text = MOD_RS.read_text()
        found = "pub mod decision_engine;" in text
    except FileNotFoundError:
        found = False
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "not found",
    }


def check_test_count():
    try:
        text = IMPL.read_text()
        count = len(re.findall(r"#\[test\]", text))
    except FileNotFoundError:
        count = 0
    return {
        "check": "unit test count",
        "pass": count >= 25,
        "detail": f"{count} tests (minimum 25)",
    }


def check_serde_derives():
    try:
        text = IMPL.read_text()
        has_serialize = "Serialize" in text and "Deserialize" in text
    except FileNotFoundError:
        has_serialize = False
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_serialize,
        "detail": "found" if has_serialize else "not found",
    }


def check_guardrail_import():
    try:
        text = IMPL.read_text()
        has_import = "GuardrailMonitorSet" in text and "SystemState" in text
    except FileNotFoundError:
        has_import = False
    return {
        "check": "guardrail monitor integration",
        "pass": has_import,
        "detail": "found" if has_import else "not found",
    }


def check_bayesian_import():
    try:
        text = IMPL.read_text()
        has_import = "RankedCandidate" in text and "CandidateRef" in text
    except FileNotFoundError:
        has_import = False
    return {
        "check": "bayesian diagnostics integration",
        "pass": has_import,
        "detail": "found" if has_import else "not found",
    }


def check_precedence_logic():
    try:
        text = IMPL.read_text()
        has_loop = "for" in text and "candidates" in text
        has_block_check = "guardrail_filtered" in text
        has_system_check = "check_all_detailed" in text
    except FileNotFoundError:
        has_loop = has_block_check = has_system_check = False
    return {
        "check": "precedence enforcement logic",
        "pass": has_loop and has_block_check and has_system_check,
        "detail": "found" if (has_loop and has_block_check and has_system_check) else "incomplete",
    }


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.append(check_guardrail_import())
    checks.append(check_bayesian_import())
    checks.append(check_precedence_logic())

    # Required types
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))

    # Required methods
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))

    # Event codes
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))

    # Invariants
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))

    # Required tests
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = len(checks) - passing

    try:
        text = IMPL.read_text()
        test_count = len(re.findall(r"#\[test\]", text))
    except FileNotFoundError:
        test_count = 0

    return {
        "bead_id": "bd-15u3",
        "title": "Guardrail precedence enforcement (decision engine)",
        "section": "10.14",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": test_count,
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    checks = result["checks"]
    ok = result["overall_pass"]
    return ok, checks


if __name__ == "__main__":
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        v = result["verdict"]
        s = result["summary"]
        print(f"bd-15u3 decision_engine: {v} ({s['passing']}/{s['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
