#!/usr/bin/env python3
"""bd-3rya: Verify monotonic hardening state machine with one-way escalation.

Checks:
  1. hardening_state_machine.rs exists with required types
  2. HardeningLevel has 5 levels with total ordering
  3. HardeningStateMachine provides escalate, governance_rollback, replay
  4. Error codes defined
  5. Invariant markers present
  6. Unit tests cover escalation, regression, rollback, replay

Usage:
  python3 scripts/check_hardening_state.py          # human-readable
  python3 scripts/check_hardening_state.py --json    # machine-readable
  python3 scripts/check_hardening_state.py --self-test
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "hardening_state_machine.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-3rya_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"

REQUIRED_TYPES = [
    "pub enum HardeningLevel",
    "pub struct HardeningStateMachine",
    "pub struct GovernanceRollbackArtifact",
    "pub struct TransitionRecord",
    "pub enum TransitionTrigger",
    "pub enum HardeningError",
]

REQUIRED_LEVELS = [
    "Baseline",
    "Standard",
    "Enhanced",
    "Maximum",
    "Critical",
]

REQUIRED_METHODS = [
    "fn escalate(",
    "fn governance_rollback(",
    "fn replay_transitions(",
    "fn current_level(",
    "fn transition_log(",
    "fn validate(",
]

REQUIRED_ERROR_CODES = [
    "HARDEN_ILLEGAL_REGRESSION",
    "HARDEN_INVALID_ARTIFACT",
    "HARDEN_INVALID_ROLLBACK_TARGET",
    "HARDEN_AT_MAXIMUM",
]

REQUIRED_EVENT_CODES = [
    "EVD-HARDEN-001",
    "EVD-HARDEN-002",
    "EVD-HARDEN-003",
    "EVD-HARDEN-004",
]

REQUIRED_INVARIANTS = [
    "INV-HARDEN-MONOTONIC",
    "INV-HARDEN-DURABLE",
    "INV-HARDEN-AUDITABLE",
    "INV-HARDEN-GOVERNANCE",
]

REQUIRED_TESTS = [
    "level_ordering",
    "level_total_ordering_five_levels",
    "level_label_roundtrip",
    "starts_at_baseline",
    "escalate_baseline_to_standard",
    "escalate_full_chain",
    "regression_same_level_rejected",
    "regression_lower_level_rejected",
    "governance_rollback_with_valid_artifact",
    "governance_rollback_missing_signature",
    "governance_rollback_same_level_rejected",
    "full_lifecycle_escalate_rollback_escalate",
    "replay_empty_log",
    "replay_multi_transition",
    "replay_determinism",
    "error_display_all_variants",
]


def check_file(path, label):
    ok = path.is_file()
    rel = str(path.relative_to(ROOT)) if ok else str(path)
    return {
        "id": f"HSM-FILE-{label.upper().replace(' ', '-')}",
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {rel}" if ok else f"MISSING: {rel}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"id": f"HSM-{category.upper()}-MISSING",
                           "check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = path.read_text()
    for p in patterns:
        found = p in content
        short = p[:30].upper().replace(' ', '-').replace('(', '').replace(')', '')
        results.append({
            "id": f"HSM-{category.upper()}-{short}",
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"id": "HSM-MOD-REG", "check": "module registered",
                "pass": False, "detail": "mod.rs missing"}
    content = MOD_RS.read_text()
    found = "hardening_state_machine" in content
    return {
        "id": "HSM-MOD-REG",
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_test_count(path):
    if not path.is_file():
        return {"id": "HSM-TEST-COUNT", "check": "test count",
                "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {
        "id": "HSM-TEST-COUNT",
        "check": "unit test count",
        "pass": count >= 25,
        "detail": f"{count} tests (minimum 25)",
    }


def run_checks():
    checks = []

    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_module_registered())

    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_LEVELS, "level"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, REQUIRED_ERROR_CODES, "error_code"))
    checks.extend(check_content(IMPL, REQUIRED_EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, REQUIRED_INVARIANTS, "invariant"))
    checks.append(check_test_count(IMPL))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)

    return {
        "bead": "bd-3rya",
        "title": "Monotonic hardening state machine with one-way escalation",
        "section": "10.14",
        "verdict": "PASS" if passed == total else "FAIL",
        "summary": {
            "passing_checks": passed,
            "failing_checks": total - passed,
            "total_checks": total,
        },
        "checks": checks,
    }


def self_test():
    result = run_checks()
    assert isinstance(result, dict)
    assert result["bead"] == "bd-3rya"
    assert "checks" in result
    assert len(result["checks"]) > 0
    print(f"self_test passed: {result['summary']['passing_checks']}/{result['summary']['total_checks']} checks")
    return result


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== bd-3rya: Hardening State Machine Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing_checks']}/{s['total_checks']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
