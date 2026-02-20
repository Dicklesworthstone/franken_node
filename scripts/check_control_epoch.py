#!/usr/bin/env python3
"""bd-3hdv: Verify monotonic control epoch in canonical manifest state.

Checks:
  1. control_epoch.rs exists with required types and operations
  2. ControlEpoch type implements Copy + Ord + Hash traits
  3. EpochStore provides epoch_advance, epoch_read, epoch_set
  4. EpochTransition contains required fields and verify() method
  5. Error codes defined: EPOCH_REGRESSION, EPOCH_OVERFLOW, EPOCH_INVALID_MANIFEST
  6. Invariant markers present in code
  7. Unit tests cover monotonicity, regression, crash recovery, overflow

Usage:
  python3 scripts/check_control_epoch.py          # human-readable
  python3 scripts/check_control_epoch.py --json    # machine-readable
  python3 scripts/check_control_epoch.py --self-test
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "control_epoch.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-3hdv_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"

REQUIRED_TYPES = [
    "pub struct ControlEpoch",
    "pub struct EpochTransition",
    "pub struct EpochStore",
    "pub enum EpochError",
]

REQUIRED_METHODS = [
    "fn epoch_advance(",
    "fn epoch_read(",
    "fn epoch_set(",
    "fn recover(",
    "fn committed_epoch(",
    "fn verify(",
    "fn next(",
]

REQUIRED_ERROR_CODES = [
    "EPOCH_REGRESSION",
    "EPOCH_OVERFLOW",
    "EPOCH_INVALID_MANIFEST",
]

REQUIRED_EVENT_CODES = [
    "EPOCH_ADVANCED",
    "EPOCH_REGRESSION_REJECTED",
    "EPOCH_READ",
    "EPOCH_RECOVERED",
]

REQUIRED_INVARIANTS = [
    "INV-EPOCH-MONOTONIC",
    "INV-EPOCH-DURABLE",
    "INV-EPOCH-SIGNED-EVENT",
    "INV-EPOCH-NO-GAP",
]

REQUIRED_TESTS = [
    "epoch_genesis_is_zero",
    "epoch_next",
    "epoch_next_overflow",
    "epoch_ordering",
    "single_advance",
    "sequential_advances",
    "thousand_advances_monotonic",
    "regression_same_value_rejected",
    "regression_lower_value_rejected",
    "transition_event_verifiable",
    "transition_event_tamper_detected",
    "crash_recovery_preserves_committed",
    "advance_after_recovery",
    "empty_manifest_hash_rejected",
    "epoch_at_max_overflows_on_advance",
    "error_display_all_variants",
    "same_inputs_produce_same_mac",
    "different_inputs_produce_different_mac",
]

REQUIRED_TRAITS = [
    "Copy",
    "Ord",
    "Hash",
    "PartialEq",
    "Eq",
]

SPEC_CONTENT = [
    "ControlEpoch",
    "EpochTransition",
    "EpochStore",
    "INV-EPOCH-MONOTONIC",
    "INV-EPOCH-DURABLE",
    "epoch_advance",
    "epoch_read",
    "crash recovery",
]


def check_file(path, label):
    ok = path.is_file()
    rel = str(path.relative_to(ROOT)) if ok else str(path)
    return {
        "id": f"CEP-FILE-{label.upper().replace(' ', '-')}",
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {rel}" if ok else f"MISSING: {rel}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"id": f"CEP-{category.upper()}-MISSING",
                           "check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = path.read_text()
    for p in patterns:
        found = p in content
        short = p[:30].upper().replace(' ', '-').replace('(', '').replace(')', '')
        results.append({
            "id": f"CEP-{category.upper()}-{short}",
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"id": "CEP-MOD-REG", "check": "module registered in mod.rs",
                "pass": False, "detail": "mod.rs missing"}
    content = MOD_RS.read_text()
    found = "control_epoch" in content
    return {
        "id": "CEP-MOD-REG",
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_traits(path):
    results = []
    if not path.is_file():
        return results
    content = path.read_text()
    for trait_name in REQUIRED_TRAITS:
        found = trait_name in content
        results.append({
            "id": f"CEP-TRAIT-{trait_name.upper()}",
            "check": f"trait: {trait_name}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_test_count(path):
    if not path.is_file():
        return {"id": "CEP-TEST-COUNT", "check": "test count",
                "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {
        "id": "CEP-TEST-COUNT",
        "check": "unit test count",
        "pass": count >= 20,
        "detail": f"{count} tests (minimum 20)",
    }


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))

    # Module registration
    checks.append(check_module_registered())

    # Types
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))

    # Methods
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))

    # Error codes
    checks.extend(check_content(IMPL, REQUIRED_ERROR_CODES, "error_code"))

    # Event codes
    checks.extend(check_content(IMPL, REQUIRED_EVENT_CODES, "event_code"))

    # Invariants
    checks.extend(check_content(IMPL, REQUIRED_INVARIANTS, "invariant"))

    # Traits
    checks.extend(check_traits(IMPL))

    # Test count
    checks.append(check_test_count(IMPL))

    # Required tests
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    # Spec content
    checks.extend(check_content(SPEC, SPEC_CONTENT, "spec"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)

    return {
        "bead": "bd-3hdv",
        "title": "Monotonic control epoch in canonical manifest state",
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
    assert isinstance(result, dict), "Result must be a dict"
    assert result["bead"] == "bd-3hdv"
    assert "checks" in result
    assert isinstance(result["checks"], list)
    assert len(result["checks"]) > 0
    assert "verdict" in result
    assert "summary" in result
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
        print(f"=== bd-3hdv: Control Epoch Verification ===")
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
