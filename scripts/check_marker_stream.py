#!/usr/bin/env python3
"""bd-126h: Verify append-only marker stream for high-impact control events.

Checks:
  1. marker_stream.rs exists with required types and operations
  2. All 6 event types defined
  3. All 7 error codes defined
  4. Dense sequence and hash-chain invariant enforcement
  5. Torn-tail recovery
  6. Unit tests exist and cover all invariants

Usage:
  python3 scripts/check_marker_stream.py          # human-readable
  python3 scripts/check_marker_stream.py --json    # machine-readable
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "marker_stream.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-126h_contract.md"
CONFORMANCE = ROOT / "tests" / "conformance" / "marker_stream_invariants.rs"

REQUIRED_EVENT_TYPES = [
    "TrustDecision",
    "RevocationEvent",
    "QuarantineAction",
    "PolicyChange",
    "EpochTransition",
    "IncidentEscalation",
]

REQUIRED_ERROR_CODES = [
    "MKS_SEQUENCE_GAP",
    "MKS_HASH_CHAIN_BREAK",
    "MKS_TIME_REGRESSION",
    "MKS_EMPTY_STREAM",
    "MKS_INTEGRITY_FAILURE",
    "MKS_TORN_TAIL",
    "MKS_INVALID_PAYLOAD",
]

REQUIRED_OPERATIONS = [
    "fn append(",
    "fn head(",
    "fn get(",
    "fn len(",
    "fn verify_integrity(",
    "fn recover_torn_tail(",
]

REQUIRED_STRUCTS = [
    "pub struct Marker",
    "pub struct MarkerStream",
    "pub enum MarkerEventType",
    "pub enum MarkerStreamError",
]


def check_file_exists(path: Path) -> tuple[bool, str]:
    if path.is_file():
        return True, f"exists: {path.relative_to(ROOT)}"
    return False, f"MISSING: {path.relative_to(ROOT)}"


def check_content_contains(path: Path, patterns: list[str], label: str) -> list[dict]:
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"check": f"{label}: {p}", "pass": False, "detail": "file missing"})
        return results

    content = path.read_text()
    for p in patterns:
        found = p in content
        results.append({
            "check": f"{label}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_test_coverage(path: Path) -> list[dict]:
    results = []
    if not path.is_file():
        results.append({"check": "test module exists", "pass": False, "detail": "file missing"})
        return results

    content = path.read_text()
    test_count = len(re.findall(r"#\[test\]", content))
    results.append({
        "check": "unit test count",
        "pass": test_count >= 20,
        "detail": f"{test_count} tests (minimum 20)",
    })

    required_test_patterns = [
        "append_single_marker",
        "dense_sequence_numbers",
        "hash_chain_links_correctly",
        "time_regression_rejected",
        "empty_payload_hash_rejected",
        "verify_integrity_valid_stream",
        "verify_integrity_detects_hash_chain_break",
        "recover_torn_tail_corrupt_last",
        "recover_torn_tail_healthy_stream",
        "all_event_types_appendable",
        "error_codes_all_present",
        "large_stream_integrity",
    ]
    for test_name in required_test_patterns:
        found = test_name in content
        results.append({
            "check": f"test: {test_name}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    return results


def run_checks() -> dict:
    checks = []

    # 1. File existence
    for path, label in [
        (IMPL, "implementation"),
        (SPEC, "spec contract"),
        (CONFORMANCE, "conformance tests"),
    ]:
        ok, detail = check_file_exists(path)
        checks.append({"check": f"file: {label}", "pass": ok, "detail": detail})

    # 2. Required types
    checks.extend(check_content_contains(IMPL, REQUIRED_STRUCTS, "struct/enum"))

    # 3. Required event types
    checks.extend(check_content_contains(IMPL, REQUIRED_EVENT_TYPES, "event_type"))

    # 4. Required error codes
    checks.extend(check_content_contains(IMPL, REQUIRED_ERROR_CODES, "error_code"))

    # 5. Required operations
    checks.extend(check_content_contains(IMPL, REQUIRED_OPERATIONS, "operation"))

    # 6. Invariant markers in code
    invariant_markers = [
        "INV-MKS-APPEND-ONLY",
        "INV-MKS-DENSE-SEQUENCE",
        "INV-MKS-HASH-CHAIN",
        "INV-MKS-MONOTONIC-TIME",
        "INV-MKS-TORN-TAIL",
    ]
    # Check spec has invariants
    checks.extend(check_content_contains(SPEC, invariant_markers, "spec_invariant"))

    # 7. Test coverage
    checks.extend(check_test_coverage(IMPL))

    # 8. Genesis sentinel
    checks.extend(check_content_contains(IMPL, ["GENESIS_PREV_HASH"], "genesis"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)

    return {
        "bead": "bd-126h",
        "title": "Append-only marker stream for high-impact control events",
        "section": "10.14",
        "passed": passed,
        "total": total,
        "all_pass": passed == total,
        "checks": checks,
    }


def self_test():
    """Verify the checker itself works correctly."""
    result = run_checks()
    assert isinstance(result, dict)
    assert "bead" in result
    assert result["bead"] == "bd-126h"
    assert "checks" in result
    assert isinstance(result["checks"], list)
    assert len(result["checks"]) > 0
    print("self_test passed")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== bd-126h: Marker Stream Verification ===")
        print(f"Result: {'PASS' if result['all_pass'] else 'FAIL'}")
        print(f"Checks: {result['passed']}/{result['total']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["all_pass"] else 1)


if __name__ == "__main__":
    main()
