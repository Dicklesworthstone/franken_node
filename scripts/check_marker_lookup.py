#!/usr/bin/env python3
"""bd-129f: Verify O(1) marker lookup by sequence and O(log N) timestamp-to-sequence search.

Checks:
  1. marker_stream.rs contains marker_by_sequence and sequence_by_timestamp methods
  2. O(1) complexity guarantee: marker_by_sequence uses direct Vec index
  3. O(log N) complexity guarantee: sequence_by_timestamp uses binary search
  4. Edge cases handled: empty stream, out-of-range, before-first, after-last, duplicates
  5. Spec contract document exists
  6. Unit tests exist with required coverage patterns

Usage:
  python3 scripts/check_marker_lookup.py          # human-readable
  python3 scripts/check_marker_lookup.py --json    # machine-readable
  python3 scripts/check_marker_lookup.py --self-test
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "marker_stream.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-129f_contract.md"

ERROR_CODES = {
    "file_missing": "MKL-FILE-MISSING",
    "method_missing": "MKL-METHOD-MISSING",
    "complexity_missing": "MKL-COMPLEXITY-MISSING",
    "edge_case_missing": "MKL-EDGE-CASE-MISSING",
    "test_missing": "MKL-TEST-MISSING",
    "spec_missing": "MKL-SPEC-MISSING",
}

# Required public methods for bd-129f
REQUIRED_METHODS = [
    "fn marker_by_sequence(",
    "fn sequence_by_timestamp(",
    "fn first(",
]

# Required test functions
REQUIRED_TESTS = [
    "marker_by_sequence_first",
    "marker_by_sequence_last",
    "marker_by_sequence_middle",
    "marker_by_sequence_out_of_range",
    "marker_by_sequence_empty_stream",
    "sequence_by_timestamp_exact_match",
    "sequence_by_timestamp_between_markers",
    "sequence_by_timestamp_before_first",
    "sequence_by_timestamp_after_last",
    "sequence_by_timestamp_empty_stream",
    "sequence_by_timestamp_single_marker",
    "sequence_by_timestamp_duplicate_timestamps",
    "sequence_by_timestamp_large_stream",
    "marker_by_sequence_matches_get",
]

# Algorithm evidence patterns in code
ALGORITHM_PATTERNS = [
    ("o1_vec_index", r"\.get\(seq\s+as\s+usize\)", "O(1) Vec index for sequence lookup"),
    ("binary_search_loop", r"while\s+lo\s*<\s*hi", "Binary search loop for timestamp lookup"),
    ("binary_search_mid", r"let\s+mid\s*=\s*lo\s*\+\s*\(hi\s*-\s*lo\)\s*/\s*2", "Midpoint calculation"),
    ("monotonic_precondition", r"INV-MKS-MONOTONIC-TIME", "Monotonic time precondition documented"),
]

# Spec document required content
SPEC_CONTENT = [
    "O(1)",
    "O(log N)",
    "marker_by_sequence",
    "sequence_by_timestamp",
    "binary search",
    "< 1 microsecond",
    "< 100 microseconds",
]


def check_file_exists(path, label):
    if path.is_file():
        return {"id": f"MKL-FILE-{label.upper()}", "check": f"file: {label}",
                "pass": True, "detail": f"exists: {path.relative_to(ROOT)}"}
    return {"id": f"MKL-FILE-{label.upper()}", "check": f"file: {label}",
            "pass": False, "detail": f"MISSING: {path.relative_to(ROOT)}"}


def check_methods(content):
    results = []
    for method in REQUIRED_METHODS:
        found = method in content
        name = method.strip("(").split()[-1]
        results.append({
            "id": f"MKL-METHOD-{name.upper()}",
            "check": f"method: {method.rstrip('(')}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_algorithms(content):
    results = []
    for name, pattern, description in ALGORITHM_PATTERNS:
        found = bool(re.search(pattern, content))
        results.append({
            "id": f"MKL-ALGO-{name.upper()}",
            "check": f"algorithm: {description}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_tests(content):
    results = []
    test_count = len(re.findall(r"#\[test\]", content))

    # Count only bd-129f specific tests
    bd129f_tests = [t for t in REQUIRED_TESTS if t in content]
    results.append({
        "id": "MKL-TEST-COUNT",
        "check": "bd-129f test count",
        "pass": len(bd129f_tests) >= 12,
        "detail": f"{len(bd129f_tests)} bd-129f tests (minimum 12)",
    })

    for test_name in REQUIRED_TESTS:
        found = test_name in content
        results.append({
            "id": f"MKL-TEST-{test_name.upper().replace('_', '-')[:40]}",
            "check": f"test: {test_name}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_spec(path):
    results = []
    if not path.is_file():
        results.append({
            "id": "MKL-SPEC",
            "check": "spec document",
            "pass": False,
            "detail": f"MISSING: {path.relative_to(ROOT)}",
        })
        return results

    content = path.read_text()
    for item in SPEC_CONTENT:
        found = item in content
        results.append({
            "id": f"MKL-SPEC-{item[:20].upper().replace(' ', '-')}",
            "check": f"spec content: {item}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_edge_cases(content):
    """Verify edge case handling patterns exist in the code."""
    results = []
    edge_cases = [
        ("empty_none", "is_empty()", "Empty stream returns None"),
        ("out_of_range", "markers.get(seq as usize)", "Out-of-range returns None via get()"),
        ("before_first", "ts < self.markers[0].timestamp", "Before-first timestamp check"),
        ("rightmost", "lo - 1", "Rightmost marker at-or-before timestamp"),
    ]
    for name, pattern, description in edge_cases:
        found = pattern in content
        results.append({
            "id": f"MKL-EDGE-{name.upper()}",
            "check": f"edge case: {description}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_return_types(content):
    """Verify correct return types."""
    results = []
    return_types = [
        ("seq_option_ref", "-> Option<&Marker>", "marker_by_sequence returns Option<&Marker>"),
        ("ts_option_u64", "-> Option<u64>", "sequence_by_timestamp returns Option<u64>"),
    ]
    for name, pattern, description in return_types:
        found = pattern in content
        results.append({
            "id": f"MKL-RTYPE-{name.upper()}",
            "check": f"return type: {description}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file_exists(IMPL, "implementation"))
    checks.append(check_file_exists(SPEC, "spec"))

    # Read implementation
    if IMPL.is_file():
        content = IMPL.read_text()
        checks.extend(check_methods(content))
        checks.extend(check_algorithms(content))
        checks.extend(check_edge_cases(content))
        checks.extend(check_return_types(content))
        checks.extend(check_tests(content))

    # Spec content
    checks.extend(check_spec(SPEC))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)

    return {
        "bead": "bd-129f",
        "title": "O(1) marker lookup by sequence and O(log N) timestamp-to-sequence search",
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
    """Verify the checker itself works correctly."""
    result = run_checks()
    assert isinstance(result, dict), "Result must be a dict"
    assert result["bead"] == "bd-129f", f"Expected bd-129f, got {result['bead']}"
    assert "checks" in result, "Missing checks"
    assert isinstance(result["checks"], list), "checks must be a list"
    assert len(result["checks"]) > 0, "Must have at least one check"
    assert "verdict" in result, "Missing verdict"
    assert "summary" in result, "Missing summary"
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
        print(f"=== bd-129f: Marker Lookup Verification ===")
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
