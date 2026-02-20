#!/usr/bin/env python3
"""Verification script for bd-1gnb: Distributed trace correlation IDs."""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS = []


def check(check_id, description, passed, details=None):
    entry = {"id": check_id, "description": description, "status": "PASS" if passed else "FAIL"}
    if details:
        entry["details"] = details
    CHECKS.append(entry)
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {check_id}: {description}")
    if details:
        print(f"         {details}")
    return passed


def main():
    print("bd-1gnb: Distributed Trace Correlation IDs — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/trace_context.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_ctx = "struct TraceContext" in content
        has_store = "struct TraceStore" in content
        has_report = "struct ConformanceReport" in content
        has_validate = "fn validate" in content
        all_types = has_ctx and has_store and has_report and has_validate
    else:
        all_types = False
    all_pass &= check("TRC-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["TRC_MISSING_TRACE_ID", "TRC_MISSING_SPAN_ID", "TRC_INVALID_FORMAT",
                  "TRC_PARENT_NOT_FOUND", "TRC_CONFORMANCE_FAILED"]
        found = [e for e in errors if e in content]
        all_pass &= check("TRC-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("TRC-ERRORS", "Error codes", False)

    sample_path = os.path.join(ROOT, "artifacts/section_10_13/bd-1gnb/distributed_trace_sample.json")
    sample_valid = False
    if os.path.isfile(sample_path):
        try:
            data = json.load(open(sample_path))
            sample_valid = "spans" in data and len(data["spans"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("TRC-SAMPLE", "Distributed trace sample fixture", sample_valid)

    integ_path = os.path.join(ROOT, "tests/integration/trace_correlation_end_to_end.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_required = "inv_trc_required" in content
        has_propagated = "inv_trc_propagated" in content
        has_stitchable = "inv_trc_stitchable" in content
        has_conformance = "inv_trc_conformance" in content
    else:
        has_required = has_propagated = has_stitchable = has_conformance = False
    all_pass &= check("TRC-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_required and has_propagated and has_stitchable and has_conformance)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::trace_context"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("TRC-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("TRC-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1gnb_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-TRC" in content
        has_types = "TraceContext" in content and "ConformanceReport" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("TRC-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "trace_context_verification",
        "bead": "bd-1gnb",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-1gnb")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
