#!/usr/bin/env python3
"""Verification script for bd-ck2h: Conformance profile matrix."""

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
    print("bd-ck2h: Conformance Profile Matrix — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/conformance_profile.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_matrix = "struct ProfileMatrix" in content
        has_eval = "struct ClaimEvaluation" in content
        has_profile = "enum Profile" in content
        has_publish = "fn publish_claim" in content
        all_types = has_matrix and has_eval and has_profile and has_publish
    else:
        all_types = False
    all_pass &= check("CPM-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["CPM_UNKNOWN_PROFILE", "CPM_MISSING_RESULT", "CPM_CAPABILITY_FAILED",
                  "CPM_CLAIM_BLOCKED", "CPM_INVALID_MATRIX"]
        found = [e for e in errors if e in content]
        all_pass &= check("CPM-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("CPM-ERRORS", "Error codes", False)

    report_path = os.path.join(ROOT, "artifacts/section_10_13/bd-ck2h/profile_claim_report.json")
    report_valid = False
    if os.path.isfile(report_path):
        try:
            data = json.load(open(report_path))
            report_valid = "profiles" in data and "sample_evaluation" in data
        except json.JSONDecodeError:
            pass
    all_pass &= check("CPM-REPORT", "Profile claim report fixture", report_valid)

    integ_path = os.path.join(ROOT, "tests/integration/profile_claim_gate.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_matrix = "inv_cpm_matrix" in content
        has_measured = "inv_cpm_measured" in content
        has_blocked = "inv_cpm_blocked" in content
        has_metadata = "inv_cpm_metadata" in content
    else:
        has_matrix = has_measured = has_blocked = has_metadata = False
    all_pass &= check("CPM-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_matrix and has_measured and has_blocked and has_metadata)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::conformance_profile"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("CPM-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("CPM-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-ck2h_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-CPM" in content
        has_types = "ProfileMatrix" in content and "ClaimEvaluation" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("CPM-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "conformance_profile_verification",
        "bead": "bd-ck2h",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-ck2h")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
