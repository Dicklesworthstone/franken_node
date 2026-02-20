#!/usr/bin/env python3
"""Verification script for bd-1p2b: Control-plane retention policy."""

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
    print("bd-1p2b: Control-Plane Retention Policy — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/retention_policy.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_class = "enum RetentionClass" in content
        has_policy = "struct RetentionPolicy" in content
        has_registry = "struct RetentionRegistry" in content
        has_store = "struct RetentionStore" in content
        has_stored = "struct StoredMessage" in content
        all_types = has_class and has_policy and has_registry and has_store and has_stored
    else:
        all_types = False
    all_pass &= check("CPR-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["CPR_UNCLASSIFIED", "CPR_DROP_REQUIRED", "CPR_INVALID_POLICY",
                  "CPR_STORAGE_FULL", "CPR_NOT_FOUND"]
        found = [e for e in errors if e in content]
        all_pass &= check("CPR-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("CPR-ERRORS", "Error codes", False)

    matrix_path = os.path.join(ROOT, "artifacts/section_10_13/bd-1p2b/retention_policy_matrix.json")
    matrix_valid = False
    if os.path.isfile(matrix_path):
        try:
            data = json.load(open(matrix_path))
            matrix_valid = "matrix" in data and len(data["matrix"]) >= 5
        except json.JSONDecodeError:
            pass
    all_pass &= check("CPR-MATRIX", "Retention policy matrix", matrix_valid)

    integ_path = os.path.join(ROOT, "tests/integration/retention_class_enforcement.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_classified = "inv_cpr_classified" in content
        has_required = "inv_cpr_required_durable" in content
        has_ephemeral = "inv_cpr_ephemeral_policy" in content
        has_audit = "inv_cpr_auditable" in content
    else:
        has_classified = has_required = has_ephemeral = has_audit = False
    all_pass &= check("CPR-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_classified and has_required and has_ephemeral and has_audit)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::retention_policy"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("CPR-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("CPR-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1p2b_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-CPR" in content
        has_types = "RetentionClass" in content and "RetentionPolicy" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("CPR-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "retention_policy_verification",
        "bead": "bd-1p2b",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-1p2b")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
