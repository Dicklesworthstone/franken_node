#!/usr/bin/env python3
"""Verification script for bd-novi: Stable error code namespace."""

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
    print("bd-novi: Stable Error Code Namespace — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/error_code_registry.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_registry = "struct ErrorCodeRegistry" in content
        has_entry = "struct ErrorCodeEntry" in content
        has_recovery = "struct RecoveryInfo" in content
        has_register = "fn register" in content
        all_types = has_registry and has_entry and has_recovery and has_register
    else:
        all_types = False
    all_pass &= check("ECR-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["ECR_INVALID_NAMESPACE", "ECR_DUPLICATE_CODE", "ECR_MISSING_RECOVERY",
                  "ECR_FROZEN_CONFLICT", "ECR_NOT_FOUND"]
        found = [e for e in errors if e in content]
        all_pass &= check("ECR-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("ECR-ERRORS", "Error codes", False)

    catalog_path = os.path.join(ROOT, "artifacts/section_10_13/bd-novi/error_code_registry.json")
    catalog_valid = False
    if os.path.isfile(catalog_path):
        try:
            data = json.load(open(catalog_path))
            catalog_valid = "error_codes" in data and len(data["error_codes"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("ECR-CATALOG", "Error code registry fixture", catalog_valid)

    integ_path = os.path.join(ROOT, "tests/integration/error_contract_stability.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_namespaced = "inv_ecr_namespaced" in content
        has_unique = "inv_ecr_unique" in content
        has_recovery = "inv_ecr_recovery" in content
        has_frozen = "inv_ecr_frozen" in content
    else:
        has_namespaced = has_unique = has_recovery = has_frozen = False
    all_pass &= check("ECR-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_namespaced and has_unique and has_recovery and has_frozen)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::error_code_registry"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("ECR-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("ECR-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-novi_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-ECR" in content
        has_types = "ErrorCodeRegistry" in content and "RecoveryInfo" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("ECR-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "error_code_registry_verification",
        "bead": "bd-novi",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-novi")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
