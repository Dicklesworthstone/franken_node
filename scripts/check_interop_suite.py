#!/usr/bin/env python3
"""Verification script for bd-35by: Mandatory interop suites."""

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
    print("bd-35by: Mandatory Interop Suites — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/interop_suite.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_class = "enum InteropClass" in content
        has_result = "struct InteropResult" in content
        has_check = "fn check_serialization" in content
        has_suite = "fn run_suite" in content
        all_types = has_class and has_result and has_check and has_suite
    else:
        all_types = False
    all_pass &= check("IOP-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["IOP_SERIALIZATION_MISMATCH", "IOP_OBJECT_ID_MISMATCH", "IOP_SIGNATURE_INVALID",
                  "IOP_REVOCATION_DISAGREEMENT", "IOP_SOURCE_DIVERSITY_INSUFFICIENT"]
        found = [e for e in errors if e in content]
        all_pass &= check("IOP-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("IOP-ERRORS", "Error codes", False)

    fixture_path = os.path.join(ROOT, "fixtures/interop/interop_test_vectors.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.load(open(fixture_path))
            fixture_valid = "test_vectors" in data and len(data["test_vectors"]) >= 5
        except json.JSONDecodeError:
            pass
    all_pass &= check("IOP-FIXTURES", "Interop test vector fixtures", fixture_valid)

    integ_path = os.path.join(ROOT, "tests/integration/interop_mandatory_suites.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_ser = "inv_iop_serialization" in content
        has_oid = "inv_iop_object_id" in content
        has_sig = "inv_iop_signature" in content
        has_rev = "inv_iop_revocation" in content
        has_sd = "inv_iop_source_diversity" in content
    else:
        has_ser = has_oid = has_sig = has_rev = has_sd = False
    all_pass &= check("IOP-INTEG", "Integration tests cover all 5 invariants",
                       integ_exists and has_ser and has_oid and has_sig and has_rev and has_sd)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::interop_suite"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("IOP-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("IOP-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-35by_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-IOP" in content
        has_types = "InteropClass" in content and "InteropResult" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("IOP-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "interop_suite_verification",
        "bead": "bd-35by",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-35by")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
