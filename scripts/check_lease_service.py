#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-bq6y: Generic lease service."""

import json
import os
import re
import subprocess
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
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
    logger = configure_test_logging("check_lease_service")
    print("bd-bq6y: Generic Lease Service — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/lease_service.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_purpose = "enum LeasePurpose" in content
        has_lease = "struct Lease" in content
        has_service = "struct LeaseService" in content
        has_error = "enum LeaseError" in content
        has_grant = "fn grant" in content
        has_renew = "fn renew" in content
        has_use = "fn use_lease" in content
        all_types = has_purpose and has_lease and has_service and has_error and has_grant and has_renew and has_use
    else:
        all_types = False
    all_pass &= check("LS-IMPL", "Implementation with all required types and methods",
                       impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["LS_EXPIRED", "LS_STALE_USE", "LS_ALREADY_REVOKED", "LS_PURPOSE_MISMATCH"]
        found = [e for e in errors if e in content]
        all_pass &= check("LS-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("LS-ERRORS", "Error codes", False)

    if impl_exists:
        content = Path(impl_path).read_text()
        purposes = ["Operation", "StateWrite", "MigrationHandoff"]
        found = [p for p in purposes if p in content]
        all_pass &= check("LS-PURPOSES", "All 3 lease purposes present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("LS-PURPOSES", "Lease purposes", False)

    fixture_path = os.path.join(ROOT, "fixtures/lease/lease_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("LS-FIXTURES", "Lease scenarios fixture", fixture_valid)

    contract_path = os.path.join(ROOT, "artifacts/section_10_13/bd-bq6y/lease_service_contract.json")
    contract_valid = False
    if os.path.isfile(contract_path):
        try:
            data = json.loads(Path(contract_path).read_text())
            contract_valid = "leases" in data and len(data["leases"]) >= 2
        except json.JSONDecodeError:
            pass
    all_pass &= check("LS-CONTRACT", "Lease service contract artifact", contract_valid)

    integ_path = os.path.join(ROOT, "tests/integration/lease_service_contract.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_expiry = "inv_ls_expiry" in content
        has_renewal = "inv_ls_renewal" in content
        has_stale = "inv_ls_stale" in content
        has_purpose = "inv_ls_purpose" in content
    else:
        has_expiry = has_renewal = has_stale = has_purpose = False
    all_pass &= check("LS-INTEG-TESTS", "Integration tests cover all 4 invariants",
                       integ_exists and has_expiry and has_renewal and has_stale and has_purpose)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "connector::lease_service"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("LS-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("LS-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-bq6y_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-LS" in content
        has_types = "LeaseService" in content and "LeasePurpose" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("LS-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "lease_service_verification",
        "bead": "bd-bq6y",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-bq6y")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
