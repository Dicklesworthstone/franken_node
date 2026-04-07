#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-8uvb: Overlapping-lease conflict policy."""

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
    logger = configure_test_logging("check_lease_conflict")
    print("bd-8uvb: Overlapping-Lease Conflict Policy — Verification\n")
    all_pass = True

    # LC-IMPL: Implementation exists with required types
    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/lease_conflict.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_policy = "struct ConflictPolicy" in content
        has_conflict = "struct LeaseConflict" in content
        has_resolution = "struct ConflictResolution" in content
        has_fork_log = "struct ForkLogEntry" in content
        has_detector = "fn detect_conflicts" in content
        has_resolve = "fn resolve_conflict" in content
        has_fork_fn = "fn fork_log_entry" in content
        all_types = has_policy and has_conflict and has_resolution and has_fork_log and has_detector and has_resolve and has_fork_fn
    else:
        all_types = False
    all_pass &= check("OLC-IMPL", "Implementation with all required types", impl_exists and all_types)

    # OLC-ERRORS: All error codes present
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["OLC_DANGEROUS_HALT", "OLC_BOTH_ACTIVE", "OLC_NO_WINNER", "OLC_FORK_LOG_INCOMPLETE"]
        found = [e for e in errors if e in content]
        all_pass &= check("OLC-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("OLC-ERRORS", "Error codes", False)

    # OLC-FIXTURES: Fork log samples artifact
    fixtures_path = os.path.join(ROOT, "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json")
    fixtures_valid = False
    if os.path.isfile(fixtures_path):
        try:
            data = json.loads(Path(fixtures_path).read_text())
            fixtures_valid = "scenarios" in data and len(data["scenarios"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("OLC-FIXTURES", "Fork log sample fixtures", fixtures_valid)

    # OLC-INTEG: Integration tests exist
    integ_path = os.path.join(ROOT, "tests/integration/overlapping_lease_conflicts.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_deterministic = "inv_olc_deterministic" in content
        has_halt = "inv_olc_dangerous_halt" in content
        has_fork = "inv_olc_fork_log" in content
        has_classified = "inv_olc_classified" in content
    else:
        has_deterministic = has_halt = has_fork = has_classified = False
    all_pass &= check("OLC-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_deterministic and has_halt and has_fork and has_classified)

    # OLC-TESTS: Rust unit tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::lease_conflict"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("OLC-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("OLC-TESTS", "Rust unit tests pass", False, str(e))

    # OLC-SPEC: Specification with invariants
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-8uvb_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-OLC" in content
        has_types = "ConflictPolicy" in content and "LeaseConflict" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("OLC-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "lease_conflict_verification",
        "bead": "bd-8uvb",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-8uvb")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
