#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-2vs4: Lease coordinator and quorum verification."""

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
    logger = configure_test_logging("check_lease_coordinator")
    print("bd-2vs4: Lease Coordinator — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/lease_coordinator.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_candidate = "struct CoordinatorCandidate" in content
        has_selection = "struct CoordinatorSelection" in content
        has_qconfig = "struct QuorumConfig" in content
        has_verify = "fn verify_quorum" in content
        has_select = "fn select_coordinator" in content
        has_failure = "enum VerificationFailure" in content
        all_types = has_candidate and has_selection and has_qconfig and has_verify and has_select and has_failure
    else:
        all_types = False
    all_pass &= check("LC-IMPL", "Implementation with all required types",
                       impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["LC_BELOW_QUORUM", "LC_INVALID_SIGNATURE", "LC_UNKNOWN_SIGNER", "LC_NO_CANDIDATES"]
        found = [e for e in errors if e in content]
        all_pass &= check("LC-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("LC-ERRORS", "Error codes", False)

    vectors_path = os.path.join(ROOT, "artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json")
    vectors_valid = False
    if os.path.isfile(vectors_path):
        try:
            data = json.loads(Path(vectors_path).read_text())
            vectors_valid = "vectors" in data and len(data["vectors"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("LC-VECTORS", "Quorum test vectors artifact", vectors_valid)

    conf_path = os.path.join(ROOT, "tests/conformance/lease_coordinator_selection.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = Path(conf_path).read_text()
        has_determ = "inv_lc_deterministic" in content
        has_quorum = "inv_lc_quorum_tier" in content
        has_classified = "inv_lc_verify_classified" in content
        has_replay = "inv_lc_replay" in content
    else:
        has_determ = has_quorum = has_classified = has_replay = False
    all_pass &= check("LC-CONF-TESTS", "Conformance tests cover all 4 invariants",
                       conf_exists and has_determ and has_quorum and has_classified and has_replay)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "connector::lease_coordinator"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("LC-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("LC-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2vs4_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-LC" in content
        has_types = "LeaseCoordinatorService" in content and "QuorumConfig" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("LC-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "lease_coordinator_verification",
        "bead": "bd-2vs4",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-2vs4")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
