#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-1z9s: Transparency-log inclusion proof checks."""

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
    logger = configure_test_logging("check_transparency_verifier")
    print("bd-1z9s: Transparency-Log Inclusion Proof Checks — Verification\n")
    all_pass = True

    # TL-IMPL: Implementation file
    impl_path = os.path.join(ROOT, "crates/franken-node/src/supply_chain/transparency_verifier.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_root = "struct LogRoot" in content
        has_proof = "struct InclusionProof" in content
        has_policy = "struct TransparencyPolicy" in content
        has_receipt = "struct ProofReceipt" in content
        has_verify = "fn verify_inclusion" in content
        all_types = has_root and has_proof and has_policy and has_receipt and has_verify
    else:
        all_types = False
    all_pass &= check("TL-IMPL", "Implementation with LogRoot, InclusionProof, policy, verify",
                       impl_exists and all_types)

    # TL-MERKLE: Merkle path recomputation
    if impl_exists:
        content = Path(impl_path).read_text()
        has_recompute = "fn recompute_root" in content
        has_hash_pair = "fn hash_pair" in content
        all_pass &= check("TL-MERKLE", "Merkle path recomputation with hash_pair",
                          has_recompute and has_hash_pair)
    else:
        all_pass &= check("TL-MERKLE", "Merkle recomputation", False)

    # TL-ERRORS: All 4 error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["TLOG_PROOF_MISSING", "TLOG_ROOT_NOT_PINNED",
                  "TLOG_PATH_INVALID", "TLOG_LEAF_MISMATCH"]
        found = [e for e in errors if e in content]
        all_pass &= check("TL-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("TL-ERRORS", "Error codes", False)

    # TL-FIXTURES: Inclusion proof scenarios
    fixture_path = os.path.join(ROOT, "fixtures/transparency_log/inclusion_proof_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("TL-FIXTURES", "Inclusion proof scenarios fixture", fixture_valid)

    # TL-RECEIPTS: Proof receipts artifact
    receipts_path = os.path.join(ROOT, "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json")
    receipts_valid = False
    if os.path.isfile(receipts_path):
        try:
            data = json.loads(Path(receipts_path).read_text())
            receipts_valid = "receipts" in data and len(data["receipts"]) >= 2
        except json.JSONDecodeError:
            pass
    all_pass &= check("TL-RECEIPTS", "Transparency proof receipts artifact", receipts_valid)

    # TL-SECURITY-TESTS: Security test file
    sec_path = os.path.join(ROOT, "tests/security/transparency_inclusion.rs")
    sec_exists = os.path.isfile(sec_path)
    if sec_exists:
        content = Path(sec_path).read_text()
        has_install = "install" in content
        has_proof = "proof" in content
        has_pinned = "pinned" in content
    else:
        has_install = has_proof = has_pinned = False
    all_pass &= check("TL-SECURITY-TESTS", "Security tests cover install, proof, pinned roots",
                       sec_exists and has_install and has_proof and has_pinned)

    # TL-TESTS: Rust unit tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "supply_chain::transparency_verifier"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("TL-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("TL-TESTS", "Rust unit tests pass", False, str(e))

    # TL-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1z9s_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-TLOG" in content
        has_failure = "ProofFailure" in content
    else:
        has_invariants = has_failure = False
    all_pass &= check("TL-SPEC", "Specification with invariants and proof failure types",
                       spec_exists and has_invariants and has_failure)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "transparency_verifier_verification",
        "bead": "bd-1z9s",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-1z9s")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
