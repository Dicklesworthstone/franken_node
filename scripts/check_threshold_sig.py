#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-35q1: Threshold signature verification."""

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
    logger = configure_test_logging("check_threshold_sig")
    print("bd-35q1: Threshold Signature Verification — Verification\n")
    all_pass = True

    # TS-IMPL: Implementation file
    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/threshold_sig.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_config = "struct ThresholdConfig" in content
        has_artifact = "struct PublicationArtifact" in content
        has_result = "struct VerificationResult" in content
        has_verify = "fn verify_threshold" in content
        all_types = has_config and has_artifact and has_result and has_verify
    else:
        all_types = False
    all_pass &= check("TS-IMPL", "Implementation with config, artifact, result, verify_threshold",
                       impl_exists and all_types)

    # TS-QUORUM: Threshold quorum logic
    if impl_exists:
        content = Path(impl_path).read_text()
        has_threshold = "threshold" in content
        has_quorum = "valid_count >= config.threshold" in content or "valid_count" in content
        all_pass &= check("TS-QUORUM", "Quorum check against threshold", has_threshold and has_quorum)
    else:
        all_pass &= check("TS-QUORUM", "Quorum logic", False)

    # TS-ERRORS: All 4 error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["THRESH_BELOW_QUORUM", "THRESH_UNKNOWN_SIGNER",
                  "THRESH_INVALID_SIG", "THRESH_CONFIG_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("TS-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("TS-ERRORS", "Error codes", False)

    # TS-FIXTURES: Verification scenarios
    fixture_path = os.path.join(ROOT, "fixtures/threshold_sig/verification_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("TS-FIXTURES", "Verification scenarios fixture", fixture_valid)

    # TS-VECTORS: Test vectors artifact
    vectors_path = os.path.join(ROOT, "artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json")
    vectors_valid = False
    if os.path.isfile(vectors_path):
        try:
            data = json.loads(Path(vectors_path).read_text())
            vectors_valid = "vectors" in data and len(data["vectors"]) >= 2
        except json.JSONDecodeError:
            pass
    all_pass &= check("TS-VECTORS", "Threshold signature test vectors", vectors_valid)

    # TS-SECURITY-TESTS: Security test file
    sec_path = os.path.join(ROOT, "tests/security/threshold_signature_verification.rs")
    sec_exists = os.path.isfile(sec_path)
    if sec_exists:
        content = Path(sec_path).read_text()
        has_quorum = "quorum" in content
        has_partial = "partial" in content
        has_duplicate = "duplicate" in content
    else:
        has_quorum = has_partial = has_duplicate = False
    all_pass &= check("TS-SECURITY-TESTS", "Security tests cover quorum, partial, duplicate",
                       sec_exists and has_quorum and has_partial and has_duplicate)

    # TS-TESTS: Rust unit tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "security::threshold_sig"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("TS-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("TS-TESTS", "Rust unit tests pass", False, str(e))

    # TS-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-35q1_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-THRESH" in content
        has_failure = "FailureReason" in content
    else:
        has_invariants = has_failure = False
    all_pass &= check("TS-SPEC", "Specification with invariants and failure reasons",
                       spec_exists and has_invariants and has_failure)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "threshold_sig_verification",
        "bead": "bd-35q1",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-35q1")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
