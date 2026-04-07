#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-3b8m: Anti-amplification response bounds."""

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
    logger = configure_test_logging("check_anti_amplification")
    print("bd-3b8m: Anti-Amplification Response Bounds — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/anti_amplification.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_policy = "struct AmplificationPolicy" in content
        has_bound = "struct ResponseBound" in content
        has_request = "struct BoundCheckRequest" in content
        has_verdict = "struct BoundCheckVerdict" in content
        has_check = "fn check_response_bound" in content
        has_harness = "fn run_adversarial_harness" in content
        all_types = has_policy and has_bound and has_request and has_verdict and has_check and has_harness
    else:
        all_types = False
    all_pass &= check("AAR-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["AAR_RESPONSE_TOO_LARGE", "AAR_RATIO_EXCEEDED", "AAR_UNAUTH_LIMIT",
                  "AAR_ITEMS_EXCEEDED", "AAR_INVALID_POLICY"]
        found = [e for e in errors if e in content]
        all_pass &= check("AAR-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("AAR-ERRORS", "Error codes", False)

    report_path = os.path.join(ROOT, "artifacts/section_10_13/bd-3b8m/anti_amplification_test_results.json")
    report_valid = False
    if os.path.isfile(report_path):
        try:
            data = json.loads(Path(report_path).read_text())
            report_valid = "scenarios" in data and len(data["scenarios"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("AAR-REPORT", "Adversarial traffic test results", report_valid)

    integ_path = os.path.join(ROOT, "tests/integration/anti_amplification_harness.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_bounded = "inv_aar_bounded" in content
        has_unauth = "inv_aar_unauth_strict" in content
        has_audit = "inv_aar_auditable" in content
        has_det = "inv_aar_deterministic" in content
    else:
        has_bounded = has_unauth = has_audit = has_det = False
    all_pass &= check("AAR-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_bounded and has_unauth and has_audit and has_det)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::anti_amplification"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("AAR-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("AAR-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3b8m_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-AAR" in content
        has_types = "AmplificationPolicy" in content and "BoundCheckRequest" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("AAR-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "anti_amplification_verification",
        "bead": "bd-3b8m",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-3b8m")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
