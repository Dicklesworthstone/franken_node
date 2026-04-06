#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-2k74: Per-peer admission budgets."""

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
    logger = configure_test_logging("check_admission_budget")
    print("bd-2k74: Per-Peer Admission Budgets — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/admission_budget.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_budget = "struct AdmissionBudget" in content
        has_usage = "struct PeerUsage" in content
        has_request = "struct AdmissionRequest" in content
        has_verdict = "struct AdmissionVerdict" in content
        has_tracker = "struct AdmissionBudgetTracker" in content
        has_check = "fn check_admission" in content
        has_admit = "fn admit" in content
        all_types = has_budget and has_usage and has_request and has_verdict and has_tracker and has_check and has_admit
    else:
        all_types = False
    all_pass &= check("PAB-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["PAB_BYTES_EXCEEDED", "PAB_SYMBOLS_EXCEEDED", "PAB_AUTH_EXCEEDED",
                  "PAB_INFLIGHT_EXCEEDED", "PAB_CPU_EXCEEDED", "PAB_INVALID_BUDGET"]
        found = [e for e in errors if e in content]
        all_pass &= check("PAB-ERRORS", "All 6 error codes present",
                          len(found) == 6, f"found {len(found)}/6")
    else:
        all_pass &= check("PAB-ERRORS", "Error codes", False)

    report_path = os.path.join(ROOT, "artifacts/section_10_13/bd-2k74/admission_budget_violation_report.json")
    report_valid = False
    if os.path.isfile(report_path):
        try:
            data = json.loads(Path(report_path).read_text())
            report_valid = "scenarios" in data and len(data["scenarios"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("PAB-REPORT", "Admission budget violation report", report_valid)

    integ_path = os.path.join(ROOT, "tests/integration/admission_budget_enforcement.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_enforced = "inv_pab_enforced" in content
        has_bounded = "inv_pab_bounded" in content
        has_audit = "inv_pab_auditable" in content
        has_det = "inv_pab_deterministic" in content
    else:
        has_enforced = has_bounded = has_audit = has_det = False
    all_pass &= check("PAB-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_enforced and has_bounded and has_audit and has_det)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::admission_budget"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("PAB-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("PAB-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2k74_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-PAB" in content
        has_types = "AdmissionBudget" in content and "PeerUsage" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("PAB-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "admission_budget_verification",
        "bead": "bd-2k74",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-2k74")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
