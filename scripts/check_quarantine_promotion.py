#!/usr/bin/env python3
"""Verification script for bd-3cm3: Schema-gated quarantine promotion."""

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
    print("bd-3cm3: Schema-Gated Quarantine Promotion — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/quarantine_promotion.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_rule = "struct PromotionRule" in content
        has_request = "struct PromotionRequest" in content
        has_receipt = "struct ProvenanceReceipt" in content
        has_result = "struct PromotionResult" in content
        has_eval = "fn evaluate_promotion" in content
        all_types = has_rule and has_request and has_receipt and has_result and has_eval
    else:
        all_types = False
    all_pass &= check("QPR-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["QPR_SCHEMA_FAILED", "QPR_NOT_AUTHENTICATED", "QPR_NOT_REACHABLE",
                  "QPR_NOT_PINNED", "QPR_INVALID_RULE"]
        found = [e for e in errors if e in content]
        all_pass &= check("QPR-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("QPR-ERRORS", "Error codes", False)

    report_path = os.path.join(ROOT, "artifacts/section_10_13/bd-3cm3/quarantine_promotion_receipts.json")
    report_valid = False
    if os.path.isfile(report_path):
        try:
            data = json.load(open(report_path))
            report_valid = "receipts" in data and len(data["receipts"]) >= 1
        except json.JSONDecodeError:
            pass
    all_pass &= check("QPR-RECEIPTS", "Promotion receipts fixture", report_valid)

    integ_path = os.path.join(ROOT, "tests/integration/quarantine_promotion_gate.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_schema = "inv_qpr_schema_gated" in content
        has_auth = "inv_qpr_authenticated" in content
        has_receipt = "inv_qpr_receipt" in content
        has_fail = "inv_qpr_fail_closed" in content
    else:
        has_schema = has_auth = has_receipt = has_fail = False
    all_pass &= check("QPR-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_schema and has_auth and has_receipt and has_fail)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::quarantine_promotion"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("QPR-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("QPR-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3cm3_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-QPR" in content
        has_types = "PromotionRule" in content and "ProvenanceReceipt" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("QPR-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "quarantine_promotion_verification",
        "bead": "bd-3cm3",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-3cm3")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
