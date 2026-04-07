#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-1nk5: SSRF-deny default policy template."""

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
    logger = configure_test_logging("check_ssrf_policy")
    print("bd-1nk5: SSRF-Deny Default Policy Template — Verification\n")
    all_pass = True

    # SSRF-IMPL: Implementation file exists with key types
    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/ssrf_policy.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_template = "struct SsrfPolicyTemplate" in content
        has_cidr = "struct CidrRange" in content
        has_receipt = "struct PolicyReceipt" in content
        has_allowlist = "struct AllowlistEntry" in content
        all_types = has_template and has_cidr and has_receipt and has_allowlist
    else:
        all_types = False
    all_pass &= check("SSRF-IMPL", "Implementation with template, CIDR, receipt, allowlist types",
                       impl_exists and all_types)

    # SSRF-CIDRS: All 7 standard CIDR ranges
    if impl_exists:
        content = Path(impl_path).read_text()
        cidrs = ["127, 0, 0, 0", "10, 0, 0, 0", "172, 16, 0, 0",
                 "192, 168, 0, 0", "169, 254, 0, 0", "100, 64, 0, 0", "0, 0, 0, 0"]
        found = sum(1 for c in cidrs if c in content)
        all_pass &= check("SSRF-CIDRS", "All 7 standard CIDR ranges present",
                          found == 7, f"found {found}/7")
    else:
        all_pass &= check("SSRF-CIDRS", "CIDR ranges", False)

    # SSRF-ERRORS: All 4 error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["SSRF_DENIED", "SSRF_INVALID_IP", "SSRF_RECEIPT_MISSING", "SSRF_TEMPLATE_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("SSRF-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("SSRF-ERRORS", "Error codes", False)

    # SSRF-TOML: Default policy TOML
    toml_path = os.path.join(ROOT, "config/policies/network_guard_default.toml")
    toml_exists = os.path.isfile(toml_path)
    if toml_exists:
        content = Path(toml_path).read_text()
        has_cidrs = "blocked_cidrs" in content
        has_template = "ssrf_deny_default" in content
    else:
        has_cidrs = has_template = False
    all_pass &= check("SSRF-TOML", "Default policy TOML with blocked CIDRs",
                       toml_exists and has_cidrs and has_template)

    # SSRF-FIXTURES: Deny scenarios fixture
    fixture_path = os.path.join(ROOT, "fixtures/ssrf_policy/ssrf_deny_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 8
        except json.JSONDecodeError:
            pass
    all_pass &= check("SSRF-FIXTURES", "SSRF deny scenarios fixture with cases",
                       fixture_valid)

    # SSRF-REPORT: Test report artifact
    report_path = os.path.join(ROOT, "artifacts/section_10_13/bd-1nk5/ssrf_policy_test_report.json")
    report_valid = False
    if os.path.isfile(report_path):
        try:
            data = json.loads(Path(report_path).read_text())
            report_valid = "ssrf_patterns_tested" in data and data.get("verdict") == "PASS"
        except json.JSONDecodeError:
            pass
    all_pass &= check("SSRF-REPORT", "SSRF policy test report", report_valid)

    # SSRF-SECURITY-TESTS: Security test file
    sec_path = os.path.join(ROOT, "tests/security/ssrf_default_deny.rs")
    sec_exists = os.path.isfile(sec_path)
    if sec_exists:
        content = Path(sec_path).read_text()
        has_deny = "denies_" in content
        has_allow = "allows_" in content
        has_allowlist = "allowlist" in content
        has_audit = "audit" in content
    else:
        has_deny = has_allow = has_allowlist = has_audit = False
    all_pass &= check("SSRF-SECURITY-TESTS", "Security tests cover deny, allow, allowlist, audit",
                       sec_exists and has_deny and has_allow and has_allowlist and has_audit)

    # SSRF-TESTS: Rust unit tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "security::ssrf_policy"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("SSRF-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("SSRF-TESTS", "Rust unit tests pass", False, str(e))

    # SSRF-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1nk5_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-SSRF" in content
        has_receipt = "PolicyReceipt" in content
    else:
        has_invariants = has_receipt = False
    all_pass &= check("SSRF-SPEC", "Specification with invariants and receipt schema",
                       spec_exists and has_invariants and has_receipt)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "ssrf_policy_verification",
        "bead": "bd-1nk5",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-1nk5")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
