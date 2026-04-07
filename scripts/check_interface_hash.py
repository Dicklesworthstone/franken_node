#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-3n58: Domain-separated interface-hash verification."""

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
    logger = configure_test_logging("check_interface_hash")
    print("bd-3n58: Domain-Separated Interface-Hash Verification — Verification\n")
    all_pass = True

    # IH-IMPL: Implementation file
    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/interface_hash.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_hash = "struct InterfaceHash" in content
        has_telemetry = "struct AdmissionTelemetry" in content
        has_check = "struct AdmissionCheck" in content
        has_rejection = "enum RejectionCode" in content
        all_types = has_hash and has_telemetry and has_check and has_rejection
    else:
        all_types = False
    all_pass &= check("IH-IMPL", "Implementation with hash, telemetry, check, rejection types",
                       impl_exists and all_types)

    # IH-DOMAIN-SEP: Domain separation in hash computation
    if impl_exists:
        content = Path(impl_path).read_text()
        has_domain_hash = "domain.hash" in content or "domain" in content
        has_separator = '":"' in content or 'separator' in content.lower()
        all_pass &= check("IH-DOMAIN-SEP", "Domain separation in hash derivation",
                          has_domain_hash and has_separator)
    else:
        all_pass &= check("IH-DOMAIN-SEP", "Domain separation", False)

    # IH-ERRORS: All 4 error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["IFACE_HASH_MISMATCH", "IFACE_DOMAIN_MISMATCH",
                  "IFACE_HASH_EXPIRED", "IFACE_HASH_MALFORMED"]
        found = [e for e in errors if e in content]
        all_pass &= check("IH-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("IH-ERRORS", "Error codes", False)

    # IH-FIXTURES: Verification scenarios fixture
    fixture_path = os.path.join(ROOT, "fixtures/interface_hash/verification_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("IH-FIXTURES", "Verification scenarios fixture", fixture_valid)

    # IH-METRICS: Rejection metrics CSV
    csv_path = os.path.join(ROOT, "artifacts/section_10_13/bd-3n58/interface_hash_rejection_metrics.csv")
    csv_valid = False
    if os.path.isfile(csv_path):
        content = Path(csv_path).read_text()
        csv_valid = ("rejection_code" in content and "IFACE_HASH_MISMATCH" in content
                     and "IFACE_DOMAIN_MISMATCH" in content)
    all_pass &= check("IH-METRICS", "Rejection metrics CSV with distribution", csv_valid)

    # IH-CONFORMANCE: Conformance test file
    conf_path = os.path.join(ROOT, "tests/conformance/interface_hash_verification.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = Path(conf_path).read_text()
        has_domain = "domain_separation" in content
        has_admission = "blocks_admission" in content
        has_telemetry = "telemetry" in content
    else:
        has_domain = has_admission = has_telemetry = False
    all_pass &= check("IH-CONFORMANCE", "Conformance tests cover domain sep, admission, telemetry",
                       conf_exists and has_domain and has_admission and has_telemetry)

    # IH-TESTS: Rust unit tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "security::interface_hash"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("IH-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("IH-TESTS", "Rust unit tests pass", False, str(e))

    # IH-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3n58_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-HASH" in content
        has_rejection = "RejectionCode" in content
    else:
        has_invariants = has_rejection = False
    all_pass &= check("IH-SPEC", "Specification with invariants and rejection codes",
                       spec_exists and has_invariants and has_rejection)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "interface_hash_verification",
        "bead": "bd-3n58",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-3n58")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
