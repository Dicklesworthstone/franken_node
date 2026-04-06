#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-2eun: Quarantine-by-default store."""

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
    logger = configure_test_logging("check_quarantine_store")
    print("bd-2eun: Quarantine-by-Default Store — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/quarantine_store.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_config = "struct QuarantineConfig" in content
        has_entry = "struct QuarantineEntry" in content
        has_stats = "struct QuarantineStats" in content
        has_store = "struct QuarantineStore" in content
        has_ingest = "fn ingest" in content
        has_evict = "fn evict_expired" in content
        all_types = has_config and has_entry and has_stats and has_store and has_ingest and has_evict
    else:
        all_types = False
    all_pass &= check("QDS-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["QDS_QUOTA_EXCEEDED", "QDS_TTL_EXPIRED", "QDS_DUPLICATE",
                  "QDS_NOT_FOUND", "QDS_INVALID_CONFIG"]
        found = [e for e in errors if e in content]
        all_pass &= check("QDS-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("QDS-ERRORS", "Error codes", False)

    csv_path = os.path.join(ROOT, "artifacts/section_10_13/bd-2eun/quarantine_usage_metrics.csv")
    csv_valid = False
    if os.path.isfile(csv_path):
        content = Path(csv_path).read_text()
        lines = [l for l in content.strip().split("\n") if l.strip()]
        csv_valid = len(lines) >= 4
    all_pass &= check("QDS-METRICS", "Quarantine usage metrics CSV", csv_valid)

    integ_path = os.path.join(ROOT, "tests/integration/quarantine_retention.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_default = "inv_qds_default" in content
        has_bounded = "inv_qds_bounded" in content
        has_ttl = "inv_qds_ttl" in content
        has_excluded = "inv_qds_excluded" in content
    else:
        has_default = has_bounded = has_ttl = has_excluded = False
    all_pass &= check("QDS-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_default and has_bounded and has_ttl and has_excluded)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::quarantine_store"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("QDS-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("QDS-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2eun_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-QDS" in content
        has_types = "QuarantineConfig" in content and "QuarantineEntry" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("QDS-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "quarantine_store_verification",
        "bead": "bd-2eun",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-2eun")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
