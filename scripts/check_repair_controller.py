#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-91gg: Background repair controller."""

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
    logger = configure_test_logging("check_repair_controller")
    print("bd-91gg: Background Repair Controller — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/repair_controller.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_config = "struct RepairConfig" in content
        has_item = "struct RepairItem" in content
        has_alloc = "struct RepairAllocation" in content
        has_audit = "struct RepairCycleAudit" in content
        has_run = "fn run_cycle" in content
        all_types = has_config and has_item and has_alloc and has_audit and has_run
    else:
        all_types = False
    all_pass &= check("BRC-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["BRC_CAP_EXCEEDED", "BRC_INVALID_CONFIG", "BRC_NO_PENDING", "BRC_STARVATION"]
        found = [e for e in errors if e in content]
        all_pass &= check("BRC-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("BRC-ERRORS", "Error codes", False)

    csv_path = os.path.join(ROOT, "artifacts/section_10_13/bd-91gg/repair_cycle_telemetry.csv")
    csv_valid = False
    if os.path.isfile(csv_path):
        content = Path(csv_path).read_text()
        lines = [l for l in content.strip().split("\n") if l.strip()]
        csv_valid = len(lines) >= 4
    all_pass &= check("BRC-TELEMETRY", "Repair cycle telemetry CSV", csv_valid)

    integ_path = os.path.join(ROOT, "tests/integration/repair_fairness.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_bounded = "inv_brc_bounded" in content
        has_fairness = "inv_brc_fairness" in content
        has_audit = "inv_brc_auditable" in content
        has_det = "inv_brc_deterministic" in content
    else:
        has_bounded = has_fairness = has_audit = has_det = False
    all_pass &= check("BRC-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_bounded and has_fairness and has_audit and has_det)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::repair_controller"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("BRC-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("BRC-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-91gg_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-BRC" in content
        has_types = "BackgroundRepairController" in content and "RepairConfig" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("BRC-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "repair_controller_verification",
        "bead": "bd-91gg",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-91gg")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
