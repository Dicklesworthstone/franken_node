#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-29w6: Offline coverage tracker and SLO dashboards."""

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
    logger = configure_test_logging("check_offline_coverage")
    print("bd-29w6: Offline Coverage Tracker — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/offline_coverage.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_tracker = "struct OfflineCoverageTracker" in content
        has_metrics = "struct CoverageMetrics" in content
        has_slo = "struct SloTarget" in content
        has_alert = "struct SloBreachAlert" in content
        has_snapshot = "struct DashboardSnapshot" in content
        has_record = "fn record_event" in content
        has_compute = "fn compute_metrics" in content
        all_types = has_tracker and has_metrics and has_slo and has_alert and has_snapshot and has_record and has_compute
    else:
        all_types = False
    all_pass &= check("OCT-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["OCT_SLO_BREACH", "OCT_INVALID_EVENT", "OCT_NO_EVENTS", "OCT_SCOPE_UNKNOWN"]
        found = [e for e in errors if e in content]
        all_pass &= check("OCT-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("OCT-ERRORS", "Error codes", False)

    snap_path = os.path.join(ROOT, "artifacts/section_10_13/bd-29w6/offline_slo_dashboard_snapshot.json")
    snap_valid = False
    if os.path.isfile(snap_path):
        try:
            data = json.loads(Path(snap_path).read_text())
            snap_valid = "snapshots" in data and len(data["snapshots"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("OCT-FIXTURES", "SLO dashboard snapshot fixtures", snap_valid)

    integ_path = os.path.join(ROOT, "tests/integration/offline_coverage_metrics.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_cont = "inv_oct_continuous" in content
        has_breach = "inv_oct_slo_breach" in content
        has_trace = "inv_oct_traceable" in content
        has_det = "inv_oct_deterministic" in content
    else:
        has_cont = has_breach = has_trace = has_det = False
    all_pass &= check("OCT-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_cont and has_breach and has_trace and has_det)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::offline_coverage"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("OCT-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("OCT-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-29w6_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-OCT" in content
        has_types = "OfflineCoverageTracker" in content and "CoverageMetrics" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("OCT-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "offline_coverage_verification",
        "bead": "bd-29w6",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-29w6")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
