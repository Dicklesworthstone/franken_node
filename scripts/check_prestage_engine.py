#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-2t5u: Predictive pre-staging engine."""

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
    logger = configure_test_logging("check_prestage_engine")
    print("bd-2t5u: Predictive Pre-staging Engine — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/prestage_engine.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_config = "struct PrestageConfig" in content
        has_candidate = "struct ArtifactCandidate" in content
        has_decision = "struct PrestageDecision" in content
        has_report = "struct PrestageReport" in content
        has_evaluate = "fn evaluate_candidates" in content
        has_quality = "fn measure_quality" in content
        all_types = has_config and has_candidate and has_decision and has_report and has_evaluate and has_quality
    else:
        all_types = False
    all_pass &= check("PSE-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["PSE_BUDGET_EXCEEDED", "PSE_INVALID_CONFIG", "PSE_NO_CANDIDATES", "PSE_THRESHOLD_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("PSE-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("PSE-ERRORS", "Error codes", False)

    report_path = os.path.join(ROOT, "artifacts/section_10_13/bd-2t5u/prestaging_model_report.csv")
    report_valid = False
    if os.path.isfile(report_path):
        content = Path(report_path).read_text()
        lines = [l for l in content.strip().split("\n") if l.strip()]
        report_valid = len(lines) >= 4  # header + 3 data rows minimum
    all_pass &= check("PSE-REPORT", "Pre-staging model report CSV", report_valid)

    integ_path = os.path.join(ROOT, "tests/integration/prestaging_coverage_improvement.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_budget = "inv_pse_budget" in content
        has_coverage = "inv_pse_coverage" in content
        has_det = "inv_pse_deterministic" in content
        has_quality = "inv_pse_quality" in content
    else:
        has_budget = has_coverage = has_det = has_quality = False
    all_pass &= check("PSE-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_budget and has_coverage and has_det and has_quality)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::prestage_engine"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("PSE-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("PSE-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2t5u_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-PSE" in content
        has_types = "PrestageEngine" in content and "PrestageConfig" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("PSE-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "prestage_engine_verification",
        "bead": "bd-2t5u",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-2t5u")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
