#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-jxgt: Execution planner scorer."""

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
    logger = configure_test_logging("check_execution_scorer")
    print("bd-jxgt: Execution Planner Scorer — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/execution_scorer.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_weights = "struct ScoringWeights" in content
        has_input = "struct CandidateInput" in content
        has_scored = "struct ScoredCandidate" in content
        has_decision = "struct PlannerDecision" in content
        has_score_fn = "fn score_candidates" in content
        has_validate = "fn validate_weights" in content
        all_types = has_weights and has_input and has_scored and has_decision and has_score_fn and has_validate
    else:
        all_types = False
    all_pass &= check("EPS-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["EPS_INVALID_WEIGHTS", "EPS_NO_CANDIDATES", "EPS_INVALID_INPUT", "EPS_SCORE_OVERFLOW"]
        found = [e for e in errors if e in content]
        all_pass &= check("EPS-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("EPS-ERRORS", "Error codes", False)

    fixtures_path = os.path.join(ROOT, "artifacts/section_10_13/bd-jxgt/planner_decision_explanations.json")
    fixtures_valid = False
    if os.path.isfile(fixtures_path):
        try:
            data = json.loads(Path(fixtures_path).read_text())
            fixtures_valid = "scenarios" in data and len(data["scenarios"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("EPS-FIXTURES", "Planner decision explanation fixtures", fixtures_valid)

    integ_path = os.path.join(ROOT, "tests/integration/execution_planner_determinism.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_det = "inv_eps_deterministic" in content
        has_tie = "inv_eps_tiebreak" in content
        has_exp = "inv_eps_explainable" in content
        has_rej = "inv_eps_reject_invalid" in content
    else:
        has_det = has_tie = has_exp = has_rej = False
    all_pass &= check("EPS-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_det and has_tie and has_exp and has_rej)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::execution_scorer"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("EPS-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("EPS-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-jxgt_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-EPS" in content
        has_types = "ExecutionScorer" in content and "ScoringWeights" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("EPS-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "execution_scorer_verification",
        "bead": "bd-jxgt",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-jxgt")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
