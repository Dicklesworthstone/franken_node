#!/usr/bin/env python3
"""bd-2igi: Verify Bayesian posterior diagnostics implementation.

Usage:
  python3 scripts/check_bayesian_diagnostics.py          # human-readable
  python3 scripts/check_bayesian_diagnostics.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "bayesian_diagnostics.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-2igi_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
DIAGNOSTICS_REPORT = ROOT / "artifacts" / "10.14" / "posterior_diagnostics_report.json"

REQUIRED_TYPES = [
    "pub struct BayesianDiagnostics",
    "pub struct CandidateRef",
    "pub struct Observation",
    "pub struct RankedCandidate",
    "pub enum DiagnosticConfidence",
    "struct BetaState",
]

REQUIRED_METHODS = [
    "fn new(",
    "fn update(",
    "fn rank_candidates(",
    "fn replay_from(",
    "fn total_observations(",
    "fn overall_confidence(",
    "fn to_json(",
    "fn candidates_seen(",
    "fn with_epoch(",
    "fn mean(",
    "fn confidence_interval_95(",
]

EVENT_CODES = [
    "EVD-BAYES-001",
    "EVD-BAYES-002",
    "EVD-BAYES-003",
    "EVD-BAYES-004",
]

INVARIANTS = [
    "INV-BAYES-ADVISORY",
    "INV-BAYES-REPRODUCIBLE",
    "INV-BAYES-NORMALIZED",
    "INV-BAYES-TRANSPARENT",
]

REQUIRED_TESTS = [
    "test_new_is_empty",
    "test_default_is_empty",
    "test_with_epoch",
    "test_update_single_success",
    "test_update_single_failure",
    "test_update_chaining",
    "test_rank_empty_candidates",
    "test_rank_no_observations_uniform",
    "test_rank_with_observations",
    "test_rank_posterior_sums_to_one",
    "test_rank_descending_order",
    "test_confidence_interval_bounds",
    "test_confidence_interval_narrows",
    "test_guardrail_filtered_flag",
    "test_guardrail_does_not_reorder",
    "test_replay_from_reproducible",
    "test_replay_from_empty",
    "test_replay_matches_incremental",
    "test_uniform_prior_converges",
    "test_contradictory_observations",
    "test_overall_confidence_low",
    "test_overall_confidence_medium",
    "test_overall_confidence_high",
    "test_single_candidate",
    "test_many_candidates",
    "test_unobserved_candidate",
    "test_serialization_roundtrip",
    "test_ranked_candidate_serialization",
    "test_event_codes_defined",
    "test_prior_prob_reflects_candidate_count",
    "test_observation_count_per_candidate",
]


def check_file(path, label):
    ok = path.is_file()
    rel = str(path.relative_to(ROOT)) if ok else str(path)
    return {"check": f"file: {label}", "pass": ok,
            "detail": f"exists: {rel}" if ok else f"MISSING: {rel}"}


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = path.read_text()
    for p in patterns:
        found = p in content
        results.append({"check": f"{category}: {p}", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"check": "module registered", "pass": False, "detail": "mod.rs missing"}
    content = MOD_RS.read_text()
    found = "bayesian_diagnostics" in content
    return {"check": "module registered in mod.rs", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_test_count():
    if not IMPL.is_file():
        return {"check": "test count", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "unit test count", "pass": count >= 25,
            "detail": f"{count} tests (minimum 25)"}


def check_btreemap_usage():
    if not IMPL.is_file():
        return {"check": "BTreeMap for determinism", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "BTreeMap" in content
    return {"check": "BTreeMap for deterministic ordering", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_beta_distribution():
    if not IMPL.is_file():
        return {"check": "Beta distribution conjugate update", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "BetaState" in content and "alpha" in content and "beta" in content
    return {"check": "Beta distribution conjugate update", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_serialization():
    if not IMPL.is_file():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "Serialize" in content and "Deserialize" in content
    return {"check": "Serialize/Deserialize derives", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def self_test():
    result = run_checks()
    all_pass = result["verdict"] == "PASS"
    return all_pass, result["checks"]


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(DIAGNOSTICS_REPORT, "diagnostics report"))
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_btreemap_usage())
    checks.append(check_beta_distribution())
    checks.append(check_serialization())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    test_count = len(re.findall(r"#\[test\]", IMPL.read_text())) if IMPL.is_file() else 0
    return {
        "bead_id": "bd-2igi",
        "title": "Bayesian posterior diagnostics for explainable policy ranking",
        "section": "10.14",
        "overall_pass": passed == total,
        "verdict": "PASS" if passed == total else "FAIL",
        "test_count": test_count,
        "summary": {"passing": passed, "failing": total - passed, "total": total},
        "checks": checks,
    }


def main():
    if "--self-test" in sys.argv:
        ok, results = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'}")
        return

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== bd-2igi: Bayesian Diagnostics Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing']}/{s['total']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
