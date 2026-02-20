#!/usr/bin/env python3
"""Verification script for bd-29ct: Adversarial fuzz corpus gates."""

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
    print("bd-29ct: Adversarial Fuzz Corpus Gates — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/fuzz_corpus.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_corpus = "struct FuzzCorpus" in content
        has_target = "struct FuzzTarget" in content
        has_verdict = "struct FuzzGateVerdict" in content
        has_run = "fn run_gate" in content
        all_types = has_corpus and has_target and has_verdict and has_run
    else:
        all_types = False
    all_pass &= check("FCG-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["FCG_MISSING_TARGET", "FCG_INSUFFICIENT_CORPUS", "FCG_REGRESSION",
                  "FCG_UNTRIAGED_CRASH", "FCG_GATE_FAILED"]
        found = [e for e in errors if e in content]
        all_pass &= check("FCG-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("FCG-ERRORS", "Error codes", False)

    summary_path = os.path.join(ROOT, "artifacts/section_10_13/bd-29ct/fuzz_campaign_summary.json")
    summary_valid = False
    if os.path.isfile(summary_path):
        try:
            data = json.load(open(summary_path))
            summary_valid = "targets" in data and len(data["targets"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("FCG-SUMMARY", "Fuzz campaign summary fixture", summary_valid)

    integ_path = os.path.join(ROOT, "tests/integration/fuzz_corpus_gates.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_targets = "inv_fcg_targets" in content
        has_corpus = "inv_fcg_corpus" in content
        has_triage = "inv_fcg_triage" in content
        has_gate = "inv_fcg_gate" in content
    else:
        has_targets = has_corpus = has_triage = has_gate = False
    all_pass &= check("FCG-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_targets and has_corpus and has_triage and has_gate)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::fuzz_corpus"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("FCG-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("FCG-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-29ct_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-FCG" in content
        has_types = "FuzzCorpus" in content or "FuzzTarget" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("FCG-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "fuzz_corpus_verification",
        "bead": "bd-29ct",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-29ct")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
