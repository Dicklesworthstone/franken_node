#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-29ct: Adversarial fuzz corpus gates."""

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
    logger = configure_test_logging("check_fuzz_corpus")
    print("bd-29ct: Adversarial Fuzz Corpus Gates — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/fuzz_corpus.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_fixture_adapter = "struct DeterministicFuzzTestAdapter" in content
        has_fixture_target = "struct DeterministicFuzzTarget" in content
        has_fixture_report = "struct DeterministicFuzzGateReport" in content
        has_fixture_run = "fn run_fixture_gate" in content
        has_fixture_marker = "synthetic_test_fixture" in content
        all_types = (
            has_fixture_adapter
            and has_fixture_target
            and has_fixture_report
            and has_fixture_run
            and has_fixture_marker
        )
        has_truthful_report = "struct TruthfulFuzzGateReport" in content
        has_truthful_target = "struct FuzzTargetDescriptor" in content
        has_truthful_run = "fn run_truthful_fuzz_gate" in content
    else:
        all_types = False
        has_truthful_report = has_truthful_target = has_truthful_run = False
    all_pass &= check(
        "FCG-IMPL",
        "Implementation exposes explicit deterministic fixture adapter types",
        impl_exists and all_types,
    )
    all_pass &= check(
        "FCG-LIVE-IMPL",
        "Truthful live gate surface present",
        impl_exists and has_truthful_report and has_truthful_target and has_truthful_run,
    )

    if impl_exists:
        content = Path(impl_path).read_text()
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
            data = json.loads(Path(summary_path).read_text())
            summary_valid = "targets" in data and len(data["targets"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("FCG-SUMMARY", "Fuzz campaign summary fixture", summary_valid)

    integ_path = os.path.join(ROOT, "tests/integration/fuzz_corpus_gates.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_targets = "inv_fcg_targets" in content
        has_corpus = "inv_fcg_corpus" in content
        has_triage = "inv_fcg_triage" in content
        has_gate = "inv_fcg_gate" in content
        has_fixture_marker_test = "fixture_gate_reports_explicit_test_adapter_marker" in content
        has_truthful_exec = "truthful_gate_executes_checked_in_targets" in content
        has_truthful_artifacts = "truthful_gate_reports_explicit_coverage_and_relative_artifacts" in content
    else:
        has_targets = has_corpus = has_triage = has_gate = False
        has_fixture_marker_test = False
        has_truthful_exec = has_truthful_artifacts = False
    all_pass &= check("FCG-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_targets and has_corpus and has_triage and has_gate)
    all_pass &= check(
        "FCG-FIXTURE-INTEG",
        "Integration tests prove the deterministic fixture adapter is explicitly marked",
        integ_exists and has_fixture_marker_test,
    )
    all_pass &= check(
        "FCG-LIVE-INTEG",
        "Integration tests cover truthful live gate execution/reporting",
        integ_exists and has_truthful_exec and has_truthful_artifacts,
    )

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::fuzz_corpus"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("FCG-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("FCG-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-29ct_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-FCG" in content
        has_types = "DeterministicFuzzTestAdapter" in content or "TruthfulFuzzGateReport" in content
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
