#!/usr/bin/env python3
"""Verification script for bd-3i9o: Provenance/attestation policy gates."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

CHECKS = []
PROVENANCE_GATE_UNIT_FILTER = "supply_chain::provenance_gate"
PROVENANCE_GATE_SECURITY_TARGET = "attestation_gate"
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
TEST_RESULT_RE = re.compile(
    r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
    re.IGNORECASE,
)


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


def parse_rust_test_summary(output):
    running = sum(int(match) for match in re.findall(r"running (\d+) test(?:s)?", output))
    result_matches = TEST_RESULT_RE.findall(output)
    passed = sum(int(match[0]) for match in result_matches)
    failed = sum(int(match[1]) for match in result_matches)
    filtered = sum(int(match[4]) for match in result_matches)
    return {
        "running": running,
        "passed": passed,
        "failed": failed,
        "filtered": filtered,
    }


def summarize_failure_output(output, max_lines=6):
    cleaned_lines = [
        ANSI_ESCAPE_RE.sub("", line).strip() for line in output.splitlines()
    ]
    cleaned_lines = [line for line in cleaned_lines if line]
    error_start = next(
        (idx for idx, line in enumerate(cleaned_lines) if "error" in line.lower()),
        None,
    )
    snippet = (
        cleaned_lines[error_start:error_start + max_lines]
        if error_start is not None
        else cleaned_lines[:max_lines]
    )
    return " | ".join(snippet)


def select_failure_excerpt(*outputs):
    for output in outputs:
        excerpt = summarize_failure_output(output)
        if excerpt:
            return excerpt
    return ""


def run_gate_unit_tests():
    result = subprocess.run(
        [
            "rch",
            "exec",
            "--",
            "cargo",
            "test",
            "-p",
            "frankenengine-node",
            "--lib",
            "--",
            PROVENANCE_GATE_UNIT_FILTER,
        ],
        capture_output=True,
        text=True,
        timeout=3600,
        cwd=ROOT,
    )
    output = result.stdout + result.stderr
    summary = parse_rust_test_summary(output)
    summary["returncode"] = result.returncode
    return summary, output


def run_gate_security_tests():
    result = subprocess.run(
        [
            "rch",
            "exec",
            "--",
            "cargo",
            "test",
            "-p",
            "frankenengine-node",
            "--test",
            PROVENANCE_GATE_SECURITY_TARGET,
        ],
        capture_output=True,
        text=True,
        timeout=3600,
        cwd=ROOT,
    )
    output = result.stdout + result.stderr
    summary = parse_rust_test_summary(output)
    summary["returncode"] = result.returncode
    return summary, output


def main():
    CHECKS.clear()
    logger = configure_test_logging("check_provenance_gate")
    print("bd-3i9o: Provenance/Attestation Policy Gates — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/supply_chain/provenance_gate.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_policy = "struct ProvenancePolicy" in content
        has_prov = "struct ArtifactProvenance" in content
        has_gate = "struct GateDecision" in content
        has_eval = "fn evaluate_gate" in content
        all_types = has_policy and has_prov and has_gate and has_eval
    else:
        all_types = False
    all_pass &= check("PG-IMPL", "Implementation with policy, provenance, gate, evaluate",
                       impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        attest = ["Slsa", "Sigstore", "InToto"]
        found = [a for a in attest if a in content]
        all_pass &= check("PG-ATTEST", "Attestation types present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("PG-ATTEST", "Attestation types", False)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["PROV_ATTEST_MISSING", "PROV_ASSURANCE_LOW",
                  "PROV_BUILDER_UNTRUSTED", "PROV_POLICY_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("PG-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("PG-ERRORS", "Error codes", False)

    fixture_path = os.path.join(ROOT, "fixtures/provenance/gate_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("PG-FIXTURES", "Gate scenarios fixture", fixture_valid)

    decisions_path = os.path.join(ROOT, "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json")
    decisions_valid = False
    if os.path.isfile(decisions_path):
        try:
            data = json.loads(Path(decisions_path).read_text())
            decisions_valid = "decisions" in data and len(data["decisions"]) >= 2
        except json.JSONDecodeError:
            pass
    all_pass &= check("PG-DECISIONS", "Provenance gate decisions artifact", decisions_valid)

    sec_path = os.path.join(ROOT, "tests/security/attestation_gate.rs")
    sec_exists = os.path.isfile(sec_path)
    if sec_exists:
        content = Path(sec_path).read_text()
        has_attest = "attestation" in content.lower()
        has_assurance = "assurance" in content.lower()
        has_builder = "builder" in content.lower()
    else:
        has_attest = has_assurance = has_builder = False
    all_pass &= check("PG-SECURITY-TESTS", "Security tests cover attestation, assurance, builder",
                       sec_exists and has_attest and has_assurance and has_builder)

    harness_path = os.path.join(ROOT, "crates/franken-node/tests/attestation_gate.rs")
    harness_exists = os.path.isfile(harness_path)
    if harness_exists:
        harness_content = Path(harness_path).read_text()
        harness_wired = "../../../tests/security/attestation_gate.rs" in harness_content
    else:
        harness_wired = False
    all_pass &= check(
        "PG-HARNESS",
        "Cargo harness wires provenance gate security tests",
        harness_exists and harness_wired,
    )

    try:
        unit_summary, unit_output = run_gate_unit_tests()
        security_summary, security_output = run_gate_security_tests()
        unit_ok = (
            unit_summary["returncode"] == 0
            and unit_summary["running"] > 0
            and unit_summary["passed"] > 0
            and unit_summary["failed"] == 0
        )
        security_ok = (
            security_summary["returncode"] == 0
            and security_summary["running"] > 0
            and security_summary["passed"] > 0
            and security_summary["failed"] == 0
        )
        tests_pass = unit_ok and security_ok
        details = (
            f"unit {unit_summary['passed']} passed / {unit_summary['running']} ran / {unit_summary['filtered']} filtered; "
            f"security {security_summary['passed']} passed / {security_summary['running']} ran / {security_summary['filtered']} filtered"
        )
        if not tests_pass:
            failure_excerpt = select_failure_excerpt(
                unit_output if not unit_ok else "",
                security_output if not security_ok else "",
            )
            if failure_excerpt:
                details = (
                    f"{details}; rc=({unit_summary['returncode']}, {security_summary['returncode']}); "
                    f"{failure_excerpt}"
                )
        all_pass &= check(
            "PG-TESTS",
            "Rust provenance gate unit and security tests pass",
            tests_pass,
            details,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check(
            "PG-TESTS",
            "Rust provenance gate unit and security tests pass",
            False,
            str(e),
        )

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3i9o_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-PROV" in content
        has_gate = "GateDecision" in content or "GateFailure" in content
    else:
        has_invariants = has_gate = False
    all_pass &= check("PG-SPEC", "Specification with invariants and gate types",
                       spec_exists and has_invariants and has_gate)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "provenance_gate_verification",
        "bead": "bd-3i9o",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-3i9o")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
