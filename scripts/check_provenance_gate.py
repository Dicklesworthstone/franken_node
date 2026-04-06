#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-3i9o: Provenance/attestation policy gates."""

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

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "supply_chain::provenance_gate"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("PG-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("PG-TESTS", "Rust unit tests pass", False, str(e))

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
