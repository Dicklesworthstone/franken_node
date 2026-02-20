#!/usr/bin/env python3
"""Verification script for bd-12h8: Artifact persistence with replay hooks."""

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
    print("bd-12h8: Artifact Persistence with Replay Hooks — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/artifact_persistence.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_type = "enum ArtifactType" in content
        has_persisted = "struct PersistedArtifact" in content
        has_hook = "struct ReplayHook" in content
        has_store = "struct ArtifactStore" in content
        has_persist = "fn persist" in content
        has_replay = "fn replay_hooks" in content
        all_types = has_type and has_persisted and has_hook and has_store and has_persist and has_replay
    else:
        all_types = False
    all_pass &= check("PRA-IMPL", "Implementation with all required types", impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["PRA_UNKNOWN_TYPE", "PRA_DUPLICATE", "PRA_SEQUENCE_GAP",
                  "PRA_REPLAY_MISMATCH", "PRA_INVALID_ARTIFACT"]
        found = [e for e in errors if e in content]
        all_pass &= check("PRA-ERRORS", "All 5 error codes present",
                          len(found) == 5, f"found {len(found)}/5")
    else:
        all_pass &= check("PRA-ERRORS", "Error codes", False)

    fixture_path = os.path.join(ROOT, "artifacts/section_10_13/bd-12h8/artifact_replay_fixtures.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.load(open(fixture_path))
            fixture_valid = "fixtures" in data and len(data["fixtures"]) >= 6
        except json.JSONDecodeError:
            pass
    all_pass &= check("PRA-FIXTURES", "Replay fixtures with all 6 artifact types", fixture_valid)

    integ_path = os.path.join(ROOT, "tests/integration/artifact_replay_hooks.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = open(integ_path).read()
        has_complete = "inv_pra_complete" in content
        has_durable = "inv_pra_durable" in content
        has_replay = "inv_pra_replay" in content
        has_ordered = "inv_pra_ordered" in content
    else:
        has_complete = has_durable = has_replay = has_ordered = False
    all_pass &= check("PRA-INTEG", "Integration tests cover all 4 invariants",
                       integ_exists and has_complete and has_durable and has_replay and has_ordered)

    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::artifact_persistence"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("PRA-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("PRA-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-12h8_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-PRA" in content
        has_types = "ArtifactType" in content and "PersistedArtifact" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("PRA-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "artifact_persistence_verification",
        "bead": "bd-12h8",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-12h8")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
