#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-1vvs: Strict-Plus Isolation Backend."""

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
    logger = configure_test_logging("check_isolation_backend")
    print("bd-1vvs: Strict-Plus Isolation Backend — Verification\n")
    all_pass = True

    # ISOL-IMPL: Implementation file with core types
    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/isolation_backend.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_backend = "enum IsolationBackend" in content
        has_caps = "struct PlatformCapabilities" in content
        has_select = "fn select_backend" in content
        has_verify = "fn verify_policy_enforcement" in content
        all_types = has_backend and has_caps and has_select and has_verify
    else:
        all_types = False
    all_pass &= check("ISOL-IMPL", "Implementation with backends, capabilities, selection, verification",
                      impl_exists and all_types)

    # ISOL-BACKENDS: All 4 backends
    if impl_exists:
        content = Path(impl_path).read_text()
        backends = ["MicroVm", "Hardened", "OsSandbox", "Container"]
        found = [b for b in backends if b in content]
        all_pass &= check("ISOL-BACKENDS", "All 4 isolation backends defined",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("ISOL-BACKENDS", "All 4 backends", False)

    # ISOL-ERRORS: All 4 error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["ISOLATION_BACKEND_UNAVAILABLE", "ISOLATION_PROBE_FAILED",
                  "ISOLATION_INIT_FAILED", "ISOLATION_POLICY_MISMATCH"]
        found = [e for e in errors if e in content]
        all_pass &= check("ISOL-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("ISOL-ERRORS", "All 4 error codes", False)

    # ISOL-FIXTURES: Fixture files
    fixture_path = os.path.join(ROOT, "fixtures/isolation/backend_selection_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("ISOL-FIXTURES", "Backend selection fixture with scenarios", fixture_valid)

    # ISOL-MATRIX: Runtime matrix CSV
    matrix_path = os.path.join(ROOT, "artifacts/section_10_13/bd-1vvs/strict_plus_runtime_matrix.csv")
    matrix_valid = False
    if os.path.isfile(matrix_path):
        content = Path(matrix_path).read_text()
        matrix_valid = "microvm" in content and "hardened" in content and "os_sandbox" in content
    all_pass &= check("ISOL-MATRIX", "Runtime matrix CSV with all backends", matrix_valid)

    # ISOL-INTEGRATION: Integration test file
    integ_path = os.path.join(ROOT, "tests/integration/strict_plus_isolation.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_e2e = "end_to_end" in content
        has_fallback = "fallback" in content
        has_policy = "policy" in content.lower()
    else:
        has_e2e = has_fallback = has_policy = False
    all_pass &= check("ISOL-INTEGRATION", "Integration tests with e2e, fallback, policy checks",
                      integ_exists and has_e2e and has_fallback and has_policy)

    # ISOL-TESTS: Rust tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "security::isolation_backend"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("ISOL-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("ISOL-TESTS", "Rust unit tests pass", False, str(e))

    # ISOL-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1vvs_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-STRICT-PLUS" in content
        has_backends = "microvm" in content and "hardened" in content
    else:
        has_invariants = has_backends = False
    all_pass &= check("ISOL-SPEC", "Specification with invariants and backend matrix",
                      spec_exists and has_invariants and has_backends)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "isolation_backend_verification",
        "bead": "bd-1vvs",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-1vvs")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
