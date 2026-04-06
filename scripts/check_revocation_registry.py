#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-y7lu: Revocation registry with monotonic heads."""

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
    logger = configure_test_logging("check_revocation_registry")
    print("bd-y7lu: Revocation Registry — Verification\n")
    all_pass = True

    # Check implementation
    impl_path = os.path.join(ROOT, "crates/franken-node/src/supply_chain/revocation_registry.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_head = "struct RevocationHead" in content
        has_registry = "struct RevocationRegistry" in content
        has_error = "enum RevocationError" in content
        has_advance = "fn advance_head" in content
        has_recover = "fn recover_from_log" in content
        has_revoked = "fn is_revoked" in content
        all_types = has_head and has_registry and has_error and has_advance and has_recover and has_revoked
    else:
        all_types = False
    all_pass &= check("RR-IMPL", "Implementation with all required types and methods",
                       impl_exists and all_types)

    # Check error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["REV_STALE_HEAD", "REV_ZONE_NOT_FOUND", "REV_RECOVERY_FAILED"]
        found = [e for e in errors if e in content]
        all_pass &= check("RR-ERRORS", "All 3 error codes present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("RR-ERRORS", "Error codes", False)

    # Check fixtures
    fixture_path = os.path.join(ROOT, "fixtures/revocation/registry_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("RR-FIXTURES", "Registry scenarios fixture", fixture_valid)

    # Check head history
    history_path = os.path.join(ROOT, "artifacts/section_10_13/bd-y7lu/revocation_head_history.json")
    history_valid = False
    if os.path.isfile(history_path):
        try:
            data = json.loads(Path(history_path).read_text())
            history_valid = "zones" in data and len(data["zones"]) >= 2
        except json.JSONDecodeError:
            pass
    all_pass &= check("RR-HISTORY", "Revocation head history artifact", history_valid)

    # Check conformance tests
    conf_path = os.path.join(ROOT, "tests/conformance/revocation_head_monotonicity.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = Path(conf_path).read_text()
        has_monotonic = "inv_rev_monotonic" in content
        has_stale = "inv_rev_stale" in content
        has_recoverable = "inv_rev_recoverable" in content
        has_isolated = "inv_rev_zone_isolated" in content
    else:
        has_monotonic = has_stale = has_recoverable = has_isolated = False
    all_pass &= check("RR-CONF-TESTS", "Conformance tests cover all 4 invariants",
                       conf_exists and has_monotonic and has_stale and has_recoverable and has_isolated)

    # Run Rust unit tests
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "supply_chain::revocation_registry"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("RR-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("RR-TESTS", "Rust unit tests pass", False, str(e))

    # Check spec
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-y7lu_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-REV" in content
        has_types = "RevocationHead" in content and "RevocationRegistry" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("RR-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "revocation_registry_verification",
        "bead": "bd-y7lu",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-y7lu")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
