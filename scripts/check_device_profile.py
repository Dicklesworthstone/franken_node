#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-8vby: Device profile registry and placement policy."""

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
    logger = configure_test_logging("check_device_profile")
    print("bd-8vby: Device Profile Registry — Verification\n")
    all_pass = True

    # DPR-IMPL: Implementation exists with required types
    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/device_profile.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_profile = "struct DeviceProfile" in content
        has_constraint = "struct PlacementConstraint" in content
        has_policy = "struct PlacementPolicy" in content
        has_result = "struct PlacementResult" in content
        has_registry = "struct DeviceProfileRegistry" in content
        has_validate = "fn validate_profile" in content
        has_evaluate = "fn evaluate_placement" in content
        all_types = has_profile and has_constraint and has_policy and has_result and has_registry and has_validate and has_evaluate
    else:
        all_types = False
    all_pass &= check("DPR-IMPL", "Implementation with all required types", impl_exists and all_types)

    # DPR-ERRORS: All error codes present
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["DPR_SCHEMA_INVALID", "DPR_STALE_PROFILE", "DPR_INVALID_CONSTRAINT", "DPR_NO_MATCH"]
        found = [e for e in errors if e in content]
        all_pass &= check("DPR-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("DPR-ERRORS", "Error codes", False)

    # DPR-FIXTURES: Device profile examples
    fixtures_path = os.path.join(ROOT, "artifacts/section_10_13/bd-8vby/device_profile_examples.json")
    fixtures_valid = False
    if os.path.isfile(fixtures_path):
        try:
            data = json.loads(Path(fixtures_path).read_text())
            fixtures_valid = "profiles" in data and len(data["profiles"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("DPR-FIXTURES", "Device profile example fixtures", fixtures_valid)

    # DPR-CONF: Conformance tests exist and cover invariants
    conf_path = os.path.join(ROOT, "tests/conformance/placement_policy_schema.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = Path(conf_path).read_text()
        has_schema = "inv_dpr_schema" in content
        has_freshness = "inv_dpr_freshness" in content
        has_deterministic = "inv_dpr_deterministic" in content
        has_reject = "inv_dpr_reject_invalid" in content
    else:
        has_schema = has_freshness = has_deterministic = has_reject = False
    all_pass &= check("DPR-CONF", "Conformance tests cover all 4 invariants",
                       conf_exists and has_schema and has_freshness and has_deterministic and has_reject)

    # DPR-TESTS: Rust unit tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::device_profile"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("DPR-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("DPR-TESTS", "Rust unit tests pass", False, str(e))

    # DPR-SPEC: Specification with invariants
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-8vby_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-DPR" in content
        has_types = "DeviceProfileRegistry" in content and "PlacementPolicy" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("DPR-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "device_profile_verification",
        "bead": "bd-8vby",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-8vby")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
