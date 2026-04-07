#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-3ua7: Sandbox Profile System."""

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
    logger = configure_test_logging("check_sandbox_profiles")
    print("bd-3ua7: Sandbox Profile System — Verification\n")
    all_pass = True

    # SANDBOX-IMPL: Implementation file with all types
    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/sandbox_policy_compiler.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_profile = "enum SandboxProfile" in content
        has_compiler = "fn compile_policy" in content
        has_tracker = "struct ProfileTracker" in content
        has_audit = "struct ProfileAuditRecord" in content
        all_types = has_profile and has_compiler and has_tracker and has_audit
    else:
        all_types = False
    all_pass &= check("SANDBOX-IMPL", "Implementation with profiles, compiler, tracker, audit",
                      impl_exists and all_types)

    # SANDBOX-PROFILES: All 4 profiles
    if impl_exists:
        content = Path(impl_path).read_text()
        profiles = ["Strict", "StrictPlus", "Moderate", "Permissive"]
        found = [p for p in profiles if p in content]
        all_pass &= check("SANDBOX-PROFILES", "All 4 profiles defined",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("SANDBOX-PROFILES", "All 4 profiles defined", False)

    # SANDBOX-CAPABILITIES: 6 capabilities
    if impl_exists:
        content = Path(impl_path).read_text()
        caps = ["network_access", "fs_read", "fs_write", "process_exec", "ipc", "env_access"]
        found = [c for c in caps if c in content]
        all_pass &= check("SANDBOX-CAPABILITIES", "All 6 capabilities defined",
                          len(found) == 6, f"found {len(found)}/6")
    else:
        all_pass &= check("SANDBOX-CAPABILITIES", "All 6 capabilities", False)

    # SANDBOX-ERRORS: All 4 error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["SANDBOX_DOWNGRADE_BLOCKED", "SANDBOX_PROFILE_UNKNOWN",
                  "SANDBOX_POLICY_CONFLICT", "SANDBOX_COMPILE_ERROR"]
        found = [e for e in errors if e in content]
        all_pass &= check("SANDBOX-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("SANDBOX-ERRORS", "All 4 error codes", False)

    # SANDBOX-FIXTURES: Fixture files
    fixture_dir = os.path.join(ROOT, "fixtures/sandbox_profiles")
    expected = ["profile_capabilities.json", "downgrade_scenarios.json"]
    found_fixtures = [f for f in expected if os.path.isfile(os.path.join(fixture_dir, f))]
    all_pass &= check("SANDBOX-FIXTURES", "Fixture files for capabilities and downgrades",
                      len(found_fixtures) == len(expected),
                      f"found {len(found_fixtures)}/{len(expected)}")

    # SANDBOX-COMPILER-OUTPUT: Compiled output artifact
    output_path = os.path.join(ROOT, "artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json")
    output_valid = False
    if os.path.isfile(output_path):
        try:
            data = json.loads(Path(output_path).read_text())
            output_valid = "compiled_policies" in data and len(data["compiled_policies"]) == 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("SANDBOX-COMPILER-OUTPUT", "Compiled policy output for all 4 profiles",
                      output_valid)

    # SANDBOX-CONFORMANCE: Conformance test file
    conf_path = os.path.join(ROOT, "tests/conformance/sandbox_profile_conformance.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = Path(conf_path).read_text()
        has_order = "order" in content.lower()
        has_downgrade = "downgrade" in content.lower()
        has_audit = "audit" in content.lower()
        all_aspects = has_order and has_downgrade and has_audit
    else:
        all_aspects = False
    all_pass &= check("SANDBOX-CONFORMANCE", "Conformance tests cover ordering, downgrade, audit",
                      conf_exists and all_aspects)

    # SANDBOX-TESTS: Rust tests pass
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "security::sandbox_policy_compiler"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = sum(int(m) for m in matches)
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("SANDBOX-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("SANDBOX-TESTS", "Rust unit tests pass", False, str(e))

    # SANDBOX-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3ua7_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-SANDBOX" in content
        has_profiles = "strict" in content and "moderate" in content and "permissive" in content
    else:
        has_invariants = has_profiles = False
    all_pass &= check("SANDBOX-SPEC", "Specification with invariants and profile definitions",
                      spec_exists and has_invariants and has_profiles)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "sandbox_profile_verification",
        "bead": "bd-3ua7",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-3ua7")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
