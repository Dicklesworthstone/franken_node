#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-2yc4: Crash-loop detector with automatic rollback."""

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
    logger = configure_test_logging("check_crash_loop_detector")
    print("bd-2yc4: Crash-Loop Detector — Verification\n")
    all_pass = True

    # Check implementation
    impl_path = os.path.join(ROOT, "crates/franken-node/src/runtime/crash_loop_detector.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_config = "struct CrashLoopConfig" in content
        has_event = "struct CrashEvent" in content
        has_pin = "struct KnownGoodPin" in content
        has_decision = "struct RollbackDecision" in content
        has_detector = "struct CrashLoopDetector" in content
        has_evaluate = "fn evaluate" in content
        all_types = has_config and has_event and has_pin and has_decision and has_detector and has_evaluate
    else:
        all_types = False
    all_pass &= check("CLD-IMPL", "Implementation with all required types",
                       impl_exists and all_types)

    # Check error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["CLD_THRESHOLD_EXCEEDED", "CLD_NO_KNOWN_GOOD",
                  "CLD_PIN_UNTRUSTED", "CLD_COOLDOWN_ACTIVE"]
        found = [e for e in errors if e in content]
        all_pass &= check("CLD-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("CLD-ERRORS", "Error codes", False)

    # Check sliding window
    if impl_exists:
        content = Path(impl_path).read_text()
        has_window = "crashes_in_window" in content
        has_looping = "is_looping" in content
        has_cooldown = "in_cooldown" in content
        all_pass &= check("CLD-WINDOW", "Sliding window and cooldown logic",
                          has_window and has_looping and has_cooldown)
    else:
        all_pass &= check("CLD-WINDOW", "Sliding window", False)

    # Check fixtures
    fixture_path = os.path.join(ROOT, "fixtures/runtime/crash_loop_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("CLD-FIXTURES", "Crash loop scenarios fixture", fixture_valid)

    # Check incident bundle
    bundle_path = os.path.join(ROOT, "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json")
    bundle_valid = False
    if os.path.isfile(bundle_path):
        try:
            data = json.loads(Path(bundle_path).read_text())
            bundle_valid = "incidents" in data and len(data["incidents"]) >= 2
        except json.JSONDecodeError:
            pass
    all_pass &= check("CLD-BUNDLE", "Incident bundle artifact", bundle_valid)

    # Check integration tests
    integ_path = os.path.join(ROOT, "tests/integration/crash_loop_rollback.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_threshold = "inv_cld_threshold" in content
        has_rollback = "inv_cld_rollback" in content
        has_trust = "inv_cld_trust" in content
        has_audit = "inv_cld_audit" in content
    else:
        has_threshold = has_rollback = has_trust = has_audit = False
    all_pass &= check("CLD-INTEG-TESTS", "Integration tests cover all 4 invariants",
                       integ_exists and has_threshold and has_rollback and has_trust and has_audit)

    # Run Rust unit tests
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "runtime::crash_loop_detector"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("CLD-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("CLD-TESTS", "Rust unit tests pass", False, str(e))

    # Check spec
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2yc4_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-CLD" in content
        has_types = "RollbackDecision" in content and "CrashLoopConfig" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("CLD-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "crash_loop_detector_verification",
        "bead": "bd-2yc4",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-2yc4")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
