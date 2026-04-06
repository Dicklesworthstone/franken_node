#!/usr/bin/env python3
from pathlib import Path
"""Verification script for bd-w0jq: Degraded-mode audit events."""

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
    logger = configure_test_logging("check_degraded_mode_audit")
    print("bd-w0jq: Degraded-Mode Audit Events — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/degraded_mode_audit.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_event = "struct DegradedModeEvent" in content
        has_log = "struct DegradedModeAuditLog" in content
        has_error = "enum AuditError" in content
        has_validate = "fn validate_schema" in content
        has_emit = "fn emit" in content
        all_types = has_event and has_log and has_error and has_validate and has_emit
    else:
        all_types = False
    all_pass &= check("DM-IMPL", "Implementation with all required types",
                       impl_exists and all_types)

    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["DM_MISSING_FIELD", "DM_EVENT_NOT_FOUND", "DM_SCHEMA_VIOLATION"]
        found = [e for e in errors if e in content]
        all_pass &= check("DM-ERRORS", "All 3 error codes present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("DM-ERRORS", "Error codes", False)

    fixture_path = os.path.join(ROOT, "fixtures/security/degraded_mode_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.loads(Path(fixture_path).read_text())
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("DM-FIXTURES", "Degraded mode scenarios fixture", fixture_valid)

    events_path = os.path.join(ROOT, "artifacts/section_10_13/bd-w0jq/degraded_mode_events.jsonl")
    events_valid = False
    if os.path.isfile(events_path):
        lines = Path(events_path).read_text().strip().split("\n")
        try:
            entries = [json.loads(line) for line in lines]
            events_valid = len(entries) >= 2 and all(
                e.get("event_type") == "degraded_mode_override" for e in entries
            )
        except json.JSONDecodeError:
            pass
    all_pass &= check("DM-EVENTS", "Degraded mode events JSONL artifact", events_valid)

    conf_path = os.path.join(ROOT, "tests/conformance/degraded_mode_audit_events.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = Path(conf_path).read_text()
        has_required = "inv_dm_event_required" in content
        has_schema = "inv_dm_schema" in content
        has_corr = "inv_dm_correlation" in content
        has_immutable = "inv_dm_immutable" in content
    else:
        has_required = has_schema = has_corr = has_immutable = False
    all_pass &= check("DM-CONF-TESTS", "Conformance tests cover all 4 invariants",
                       conf_exists and has_required and has_schema and has_corr and has_immutable)

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--",
             "security::degraded_mode_audit"],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("DM-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("DM-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-w0jq_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-DM" in content
        has_types = "DegradedModeEvent" in content and "DegradedModeAuditLog" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("DM-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "degraded_mode_audit_verification",
        "bead": "bd-w0jq",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-w0jq")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
