#!/usr/bin/env python3
"""Verification script for bd-b44: State Schema Version Contracts."""

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
SCHEMA_MIGRATION_TEST_TARGET = "state_migration_contract"
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


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
    running = sum(int(m) for m in re.findall(r"running (\d+) test(?:s)?", output))
    result_matches = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
        output,
    )
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


def run_schema_migration_tests():
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
            SCHEMA_MIGRATION_TEST_TARGET,
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
    logger = configure_test_logging("check_schema_migration")
    print("bd-b44: State Schema Migration — Verification\n")
    all_pass = True

    # MIGRATE-IMPL: Implementation file exists
    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/schema_migration.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = Path(impl_path).read_text()
        has_version = "struct SchemaVersion" in content
        has_contract = "struct SchemaContract" in content
        has_hint = "struct MigrationHint" in content
        has_registry = "struct MigrationRegistry" in content
        has_plan = "struct MigrationPlan" in content
        all_types = has_version and has_contract and has_hint and has_registry and has_plan
    else:
        all_types = False
    all_pass &= check("MIGRATE-IMPL", "Implementation with all core types", impl_exists and all_types)

    # MIGRATE-HINTS: All 4 hint types
    if impl_exists:
        content = Path(impl_path).read_text()
        hints = ["AddField", "RemoveField", "RenameField", "Transform"]
        found = [h for h in hints if h in content]
        all_pass &= check("MIGRATE-HINTS", "All 4 hint types (add/remove/rename/transform)",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("MIGRATE-HINTS", "All 4 hint types", False)

    # MIGRATE-ERRORS: All 4 error codes
    if impl_exists:
        content = Path(impl_path).read_text()
        errors = ["MIGRATION_PATH_MISSING", "MIGRATION_ALREADY_APPLIED",
                  "MIGRATION_ROLLBACK_FAILED", "SCHEMA_VERSION_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("MIGRATE-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("MIGRATE-ERRORS", "All 4 error codes", False)

    # MIGRATE-IDEMPOTENT: Idempotency check function
    if impl_exists:
        content = Path(impl_path).read_text()
        has_idemp = "fn check_idempotency" in content
        all_pass &= check("MIGRATE-IDEMPOTENT", "Idempotency check function", has_idemp)
    else:
        all_pass &= check("MIGRATE-IDEMPOTENT", "Idempotency check function", False)

    # MIGRATE-FIXTURES: Fixture files
    fixture_dir = os.path.join(ROOT, "fixtures/schema_migration")
    expected = ["migration_paths.json", "idempotency_scenarios.json"]
    found_fixtures = [f for f in expected if os.path.isfile(os.path.join(fixture_dir, f))]
    all_pass &= check("MIGRATE-FIXTURES", "Migration fixture files",
                      len(found_fixtures) == len(expected),
                      f"found {len(found_fixtures)}/{len(expected)}")

    # MIGRATE-RECEIPTS: Receipts artifact
    receipts_path = os.path.join(ROOT, "artifacts/section_10_13/bd-b44/state_migration_receipts.json")
    receipts_valid = False
    if os.path.isfile(receipts_path):
        try:
            data = json.loads(Path(receipts_path).read_text())
            receipts_valid = "receipts" in data and len(data["receipts"]) > 0
        except json.JSONDecodeError:
            pass
    all_pass &= check("MIGRATE-RECEIPTS", "Migration receipts artifact", receipts_valid)

    # MIGRATE-INTEGRATION: Integration test file
    integ_path = os.path.join(ROOT, "tests/integration/state_migration_contract.rs")
    integ_exists = os.path.isfile(integ_path)
    if integ_exists:
        content = Path(integ_path).read_text()
        has_e2e = "end_to_end" in content
        has_idemp = "idempotent" in content
        has_range = "range_check" in content or "contract" in content
    else:
        has_e2e = has_idemp = has_range = False
    all_pass &= check("MIGRATE-INTEGRATION", "Integration tests with e2e, idempotency, contract checks",
                      integ_exists and has_e2e and has_idemp and has_range)

    # MIGRATE-HARNESS: Cargo integration harness exists
    harness_path = os.path.join(ROOT, "crates/franken-node/tests/state_migration_contract.rs")
    harness_exists = os.path.isfile(harness_path)
    if harness_exists:
        harness_content = Path(harness_path).read_text()
        harness_wired = "../../../tests/integration/state_migration_contract.rs" in harness_content
    else:
        harness_wired = False
    all_pass &= check(
        "MIGRATE-HARNESS",
        "Cargo harness wires the schema migration integration test target",
        harness_exists and harness_wired,
    )

    # MIGRATE-TESTS: Rust tests pass
    try:
        summary, output = run_schema_migration_tests()
        tests_pass = (
            summary["returncode"] == 0
            and summary["running"] > 0
            and summary["passed"] > 0
            and summary["failed"] == 0
        )
        details = f"{summary['passed']} passed / {summary['running']} ran / {summary['filtered']} filtered"
        if not tests_pass:
            failure_excerpt = summarize_failure_output(output)
            if failure_excerpt:
                details = f"{details}; rc={summary['returncode']}; {failure_excerpt}"
        all_pass &= check(
            "MIGRATE-TESTS",
            "Rust schema migration integration tests pass",
            tests_pass,
            details,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check(
            "MIGRATE-TESTS",
            "Rust schema migration integration tests pass",
            False,
            str(e),
        )

    # MIGRATE-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-b44_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = Path(spec_path).read_text()
        has_invariants = "INV-MIGRATE" in content
        has_hints = "add_field" in content and "remove_field" in content
    else:
        has_invariants = has_hints = False
    all_pass &= check("MIGRATE-SPEC", "Specification with invariants and hint types",
                      spec_exists and has_invariants and has_hints)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "schema_migration_verification",
        "bead": "bd-b44",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-b44")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
