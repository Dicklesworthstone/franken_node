#!/usr/bin/env python3
"""Verification script for bd-w0jq: Degraded-mode audit events."""

import json
import os
import re
import subprocess
import sys

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

CHECKS = []
DEGRADED_MODE_UNIT_FILTER = "security::degraded_mode_audit"
DEGRADED_MODE_CONFORMANCE_TARGET = "degraded_mode_audit_events"
DEGRADED_MODE_TEST_TIMEOUT_SECONDS = int(
    os.environ.get("FRANKEN_NODE_DEGRADED_MODE_TEST_TIMEOUT_SECONDS", "600")
)
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


def run_degraded_mode_unit_tests():
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
            DEGRADED_MODE_UNIT_FILTER,
        ],
        capture_output=True,
        text=True,
        timeout=DEGRADED_MODE_TEST_TIMEOUT_SECONDS,
        cwd=ROOT,
    )
    output = result.stdout + result.stderr
    summary = parse_rust_test_summary(output)
    summary["returncode"] = result.returncode
    return summary, output


def run_degraded_mode_conformance_tests():
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
            DEGRADED_MODE_CONFORMANCE_TARGET,
        ],
        capture_output=True,
        text=True,
        timeout=DEGRADED_MODE_TEST_TIMEOUT_SECONDS,
        cwd=ROOT,
    )
    output = result.stdout + result.stderr
    summary = parse_rust_test_summary(output)
    summary["returncode"] = result.returncode
    return summary, output


def main():
    CHECKS.clear()
    logger = configure_test_logging("check_degraded_mode_audit")
    print("bd-w0jq: Degraded-Mode Audit Events — Verification\n")
    all_pass = True

    impl_path = ROOT / "crates/franken-node/src/security/degraded_mode_audit.rs"
    impl_exists = impl_path.is_file()
    if impl_exists:
        content = impl_path.read_text(encoding="utf-8")
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
        content = impl_path.read_text(encoding="utf-8")
        errors = ["DM_MISSING_FIELD", "DM_EVENT_NOT_FOUND", "DM_SCHEMA_VIOLATION"]
        found = [e for e in errors if e in content]
        all_pass &= check("DM-ERRORS", "All 3 error codes present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("DM-ERRORS", "Error codes", False)

    fixture_path = ROOT / "fixtures/security/degraded_mode_scenarios.json"
    fixture_valid = False
    if fixture_path.is_file():
        try:
            data = json.loads(fixture_path.read_text(encoding="utf-8"))
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("DM-FIXTURES", "Degraded mode scenarios fixture", fixture_valid)

    events_path = ROOT / "artifacts/section_10_13/bd-w0jq/degraded_mode_events.jsonl"
    events_valid = False
    if events_path.is_file():
        lines = events_path.read_text(encoding="utf-8").strip().split("\n")
        try:
            entries = [json.loads(line) for line in lines]
            events_valid = len(entries) >= 2 and all(
                e.get("event_type") == "degraded_mode_override" for e in entries
            )
        except json.JSONDecodeError:
            pass
    all_pass &= check("DM-EVENTS", "Degraded mode events JSONL artifact", events_valid)

    conf_path = ROOT / "tests/conformance/degraded_mode_audit_events.rs"
    conf_exists = conf_path.is_file()
    if conf_exists:
        content = conf_path.read_text(encoding="utf-8")
        has_required = "inv_dm_event_required" in content
        has_schema = "inv_dm_schema" in content
        has_corr = "inv_dm_correlation" in content
        has_immutable = "inv_dm_immutable" in content
    else:
        has_required = has_schema = has_corr = has_immutable = False
    all_pass &= check("DM-CONF-TESTS", "Conformance tests cover all 4 invariants",
                       conf_exists and has_required and has_schema and has_corr and has_immutable)

    harness_path = ROOT / "crates/franken-node/tests/degraded_mode_audit_events.rs"
    harness_exists = harness_path.is_file()
    if harness_exists:
        harness_content = harness_path.read_text(encoding="utf-8")
        harness_wired = "../../../tests/conformance/degraded_mode_audit_events.rs" in harness_content
    else:
        harness_wired = False
    all_pass &= check(
        "DM-HARNESS",
        "Cargo harness wires degraded-mode conformance tests",
        harness_exists and harness_wired,
    )

    try:
        unit_summary, unit_output = run_degraded_mode_unit_tests()
        conformance_summary, conformance_output = run_degraded_mode_conformance_tests()
        unit_ok = (
            unit_summary["returncode"] == 0
            and unit_summary["running"] > 0
            and unit_summary["passed"] > 0
            and unit_summary["failed"] == 0
        )
        conformance_ok = (
            conformance_summary["returncode"] == 0
            and conformance_summary["running"] > 0
            and conformance_summary["passed"] > 0
            and conformance_summary["failed"] == 0
        )
        tests_pass = unit_ok and conformance_ok
        details = (
            f"unit {unit_summary['passed']} passed / {unit_summary['running']} ran / {unit_summary['filtered']} filtered; "
            f"conformance {conformance_summary['passed']} passed / {conformance_summary['running']} ran / {conformance_summary['filtered']} filtered"
        )
        if not tests_pass:
            failure_excerpt = select_failure_excerpt(
                unit_output if not unit_ok else "",
                conformance_output if not conformance_ok else "",
            )
            if failure_excerpt:
                details = (
                    f"{details}; rc=({unit_summary['returncode']}, {conformance_summary['returncode']}); "
                    f"{failure_excerpt}"
                )
        all_pass &= check(
            "DM-TESTS",
            "Rust degraded-mode unit and conformance tests pass",
            tests_pass,
            details,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check(
            "DM-TESTS",
            "Rust degraded-mode unit and conformance tests pass",
            False,
            str(e),
        )

    spec_path = ROOT / "docs/specs/section_10_13/bd-w0jq_contract.md"
    spec_exists = spec_path.is_file()
    if spec_exists:
        content = spec_path.read_text(encoding="utf-8")
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

    evidence_dir = ROOT / "artifacts/section_10_13/bd-w0jq"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    with (evidence_dir / "verification_evidence.json").open("w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
