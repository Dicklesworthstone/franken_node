#!/usr/bin/env python3
"""Verification script for bd-w0jq: Degraded-mode audit events."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL_PATH = ROOT / "crates/franken-node/src/security/degraded_mode_audit.rs"
FIXTURE_PATH = ROOT / "fixtures/security/degraded_mode_scenarios.json"
EVENTS_PATH = ROOT / "artifacts/section_10_13/bd-w0jq/degraded_mode_events.jsonl"
CONFORMANCE_PATH = ROOT / "tests/conformance/degraded_mode_audit_events.rs"
HARNESS_PATH = ROOT / "crates/franken-node/tests/degraded_mode_audit_events.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-w0jq_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-w0jq/verification_evidence.json"
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


def read_utf8(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def record_check(
    checks: list[dict[str, str]],
    check_id: str,
    description: str,
    status: str,
    details: str | None = None,
    *,
    emit_human: bool,
) -> bool:
    entry = {"id": check_id, "description": description, "status": status}
    if details:
        entry["details"] = details
    checks.append(entry)
    if emit_human:
        print(f"  [{status}] {check_id}: {description}")
        if details:
            print(f"         {details}")
    return status == "PASS"


def check(
    checks: list[dict[str, str]],
    check_id: str,
    description: str,
    passed: bool,
    details: str | None = None,
    *,
    emit_human: bool,
) -> bool:
    return record_check(
        checks,
        check_id,
        description,
        "PASS" if passed else "FAIL",
        details,
        emit_human=emit_human,
    )


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


def build_evidence(checks: list[dict[str, str]], mode: str) -> dict[str, object]:
    passing = sum(1 for check_entry in checks if check_entry["status"] == "PASS")
    failing = sum(1 for check_entry in checks if check_entry["status"] == "FAIL")
    skipped = sum(1 for check_entry in checks if check_entry["status"] == "SKIP")
    total = len(checks)
    verdict = "FAIL" if failing else "PARTIAL" if skipped else "PASS"
    return {
        "gate": "degraded_mode_audit_verification",
        "bead": "bd-w0jq",
        "section": "10.13",
        "mode": mode,
        "verdict": verdict,
        "checks": checks,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": failing,
            "skipped_checks": skipped,
        },
    }


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-w0jq: Degraded-Mode Audit Events - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_event = "struct DegradedModeEvent" in content
        has_log = "struct DegradedModeAuditLog" in content
        has_error = "enum AuditError" in content
        has_validate = "fn validate_schema" in content
        has_emit = "fn emit" in content
        all_types = has_event and has_log and has_error and has_validate and has_emit
    else:
        all_types = False
    check(
        checks,
        "DM-IMPL",
        "Implementation with all required types",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        errors = ["DM_MISSING_FIELD", "DM_EVENT_NOT_FOUND", "DM_SCHEMA_VIOLATION"]
        found = [e for e in errors if e in content]
        check(
            checks,
            "DM-ERRORS",
            "All 3 error codes present",
            len(found) == 3,
            f"found {len(found)}/3",
            emit_human=emit_human,
        )
    else:
        check(checks, "DM-ERRORS", "Error codes", False, emit_human=emit_human)

    fixture_valid = False
    fixture_content = read_utf8(FIXTURE_PATH)
    if fixture_content is not None:
        try:
            data = json.loads(fixture_content)
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    check(
        checks,
        "DM-FIXTURES",
        "Degraded mode scenarios fixture",
        fixture_valid,
        emit_human=emit_human,
    )

    events_valid = False
    events_content = read_utf8(EVENTS_PATH)
    if events_content is not None:
        lines = events_content.strip().split("\n")
        try:
            entries = [json.loads(line) for line in lines]
            events_valid = len(entries) >= 2 and all(
                e.get("event_type") == "degraded_mode_override" for e in entries
            )
        except json.JSONDecodeError:
            pass
    check(
        checks,
        "DM-EVENTS",
        "Degraded mode events JSONL artifact",
        events_valid,
        emit_human=emit_human,
    )

    conformance_content = read_utf8(CONFORMANCE_PATH)
    conf_exists = conformance_content is not None
    if conformance_content is not None:
        has_required = "inv_dm_event_required" in conformance_content
        has_schema = "inv_dm_schema" in conformance_content
        has_corr = "inv_dm_correlation" in conformance_content
        has_immutable = "inv_dm_immutable" in conformance_content
    else:
        has_required = has_schema = has_corr = has_immutable = False
    check(
        checks,
        "DM-CONF-TESTS",
        "Conformance tests cover all 4 invariants",
        conf_exists and has_required and has_schema and has_corr and has_immutable,
        emit_human=emit_human,
    )

    harness_content = read_utf8(HARNESS_PATH)
    harness_exists = harness_content is not None
    if harness_content is not None:
        harness_wired = "../../../tests/conformance/degraded_mode_audit_events.rs" in harness_content
    else:
        harness_wired = False
    check(
        checks,
        "DM-HARNESS",
        "Cargo harness wires degraded-mode conformance tests",
        harness_exists and harness_wired,
        emit_human=emit_human,
    )

    if run_tests:
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
            check(
                checks,
                "DM-TESTS",
                "Rust degraded-mode unit and conformance tests pass",
                tests_pass,
                details,
                emit_human=emit_human,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            check(
                checks,
                "DM-TESTS",
                "Rust degraded-mode unit and conformance tests pass",
                False,
                str(e),
                emit_human=emit_human,
            )
    else:
        record_check(
            checks,
            "DM-TESTS",
            "Rust degraded-mode unit and conformance tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-DM" in spec_content
        has_types = "DegradedModeEvent" in spec_content and "DegradedModeAuditLog" in spec_content
    else:
        has_invariants = has_types = False
    check(
        checks,
        "DM-SPEC",
        "Specification with invariants and types",
        spec_exists and has_invariants and has_types,
        emit_human=emit_human,
    )

    evidence = build_evidence(checks, "full" if run_tests else "structural")
    if emit_human:
        summary = evidence["summary"]
        print(
            f"\nResult: {summary['passing_checks']}/{summary['total_checks']} checks passed"
            f" ({summary['skipped_checks']} skipped)"
        )
    return evidence


def write_evidence(path: Path, evidence: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit evidence JSON to stdout")
    parser.add_argument(
        "--run-rust-tests",
        action="store_true",
        help="run the expensive rch cargo test proof even in JSON mode",
    )
    parser.add_argument(
        "--structural-only",
        "--skip-rust",
        action="store_true",
        dest="structural_only",
        help="skip the expensive Rust test proof and only validate checked-in structure",
    )
    parser.add_argument(
        "--write-evidence",
        action="store_true",
        help="write artifacts/section_10_13/bd-w0jq/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only/--skip-rust are mutually exclusive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run_tests = args.run_rust_tests or (not args.json and not args.structural_only)
    write_artifact = args.write_evidence or not args.json
    logger = configure_test_logging("check_degraded_mode_audit")
    logger.info(
        "starting verification",
        extra={"json_mode": args.json, "run_rust_tests": run_tests, "write_evidence": write_artifact},
    )

    evidence = run_checks(run_tests=run_tests, emit_human=not args.json)

    if write_artifact:
        write_evidence(EVIDENCE_PATH, evidence)

    if args.json:
        print(json.dumps(evidence, indent=2))

    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
