#!/usr/bin/env python3
"""Verification script for bd-1d7n: Deterministic activation pipeline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL_PATH = ROOT / "crates/franken-node/src/connector/activation_pipeline.rs"
FIXTURE_PATH = ROOT / "fixtures/activation/pipeline_scenarios.json"
TRANSCRIPT_PATH = ROOT / "artifacts/section_10_13/bd-1d7n/activation_stage_transcript.jsonl"
INTEGRATION_PATH = ROOT / "tests/integration/activation_pipeline_determinism.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-1d7n_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-1d7n/verification_evidence.json"


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


def run_rust_tests() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [
                "rch",
                "exec",
                "--",
                "cargo",
                "test",
                "-p",
                "frankenengine-node",
                "--",
                "connector::activation_pipeline",
            ],
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=ROOT / "crates/franken-node",
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)

    test_output = result.stdout + result.stderr
    matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
    rust_tests = sum(int(match) for match in matches)
    tests_pass = result.returncode == 0 and rust_tests > 0
    return tests_pass, f"{rust_tests} tests passed"


def build_evidence(checks: list[dict[str, str]], mode: str) -> dict[str, object]:
    passing = sum(1 for check_entry in checks if check_entry["status"] == "PASS")
    failing = sum(1 for check_entry in checks if check_entry["status"] == "FAIL")
    skipped = sum(1 for check_entry in checks if check_entry["status"] == "SKIP")
    total = len(checks)
    return {
        "gate": "activation_pipeline_verification",
        "bead": "bd-1d7n",
        "section": "10.13",
        "mode": mode,
        "verdict": "PASS" if failing == 0 else "FAIL",
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
        print("bd-1d7n: Deterministic Activation Pipeline - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_stage = "enum ActivationStage" in content
        has_result = "struct StageResult" in content
        has_transcript = "struct ActivationTranscript" in content
        has_error = "enum StageError" in content
        has_activate = "fn activate" in content
        has_default_fail_closed = (
            "struct DefaultExecutor" in content
            and "ACTIVATION_EXECUTOR_REQUIRED" in content
            and "Err(ACTIVATION_EXECUTOR_REQUIRED.to_string())" in content
        )
        has_fixture_executor = "struct FixtureActivationExecutor" in content
        all_types = (
            has_stage
            and has_result
            and has_transcript
            and has_error
            and has_activate
            and has_default_fail_closed
            and has_fixture_executor
        )
    else:
        all_types = False
    check(
        checks,
        "AP-IMPL",
        "Implementation with required types, fail-closed default, fixture executor, and activate fn",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        stages = ["SandboxCreate", "SecretMount", "CapabilityIssue", "HealthReady"]
        found = [stage for stage in stages if stage in content]
        check(
            checks,
            "AP-STAGES",
            "All 4 activation stages present",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "AP-STAGES", "Activation stages", False, emit_human=emit_human)

    if content is not None:
        errors = [
            "ACT_SANDBOX_FAILED",
            "ACT_SECRET_MOUNT_FAILED",
            "ACT_CAPABILITY_FAILED",
            "ACT_HEALTH_FAILED",
        ]
        found = [error_code for error_code in errors if error_code in content]
        check(
            checks,
            "AP-ERRORS",
            "All 4 error codes present",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "AP-ERRORS", "Error codes", False, emit_human=emit_human)

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
        "AP-FIXTURES",
        "Pipeline scenarios fixture",
        fixture_valid,
        emit_human=emit_human,
    )

    transcript_valid = False
    transcript_content = read_utf8(TRANSCRIPT_PATH)
    if transcript_content is not None:
        lines = transcript_content.strip().split("\n")
        try:
            entries = [json.loads(line) for line in lines]
            has_events = any(e.get("event") == "activation_complete" for e in entries)
            has_stages = any(e.get("event") == "stage_complete" for e in entries)
            transcript_valid = has_events and has_stages and len(entries) >= 4
        except json.JSONDecodeError:
            pass
    check(
        checks,
        "AP-TRANSCRIPT",
        "Stage transcript artifact",
        transcript_valid,
        emit_human=emit_human,
    )

    integration_content = read_utf8(INTEGRATION_PATH)
    integ_exists = integration_content is not None
    if integration_content is not None:
        has_order = "inv_act_stage_order" in integration_content
        has_health = "inv_act_health_last" in integration_content
        has_determ = "inv_act_deterministic" in integration_content
        has_secret = "inv_act_no_secret_leak" in integration_content
    else:
        has_order = has_health = has_determ = has_secret = False
    check(
        checks,
        "AP-INTEG-TESTS",
        "Integration tests cover all 4 invariants",
        integ_exists and has_order and has_health and has_determ and has_secret,
        emit_human=emit_human,
    )

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "AP-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "AP-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-ACT" in spec_content
        has_stages_spec = "SandboxCreate" in spec_content and "HealthReady" in spec_content
    else:
        has_invariants = has_stages_spec = False
    check(
        checks,
        "AP-SPEC",
        "Specification with invariants and stages",
        spec_exists and has_invariants and has_stages_spec,
        emit_human=emit_human,
    )

    if content is not None:
        has_cleanup = "tracker.cleanup()" in content
        has_no_leak = "NO-SECRET-LEAK" in content or "no_secret_leak" in content.lower() or "cleanup" in content.lower()
    else:
        has_cleanup = has_no_leak = False
    check(
        checks,
        "AP-SECRET-CLEANUP",
        "Secret cleanup on failure path",
        has_cleanup and has_no_leak,
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
        help="write artifacts/section_10_13/bd-1d7n/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only/--skip-rust are mutually exclusive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run_tests = args.run_rust_tests or (not args.json and not args.structural_only)
    write_artifact = args.write_evidence or not args.json
    logger = configure_test_logging("check_activation_pipeline")
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
