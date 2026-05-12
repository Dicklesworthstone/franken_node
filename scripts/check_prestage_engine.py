#!/usr/bin/env python3
"""Verification script for bd-2t5u: Predictive pre-staging engine."""

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

IMPL_PATH = ROOT / "crates/franken-node/src/connector/prestage_engine.rs"
REPORT_PATH = ROOT / "artifacts/section_10_13/bd-2t5u/prestaging_model_report.csv"
INTEGRATION_PATH = ROOT / "tests/integration/prestaging_coverage_improvement.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-2t5u_contract.md"
PLAN_SPEC_PATH = ROOT / "docs/specs/predictive_prestaging.md"
PLAN_PATH = ROOT / "docs/plans/PLAN_TO_CREATE_FRANKEN_NODE.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-2t5u/verification_evidence.json"


def read_utf8(path: Path) -> str | None:
    """Read a UTF-8 text file and return None for missing/unreadable paths."""
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
                "connector::prestage_engine",
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


def should_run_rust_tests(args: argparse.Namespace) -> bool:
    return args.run_rust_tests or not args.structural_only


def compute_verdict(*, failing: int, skipped: int, mode: str) -> str:
    if failing > 0:
        return "FAIL"
    if skipped > 0:
        return "PARTIAL" if mode == "structural" else "FAIL"
    return "PASS"


def build_evidence(checks: list[dict[str, str]], mode: str) -> dict[str, object]:
    passing = sum(1 for check_entry in checks if check_entry["status"] == "PASS")
    failing = sum(1 for check_entry in checks if check_entry["status"] == "FAIL")
    skipped = sum(1 for check_entry in checks if check_entry["status"] == "SKIP")
    total = len(checks)
    return {
        "gate": "prestage_engine_verification",
        "bead": "bd-2t5u",
        "section": "10.13",
        "mode": mode,
        "verdict": compute_verdict(failing=failing, skipped=skipped, mode=mode),
        "checks": checks,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": failing,
            "skipped_checks": skipped,
        },
    }


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
        action="store_true",
        help="skip the expensive Rust test proof and only validate checked-in structure",
    )
    parser.add_argument(
        "--write-evidence",
        action="store_true",
        help="write artifacts/section_10_13/bd-2t5u/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-2t5u: Predictive Pre-staging Engine - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_config = "struct PrestageConfig" in content
        has_candidate = "struct ArtifactCandidate" in content
        has_decision = "struct PrestageDecision" in content
        has_report = "struct PrestageReport" in content
        has_evaluate = "fn evaluate_candidates" in content
        has_quality = "fn measure_quality" in content
        all_types = has_config and has_candidate and has_decision and has_report and has_evaluate and has_quality
    else:
        all_types = False
    check(
        checks,
        "PSE-IMPL",
        "Implementation with all required types",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        errors = ["PSE_BUDGET_EXCEEDED", "PSE_INVALID_CONFIG", "PSE_NO_CANDIDATES", "PSE_THRESHOLD_INVALID"]
        found = [error_code for error_code in errors if error_code in content]
        check(
            checks,
            "PSE-ERRORS",
            "All 4 error codes present",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "PSE-ERRORS", "Error codes", False, emit_human=emit_human)

    report_valid = False
    report_details = None
    report_content = read_utf8(REPORT_PATH)
    if report_content is not None:
        lines = [line for line in report_content.splitlines() if line.strip()]
        header = lines[0] if lines else ""
        has_header = "scenario" in header and "precision" in header
        report_valid = len(lines) >= 4 and has_header
        report_details = f"found {max(len(lines) - 1, 0)} data rows"
    else:
        report_details = f"unable to read {REPORT_PATH}"
    check(
        checks,
        "PSE-REPORT",
        "Pre-staging model report CSV",
        report_valid,
        report_details,
        emit_human=emit_human,
    )

    integration_content = read_utf8(INTEGRATION_PATH)
    integ_exists = integration_content is not None
    if integration_content is not None:
        has_budget = "inv_pse_budget" in integration_content
        has_coverage = "inv_pse_coverage" in integration_content
        has_det = "inv_pse_deterministic" in integration_content
        has_quality = "inv_pse_quality" in integration_content
    else:
        has_budget = has_coverage = has_det = has_quality = False
    check(
        checks,
        "PSE-INTEG",
        "Integration tests cover all 4 invariants",
        integ_exists and has_budget and has_coverage and has_det and has_quality,
        emit_human=emit_human,
    )

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "PSE-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "PSE-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-PSE" in spec_content
        has_types = "PrestageEngine" in spec_content and "PrestageConfig" in spec_content
    else:
        has_invariants = has_types = False
    check(
        checks,
        "PSE-SPEC",
        "Specification with invariants and types",
        spec_exists and has_invariants and has_types,
        emit_human=emit_human,
    )

    plan_spec_content = read_utf8(PLAN_SPEC_PATH)
    plan_spec_valid = (
        plan_spec_content is not None
        and "docs/specs/section_10_13/bd-2t5u_contract.md" in plan_spec_content
        and "tests/integration/prestaging_coverage_improvement.rs" in plan_spec_content
        and "tests/perf/prestaging_coverage_improvement.rs" not in plan_spec_content
        and "INV-PSE-BUDGET" in plan_spec_content
        and "INV-PSE-QUALITY" in plan_spec_content
    )
    check(
        checks,
        "PSE-PLAN-SPEC",
        "Plan-level spec path bridges to canonical contract and integration test",
        plan_spec_valid,
        emit_human=emit_human,
    )

    plan_content = read_utf8(PLAN_PATH)
    plan_paths_valid = (
        plan_content is not None
        and "docs/specs/predictive_prestaging.md" in plan_content
        and "docs/specs/section_10_13/bd-2t5u_contract.md" in plan_content
        and "tests/integration/prestaging_coverage_improvement.rs" in plan_content
        and "artifacts/section_10_13/bd-2t5u/prestaging_model_report.csv" in plan_content
        and "tests/perf/prestaging_coverage_improvement.rs" not in plan_content
        and "artifacts/10.13/prestaging_model_report.csv" not in plan_content
    )
    check(
        checks,
        "PSE-PLAN-PATHS",
        "Project plan cites current pre-staging artifact paths",
        plan_paths_valid,
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


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run_tests = should_run_rust_tests(args)
    write_artifact = args.write_evidence or not args.json
    logger = configure_test_logging("check_prestage_engine")
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
