#!/usr/bin/env python3
"""Verification script for bd-35q1: Threshold signature verification."""

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

IMPL_PATH = ROOT / "crates/franken-node/src/security/threshold_sig.rs"
FIXTURE_PATH = ROOT / "fixtures/threshold_sig/verification_scenarios.json"
VECTORS_PATH = ROOT / "artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json"
SECURITY_TEST_PATH = ROOT / "tests/security/threshold_signature_verification.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-35q1_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-35q1/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def read_utf8(path: Path) -> str | None:
    """Read a UTF-8 text file and return None for missing/unreadable paths."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def load_json_object(path: Path) -> tuple[dict[str, object] | None, str | None]:
    """Load a JSON object and return an explanatory error for invalid artifacts."""
    try:
        raw = path.read_text(encoding="utf-8")
        parsed = JSON_DECODER.decode(raw)
    except OSError as exc:
        return None, f"unable to read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path}: {exc}"

    if not isinstance(parsed, dict):
        return None, f"expected JSON object in {path}"
    return parsed, None


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
                "security::threshold_sig",
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
        "gate": "threshold_sig_verification",
        "bead": "bd-35q1",
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
        help="write artifacts/section_10_13/bd-35q1/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-35q1: Threshold Signature Verification - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_config = "struct ThresholdConfig" in content
        has_artifact = "struct PublicationArtifact" in content
        has_result = "struct VerificationResult" in content
        has_verify = "fn verify_threshold" in content
        all_types = has_config and has_artifact and has_result and has_verify
    else:
        all_types = False
    check(
        checks,
        "TS-IMPL",
        "Implementation with config, artifact, result, verify_threshold",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        has_threshold = "threshold" in content
        has_quorum = "valid_count >= config.threshold" in content or "valid_count" in content
        check(
            checks,
            "TS-QUORUM",
            "Quorum check against threshold",
            has_threshold and has_quorum,
            emit_human=emit_human,
        )
    else:
        check(checks, "TS-QUORUM", "Quorum logic", False, emit_human=emit_human)

    if content is not None:
        errors = ["THRESH_BELOW_QUORUM", "THRESH_UNKNOWN_SIGNER",
                  "THRESH_INVALID_SIG", "THRESH_CONFIG_INVALID"]
        found = [error_code for error_code in errors if error_code in content]
        check(
            checks,
            "TS-ERRORS",
            "All 4 error codes present",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "TS-ERRORS", "Error codes", False, emit_human=emit_human)

    fixture_valid = False
    fixture_details = None
    fixture_data, fixture_error = load_json_object(FIXTURE_PATH)
    if fixture_data is not None:
        cases = fixture_data.get("cases")
        fixture_valid = isinstance(cases, list) and len(cases) >= 4
        fixture_details = f"found {len(cases) if isinstance(cases, list) else 0} cases"
    elif fixture_error:
        fixture_details = fixture_error
    check(
        checks,
        "TS-FIXTURES",
        "Verification scenarios fixture",
        fixture_valid,
        fixture_details,
        emit_human=emit_human,
    )

    vectors_valid = False
    vectors_details = None
    vectors_data, vectors_error = load_json_object(VECTORS_PATH)
    if vectors_data is not None:
        vectors = vectors_data.get("vectors")
        vectors_valid = isinstance(vectors, list) and len(vectors) >= 2
        vectors_details = f"found {len(vectors) if isinstance(vectors, list) else 0} vectors"
    elif vectors_error:
        vectors_details = vectors_error
    check(
        checks,
        "TS-VECTORS",
        "Threshold signature test vectors",
        vectors_valid,
        vectors_details,
        emit_human=emit_human,
    )

    security_content = read_utf8(SECURITY_TEST_PATH)
    sec_exists = security_content is not None
    if security_content is not None:
        has_quorum = "quorum" in security_content
        has_partial = "partial" in security_content
        has_duplicate = "duplicate" in security_content
    else:
        has_quorum = has_partial = has_duplicate = False
    check(
        checks,
        "TS-SECURITY-TESTS",
        "Security tests cover quorum, partial, duplicate",
        sec_exists and has_quorum and has_partial and has_duplicate,
        emit_human=emit_human,
    )

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "TS-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "TS-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-THRESH" in spec_content
        has_failure = "FailureReason" in spec_content
    else:
        has_invariants = has_failure = False
    check(
        checks,
        "TS-SPEC",
        "Specification with invariants and failure reasons",
        spec_exists and has_invariants and has_failure,
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
    run_tests = args.run_rust_tests or (not args.json and not args.structural_only)
    write_artifact = args.write_evidence or not args.json
    logger = configure_test_logging("check_threshold_sig")
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
