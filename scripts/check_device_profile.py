#!/usr/bin/env python3
"""Verification script for bd-8vby: Device profile registry and placement policy."""

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

IMPL_PATH = ROOT / "crates/franken-node/src/connector/device_profile.rs"
FIXTURES_PATH = ROOT / "artifacts/section_10_13/bd-8vby/device_profile_examples.json"
CONF_PATH = ROOT / "tests/conformance/placement_policy_schema.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-8vby_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-8vby/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def read_utf8(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def load_json_object(path: Path) -> tuple[dict[str, object] | None, str | None]:
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
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::device_profile"],
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
        "gate": "device_profile_verification",
        "bead": "bd-8vby",
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
        help="write artifacts/section_10_13/bd-8vby/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-8vby: Device Profile Registry - Verification\n")

    # DPR-IMPL: Implementation exists with required types
    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
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
    check(
        checks,
        "DPR-IMPL",
        "Implementation with all required types",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    # DPR-ERRORS: All error codes present
    if content is not None:
        errors = ["DPR_SCHEMA_INVALID", "DPR_STALE_PROFILE", "DPR_INVALID_CONSTRAINT", "DPR_NO_MATCH"]
        found = [e for e in errors if e in content]
        check(
            checks,
            "DPR-ERRORS",
            "All 4 error codes present",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "DPR-ERRORS", "Error codes", False, emit_human=emit_human)

    # DPR-FIXTURES: Device profile examples
    fixtures_valid = False
    fixture_details = None
    fixture_data, fixture_error = load_json_object(FIXTURES_PATH)
    if fixture_data is not None:
        profiles = fixture_data.get("profiles")
        fixtures_valid = isinstance(profiles, list) and len(profiles) >= 3
        fixture_details = f"found {len(profiles) if isinstance(profiles, list) else 0} profiles"
    elif fixture_error:
        fixture_details = fixture_error
    check(
        checks,
        "DPR-FIXTURES",
        "Device profile example fixtures",
        fixtures_valid,
        fixture_details,
        emit_human=emit_human,
    )

    # DPR-CONF: Conformance tests exist and cover invariants
    conformance_content = read_utf8(CONF_PATH)
    conf_exists = conformance_content is not None
    if conformance_content is not None:
        has_schema = "inv_dpr_schema" in conformance_content
        has_freshness = "inv_dpr_freshness" in conformance_content
        has_deterministic = "inv_dpr_deterministic" in conformance_content
        has_reject = "inv_dpr_reject_invalid" in conformance_content
    else:
        has_schema = has_freshness = has_deterministic = has_reject = False
    check(
        checks,
        "DPR-CONF",
        "Conformance tests cover all 4 invariants",
        conf_exists and has_schema and has_freshness and has_deterministic and has_reject,
        emit_human=emit_human,
    )

    # DPR-TESTS: Rust unit tests pass
    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "DPR-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "DPR-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    # DPR-SPEC: Specification with invariants
    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-DPR" in spec_content
        has_types = "DeviceProfileRegistry" in spec_content and "PlacementPolicy" in spec_content
    else:
        has_invariants = has_types = False
    check(
        checks,
        "DPR-SPEC",
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


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run_tests = should_run_rust_tests(args)
    write_artifact = args.write_evidence or not args.json
    logger = configure_test_logging("check_device_profile")
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
