#!/usr/bin/env python3
"""Verification script for bd-17mb: Fail-closed manifest negotiation."""

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

IMPL_PATH = ROOT / "crates/franken-node/src/connector/manifest_negotiation.rs"
FIXTURE_PATH = ROOT / "fixtures/manifest_negotiation/negotiation_scenarios.json"
TRACE_PATH = ROOT / "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json"
CONFORMANCE_PATH = ROOT / "tests/conformance/manifest_negotiation_fail_closed.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-17mb_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-17mb/verification_evidence.json"
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
                "connector::manifest_negotiation",
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
        "gate": "manifest_negotiation_verification",
        "bead": "bd-17mb",
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
        help="write artifacts/section_10_13/bd-17mb/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-17mb: Fail-Closed Manifest Negotiation - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_semver = "struct SemVer" in content
        has_manifest = "struct ConnectorManifest" in content
        has_host = "struct HostCapabilities" in content
        has_negotiate = "fn negotiate" in content
        all_types = has_semver and has_manifest and has_host and has_negotiate
    else:
        all_types = False
    check(
        checks,
        "MN-IMPL",
        "Implementation with SemVer, manifest, host caps, negotiate",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        has_ord = "impl Ord for SemVer" in content
        has_cmp = "self.major" in content and ".cmp(" in content
        check(
            checks,
            "MN-SEMVER",
            "Semantic version ordering implemented",
            has_ord and has_cmp,
            emit_human=emit_human,
        )
    else:
        check(checks, "MN-SEMVER", "SemVer ordering", False, emit_human=emit_human)

    if content is not None:
        errors = ["MANIFEST_VERSION_UNSUPPORTED", "MANIFEST_FEATURE_MISSING",
                  "MANIFEST_TRANSPORT_MISMATCH", "MANIFEST_INVALID"]
        found = [error_code for error_code in errors if error_code in content]
        check(
            checks,
            "MN-ERRORS",
            "All 4 error codes present",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "MN-ERRORS", "Error codes", False, emit_human=emit_human)

    if content is not None:
        caps = ["Http1", "Http2", "Http3", "WebSocket", "Grpc"]
        found = [capability for capability in caps if capability in content]
        check(
            checks,
            "MN-TRANSPORT",
            "All 5 transport capability types",
            len(found) == 5,
            f"found {len(found)}/5",
            emit_human=emit_human,
        )
    else:
        check(checks, "MN-TRANSPORT", "Transport caps", False, emit_human=emit_human)

    fixture_valid = False
    fixture_details = None
    fixture_data, fixture_error = load_json_object(FIXTURE_PATH)
    if fixture_data is not None:
        cases = fixture_data.get("cases")
        fixture_valid = isinstance(cases, list) and len(cases) >= 5
        fixture_details = f"found {len(cases) if isinstance(cases, list) else 0} cases"
    elif fixture_error:
        fixture_details = fixture_error
    check(
        checks,
        "MN-FIXTURES",
        "Negotiation scenarios fixture",
        fixture_valid,
        fixture_details,
        emit_human=emit_human,
    )

    trace_valid = False
    trace_details = None
    trace_data, trace_error = load_json_object(TRACE_PATH)
    if trace_data is not None:
        negotiations = trace_data.get("negotiations")
        trace_valid = isinstance(negotiations, list) and len(negotiations) >= 2
        trace_details = f"found {len(negotiations) if isinstance(negotiations, list) else 0} negotiations"
    elif trace_error:
        trace_details = trace_error
    check(
        checks,
        "MN-TRACE",
        "Manifest negotiation trace artifact",
        trace_valid,
        trace_details,
        emit_human=emit_human,
    )

    conformance_content = read_utf8(CONFORMANCE_PATH)
    conf_exists = conformance_content is not None
    if conformance_content is not None:
        has_fail_closed = "fails_closed" in conformance_content
        has_semantic = "semantic" in conformance_content.lower()
        has_trace = "trace" in conformance_content
    else:
        has_fail_closed = has_semantic = has_trace = False
    check(
        checks,
        "MN-CONFORMANCE",
        "Conformance tests cover fail-closed, semantic, trace",
        conf_exists and has_fail_closed and has_semantic and has_trace,
        emit_human=emit_human,
    )

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "MN-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "MN-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-MANIFEST" in spec_content
        has_outcome = "Outcome" in spec_content
    else:
        has_invariants = has_outcome = False
    check(
        checks,
        "MN-SPEC",
        "Specification with invariants and outcome types",
        spec_exists and has_invariants and has_outcome,
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
    logger = configure_test_logging("check_manifest_negotiation")
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
