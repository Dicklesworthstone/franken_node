#!/usr/bin/env python3
"""Verification script for bd-19u: CRDT State Mode Scaffolding."""

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

IMPL_PATH = ROOT / "crates/franken-node/src/connector/crdt.rs"
FIXTURE_DIR = ROOT / "fixtures/crdt"
CONFORMANCE_PATH = ROOT / "tests/conformance/crdt_merge_fixtures.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-19u_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-19u/verification_evidence.json"
EXPECTED_FIXTURES = [
    "lww_map_merge.json",
    "or_set_merge.json",
    "gcounter_merge.json",
    "pncounter_merge.json",
]


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
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::crdt"],
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
    verdict = "FAIL" if failing else "PARTIAL" if skipped else "PASS"
    return {
        "gate": "crdt_verification",
        "bead": "bd-19u",
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
        print("bd-19u: CRDT State Mode Scaffolding - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_lww = "struct LwwMap" in content
        has_or = "struct OrSet" in content
        has_gc = "struct GCounter" in content
        has_pn = "struct PnCounter" in content
        all_types = has_lww and has_or and has_gc and has_pn
    else:
        all_types = False
    check(
        checks,
        "CRDT-IMPL",
        "Implementation file with all 4 CRDT types",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        merge_count = content.count("fn merge(")
        check(
            checks,
            "CRDT-MERGE",
            "All 4 CRDT types implement merge",
            merge_count >= 4,
            f"found {merge_count} merge methods",
            emit_human=emit_human,
        )
    else:
        check(checks, "CRDT-MERGE", "All 4 CRDT types implement merge", False, emit_human=emit_human)

    if content is not None:
        has_error = "enum CrdtError" in content and "TypeMismatch" in content
        check(
            checks,
            "CRDT-ERROR",
            "CrdtError with TypeMismatch variant",
            has_error,
            emit_human=emit_human,
        )
    else:
        check(checks, "CRDT-ERROR", "CrdtError with TypeMismatch variant", False, emit_human=emit_human)

    if content is not None:
        tagged_count = content.count("pub crdt_type: CrdtType")
        check(
            checks,
            "CRDT-TAGGED",
            "Schema tag on each CRDT struct",
            tagged_count >= 4,
            f"found {tagged_count} crdt_type fields",
            emit_human=emit_human,
        )
    else:
        check(checks, "CRDT-TAGGED", "Schema tag on each CRDT struct", False, emit_human=emit_human)

    found_fixtures = [fixture for fixture in EXPECTED_FIXTURES if (FIXTURE_DIR / fixture).is_file()]
    check(
        checks,
        "CRDT-FIXTURES",
        "Merge fixture files for all 4 types",
        len(found_fixtures) == len(EXPECTED_FIXTURES),
        f"found {len(found_fixtures)}/{len(EXPECTED_FIXTURES)}",
        emit_human=emit_human,
    )

    fixture_valid = True
    for fixture in EXPECTED_FIXTURES:
        fpath = FIXTURE_DIR / fixture
        fixture_content = read_utf8(fpath)
        if fixture_content is not None:
            try:
                data = json.loads(fixture_content)
                if "cases" not in data or len(data["cases"]) == 0:
                    fixture_valid = False
            except (json.JSONDecodeError, KeyError):
                fixture_valid = False
        else:
            fixture_valid = False
    check(
        checks,
        "CRDT-FIXTURE-VALID",
        "Fixture files are valid JSON with cases",
        fixture_valid,
        emit_human=emit_human,
    )

    conformance_content = read_utf8(CONFORMANCE_PATH)
    conf_exists = conformance_content is not None
    if conformance_content is not None:
        has_comm = "commutativity" in conformance_content
        has_assoc = "associativity" in conformance_content
        has_idemp = "idempotency" in conformance_content
        all_laws = has_comm and has_assoc and has_idemp
    else:
        all_laws = False
    check(
        checks,
        "CRDT-CONFORMANCE",
        "Conformance tests cover all 3 merge laws",
        conf_exists and all_laws,
        emit_human=emit_human,
    )

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "CRDT-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "CRDT-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_types = (
            "lww_map" in spec_content
            and "or_set" in spec_content
            and "gcounter" in spec_content
            and "pncounter" in spec_content
        )
    else:
        has_types = False
    check(
        checks,
        "CRDT-SPEC",
        "Specification contract exists with all types",
        spec_exists and has_types,
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
        help="write artifacts/section_10_13/bd-19u/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only/--skip-rust are mutually exclusive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run_tests = args.run_rust_tests or (not args.json and not args.structural_only)
    write_artifact = args.write_evidence or not args.json
    logger = configure_test_logging("check_crdt")
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
