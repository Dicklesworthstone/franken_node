#!/usr/bin/env python3
"""Verification script for bd-3ua7: Sandbox Profile System."""

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

IMPL_PATH = ROOT / "crates/franken-node/src/security/sandbox_policy_compiler.rs"
FIXTURE_DIR = ROOT / "fixtures/sandbox_profiles"
COMPILER_OUTPUT_PATH = ROOT / "artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json"
CONFORMANCE_PATH = ROOT / "tests/conformance/sandbox_profile_conformance.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-3ua7_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-3ua7/verification_evidence.json"
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
                "security::sandbox_policy_compiler",
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
        "gate": "sandbox_profile_verification",
        "bead": "bd-3ua7",
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
        help="write artifacts/section_10_13/bd-3ua7/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-3ua7: Sandbox Profile System - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_profile = "enum SandboxProfile" in content
        has_compiler = "fn compile_policy" in content
        has_tracker = "struct ProfileTracker" in content
        has_audit = "struct ProfileAuditRecord" in content
        all_types = has_profile and has_compiler and has_tracker and has_audit
    else:
        all_types = False
    check(
        checks,
        "SANDBOX-IMPL",
        "Implementation with profiles, compiler, tracker, audit",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        profiles = ["Strict", "StrictPlus", "Moderate", "Permissive"]
        found = [profile for profile in profiles if profile in content]
        check(
            checks,
            "SANDBOX-PROFILES",
            "All 4 profiles defined",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "SANDBOX-PROFILES", "All 4 profiles defined", False, emit_human=emit_human)

    if content is not None:
        caps = ["network_access", "fs_read", "fs_write", "process_exec", "ipc", "env_access"]
        found = [capability for capability in caps if capability in content]
        check(
            checks,
            "SANDBOX-CAPABILITIES",
            "All 6 capabilities defined",
            len(found) == 6,
            f"found {len(found)}/6",
            emit_human=emit_human,
        )
    else:
        check(checks, "SANDBOX-CAPABILITIES", "All 6 capabilities", False, emit_human=emit_human)

    if content is not None:
        errors = ["SANDBOX_DOWNGRADE_BLOCKED", "SANDBOX_PROFILE_UNKNOWN",
                  "SANDBOX_POLICY_CONFLICT", "SANDBOX_COMPILE_ERROR"]
        found = [error_code for error_code in errors if error_code in content]
        check(
            checks,
            "SANDBOX-ERRORS",
            "All 4 error codes present",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "SANDBOX-ERRORS", "All 4 error codes", False, emit_human=emit_human)

    expected = ["profile_capabilities.json", "downgrade_scenarios.json"]
    found_fixtures = [fixture for fixture in expected if (FIXTURE_DIR / fixture).is_file()]
    check(
        checks,
        "SANDBOX-FIXTURES",
        "Fixture files for capabilities and downgrades",
        len(found_fixtures) == len(expected),
        f"found {len(found_fixtures)}/{len(expected)}",
        emit_human=emit_human,
    )

    output_valid = False
    output_details = None
    output_data, output_error = load_json_object(COMPILER_OUTPUT_PATH)
    if output_data is not None:
        compiled_policies = output_data.get("compiled_policies")
        output_valid = isinstance(compiled_policies, list) and len(compiled_policies) == 4
        output_details = f"found {len(compiled_policies) if isinstance(compiled_policies, list) else 0} policies"
    elif output_error:
        output_details = output_error
    check(
        checks,
        "SANDBOX-COMPILER-OUTPUT",
        "Compiled policy output for all 4 profiles",
        output_valid,
        output_details,
        emit_human=emit_human,
    )

    conformance_content = read_utf8(CONFORMANCE_PATH)
    conf_exists = conformance_content is not None
    if conformance_content is not None:
        lower_conformance = conformance_content.lower()
        has_order = "order" in lower_conformance
        has_downgrade = "downgrade" in lower_conformance
        has_audit = "audit" in lower_conformance
        all_aspects = has_order and has_downgrade and has_audit
    else:
        all_aspects = False
    check(
        checks,
        "SANDBOX-CONFORMANCE",
        "Conformance tests cover ordering, downgrade, audit",
        conf_exists and all_aspects,
        emit_human=emit_human,
    )

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "SANDBOX-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "SANDBOX-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-SANDBOX" in spec_content
        has_profiles = "strict" in spec_content and "moderate" in spec_content and "permissive" in spec_content
    else:
        has_invariants = has_profiles = False
    check(
        checks,
        "SANDBOX-SPEC",
        "Specification with invariants and profile definitions",
        spec_exists and has_invariants and has_profiles,
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
    logger = configure_test_logging("check_sandbox_profiles")
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
