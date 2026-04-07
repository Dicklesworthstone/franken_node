#!/usr/bin/env python3
"""Verification script for bd-2m2b: Network Guard Egress Layer."""

import json
import os
import re
import subprocess
import sys

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CHECKS: list[dict[str, object]] = []
NETWORK_GUARD_TEST_FILTER = "security::network_guard"
NETWORK_GUARD_SECURITY_TARGET = "remote_cap_enforcement"
GUARD_TEST_TIMEOUT_SECONDS = int(
    os.environ.get("FRANKEN_NODE_GUARD_TEST_TIMEOUT_SECONDS", "600")
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


def load_non_empty_lines(path: Path) -> list[str]:
    with path.open(encoding="utf-8") as file_handle:
        return [line.strip() for line in file_handle if line.strip()]


def load_json_document(path: Path) -> dict[str, object] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def audit_samples_are_valid(audit_path: Path) -> bool:
    try:
        lines = load_non_empty_lines(audit_path)
    except OSError:
        return False
    if len(lines) < 2:
        return False

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return False
        if "trace_id" not in event or "action" not in event:
            return False

    return True


def build_guard_test_command() -> list[str]:
    return [
        "rch",
        "exec",
        "--",
        "cargo",
        "test",
        "-p",
        "frankenengine-node",
        "--lib",
        "--",
        NETWORK_GUARD_TEST_FILTER,
    ]


def build_guard_security_test_command() -> list[str]:
    return [
        "rch",
        "exec",
        "--",
        "cargo",
        "test",
        "-p",
        "frankenengine-node",
        "--test",
        NETWORK_GUARD_SECURITY_TARGET,
    ]


def parse_rust_test_summary(output: str) -> dict[str, int]:
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


def summarize_failure_output(output: str, max_lines: int = 6) -> str:
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


def select_failure_excerpt(*outputs: str) -> str:
    for output in outputs:
        excerpt = summarize_failure_output(output)
        if excerpt:
            return excerpt
    return ""


def run_guard_unit_tests() -> tuple[dict[str, int], str]:
    result = subprocess.run(
        build_guard_test_command(),
        capture_output=True,
        text=True,
        timeout=GUARD_TEST_TIMEOUT_SECONDS,
        cwd=ROOT,
    )
    output = result.stdout + result.stderr
    summary = parse_rust_test_summary(output)
    summary["returncode"] = result.returncode
    return summary, output


def run_guard_security_tests() -> tuple[dict[str, int], str]:
    result = subprocess.run(
        build_guard_security_test_command(),
        capture_output=True,
        text=True,
        timeout=GUARD_TEST_TIMEOUT_SECONDS,
        cwd=ROOT,
    )
    output = result.stdout + result.stderr
    summary = parse_rust_test_summary(output)
    summary["returncode"] = result.returncode
    return summary, output


def main():
    from scripts.lib.test_logger import configure_test_logging

    CHECKS.clear()
    configure_test_logging("check_network_guard")
    print("bd-2m2b: Network Guard Egress Layer — Verification\n")
    all_pass = True

    # GUARD-IMPL: Implementation file
    impl_path = ROOT / "crates/franken-node/src/security/network_guard.rs"
    impl_exists = impl_path.is_file()
    if impl_exists:
        content = impl_path.read_text(encoding="utf-8")
        has_guard = "struct NetworkGuard" in content
        has_policy = "struct EgressPolicy" in content
        has_rule = "struct EgressRule" in content
        has_audit = "struct AuditEvent" in content
        all_types = has_guard and has_policy and has_rule and has_audit
    else:
        all_types = False
    all_pass &= check("GUARD-IMPL", "Implementation with guard, policy, rules, audit events",
                      impl_exists and all_types)

    # GUARD-PROTOCOLS: HTTP and TCP support
    if impl_exists:
        content = impl_path.read_text(encoding="utf-8")
        has_http = "Http" in content
        has_tcp = "Tcp" in content
        all_pass &= check("GUARD-PROTOCOLS", "HTTP and TCP protocol support", has_http and has_tcp)
    else:
        all_pass &= check("GUARD-PROTOCOLS", "Protocol support", False)

    # GUARD-ERRORS: All 3 error codes
    if impl_exists:
        content = impl_path.read_text(encoding="utf-8")
        errors = ["GUARD_POLICY_INVALID", "GUARD_EGRESS_DENIED", "GUARD_AUDIT_FAILED"]
        found = [e for e in errors if e in content]
        all_pass &= check("GUARD-ERRORS", "All 3 error codes present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("GUARD-ERRORS", "Error codes", False)

    # GUARD-FIXTURES: Fixture files
    fixture_path = ROOT / "fixtures/network_guard/egress_policy_scenarios.json"
    fixture_valid = False
    if fixture_path.is_file():
        data = load_json_document(fixture_path)
        if data is not None:
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
    all_pass &= check("GUARD-FIXTURES", "Egress policy fixture with scenarios", fixture_valid)

    # GUARD-AUDIT-SAMPLES: Audit JSONL samples
    audit_path = ROOT / "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl"
    audit_valid = False
    if audit_path.is_file():
        audit_valid = audit_samples_are_valid(audit_path)
    all_pass &= check("GUARD-AUDIT-SAMPLES", "Audit JSONL samples with trace IDs", audit_valid)

    # GUARD-CONFORMANCE: Conformance test file
    conf_path = ROOT / "tests/conformance/network_guard_policy.rs"
    conf_exists = conf_path.is_file()
    if conf_exists:
        content = conf_path.read_text(encoding="utf-8")
        has_deny = "default_deny" in content or "deny" in content.lower()
        has_order = "order" in content.lower()
        has_audit = "audit" in content.lower()
    else:
        has_deny = has_order = has_audit = False
    all_pass &= check("GUARD-CONFORMANCE", "Conformance tests cover deny, ordering, audit",
                      conf_exists and has_deny and has_order and has_audit)

    # GUARD-HARNESS: Security tests are wired into Cargo.
    harness_path = ROOT / "crates/franken-node/tests/remote_cap_enforcement.rs"
    harness_exists = harness_path.is_file()
    if harness_exists:
        harness_content = harness_path.read_text(encoding="utf-8")
        harness_wired = "../../../tests/security/remote_cap_enforcement.rs" in harness_content
    else:
        harness_wired = False
    all_pass &= check(
        "GUARD-HARNESS",
        "Cargo harness wires remote capability enforcement tests",
        harness_exists and harness_wired,
    )

    # GUARD-TESTS: Rust unit and security tests pass.
    try:
        unit_summary, unit_output = run_guard_unit_tests()
        security_summary, security_output = run_guard_security_tests()
        unit_ok = (
            unit_summary["returncode"] == 0
            and unit_summary["running"] > 0
            and unit_summary["passed"] > 0
            and unit_summary["failed"] == 0
        )
        security_ok = (
            security_summary["returncode"] == 0
            and security_summary["running"] > 0
            and security_summary["passed"] > 0
            and security_summary["failed"] == 0
        )
        tests_pass = unit_ok and security_ok
        details = (
            f"unit {unit_summary['passed']} passed / {unit_summary['running']} ran / {unit_summary['filtered']} filtered; "
            f"security {security_summary['passed']} passed / {security_summary['running']} ran / {security_summary['filtered']} filtered"
        )
        if not tests_pass:
            failure_excerpt = select_failure_excerpt(
                unit_output if not unit_ok else "",
                security_output if not security_ok else "",
            )
            if failure_excerpt:
                details = (
                    f"{details}; rc=({unit_summary['returncode']}, {security_summary['returncode']}); "
                    f"{failure_excerpt}"
                )
        all_pass &= check(
            "GUARD-TESTS",
            "Rust network guard unit and security tests pass",
            tests_pass,
            details,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check(
            "GUARD-TESTS",
            "Rust network guard unit and security tests pass",
            False,
            str(e),
        )

    # GUARD-SPEC: Spec contract
    spec_path = ROOT / "docs/specs/section_10_13/bd-2m2b_contract.md"
    spec_exists = spec_path.is_file()
    if spec_exists:
        content = spec_path.read_text(encoding="utf-8")
        has_invariants = "INV-GUARD" in content
        has_audit = "Audit Event" in content
    else:
        has_invariants = has_audit = False
    all_pass &= check("GUARD-SPEC", "Specification with invariants and audit event schema",
                      spec_exists and has_invariants and has_audit)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "network_guard_verification",
        "bead": "bd-2m2b",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = ROOT / "artifacts/section_10_13/bd-2m2b"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    with (evidence_dir / "verification_evidence.json").open("w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
