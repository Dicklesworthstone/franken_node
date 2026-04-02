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
GUARD_TEST_TIMEOUT_SECONDS = int(
    os.environ.get("FRANKEN_NODE_GUARD_TEST_TIMEOUT_SECONDS", "600")
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


def main():
    from scripts.lib.test_logger import configure_test_logging

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

    # GUARD-TESTS: Rust tests pass
    try:
        result = subprocess.run(
            build_guard_test_command(),
            capture_output=True, text=True, timeout=GUARD_TEST_TIMEOUT_SECONDS,
            cwd=ROOT,
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("GUARD-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("GUARD-TESTS", "Rust unit tests pass", False, str(e))

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
