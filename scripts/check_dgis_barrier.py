#!/usr/bin/env python3
"""Verification gate for DGIS trust barrier primitives (bd-1tnu).

Checks:
1. Barrier primitives source file exists and contains all 4 barrier types
2. Unit tests exist and cover each barrier category
3. Audit receipt types are defined with required fields
4. Event codes follow DGIS-BARRIER-NNN convention
5. Composition conflict detection is implemented
6. Override mechanism with justification validation exists
7. Policy engine (BarrierPlan) wiring is present

Usage:
    python3 scripts/check_dgis_barrier.py          # human-readable
    python3 scripts/check_dgis_barrier.py --json    # machine-readable
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

BARRIER_SRC = ROOT / "crates/franken-node/src/security/dgis/barrier_primitives.rs"
DGIS_MOD = ROOT / "crates/franken-node/src/security/dgis/mod.rs"
SECURITY_MOD = ROOT / "crates/franken-node/src/security/mod.rs"


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read_text(path))


def _strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = _rust_block_comment_end(text, i + 2)
            continue

        raw_end = _rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = _rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def _rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def _rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor

REQUIRED_BARRIER_TYPES = [
    "SandboxEscalation",
    "CompositionFirewall",
    "VerifiedForkPin",
    "StagedRolloutFence",
]

REQUIRED_EVENT_CODE_PREFIX = "DGIS-BARRIER-"

REQUIRED_TEST_PATTERNS = [
    "sandbox_escalation_denies",
    "sandbox_escalation_allows",
    "firewall_blocks",
    "firewall_allows",
    "fork_pin_rejects",
    "fork_pin_accepts",
    "rollout_fence_blocks",
    "rollout_fence_allows",
    "rollout_fence_advances",
    "rollout_fence_rollback",
    "override_requires_signature",
    "override_with_valid_justification",
    "multiple_barriers_on_same_node",
    "two_rollout_fences.*conflict",
    "barrier_removal_emits_receipt",
    "audit_log_records",
    "check_returns_not_applicable_when_only_other_barrier_kinds_exist",
    "audit_log_and_jsonl_export_preserve_not_applicable_receipts",
    "barrier_plan_applies",
]

REQUIRED_STRUCTS = [
    "BarrierEngine",
    "Barrier",
    "BarrierConfig",
    "BarrierAuditReceipt",
    "OverrideJustification",
    "BarrierPlan",
    "RolloutState",
    "SandboxEscalationConfig",
    "CompositionFirewallConfig",
    "VerifiedForkPinConfig",
    "StagedRolloutFenceConfig",
]


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def check_source_exists() -> CheckResult:
    """Check barrier_primitives.rs exists."""
    if BARRIER_SRC.exists():
        size = BARRIER_SRC.stat().st_size
        return CheckResult("source_exists", True, f"barrier_primitives.rs exists ({size} bytes)", {"size": size})
    return CheckResult("source_exists", False, "barrier_primitives.rs not found")


def check_module_wiring() -> CheckResult:
    """Check dgis module is wired into security/mod.rs."""
    issues = []
    if not DGIS_MOD.exists():
        issues.append("dgis/mod.rs not found")
    if not SECURITY_MOD.exists():
        issues.append("security/mod.rs not found")
    else:
        content = _read_rust_source(SECURITY_MOD)
        if "pub mod dgis" not in content:
            issues.append("dgis not declared in security/mod.rs")
    if issues:
        return CheckResult("module_wiring", False, "; ".join(issues))
    return CheckResult("module_wiring", True, "dgis module properly wired into security")


def check_barrier_types() -> CheckResult:
    """Check all 4 barrier types are defined."""
    if not BARRIER_SRC.exists():
        return CheckResult("barrier_types", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    missing = [bt for bt in REQUIRED_BARRIER_TYPES if bt not in content]
    if missing:
        return CheckResult("barrier_types", False, f"missing barrier types: {missing}", {"missing": missing})
    return CheckResult("barrier_types", True, f"all {len(REQUIRED_BARRIER_TYPES)} barrier types defined")


def check_event_codes() -> CheckResult:
    """Check structured event codes follow convention."""
    if not BARRIER_SRC.exists():
        return CheckResult("event_codes", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    codes = re.findall(r'"(DGIS-BARRIER-[\w-]+)"', content)
    if len(codes) < 10:
        return CheckResult("event_codes", False, f"only {len(codes)} event codes found, expected >= 10", {"found": codes})
    return CheckResult("event_codes", True, f"{len(codes)} event codes defined", {"codes": codes})


def check_required_structs() -> CheckResult:
    """Check all required structs/enums are defined."""
    if not BARRIER_SRC.exists():
        return CheckResult("structs", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    missing = [s for s in REQUIRED_STRUCTS if f"pub struct {s}" not in content and f"pub enum {s}" not in content]
    if missing:
        return CheckResult("structs", False, f"missing structs: {missing}", {"missing": missing})
    return CheckResult("structs", True, f"all {len(REQUIRED_STRUCTS)} required structs present")


def check_test_coverage() -> CheckResult:
    """Check unit tests cover all barrier categories."""
    if not BARRIER_SRC.exists():
        return CheckResult("test_coverage", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    missing = []
    for pattern in REQUIRED_TEST_PATTERNS:
        if not re.search(pattern, content):
            missing.append(pattern)
    if missing:
        return CheckResult("test_coverage", False, f"missing test patterns: {missing}", {"missing": missing})
    return CheckResult("test_coverage", True, f"all {len(REQUIRED_TEST_PATTERNS)} test patterns found")


def check_audit_receipt_fields() -> CheckResult:
    """Check audit receipts have required fields."""
    if not BARRIER_SRC.exists():
        return CheckResult("audit_receipts", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    required_fields = ["receipt_id", "event_code", "barrier_id", "node_id", "barrier_type", "action", "timestamp", "trace_id"]
    missing = [f for f in required_fields if f"pub {f}:" not in content]
    if missing:
        return CheckResult("audit_receipts", False, f"missing receipt fields: {missing}", {"missing": missing})
    return CheckResult("audit_receipts", True, "audit receipts have all required fields")


def check_override_mechanism() -> CheckResult:
    """Check override mechanism with justification validation."""
    if not BARRIER_SRC.exists():
        return CheckResult("override_mechanism", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    checks = {
        "override_justification_struct": "pub struct OverrideJustification" in content,
        "principal_identity_field": "principal_identity" in content,
        "signature_field": "signature_hex" in content,
        "validate_method": "fn validate(" in content,
        "override_barrier_method": "fn override_barrier(" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("override_mechanism", False, f"missing override components: {failed}", {"missing": failed})
    return CheckResult("override_mechanism", True, "override mechanism with justification validation present")


def check_composition_detection() -> CheckResult:
    """Check composition conflict detection is implemented."""
    if not BARRIER_SRC.exists():
        return CheckResult("composition", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    checks = {
        "composition_validity_check": "check_composition_validity" in content,
        "composition_conflict_error": "CompositionConflict" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("composition", False, f"missing composition checks: {failed}", {"missing": failed})
    return CheckResult("composition", True, "composition conflict detection implemented")


def check_policy_engine_wiring() -> CheckResult:
    """Check policy engine / barrier plan wiring."""
    if not BARRIER_SRC.exists():
        return CheckResult("policy_engine", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    checks = {
        "barrier_plan_struct": "pub struct BarrierPlan" in content,
        "apply_to_method": "fn apply_to(" in content,
        "source_plan_id": "source_plan_id" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("policy_engine", False, f"missing policy engine components: {failed}", {"missing": failed})
    return CheckResult("policy_engine", True, "barrier plan policy engine wiring present")


def check_jsonl_export() -> CheckResult:
    """Check JSONL export capability for audit log."""
    if not BARRIER_SRC.exists():
        return CheckResult("jsonl_export", False, "source file missing")
    content = _read_rust_source(BARRIER_SRC)
    if "export_audit_log_jsonl" in content:
        return CheckResult("jsonl_export", True, "JSONL export method present")
    return CheckResult("jsonl_export", False, "missing export_audit_log_jsonl method")


def run_all_checks() -> list[CheckResult]:
    """Run all verification checks."""
    return [
        check_source_exists(),
        check_module_wiring(),
        check_barrier_types(),
        check_event_codes(),
        check_required_structs(),
        check_test_coverage(),
        check_audit_receipt_fields(),
        check_override_mechanism(),
        check_composition_detection(),
        check_policy_engine_wiring(),
        check_jsonl_export(),
    ]


def self_test() -> bool:
    """Self-test: verify the checker itself works."""
    results = run_all_checks()
    if len(results) < 10:
        raise AssertionError(f"expected >= 10 checks, got {len(results)}")
    for r in results:
        if not isinstance(r.name, str) or not r.name:
            raise AssertionError("check result has an invalid name")
        if not isinstance(r.passed, bool):
            raise AssertionError(f"{r.name} result has a non-bool passed value")
        if not isinstance(r.message, str):
            raise AssertionError(f"{r.name} result has a non-string message")
    return True


def main():
    configure_test_logging("check_dgis_barrier")
    parser = argparse.ArgumentParser(description="DGIS barrier primitives verification gate")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="run self-test")
    args = parser.parse_args()

    if args.self_test:
        try:
            self_test()
            print("self_test: PASS")
            sys.exit(0)
        except AssertionError as e:
            print(f"self_test: FAIL - {e}")
            sys.exit(1)

    results = run_all_checks()
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    all_pass = passed == total

    if args.json:
        output = {
            "gate": "dgis_barrier_primitives",
            "bead": "bd-1tnu",
            "section": "10.20",
            "verdict": "PASS" if all_pass else "FAIL",
            "passed": passed,
            "total": total,
            "checks": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "message": r.message,
                    **({"details": r.details} if r.details else {}),
                }
                for r in results
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"  [{status}] {r.name}: {r.message}")
        print(f"\n{'PASS' if all_pass else 'FAIL'}: {passed}/{total} checks passed")

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
