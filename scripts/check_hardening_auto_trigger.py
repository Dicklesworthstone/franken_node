#!/usr/bin/env python3
"""bd-1zym: Verify automatic hardening trigger on guardrail rejection evidence.

Checks:
  1. hardening_auto_trigger.rs exists with required types and methods
  2. Event codes EVD-AUTOTRIG-001 through 004
  3. Idempotency key and dedup logic
  4. Causal evidence pointers in trigger events
  5. Integration with hardening_state_machine and guardrail_monitor
  6. Unit tests cover required scenarios

Usage:
  python3 scripts/check_hardening_auto_trigger.py          # human-readable
  python3 scripts/check_hardening_auto_trigger.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "hardening_auto_trigger.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-1zym_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
SM_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "hardening_state_machine.rs"
GUARD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "guardrail_monitor.rs"

REQUIRED_TYPES = [
    "pub enum TriggerResult",
    "pub struct TriggerEvent",
    "pub struct TriggerConfig",
    "pub struct HardeningAutoTrigger",
]

REQUIRED_METHODS = [
    "fn on_guardrail_rejection(",
    "fn reset_idempotency(",
    "fn events(",
    "fn event_count(",
    "fn dedup_count(",
    "fn to_jsonl(",
    "fn event_code(",
    "fn with_defaults(",
]

EVENT_CODES = [
    "EVD-AUTOTRIG-001",
    "EVD-AUTOTRIG-002",
    "EVD-AUTOTRIG-003",
    "EVD-AUTOTRIG-004",
]

INVARIANTS = [
    "INV-AUTOTRIG-LATENCY",
    "INV-AUTOTRIG-IDEMPOTENT",
    "INV-AUTOTRIG-CAUSAL",
]

TRIGGER_RESULT_VARIANTS = [
    "Escalated",
    "AlreadyAtMax",
    "Suppressed",
]

REQUIRED_TESTS = [
    "trigger_result_escalated_display",
    "trigger_result_already_at_max_display",
    "trigger_result_suppressed_display",
    "trigger_result_event_codes",
    "trigger_event_to_jsonl",
    "next_level_progression",
    "single_rejection_triggers_escalation",
    "sequential_rejections_escalate_through_levels",
    "already_at_max_returns_correctly",
    "duplicate_rejection_is_idempotent",
    "duplicate_at_same_level_is_idempotent",
    "same_budget_different_epoch_is_not_deduped",
    "different_budget_same_epoch_is_not_deduped",
    "idempotency_across_100_duplicates",
    "idempotency_disabled",
    "trigger_event_has_causal_pointers",
    "trigger_events_accumulate",
    "reset_clears_dedup_state",
    "default_config_values",
    "escalation_latency_is_zero_for_synchronous",
    "full_escalation_then_max",
    "events_export_as_jsonl",
]


def check_file(path, label):
    ok = path.is_file()
    rel = str(path.relative_to(ROOT)) if ok else str(path)
    return {"check": f"file: {label}", "pass": ok,
            "detail": f"exists: {rel}" if ok else f"MISSING: {rel}"}


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = path.read_text()
    for p in patterns:
        found = p in content
        results.append({"check": f"{category}: {p}", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"check": "module registered", "pass": False, "detail": "mod.rs missing"}
    content = MOD_RS.read_text()
    found = "hardening_auto_trigger" in content
    return {"check": "module registered in mod.rs", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_upstream_imports():
    """Verify the implementation imports from upstream dependencies."""
    if not IMPL.is_file():
        return [
            {"check": "imports HardeningStateMachine", "pass": False, "detail": "file missing"},
            {"check": "imports GuardrailRejection", "pass": False, "detail": "file missing"},
        ]
    content = IMPL.read_text()
    results = []
    sm_import = "HardeningStateMachine" in content and "HardeningLevel" in content
    results.append({"check": "imports HardeningStateMachine + HardeningLevel", "pass": sm_import,
                     "detail": "found" if sm_import else "NOT FOUND"})
    guard_import = "GuardrailRejection" in content and "BudgetId" in content
    results.append({"check": "imports GuardrailRejection + BudgetId", "pass": guard_import,
                     "detail": "found" if guard_import else "NOT FOUND"})
    return results


def check_idempotency_key():
    if not IMPL.is_file():
        return {"check": "idempotency key struct", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    has_key = "IdempotencyKey" in content and "HashSet" in content
    return {"check": "idempotency key with HashSet dedup", "pass": has_key,
            "detail": "found" if has_key else "NOT FOUND"}


def check_test_count(path):
    if not path.is_file():
        return {"check": "test count", "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "unit test count", "pass": count >= 20,
            "detail": f"{count} tests (minimum 20)"}


def check_next_level_function():
    if not IMPL.is_file():
        return {"check": "next_level function", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "fn next_level(" in content
    return {"check": "next_level escalation mapping", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_upstream_deps_exist():
    results = []
    for path, label in [(SM_RS, "hardening_state_machine.rs"), (GUARD_RS, "guardrail_monitor.rs")]:
        ok = path.is_file()
        results.append({"check": f"upstream: {label}", "pass": ok,
                        "detail": "exists" if ok else "MISSING"})
    return results


def self_test():
    result = run_checks()
    all_pass = result["verdict"] == "PASS"
    return all_pass, result["checks"]


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_module_registered())
    checks.extend(check_upstream_deps_exist())
    checks.extend(check_upstream_imports())
    checks.append(check_idempotency_key())
    checks.append(check_next_level_function())
    checks.append(check_test_count(IMPL))
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, TRIGGER_RESULT_VARIANTS, "variant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-1zym",
        "title": "Automatic hardening trigger on guardrail rejection evidence",
        "section": "10.14",
        "overall_pass": passed == total,
        "verdict": "PASS" if passed == total else "FAIL",
        "test_count": len(re.findall(r"#\[test\]", IMPL.read_text())) if IMPL.is_file() else 0,
        "summary": {"passing": passed, "failing": total - passed, "total": total},
        "checks": checks,
    }


def main():
    if "--self-test" in sys.argv:
        ok, results = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'}")
        return

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== bd-1zym: Hardening Auto Trigger Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing']}/{s['total']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
