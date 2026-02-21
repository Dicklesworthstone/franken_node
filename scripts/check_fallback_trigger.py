#!/usr/bin/env python3
"""Verification script for bd-3v8f: fallback trigger contract field.

Usage:
    python3 scripts/check_fallback_trigger.py              # human-readable
    python3 scripts/check_fallback_trigger.py --json        # machine-readable JSON
    python3 scripts/check_fallback_trigger.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_11" / "bd-3v8f_contract.md"
POLICY = ROOT / "docs" / "policy" / "fallback_trigger.md"

EVENT_CODES = ["FBT-001", "FBT-002", "FBT-003", "FBT-004"]

INVARIANTS = ["INV-FBT-DETECT", "INV-FBT-REVERT", "INV-FBT-SAFE", "INV-FBT-AUDIT"]

ROLLBACK_MECHANISMS = ["automatic", "semi-automatic", "manual"]

REQUIRED_FIELDS = [
    "trigger_conditions",
    "fallback_target_state",
    "rollback_mechanism",
    "max_detection_latency_s",
    "recovery_time_objective_s",
    "subsystem_id",
    "rationale",
]

MAX_DETECTION_LATENCY_S = 5
MAX_RECOVERY_TIME_OBJECTIVE_S = 30

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    """Return a relative path string, guarding against non-ROOT paths."""
    s_path = str(path)
    s_root = str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file_exists: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _file_contains(path: Path, keyword: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: '{keyword}'", False, "file missing")
    content = path.read_text(encoding="utf-8")
    found = keyword in content
    return _check(
        f"{label}: '{keyword}'",
        found,
        "found" if found else "not found in file",
    )


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_spec_exists() -> dict[str, Any]:
    """C01: Spec contract file exists."""
    return _file_exists(SPEC, "spec contract")


def check_policy_exists() -> dict[str, Any]:
    """C02: Policy document exists."""
    return _file_exists(POLICY, "policy document")


def check_spec_fallback_trigger_keyword() -> dict[str, Any]:
    """C03: Spec mentions 'fallback trigger'."""
    return _file_contains(SPEC, "fallback trigger", "spec_keyword")


def check_spec_deterministic_keyword() -> dict[str, Any]:
    """C04: Spec mentions 'deterministic'."""
    return _file_contains(SPEC, "deterministic", "spec_keyword")


def check_spec_rollback_mechanisms() -> dict[str, Any]:
    """C05: Spec defines all three rollback mechanisms."""
    if not SPEC.is_file():
        return _check("spec_rollback_mechanisms", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [m for m in ROLLBACK_MECHANISMS if m not in content]
    passed = len(missing) == 0
    detail = "all 3 rollback mechanisms present" if passed else f"missing: {missing}"
    return _check("spec_rollback_mechanisms", passed, detail)


def check_spec_required_fields() -> dict[str, Any]:
    """C06: Spec defines all 7 required contract fields."""
    if not SPEC.is_file():
        return _check("spec_required_fields", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [f for f in REQUIRED_FIELDS if f not in content]
    passed = len(missing) == 0
    detail = "all 7 required fields present" if passed else f"missing: {missing}"
    return _check("spec_required_fields", passed, detail)


def check_spec_event_codes() -> dict[str, Any]:
    """C07: Spec defines all four event codes FBT-001 through FBT-004."""
    if not SPEC.is_file():
        return _check("spec_event_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes present" if passed else f"missing: {missing}"
    return _check("spec_event_codes", passed, detail)


def check_spec_invariants() -> dict[str, Any]:
    """C08: Spec defines all four INV-FBT invariants."""
    if not SPEC.is_file():
        return _check("spec_invariants", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants present" if passed else f"missing: {missing}"
    return _check("spec_invariants", passed, detail)


def check_spec_detection_latency_threshold() -> dict[str, Any]:
    """C09: Spec defines max detection latency <= 5s."""
    return _file_contains(SPEC, "<= 5", "spec_threshold")


def check_spec_rto_threshold() -> dict[str, Any]:
    """C10: Spec defines recovery time objective <= 30s."""
    return _file_contains(SPEC, "<= 30", "spec_threshold")


def check_spec_coverage_requirement() -> dict[str, Any]:
    """C11: Spec requires 100% coverage of critical subsystems."""
    return _file_contains(SPEC, "100%", "spec_threshold")


def check_spec_safe_state_keyword() -> dict[str, Any]:
    """C12: Spec mentions 'known-safe state'."""
    return _file_contains(SPEC, "known-safe state", "spec_keyword")


def check_policy_contract_fields() -> dict[str, Any]:
    """C13: Policy defines all 7 required contract fields."""
    if not POLICY.is_file():
        return _check("policy_contract_fields", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [f for f in REQUIRED_FIELDS if f not in content]
    passed = len(missing) == 0
    detail = "all 7 required fields in policy" if passed else f"missing: {missing}"
    return _check("policy_contract_fields", passed, detail)


def check_policy_rollback_mechanisms() -> dict[str, Any]:
    """C14: Policy defines all three rollback mechanisms."""
    if not POLICY.is_file():
        return _check("policy_rollback_mechanisms", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [m for m in ROLLBACK_MECHANISMS if m not in content]
    passed = len(missing) == 0
    detail = "all 3 rollback mechanisms in policy" if passed else f"missing: {missing}"
    return _check("policy_rollback_mechanisms", passed, detail)


def check_policy_governance() -> dict[str, Any]:
    """C15: Policy defines governance section."""
    return _file_contains(POLICY, "Governance", "policy_section")


def check_policy_appeal_process() -> dict[str, Any]:
    """C16: Policy defines appeal process."""
    return _file_contains(POLICY, "Appeal Process", "policy_section")


def check_policy_event_codes() -> dict[str, Any]:
    """C17: Policy references all four event codes."""
    if not POLICY.is_file():
        return _check("policy_event_codes", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes in policy" if passed else f"missing: {missing}"
    return _check("policy_event_codes", passed, detail)


def check_policy_invariants() -> dict[str, Any]:
    """C18: Policy references all four invariants."""
    if not POLICY.is_file():
        return _check("policy_invariants", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants in policy" if passed else f"missing: {missing}"
    return _check("policy_invariants", passed, detail)


def check_policy_timing_guarantees() -> dict[str, Any]:
    """C19: Policy documents timing guarantees section."""
    return _file_contains(POLICY, "Timing Guarantees", "policy_section")


def check_policy_downgrade_triggers() -> dict[str, Any]:
    """C20: Policy documents downgrade triggers."""
    return _file_contains(POLICY, "Downgrade Triggers", "policy_section")


def check_policy_validation_rules() -> dict[str, Any]:
    """C21: Policy documents validation rules."""
    return _file_contains(POLICY, "Validation", "policy_section")


def check_policy_audit_trail() -> dict[str, Any]:
    """C22: Policy documents audit trail requirements."""
    return _file_contains(POLICY, "Audit Trail", "policy_section")


# ---------------------------------------------------------------------------
# Fallback trigger validation helpers
# ---------------------------------------------------------------------------

def validate_fallback_trigger(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate a fallback_trigger contract object. Returns list of check results."""
    results: list[dict[str, Any]] = []

    # trigger_conditions: non-empty list of non-empty strings
    tc = obj.get("trigger_conditions")
    tc_ok = (
        isinstance(tc, list)
        and len(tc) > 0
        and all(isinstance(c, str) and len(c) > 0 for c in tc)
    )
    results.append({
        "name": "trigger_conditions_valid",
        "passed": tc_ok,
        "detail": f"count={len(tc)}" if isinstance(tc, list) else "missing or invalid",
    })

    # fallback_target_state: non-empty string
    fts = obj.get("fallback_target_state")
    fts_ok = isinstance(fts, str) and len(fts) > 0
    results.append({
        "name": "fallback_target_state_valid",
        "passed": fts_ok,
        "detail": f"state={fts}" if fts_ok else "missing or empty",
    })

    # rollback_mechanism: one of the allowed values
    rm = obj.get("rollback_mechanism")
    rm_ok = rm in ROLLBACK_MECHANISMS
    results.append({
        "name": "rollback_mechanism_valid",
        "passed": rm_ok,
        "detail": f"mechanism={rm}" if rm_ok else f"invalid: {rm}",
    })

    # max_detection_latency_s: positive number <= MAX_DETECTION_LATENCY_S
    mdl = obj.get("max_detection_latency_s")
    mdl_ok = isinstance(mdl, (int, float)) and 0 < mdl <= MAX_DETECTION_LATENCY_S
    results.append({
        "name": "max_detection_latency_valid",
        "passed": mdl_ok,
        "detail": f"latency={mdl}s" if mdl_ok else f"invalid: {mdl}",
    })

    # recovery_time_objective_s: positive number <= MAX_RECOVERY_TIME_OBJECTIVE_S
    rto = obj.get("recovery_time_objective_s")
    rto_ok = isinstance(rto, (int, float)) and 0 < rto <= MAX_RECOVERY_TIME_OBJECTIVE_S
    results.append({
        "name": "recovery_time_objective_valid",
        "passed": rto_ok,
        "detail": f"rto={rto}s" if rto_ok else f"invalid: {rto}",
    })

    # subsystem_id: non-empty string
    sid = obj.get("subsystem_id")
    sid_ok = isinstance(sid, str) and len(sid) > 0
    results.append({
        "name": "subsystem_id_valid",
        "passed": sid_ok,
        "detail": f"id={sid}" if sid_ok else "missing or empty",
    })

    # rationale: non-empty string
    rat = obj.get("rationale")
    rat_ok = isinstance(rat, str) and len(rat) > 0
    results.append({
        "name": "rationale_valid",
        "passed": rat_ok,
        "detail": "present" if rat_ok else "missing or empty",
    })

    return results


def compute_total_recovery_time(
    detection_latency: float, recovery_objective: float
) -> float:
    """Compute worst-case total recovery time."""
    return detection_latency + recovery_objective


# ---------------------------------------------------------------------------
# All check functions
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_spec_fallback_trigger_keyword,
    check_spec_deterministic_keyword,
    check_spec_rollback_mechanisms,
    check_spec_required_fields,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_detection_latency_threshold,
    check_spec_rto_threshold,
    check_spec_coverage_requirement,
    check_spec_safe_state_keyword,
    check_policy_contract_fields,
    check_policy_rollback_mechanisms,
    check_policy_governance,
    check_policy_appeal_process,
    check_policy_event_codes,
    check_policy_invariants,
    check_policy_timing_guarantees,
    check_policy_downgrade_triggers,
    check_policy_validation_rules,
    check_policy_audit_trail,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    """Run all checks and return structured result."""
    global RESULTS
    RESULTS = []

    for fn in ALL_CHECKS:
        fn()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3v8f",
        "title": "Fallback trigger contract field",
        "section": "11",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    """Run self-test: execute all checks and report pass/fail."""
    report = run_all()
    total = report["total"]
    passed = report["passed"]
    failed = report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-3v8f: fallback trigger contract field"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    report = run_all()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{report['passed']}/{report['total']} checks pass (verdict={report['verdict']})")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
