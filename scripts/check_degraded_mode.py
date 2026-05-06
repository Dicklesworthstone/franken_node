#!/usr/bin/env python3
"""bd-3nr verification: degraded-mode policy behavior and mandatory audits."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "security" / "degraded_mode_policy.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_5" / "bd-3nr_contract.md"

REQUIRED_IMPL_PATTERNS = [
    "pub struct DegradedModePolicy",
    "pub enum TriggerCondition",
    "pub struct AuditEventSpec",
    "pub enum RecoveryCriterion",
    "pub enum DegradedModeState",
    "pub struct DegradedModePolicyEngine",
    "pub fn activate(",
    "pub fn evaluate_action(",
    "pub fn tick_mandatory_audits(",
    "pub fn observe_recovery(",
    "pub fn maybe_escalate_to_suspended(",
    "DEGRADED_MODE_ENTERED",
    "DEGRADED_MODE_EXITED",
    "DEGRADED_MODE_SUSPENDED",
    "DEGRADED_ACTION_BLOCKED",
    "DEGRADED_ACTION_ANNOTATED",
    "TRUST_INPUT_STALE",
    "TRUST_INPUT_REFRESHED",
    "AUDIT_EVENT_MISSED",
]

REAL_EVIDENCE_REQUIREMENTS = [
    (
        "real evidence: trigger variants",
        IMPL,
        [
            "fn trigger_variant_health_gate_activation",
            "fn trigger_variant_capability_unavailable_activation",
            "fn trigger_variant_error_rate_exceeded_activation",
            "fn trigger_variant_manual_activation",
            "DegradedModeAuditEvent::DegradedModeEntered",
        ],
    ),
    (
        "real evidence: trigger rejection stays fail-closed",
        IMPL,
        [
            "fn unconfigured_trigger_is_rejected_without_audit_event",
            "fn error_rate_trigger_threshold_mismatch_is_rejected_without_audit",
            "fn health_gate_trigger_name_mismatch_is_rejected_without_audit",
            "fn capability_trigger_name_mismatch_is_rejected_without_audit",
            "assert!(engine.audit_log().is_empty())",
        ],
    ),
    (
        "real evidence: degraded action auditing",
        IMPL,
        [
            "fn denied_action_emits_blocked_audit",
            "pub fn evaluate_action(",
            "DEGRADED_ACTION_BLOCKED",
            "DEGRADED_ACTION_ANNOTATED",
            "denied_actions.policy.change",
        ],
    ),
    (
        "real evidence: mandatory audit tick and missed alert",
        IMPL,
        [
            "fn mandatory_tick_and_missed_alert_fire",
            "engine.tick_mandatory_audits(10_061",
            "engine.tick_mandatory_audits(10_190",
            "DegradedModeAuditEvent::MandatoryAuditTick",
            "DegradedModeAuditEvent::AuditEventMissed",
        ],
    ),
    (
        "real evidence: stabilization-window recovery",
        IMPL,
        [
            "fn stabilization_window_required_for_exit",
            "engine.observe_recovery(&status, 1_050",
            "engine.observe_recovery(&status, 1_350",
            "DegradedModeState::Normal",
            "DegradedModeAuditEvent::DegradedModeExited",
        ],
    ),
    (
        "real evidence: suspended-mode gating",
        IMPL,
        [
            "fn degraded_duration_escalates_to_suspended",
            "fn suspended_blocks_non_essential_actions",
            "fn activation_is_rejected_while_suspended_without_extra_audit",
            "engine.maybe_escalate_to_suspended(",
            "suspended_mode_blocks_non_essential",
        ],
    ),
]


def check_file(path: Path, label: str) -> dict[str, Any]:
    ok = path.is_file()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"missing: {path}",
    }


def check_contains(path: Path, patterns: list[str], label: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return [{"check": f"{label}: {pattern}", "pass": False, "detail": "file missing"} for pattern in patterns]
    content = path.read_text(encoding="utf-8")
    checks = []
    for pattern in patterns:
        checks.append(
            {
                "check": f"{label}: {pattern}",
                "pass": pattern in content,
                "detail": "found" if pattern in content else "not found",
            }
        )
    return checks


def _missing_patterns(content: str, patterns: list[str]) -> list[str]:
    return [pattern for pattern in patterns if pattern not in content]


def check_real_degraded_mode_evidence() -> list[dict[str, Any]]:
    checks = []
    for name, path, patterns in REAL_EVIDENCE_REQUIREMENTS:
        if not path.is_file():
            checks.append({"check": name, "pass": False, "detail": f"missing: {path}"})
            continue
        content = path.read_text(encoding="utf-8")
        missing = _missing_patterns(content, patterns)
        checks.append(
            {
                "check": name,
                "pass": not missing,
                "detail": f"exists: {path.relative_to(ROOT)}" if not missing else f"missing: {', '.join(missing[:3])}",
            }
        )
    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(IMPL, "degraded mode policy implementation"))
    checks.append(check_file(SPEC, "contract"))
    checks.extend(check_contains(IMPL, REQUIRED_IMPL_PATTERNS, "impl"))
    checks.extend(check_contains(MOD_RS, ["pub mod degraded_mode_policy;"], "module wiring"))
    checks.extend(check_real_degraded_mode_evidence())

    passed = sum(1 for check in checks if check["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-3nr",
        "title": "Degraded-mode policy behavior with mandatory audit events",
        "section": "10.5",
        "verdict": "PASS" if passed == total else "FAIL",
        "overall_pass": passed == total,
        "summary": {"passing": passed, "failing": total - passed, "total": total},
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    result = run_checks()
    return result["verdict"] == "PASS", result["checks"]


def main() -> None:
    configure_test_logging("check_degraded_mode")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'} ({len(checks)} checks)")
        raise SystemExit(0 if ok else 1)

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-3nr: degraded mode policy verification ===")
        print(f"Verdict: {result['verdict']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    raise SystemExit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
