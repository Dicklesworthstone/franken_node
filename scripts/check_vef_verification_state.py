#!/usr/bin/env python3
"""Verification checker for bd-8qlj: VEF verification state in control transitions.

Verifies the verification state manager including risk-level-dependent
authorization, fail-closed proof requirements, audit logging, and
deterministic state management.

Usage:
    python3 scripts/check_vef_verification_state.py          # human-readable
    python3 scripts/check_vef_verification_state.py --json    # machine-readable
    python3 scripts/check_vef_verification_state.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BEAD_ID = "bd-8qlj"
SECTION = "10.18"

IMPL_FILE = ROOT / "crates" / "franken-node" / "src" / "vef" / "verification_state.rs"
MOD_FILE = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
EVIDENCE_FILE = ROOT / "artifacts" / "section_10_18" / BEAD_ID / "verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts" / "section_10_18" / BEAD_ID / "verification_summary.md"

REQUIRED_SYMBOLS = [
    "pub enum RiskLevel",
    "pub enum TransitionResult",
    "pub enum ActionResult",
    "pub enum VefStateError",
    "pub struct ProofStatus",
    "pub struct ControlState",
    "pub struct TransitionRequest",
    "pub struct ActionRequest",
    "pub struct StateAuditEntry",
    "pub struct VerificationStateManager",
    "pub fn new",
    "pub fn register_entity",
    "pub fn attach_proof",
    "pub fn request_transition",
    "pub fn authorize_action",
    "pub fn state",
    "pub fn audit_log",
    "pub fn is_fresh",
]

RISK_LEVELS = [
    "Low",
    "Medium",
    "High",
    "Critical",
]

EVENT_CODES = [
    "VEF_STATE_TRANSITION_REQUESTED",
    "VEF_STATE_TRANSITION_APPROVED",
    "VEF_STATE_TRANSITION_BLOCKED",
    "VEF_STATE_ACTION_AUTHORIZED",
    "VEF_STATE_ACTION_DENIED",
]

ERROR_CODES = [
    "ERR_VEF_STATE_NO_PROOF",
    "ERR_VEF_STATE_STALE_PROOF",
    "ERR_VEF_STATE_INVALID_TRANSITION",
    "ERR_VEF_STATE_RISK_EXCEEDED",
    "ERR_VEF_STATE_POLICY_MISSING",
]

ERROR_VARIANTS = [
    "NoProof",
    "StaleProof",
    "InvalidTransition",
    "RiskExceeded",
    "PolicyMissing",
]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }
    RESULTS.append(entry)
    return entry


def _read_impl() -> str:
    return IMPL_FILE.read_text() if IMPL_FILE.is_file() else ""


def check_file_presence() -> None:
    _check("impl_exists", IMPL_FILE.is_file(), str(IMPL_FILE.relative_to(ROOT)))
    _check("mod_exists", MOD_FILE.is_file(), str(MOD_FILE.relative_to(ROOT)))


def check_mod_wiring() -> None:
    if not MOD_FILE.is_file():
        _check("mod_wires_verification_state", False, "mod.rs missing")
        return
    mod_text = MOD_FILE.read_text()
    _check("mod_wires_verification_state", "pub mod verification_state;" in mod_text, "pub mod verification_state;")


def check_impl_symbols() -> None:
    src = _read_impl()
    for sym in REQUIRED_SYMBOLS:
        label = sym.split()[-1]
        _check(f"impl_symbol_{label}", sym in src, sym)


def check_risk_levels() -> None:
    src = _read_impl()
    for level in RISK_LEVELS:
        _check(f"risk_level_{level}", level in src, level)


def check_event_codes() -> None:
    src = _read_impl()
    for code in EVENT_CODES:
        _check(f"event_{code}", code in src, code)


def check_error_codes() -> None:
    src = _read_impl()
    for code in ERROR_CODES:
        _check(f"error_code_{code}", code in src, code)


def check_error_variants() -> None:
    src = _read_impl()
    for variant in ERROR_VARIANTS:
        _check(f"error_variant_{variant}", variant in src, variant)


def check_contract_properties() -> None:
    src = _read_impl()
    src_lower = src.lower()

    _check("contract_fail_closed",
           "INV-VEF-STATE-FAIL-CLOSED" in src or ("noproof" in src_lower and "staleproof" in src_lower),
           "fail-closed on missing/stale proof")

    _check("contract_risk_bound",
           "INV-VEF-STATE-RISK-BOUND" in src or "required_risk_level" in src,
           "risk-level-bound actions")

    _check("contract_audit_trail",
           "INV-VEF-STATE-AUDIT-TRAIL" in src or "audit_log" in src,
           "complete audit trail")

    _check("contract_no_escalation",
           "INV-VEF-STATE-NO-ESCALATION" in src or ("escalat" in src_lower),
           "no-escalation-without-proof")

    _check("contract_schema_version",
           "verification-state-v1" in src,
           "schema version present")

    _check("contract_deterministic_storage",
           "BTreeMap" in src,
           "BTreeMap for deterministic ordering")

    _check("contract_proof_freshness",
           "is_fresh" in src and "max_age_seconds" in src,
           "proof freshness check with max_age")

    _check("contract_downgrade_no_proof",
           "downgrade" in src_lower or ("transition" in src_lower and "lower" in src_lower),
           "downgrade does not require proof")

    _check("contract_transition_count",
           "transition_count" in src,
           "transition counter tracked")

    _check("contract_saturating_sub",
           "saturating_sub" in src,
           "saturating arithmetic for safety")

    _check("contract_display_impl",
           "impl fmt::Display for VefStateError" in src or "impl Display for VefStateError" in src
           or ("Display" in src and "VefStateError" in src),
           "Display impl for error type")

    _check("contract_default_impl",
           "Default" in src and "VerificationStateManager" in src,
           "Default impl for manager")


def check_unit_tests() -> None:
    src = _read_impl()
    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 15, f"{test_count} tests")


def check_evidence() -> None:
    if not EVIDENCE_FILE.is_file():
        _check("evidence_exists", False, str(EVIDENCE_FILE.relative_to(ROOT)))
        return
    _check("evidence_exists", True, str(EVIDENCE_FILE.relative_to(ROOT)))
    try:
        data = json.loads(EVIDENCE_FILE.read_text())
        _check("evidence_parseable", True, "valid JSON")
        _check("evidence_bead_id", data.get("bead_id") == BEAD_ID, str(data.get("bead_id")))
        verdict = data.get("verdict", data.get("overall_pass"))
        _check("evidence_verdict", bool(verdict == "PASS" or verdict is True), str(verdict))
    except (json.JSONDecodeError, OSError):
        _check("evidence_parseable", False, "parse error")


def check_summary() -> None:
    if not SUMMARY_FILE.is_file():
        _check("summary_exists", False, str(SUMMARY_FILE.relative_to(ROOT)))
        return
    _check("summary_exists", True, str(SUMMARY_FILE.relative_to(ROOT)))
    text = SUMMARY_FILE.read_text()
    _check("summary_mentions_bead", BEAD_ID in text, BEAD_ID)
    _check("summary_mentions_pass", "PASS" in text.upper(), "PASS")


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()
    check_file_presence()
    check_mod_wiring()
    check_impl_symbols()
    check_risk_levels()
    check_event_codes()
    check_error_codes()
    check_error_variants()
    check_contract_properties()
    check_unit_tests()
    check_evidence()
    check_summary()
    return RESULTS


def run_all() -> dict[str, Any]:
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    return {
        "bead_id": BEAD_ID,
        "title": "VEF verification state in high-risk control transitions",
        "section": SECTION,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("symbol_count", len(REQUIRED_SYMBOLS) == 18, str(len(REQUIRED_SYMBOLS)))
    push("risk_level_count", len(RISK_LEVELS) == 4, str(len(RISK_LEVELS)))
    push("event_code_count", len(EVENT_CODES) == 5, str(len(EVENT_CODES)))
    push("error_code_count", len(ERROR_CODES) == 5, str(len(ERROR_CODES)))
    push("error_variant_count", len(ERROR_VARIANTS) == 5, str(len(ERROR_VARIANTS)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")

    passed = sum(1 for e in checks if e["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": BEAD_ID,
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Verification checker for {BEAD_ID}")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        result = self_test()
    else:
        result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  [{BEAD_ID}] {result['verdict']} ({result['passed']}/{result['total']})\n")
        for r in result["checks"]:
            mark = "+" if r["pass"] else "x"
            print(f"  [{mark}] {r['check']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
