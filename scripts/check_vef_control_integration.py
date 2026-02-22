#!/usr/bin/env python3
"""Verification script for bd-8qlj: VEF control-transition gate integration.

Usage:
    python3 scripts/check_vef_control_integration.py
    python3 scripts/check_vef_control_integration.py --json
    python3 scripts/check_vef_control_integration.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "crates" / "franken-node" / "src" / "vef" / "control_integration.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-8qlj_contract.md"
UNIT_TEST = ROOT / "tests" / "test_check_vef_control_integration.py"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-8qlj" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-8qlj" / "verification_summary.md"

TRANSITION_TYPES = [
    "CapabilityGrant",
    "TrustLevelChange",
    "ArtifactPromotion",
    "PolicyOverride",
]

VERIFICATION_STATES = [
    "Verified",
    "Unverified",
    "Expired",
    "Invalid",
]

REQUIRED_EVENT_CODES = [
    "CTL-001",
    "CTL-002",
    "CTL-003",
    "CTL-004",
    "CTL-005",
    "CTL-006",
    "CTL-007",
    "CTL-008",
]

REQUIRED_ERROR_CODES = [
    "ERR-CTL-MISSING-EVIDENCE",
    "ERR-CTL-EXPIRED-EVIDENCE",
    "ERR-CTL-SCOPE-MISMATCH",
    "ERR-CTL-INVALID-HASH",
    "ERR-CTL-INSUFFICIENT-TRUST",
    "ERR-CTL-INTERNAL",
]

REQUIRED_INVARIANTS = [
    "INV-CTL-EVIDENCE-REQUIRED",
    "INV-CTL-DENY-LOGGED",
    "INV-CTL-NO-BYPASS",
]

REQUIRED_IMPL_SYMBOLS = [
    "pub enum TransitionType",
    "pub enum VerificationState",
    "pub enum AuthorizationDecision",
    "pub struct VefEvidenceRef",
    "pub struct TransitionRequest",
    "pub struct DenialReason",
    "pub struct GateEvent",
    "pub struct GatePolicy",
    "pub struct TransitionOverride",
    "pub struct GateMetrics",
    "pub struct TransitionMetrics",
    "pub struct ActorTrustContext",
    "pub struct ControlTransitionGate",
    "pub fn evaluate",
    "pub fn evaluate_batch",
    "pub fn events",
    "pub fn drain_events",
    "pub fn metrics",
    "pub fn policy",
    "pub fn set_now_millis",
    "pub fn new",
]

REQUIRED_EVIDENCE_FIELDS = [
    "evidence_id",
    "evidence_hash",
    "scope",
    "state",
    "created_at_millis",
    "expires_at_millis",
    "trace_id",
]

REQUIRED_REQUEST_FIELDS = [
    "request_id",
    "transition_type",
    "actor_identity",
    "target_identity",
    "evidence_refs",
    "context",
    "trace_id",
    "requested_at_millis",
]

REQUIRED_METRICS_FIELDS = [
    "total_requests",
    "authorized_count",
    "denied_count",
    "pending_count",
    "denied_missing_evidence",
    "denied_expired_evidence",
    "denied_scope_mismatch",
    "denied_invalid_hash",
    "denied_insufficient_trust",
    "per_transition_type",
]

RESULTS: list[dict[str, Any]] = []


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _safe_rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if str(path).startswith(str(ROOT)) else str(path)


def _check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("ok" if passed else "NOT FOUND"),
        }
    )


def _load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def check_file_presence() -> None:
    files = [
        ("impl_exists", IMPL),
        ("mod_exists", MOD_RS),
        ("spec_contract_exists", SPEC_CONTRACT),
        ("unit_test_exists", UNIT_TEST),
        ("evidence_exists", EVIDENCE),
        ("summary_exists", SUMMARY),
    ]
    for name, path in files:
        _check(name, path.is_file(), _safe_rel(path))


def check_impl_symbols() -> None:
    src = _read(IMPL)

    for symbol in REQUIRED_IMPL_SYMBOLS:
        _check(f"impl_symbol_{symbol.split()[-1]}", symbol in src, symbol)

    for tt in TRANSITION_TYPES:
        _check(f"impl_transition_type_{tt}", tt in src, tt)

    for vs in VERIFICATION_STATES:
        _check(f"impl_verification_state_{vs}", vs in src, vs)

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_{code}", code in src, code)

    for code in REQUIRED_ERROR_CODES:
        _check(f"impl_error_{code}", code in src, code)

    for inv in REQUIRED_INVARIANTS:
        _check(f"impl_invariant_{inv}", inv in src, inv)

    for field in REQUIRED_EVIDENCE_FIELDS:
        _check(f"impl_evidence_field_{field}", field in src, field)

    for field in REQUIRED_REQUEST_FIELDS:
        _check(f"impl_request_field_{field}", field in src, field)

    for field in REQUIRED_METRICS_FIELDS:
        _check(f"impl_metrics_field_{field}", field in src, field)

    _check(
        "impl_schema_version",
        "vef-control-integration-v1" in src,
        "vef-control-integration-v1",
    )
    _check(
        "impl_uses_btreemap",
        "BTreeMap" in src,
        "BTreeMap for deterministic ordering",
    )
    _check(
        "impl_serde_derive",
        "#[derive(" in src and "Serialize" in src and "Deserialize" in src,
        "Serialize + Deserialize",
    )
    _check(
        "impl_serde_json_roundtrip",
        "serde_json" in src,
        "serde_json roundtrip in tests",
    )
    _check(
        "impl_trace_id_propagation",
        src.count("trace_id") >= 15,
        f"{src.count('trace_id')} trace_id references",
    )

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 25, f"{test_count} tests")


def check_mod_wiring() -> None:
    mod_text = _read(MOD_RS)
    _check(
        "vef_mod_wires_control_integration",
        "pub mod control_integration;" in mod_text,
        "pub mod control_integration;",
    )


def check_contract_compliance() -> None:
    """Verify implementation satisfies the key contract requirements."""
    src = _read(IMPL)

    # All transition types require evidence (INV-CTL-NO-BYPASS)
    _check(
        "contract_no_bypass",
        "requires_evidence" in src and "INV-CTL-NO-BYPASS" in src,
        "requires_evidence + INV-CTL-NO-BYPASS",
    )

    # Missing evidence denial
    _check(
        "contract_missing_evidence_denied",
        "ERR-CTL-MISSING-EVIDENCE" in src and "evidence_refs.is_empty()" in src,
        "empty evidence check with ERR-CTL-MISSING-EVIDENCE",
    )

    # Expired evidence denial
    _check(
        "contract_expired_evidence_denied",
        "is_expired_at" in src and "ERR-CTL-EXPIRED-EVIDENCE" in src,
        "expiration check with ERR-CTL-EXPIRED-EVIDENCE",
    )

    # Scope mismatch denial
    _check(
        "contract_scope_mismatch_denied",
        "covers_transition" in src and "ERR-CTL-SCOPE-MISMATCH" in src,
        "scope coverage check with ERR-CTL-SCOPE-MISMATCH",
    )

    # Invalid hash denial
    _check(
        "contract_invalid_hash_denied",
        "ERR-CTL-INVALID-HASH" in src and "Invalid" in src,
        "invalid hash/state handling",
    )

    # Pending verification
    _check(
        "contract_pending_verification",
        "PendingVerification" in src and "Unverified" in src,
        "PendingVerification for Unverified evidence",
    )

    # Trust level enforcement
    _check(
        "contract_trust_level_enforcement",
        "min_trust_level" in src and "ERR-CTL-INSUFFICIENT-TRUST" in src,
        "trust level enforcement",
    )

    # Denial event logging (INV-CTL-DENY-LOGGED)
    event_push_count = src.count("self.emit_event(")
    _check(
        "contract_deny_logged",
        event_push_count >= 6,
        f"{event_push_count} emit_event calls (INV-CTL-DENY-LOGGED)",
    )

    # Per-transition-type overrides
    _check(
        "contract_transition_overrides",
        "TransitionOverride" in src and "effective_min_evidence" in src,
        "per-transition-type policy overrides",
    )

    # Batch evaluation
    _check(
        "contract_batch_evaluate",
        "evaluate_batch" in src,
        "batch evaluation method",
    )

    # Metrics tracking
    _check(
        "contract_metrics_tracking",
        "GateMetrics" in src and "per_transition_type" in src,
        "per-transition-type metrics",
    )


def check_evidence_summary() -> None:
    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check(
            "evidence_bead_id",
            evidence.get("bead_id") == "bd-8qlj",
            str(evidence.get("bead_id")),
        )
        _check(
            "evidence_verdict_pass",
            evidence.get("verdict") == "PASS",
            str(evidence.get("verdict")),
        )

    summary = _read(SUMMARY)
    _check("summary_mentions_bead", "bd-8qlj" in summary, "bd-8qlj")
    _check("summary_mentions_pass", "PASS" in summary, "PASS")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_impl_symbols()
    check_mod_wiring()
    check_contract_compliance()
    check_evidence_summary()

    total = len(RESULTS)
    passed = sum(1 for entry in RESULTS if entry["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-8qlj",
        "title": "VEF verification state in high-risk control transitions and action authorization",
        "section": "10.18",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append(
            {"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")}
        )

    push(
        "transition_type_count",
        len(TRANSITION_TYPES) == 4,
        str(len(TRANSITION_TYPES)),
    )
    push(
        "verification_state_count",
        len(VERIFICATION_STATES) == 4,
        str(len(VERIFICATION_STATES)),
    )
    push(
        "event_code_count",
        len(REQUIRED_EVENT_CODES) == 8,
        str(len(REQUIRED_EVENT_CODES)),
    )
    push(
        "error_code_count",
        len(REQUIRED_ERROR_CODES) == 6,
        str(len(REQUIRED_ERROR_CODES)),
    )
    push(
        "invariant_count",
        len(REQUIRED_INVARIANTS) == 3,
        str(len(REQUIRED_INVARIANTS)),
    )
    push(
        "impl_symbol_count",
        len(REQUIRED_IMPL_SYMBOLS) >= 20,
        str(len(REQUIRED_IMPL_SYMBOLS)),
    )
    push(
        "evidence_field_count",
        len(REQUIRED_EVIDENCE_FIELDS) == 7,
        str(len(REQUIRED_EVIDENCE_FIELDS)),
    )
    push(
        "request_field_count",
        len(REQUIRED_REQUEST_FIELDS) == 8,
        str(len(REQUIRED_REQUEST_FIELDS)),
    )
    push(
        "metrics_field_count",
        len(REQUIRED_METRICS_FIELDS) == 10,
        str(len(REQUIRED_METRICS_FIELDS)),
    )

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push(
        "run_all_has_checks",
        isinstance(report.get("checks"), list),
        "checks list",
    )
    push(
        "run_all_total_matches",
        report.get("total") == len(report.get("checks", [])),
        "total vs checks",
    )

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": "bd-8qlj",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify bd-8qlj artifacts")
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    parser.add_argument("--self-test", action="store_true", help="run checker self-test")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['bead_id']}] {result['verdict']} ({result['passed']}/{result['total']})")
        for check in result["checks"]:
            mark = "PASS" if check["pass"] else "FAIL"
            print(f"- {mark} {check['check']}: {check['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
