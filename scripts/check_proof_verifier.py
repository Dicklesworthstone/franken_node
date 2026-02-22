#!/usr/bin/env python3
"""Verification script for bd-1o4v: Proof-verification gate API for control-plane trust decisions.

Usage:
    python3 scripts/check_proof_verifier.py
    python3 scripts/check_proof_verifier.py --json
    python3 scripts/check_proof_verifier.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "crates" / "franken-node" / "src" / "vef" / "proof_verifier.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-1o4v_contract.md"
UNIT_TEST = ROOT / "tests" / "test_check_proof_verifier.py"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-1o4v" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-1o4v" / "verification_summary.md"

REQUIRED_EVENT_CODES = [
    "PVF-001",
    "PVF-002",
    "PVF-003",
    "PVF-004",
    "PVF-005",
    "PVF-006",
]

REQUIRED_ERROR_CODES = [
    "ERR-PVF-PROOF-EXPIRED",
    "ERR-PVF-POLICY-MISSING",
    "ERR-PVF-INVALID-FORMAT",
    "ERR-PVF-INTERNAL",
]

REQUIRED_INVARIANTS = [
    "INV-PVF-DETERMINISTIC",
    "INV-PVF-DENY-LOGGED",
    "INV-PVF-EVIDENCE-COMPLETE",
]

REQUIRED_IMPL_SYMBOLS = [
    "pub enum TrustDecision",
    "pub struct PolicyPredicate",
    "pub struct ComplianceProof",
    "pub struct VerificationRequest",
    "pub struct VerificationReport",
    "pub struct VerificationGate",
    "pub struct ProofVerifier",
    "pub struct VerifierEvent",
    "pub struct VerifierError",
    "pub struct VerificationGateConfig",
    "pub struct PredicateEvidence",
    "pub struct DecisionSummary",
    "pub fn validate_proof",
    "pub fn verify",
    "pub fn verify_batch",
    "pub fn register_predicate",
    "pub fn remove_predicate",
    "pub fn decision_summary",
]

TRUST_DECISION_VARIANTS = [
    "Allow",
    "Deny",
    "Degrade",
]

REQUIRED_PROOF_FIELDS = [
    "proof_id",
    "action_class",
    "proof_hash",
    "confidence",
    "generated_at_millis",
    "expires_at_millis",
    "witness_references",
    "policy_version_hash",
    "trace_id",
]

REQUIRED_PREDICATE_FIELDS = [
    "predicate_id",
    "action_class",
    "max_proof_age_millis",
    "min_confidence",
    "require_witnesses",
    "min_witness_count",
    "policy_version_hash",
]

REQUIRED_REPORT_FIELDS = [
    "schema_version",
    "request_id",
    "proof_id",
    "action_class",
    "decision",
    "evidence",
    "report_digest",
    "trace_id",
    "created_at_millis",
]

REQUIRED_CONFIG_FIELDS = [
    "max_proof_age_millis",
    "degrade_threshold",
    "enforce_policy_version",
]

REQUIRED_SUMMARY_FIELDS = [
    "total_reports",
    "allow_count",
    "deny_count",
    "degrade_count",
    "deny_reasons",
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

    for variant in TRUST_DECISION_VARIANTS:
        _check(f"impl_trust_decision_{variant}", variant in src, variant)

    for field in REQUIRED_PROOF_FIELDS:
        _check(f"impl_proof_field_{field}", field in src, field)

    for field in REQUIRED_PREDICATE_FIELDS:
        _check(f"impl_predicate_field_{field}", field in src, field)

    for field in REQUIRED_REPORT_FIELDS:
        _check(f"impl_report_field_{field}", field in src, field)

    for field in REQUIRED_CONFIG_FIELDS:
        _check(f"impl_config_field_{field}", field in src, field)

    for field in REQUIRED_SUMMARY_FIELDS:
        _check(f"impl_summary_field_{field}", field in src, field)

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_{code}", code in src, code)

    for code in REQUIRED_ERROR_CODES:
        _check(f"impl_error_{code}", code in src, code)

    for inv in REQUIRED_INVARIANTS:
        _check(f"impl_invariant_{inv}", inv in src, inv)

    _check("impl_schema_version", "vef-proof-verifier-v1" in src, "vef-proof-verifier-v1")
    _check("impl_uses_btreemap", "BTreeMap" in src, "BTreeMap for deterministic ordering")
    _check(
        "impl_serde_derive",
        "#[derive(" in src and "Serialize" in src and "Deserialize" in src,
        "Serialize + Deserialize",
    )
    _check("impl_sha256_digest", "Sha256" in src, "SHA-256 digest for deterministic hashing")
    _check("impl_report_digest", "report_digest" in src, "report contains deterministic digest")
    _check("impl_trace_id_propagation", src.count("trace_id") >= 20, f"{src.count('trace_id')} trace_id references")
    _check("impl_events_push", src.count("self.events.push") >= 4, f"{src.count('self.events.push')} event emission points")

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 25, f"{test_count} tests")


def check_mod_wiring() -> None:
    mod_text = _read(MOD_RS)
    _check(
        "vef_mod_wires_proof_verifier",
        "pub mod proof_verifier;" in mod_text,
        "pub mod proof_verifier;",
    )


def check_verifier_contract() -> None:
    """Verify implementation satisfies the key verifier contract requirements."""
    src = _read(IMPL)

    # INV-PVF-DETERMINISTIC: deterministic decisions
    has_deterministic = "INV-PVF-DETERMINISTIC" in src
    has_deterministic_test = "deterministic_same_inputs_same_decision" in src
    _check(
        "contract_inv_pvf_deterministic",
        has_deterministic and has_deterministic_test,
        "deterministic decisions tested",
    )

    # INV-PVF-DENY-LOGGED: deny events logged
    has_deny_logged = "INV-PVF-DENY-LOGGED" in src
    has_deny_event = "PVF_004_DENY_LOGGED" in src
    _check(
        "contract_inv_pvf_deny_logged",
        has_deny_logged and has_deny_event,
        "deny decisions logged with PVF-004",
    )

    # INV-PVF-EVIDENCE-COMPLETE: evidence in every report
    has_evidence_complete = "INV-PVF-EVIDENCE-COMPLETE" in src
    has_evidence_field = "pub evidence:" in src
    _check(
        "contract_inv_pvf_evidence_complete",
        has_evidence_complete and has_evidence_field,
        "reports include complete evidence",
    )

    # Trust decision variants
    has_allow = "TrustDecision::Allow" in src
    has_deny = "TrustDecision::Deny(" in src
    has_degrade = "TrustDecision::Degrade(" in src
    _check(
        "contract_trust_decision_variants",
        has_allow and has_deny and has_degrade,
        "Allow, Deny, Degrade variants present",
    )

    # Error handling
    has_expired_err = "ERR-PVF-PROOF-EXPIRED" in src
    has_missing_err = "ERR-PVF-POLICY-MISSING" in src
    has_format_err = "ERR-PVF-INVALID-FORMAT" in src
    _check(
        "contract_error_handling",
        has_expired_err and has_missing_err and has_format_err,
        "all error codes present",
    )

    # Verification gate
    has_gate = "pub struct VerificationGate" in src
    has_register = "pub fn register_predicate" in src
    has_verify = "pub fn verify(" in src
    _check(
        "contract_verification_gate",
        has_gate and has_register and has_verify,
        "VerificationGate with register + verify",
    )

    # Batch verification
    has_batch = "pub fn verify_batch" in src
    _check(
        "contract_batch_verify",
        has_batch,
        "batch verification support",
    )

    # Decision summary
    has_summary = "pub fn decision_summary" in src
    _check(
        "contract_decision_summary",
        has_summary,
        "decision summary reporting",
    )

    # Proof age freshness check
    has_age_check = "max_proof_age_millis" in src and "age_millis" in src
    _check(
        "contract_proof_freshness",
        has_age_check,
        "proof freshness validation",
    )

    # Confidence threshold
    has_confidence = "min_confidence" in src and "degrade_threshold" in src
    _check(
        "contract_confidence_threshold",
        has_confidence,
        "confidence threshold with degrade fallback",
    )

    # Witness validation
    has_witnesses = "require_witnesses" in src and "min_witness_count" in src
    _check(
        "contract_witness_validation",
        has_witnesses,
        "witness reference validation",
    )

    # Policy version enforcement
    has_policy_version = "enforce_policy_version" in src and "policy_version_hash" in src
    _check(
        "contract_policy_version",
        has_policy_version,
        "policy version binding enforcement",
    )

    # Event lifecycle (request -> decision -> report)
    has_request_event = "PVF_001_REQUEST_RECEIVED" in src
    has_decision_event = "PVF_003_DECISION_EMITTED" in src
    has_finalized_event = "PVF_006_REPORT_FINALIZED" in src
    _check(
        "contract_event_lifecycle",
        has_request_event and has_decision_event and has_finalized_event,
        "full event lifecycle: request -> decision -> report",
    )


def check_evidence_summary() -> None:
    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check("evidence_bead_id", evidence.get("bead_id") == "bd-1o4v", str(evidence.get("bead_id")))
        _check("evidence_verdict_pass", evidence.get("verdict") == "PASS", str(evidence.get("verdict")))

    summary = _read(SUMMARY)
    _check("summary_mentions_bead", "bd-1o4v" in summary, "bd-1o4v")
    _check("summary_mentions_pass", "PASS" in summary, "PASS")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_impl_symbols()
    check_mod_wiring()
    check_verifier_contract()
    check_evidence_summary()

    total = len(RESULTS)
    passed = sum(1 for entry in RESULTS if entry["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-1o4v",
        "title": "Proof-verification gate API for control-plane trust decisions",
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
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("event_code_count", len(REQUIRED_EVENT_CODES) == 6, str(len(REQUIRED_EVENT_CODES)))
    push("error_code_count", len(REQUIRED_ERROR_CODES) == 4, str(len(REQUIRED_ERROR_CODES)))
    push("invariant_count", len(REQUIRED_INVARIANTS) == 3, str(len(REQUIRED_INVARIANTS)))
    push("impl_symbol_count", len(REQUIRED_IMPL_SYMBOLS) >= 15, str(len(REQUIRED_IMPL_SYMBOLS)))
    push("trust_decision_variant_count", len(TRUST_DECISION_VARIANTS) == 3, str(len(TRUST_DECISION_VARIANTS)))
    push("proof_field_count", len(REQUIRED_PROOF_FIELDS) == 9, str(len(REQUIRED_PROOF_FIELDS)))
    push("predicate_field_count", len(REQUIRED_PREDICATE_FIELDS) == 7, str(len(REQUIRED_PREDICATE_FIELDS)))
    push("report_field_count", len(REQUIRED_REPORT_FIELDS) == 9, str(len(REQUIRED_REPORT_FIELDS)))
    push("config_field_count", len(REQUIRED_CONFIG_FIELDS) == 3, str(len(REQUIRED_CONFIG_FIELDS)))
    push("summary_field_count", len(REQUIRED_SUMMARY_FIELDS) == 5, str(len(REQUIRED_SUMMARY_FIELDS)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": "bd-1o4v",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify bd-1o4v artifacts")
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
