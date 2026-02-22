#!/usr/bin/env python3
"""Verification checker for bd-1o4v: VEF proof-verification gate API.

Verifies the proof-verification gate implementation including trust decisions,
policy predicate evaluation, structured evidence, deterministic reports,
and classified error handling.

Usage:
    python3 scripts/check_vef_proof_verifier.py          # human-readable
    python3 scripts/check_vef_proof_verifier.py --json    # machine-readable
    python3 scripts/check_vef_proof_verifier.py --self-test
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
BEAD_ID = "bd-1o4v"
SECTION = "10.18"

IMPL_FILE = ROOT / "crates" / "franken-node" / "src" / "vef" / "proof_verifier.rs"
MOD_FILE = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
EVIDENCE_FILE = ROOT / "artifacts" / "section_10_18" / BEAD_ID / "verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts" / "section_10_18" / BEAD_ID / "verification_summary.md"

REQUIRED_SYMBOLS = [
    "pub enum TrustDecision",
    "pub struct PolicyPredicate",
    "pub struct ComplianceProof",
    "pub struct VerificationRequest",
    "pub struct PredicateEvidence",
    "pub struct VerificationReport",
    "pub struct VerifierEvent",
    "pub struct VerifierError",
    "pub struct VerificationGateConfig",
    "pub struct ProofVerifier",
    "pub struct VerificationGate",
    "pub struct DecisionSummary",
    "pub fn validate_proof",
    "pub fn register_predicate",
    "pub fn remove_predicate",
    "pub fn verify",
    "pub fn verify_batch",
    "pub fn decision_summary",
    "pub fn events",
    "pub fn reports",
    "pub fn predicates",
]

TRUST_DECISION_VARIANTS = [
    "Allow",
    "Deny",
    "Degrade",
]

EVENT_CODES = [
    "PVF-001",
    "PVF-002",
    "PVF-003",
    "PVF-004",
    "PVF-005",
    "PVF-006",
]

ERROR_CODES = [
    "ERR-PVF-PROOF-EXPIRED",
    "ERR-PVF-POLICY-MISSING",
    "ERR-PVF-INVALID-FORMAT",
    "ERR-PVF-INTERNAL",
]

PREDICATE_EVIDENCE_CHECKS = [
    "expiry",
    "freshness",
    "action_class",
    "confidence",
    "witness",
    "policy_version",
]

CONFIG_FIELDS = [
    "max_proof_age_millis",
    "degrade_threshold",
    "enforce_policy_version",
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
        _check("mod_wires_proof_verifier", False, "mod.rs missing")
        return
    mod_text = MOD_FILE.read_text()
    _check("mod_wires_proof_verifier", "pub mod proof_verifier;" in mod_text, "pub mod proof_verifier;")


def check_impl_symbols() -> None:
    src = _read_impl()
    for sym in REQUIRED_SYMBOLS:
        label = sym.split()[-1]
        _check(f"impl_symbol_{label}", sym in src, sym)


def check_trust_decisions() -> None:
    src = _read_impl()
    for variant in TRUST_DECISION_VARIANTS:
        _check(f"decision_{variant}", variant in src, variant)


def check_event_codes() -> None:
    src = _read_impl()
    for code in EVENT_CODES:
        _check(f"event_{code}", code in src, code)


def check_error_codes() -> None:
    src = _read_impl()
    for code in ERROR_CODES:
        _check(f"error_{code}", code in src, code)


def check_config_fields() -> None:
    src = _read_impl()
    for field in CONFIG_FIELDS:
        found = re.search(rf"pub\s+{field}\s*:", src) is not None
        _check(f"config_{field}", found, field)


def check_contract_properties() -> None:
    src = _read_impl()

    _check("contract_deterministic",
           "INV-PVF-DETERMINISTIC" in src or "deterministic" in src.lower(),
           "deterministic invariant")

    _check("contract_deny_logged",
           "INV-PVF-DENY-LOGGED" in src or "PVF-004" in src,
           "deny decisions logged")

    _check("contract_evidence_complete",
           "INV-PVF-EVIDENCE-COMPLETE" in src or "PredicateEvidence" in src,
           "evidence completeness")

    _check("contract_fail_closed",
           "Deny" in src and "expired" in src.lower(),
           "fail-closed on expired proofs")

    _check("contract_batch_verify",
           "verify_batch" in src,
           "batch verification support")

    _check("contract_decision_summary",
           "DecisionSummary" in src and "allow_count" in src,
           "decision summary statistics")

    _check("contract_report_digest",
           "report_digest" in src or "compute_report_digest" in src,
           "deterministic report digest")

    _check("contract_schema_version",
           "vef-proof-verifier-v1" in src,
           "vef-proof-verifier-v1")

    trace_refs = src.count("trace_id")
    _check("contract_trace_propagation", trace_refs >= 20, f"{trace_refs} trace_id references")

    _check("contract_serde_derive",
           "Serialize" in src and "Deserialize" in src,
           "Serialize + Deserialize")

    _check("contract_btreemap",
           "BTreeMap" in src,
           "BTreeMap for deterministic ordering")

    _check("contract_sha256_digest",
           "Sha256" in src or "sha256" in src,
           "SHA-256 for report digest")

    for check_name in PREDICATE_EVIDENCE_CHECKS:
        _check(f"evidence_check_{check_name}",
               check_name in src.lower(),
               f"evidence includes {check_name} check")


def check_unit_tests() -> None:
    src = _read_impl()
    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 20, f"{test_count} tests")


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
    check_trust_decisions()
    check_event_codes()
    check_error_codes()
    check_config_fields()
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
        "title": "VEF proof-verification gate API for control-plane trust decisions",
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

    push("symbol_count", len(REQUIRED_SYMBOLS) == 21, str(len(REQUIRED_SYMBOLS)))
    push("event_code_count", len(EVENT_CODES) == 6, str(len(EVENT_CODES)))
    push("error_code_count", len(ERROR_CODES) == 4, str(len(ERROR_CODES)))
    push("decision_variant_count", len(TRUST_DECISION_VARIANTS) == 3, str(len(TRUST_DECISION_VARIANTS)))
    push("config_field_count", len(CONFIG_FIELDS) == 3, str(len(CONFIG_FIELDS)))
    push("evidence_check_count", len(PREDICATE_EVIDENCE_CHECKS) == 6, str(len(PREDICATE_EVIDENCE_CHECKS)))

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
