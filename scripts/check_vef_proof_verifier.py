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
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

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


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _strip_rust_comments(src: str) -> str:
    without_block_comments = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return re.sub(r"//.*", "", without_block_comments)


def _impl_code() -> str:
    return _strip_rust_comments(_read(IMPL_FILE))


def _mod_code() -> str:
    return _strip_rust_comments(_read(MOD_FILE))


def _rust_module_decl_present(src: str, module_name: str) -> bool:
    return bool(re.search(rf"\bpub\s+mod\s+{re.escape(module_name)}\s*;", src))


def _rust_pub_item_present(src: str, item_kind: str, name: str) -> bool:
    return bool(re.search(rf"\bpub\s+{item_kind}\s+{re.escape(name)}\b", src))


def _rust_pub_fn_present(src: str, name: str) -> bool:
    return bool(re.search(rf"\bpub\s+fn\s+{re.escape(name)}\s*\(", src))


def _rust_pub_const_str_value_present(src: str, value: str) -> bool:
    return bool(
        re.search(
            rf"\bpub\s+const\s+\w+\s*:\s*&str\s*=\s*\"{re.escape(value)}\"\s*;",
            src,
        )
    )


def _rust_enum_body(src: str, enum_name: str) -> str:
    match = re.search(rf"\bpub\s+enum\s+{re.escape(enum_name)}\s*\{{(?P<body>.*?)\n\}}", src, re.DOTALL)
    return match.group("body") if match else ""


def _rust_enum_variant_present(src: str, enum_name: str, variant: str) -> bool:
    return bool(re.search(rf"\b{re.escape(variant)}\b", _rust_enum_body(src, enum_name)))


def _rust_struct_body(src: str, struct_name: str) -> str:
    match = re.search(rf"\bpub\s+struct\s+{re.escape(struct_name)}\s*\{{(?P<body>.*?)\n\}}", src, re.DOTALL)
    return match.group("body") if match else ""


def _rust_pub_struct_field_present(src: str, struct_name: str, field: str) -> bool:
    return bool(re.search(rf"\bpub\s+{re.escape(field)}\s*:", _rust_struct_body(src, struct_name)))


def _rust_test_count(src: str) -> int:
    return len(re.findall(r"#\s*\[\s*test\s*\]", src))


def _required_symbol_present(src: str, symbol: str) -> bool:
    parts = symbol.split()
    if len(parts) < 3 or parts[0] != "pub":
        return symbol in src
    if parts[1] in {"struct", "enum"}:
        return _rust_pub_item_present(src, parts[1], parts[2])
    if parts[1] == "fn":
        return _rust_pub_fn_present(src, parts[2])
    return symbol in src


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }
    RESULTS.append(entry)
    return entry


def check_file_presence() -> None:
    _check("impl_exists", IMPL_FILE.is_file(), str(IMPL_FILE.relative_to(ROOT)))
    _check("mod_exists", MOD_FILE.is_file(), str(MOD_FILE.relative_to(ROOT)))


def check_mod_wiring() -> None:
    if not MOD_FILE.is_file():
        _check("mod_wires_proof_verifier", False, "mod.rs missing")
        return
    _check("mod_wires_proof_verifier", _rust_module_decl_present(_mod_code(), "proof_verifier"), "pub mod proof_verifier;")


def check_impl_symbols() -> None:
    src = _impl_code()
    for sym in REQUIRED_SYMBOLS:
        label = sym.split()[-1]
        _check(f"impl_symbol_{label}", _required_symbol_present(src, sym), sym)


def check_trust_decisions() -> None:
    src = _impl_code()
    for variant in TRUST_DECISION_VARIANTS:
        _check(f"decision_{variant}", _rust_enum_variant_present(src, "TrustDecision", variant), variant)


def check_event_codes() -> None:
    src = _impl_code()
    for code in EVENT_CODES:
        _check(f"event_{code}", _rust_pub_const_str_value_present(src, code), code)


def check_error_codes() -> None:
    src = _impl_code()
    for code in ERROR_CODES:
        _check(f"error_{code}", _rust_pub_const_str_value_present(src, code), code)


def check_config_fields() -> None:
    src = _impl_code()
    for field in CONFIG_FIELDS:
        _check(f"config_{field}", _rust_pub_struct_field_present(src, "VerificationGateConfig", field), field)


def check_contract_properties() -> None:
    src = _impl_code()

    _check("contract_deterministic",
           _rust_pub_const_str_value_present(src, "INV-PVF-DETERMINISTIC")
           or "deterministic" in src.lower(),
           "deterministic invariant")

    _check("contract_deny_logged",
           _rust_pub_const_str_value_present(src, "INV-PVF-DENY-LOGGED")
           or _rust_pub_const_str_value_present(src, "PVF-004"),
           "deny decisions logged")

    _check("contract_evidence_complete",
           _rust_pub_const_str_value_present(src, "INV-PVF-EVIDENCE-COMPLETE")
           or _rust_pub_item_present(src, "struct", "PredicateEvidence"),
           "evidence completeness")

    _check("contract_fail_closed",
           _rust_enum_variant_present(src, "TrustDecision", "Deny") and "expired" in src.lower(),
           "fail-closed on expired proofs")

    _check("contract_batch_verify",
           _rust_pub_fn_present(src, "verify_batch"),
           "batch verification support")

    _check("contract_decision_summary",
           _rust_pub_item_present(src, "struct", "DecisionSummary")
           and _rust_pub_struct_field_present(src, "DecisionSummary", "allow_count"),
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
    src = _impl_code()
    test_count = _rust_test_count(src)
    _check("impl_minimum_unit_tests", test_count >= 20, f"{test_count} tests")


def check_evidence() -> None:
    if not EVIDENCE_FILE.is_file():
        _check("evidence_exists", False, str(EVIDENCE_FILE.relative_to(ROOT)))
        return
    _check("evidence_exists", True, str(EVIDENCE_FILE.relative_to(ROOT)))
    try:
        data = json.JSONDecoder().decode(EVIDENCE_FILE.read_text(encoding="utf-8"))
        _check("evidence_parseable", True, "valid JSON")
        _check("evidence_bead_id", data.get("bead_id") == BEAD_ID, str(data.get("bead_id")))
        verdict = data.get("verdict", data.get("overall_pass"))
        verdict_passed = verdict == "PASS" or (isinstance(verdict, bool) and verdict)
        _check("evidence_verdict", verdict_passed, str(verdict))
    except (json.JSONDecodeError, OSError):
        _check("evidence_parseable", False, "parse error")


def check_summary() -> None:
    if not SUMMARY_FILE.is_file():
        _check("summary_exists", False, str(SUMMARY_FILE.relative_to(ROOT)))
        return
    _check("summary_exists", True, str(SUMMARY_FILE.relative_to(ROOT)))
    text = SUMMARY_FILE.read_text(encoding="utf-8")
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
    configure_test_logging("check_vef_proof_verifier")
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
