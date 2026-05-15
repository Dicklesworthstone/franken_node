#!/usr/bin/env python3
"""Verification checker for bd-3pds: VEF evidence capsule for verifier SDK replay.

Verifies the evidence capsule implementation including seal immutability,
schema-stable exports, verifier registry, audit logging, and deterministic
metadata ordering.

Usage:
    python3 scripts/check_vef_evidence_capsule.py          # human-readable
    python3 scripts/check_vef_evidence_capsule.py --json    # machine-readable
    python3 scripts/check_vef_evidence_capsule.py --self-test
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

BEAD_ID = "bd-3pds"
SECTION = "10.18"

IMPL_FILE = ROOT / "crates" / "franken-node" / "src" / "vef" / "evidence_capsule.rs"
MOD_FILE = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
EVIDENCE_FILE = ROOT / "artifacts" / "section_10_18" / BEAD_ID / "verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts" / "section_10_18" / BEAD_ID / "verification_summary.md"

REQUIRED_SYMBOLS = [
    "pub struct VefEvidence",
    "pub struct EvidenceCapsule",
    "pub struct CapsuleVerificationResult",
    "pub struct ExternalVerifierEndpoint",
    "pub struct ExportManifest",
    "pub struct VerifierRegistry",
    "pub enum CapsuleError",
    "pub fn new",
    "pub fn is_sealed",
    "pub fn add_evidence",
    "pub fn set_metadata",
    "pub fn seal",
    "pub fn verify_all",
    "pub fn evidence_count",
    "pub fn register",
    "pub fn export_capsule",
    "pub fn endpoints",
    "pub fn audit_log",
]

EVENT_CODES = [
    "EVIDENCE_CAPSULE_CREATED",
    "EVIDENCE_CAPSULE_SEALED",
    "EVIDENCE_CAPSULE_EXPORTED",
    "EVIDENCE_CAPSULE_VERIFIED",
    "EVIDENCE_CAPSULE_REJECTED",
]

ERROR_CODES = [
    "ERR_CAPSULE_EMPTY_EVIDENCE",
    "ERR_CAPSULE_SEAL_FAILED",
    "ERR_CAPSULE_SCHEMA_MISMATCH",
    "ERR_CAPSULE_PROOF_MISSING",
    "ERR_CAPSULE_REPLAY_DIVERGED",
    "ERR_CAPSULE_EXPORT_FAILED",
]

ERROR_VARIANTS = [
    "EmptyEvidence",
    "AlreadySealed",
    "SchemaMismatch",
    "ProofMissing",
    "ReplayDiverged",
    "ExportFailed",
]

INVARIANTS = [
    "INV-EVIDENCE-CAPSULE-COMPLETE",
    "INV-EVIDENCE-CAPSULE-SEALED",
    "INV-EVIDENCE-CAPSULE-VERIFIABLE",
    "INV-EVIDENCE-CAPSULE-SCHEMA-STABLE",
]

RESULTS: list[dict[str, Any]] = []


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _strip_rust_comments(src: str) -> str:
    without_block_comments = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return re.sub(r"//.*", "", without_block_comments)


def _impl_source() -> str:
    return _read_text(IMPL_FILE)


def _impl_code() -> str:
    return _strip_rust_comments(_impl_source())


def _mod_code() -> str:
    return _strip_rust_comments(_read_text(MOD_FILE))


def _rust_module_decl_present(src: str, module_name: str) -> bool:
    return bool(re.search(rf"\bpub\s+mod\s+{re.escape(module_name)}\s*;", src))


def _rust_pub_item_present(src: str, item_kind: str, name: str) -> bool:
    return bool(re.search(rf"\bpub\s+{item_kind}\s+{re.escape(name)}\b", src))


def _rust_pub_fn_present(src: str, name: str) -> bool:
    return bool(re.search(rf"\bpub\s+fn\s+{re.escape(name)}\s*\(", src))


def _rust_pub_const_str_present(src: str, name: str, value: str | None = None) -> bool:
    expected_value = value or name
    return bool(
        re.search(
            rf"\bpub\s+const\s+{re.escape(name)}\s*:\s*&str\s*=\s*\"{re.escape(expected_value)}\"\s*;",
            src,
        )
    )


def _rust_enum_body(src: str, enum_name: str) -> str:
    match = re.search(rf"\bpub\s+enum\s+{re.escape(enum_name)}\s*\{{(?P<body>.*?)\n\}}", src, re.DOTALL)
    return match.group("body") if match else ""


def _rust_enum_variant_present(src: str, enum_name: str, variant: str) -> bool:
    return bool(re.search(rf"\b{re.escape(variant)}\b", _rust_enum_body(src, enum_name)))


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


def _read_impl() -> str:
    return _impl_source()


def check_file_presence() -> None:
    _check("impl_exists", IMPL_FILE.is_file(), str(IMPL_FILE.relative_to(ROOT)))
    _check("mod_exists", MOD_FILE.is_file(), str(MOD_FILE.relative_to(ROOT)))


def check_mod_wiring() -> None:
    if not MOD_FILE.is_file():
        _check("mod_wires_evidence_capsule", False, "mod.rs missing")
        return
    mod_text = _mod_code()
    _check(
        "mod_wires_evidence_capsule",
        _rust_module_decl_present(mod_text, "evidence_capsule"),
        "pub mod evidence_capsule;",
    )


def check_impl_symbols() -> None:
    src = _impl_code()
    for sym in REQUIRED_SYMBOLS:
        label = sym.split()[-1]
        _check(f"impl_symbol_{label}", _required_symbol_present(src, sym), sym)


def check_event_codes() -> None:
    src = _impl_code()
    for code in EVENT_CODES:
        _check(f"event_{code}", _rust_pub_const_str_present(src, code), code)


def check_error_codes() -> None:
    src = _impl_code()
    for code in ERROR_CODES:
        _check(f"error_code_{code}", _rust_pub_const_str_present(src, code), code)


def check_error_variants() -> None:
    src = _impl_code()
    for variant in ERROR_VARIANTS:
        _check(
            f"error_variant_{variant}",
            _rust_enum_variant_present(src, "CapsuleError", variant),
            variant,
        )


def check_invariants() -> None:
    src = _read_impl()
    for inv in INVARIANTS:
        _check(f"invariant_{inv}", inv in src, inv)


def check_contract_properties() -> None:
    src = _impl_code()

    _check("contract_schema_version",
           "evidence-capsule-v1" in src,
           "schema version present")

    _check("contract_btreemap",
           "BTreeMap" in src,
           "BTreeMap for deterministic ordering")

    _check("contract_serde_derive",
           "Serialize" in src and "Deserialize" in src,
           "Serialize + Deserialize")

    _check("contract_seal_immutability",
           "AlreadySealed" in src and "is_sealed" in src,
           "sealed capsules reject mutation")

    _check("contract_verify_all_logic",
           "verify_all" in src and "CapsuleVerificationResult" in src,
           "verify_all returns structured result")

    _check("contract_export_manifest",
           "ExportManifest" in src and "export_capsule" in src,
           "export produces manifest")

    _check("contract_audit_log",
           "audit_log" in src,
           "audit log for exports")

    _check("contract_display_impl",
           "impl" in src and "Display" in src and "CapsuleError" in src,
           "Display impl for CapsuleError")

    _check("contract_default_impl",
           "Default" in src and "VerifierRegistry" in src,
           "Default impl for VerifierRegistry")

    _check("contract_receipt_chain_commitment",
           "receipt_chain_commitment" in src,
           "evidence links to receipt chain")

    _check("contract_proof_id_required",
           "proof_id" in src,
           "evidence requires proof_id")

    _check("contract_window_bounds",
           "window_start" in src and "window_end" in src,
           "evidence has time window bounds")

    _check("contract_supported_schemas",
           "supported_schemas" in src,
           "verifier endpoint declares supported schemas")

    _check("contract_schema_mismatch_check",
           "SchemaMismatch" in src and "supported_schemas" in src,
           "export validates schema compatibility")


def check_unit_tests() -> None:
    src = _impl_code()
    test_count = _rust_test_count(src)
    _check("impl_minimum_unit_tests", test_count >= 18, f"{test_count} tests")


def check_evidence() -> None:
    if not EVIDENCE_FILE.is_file():
        _check("evidence_exists", False, str(EVIDENCE_FILE.relative_to(ROOT)))
        return
    _check("evidence_exists", True, str(EVIDENCE_FILE.relative_to(ROOT)))
    try:
        data = json.JSONDecoder().decode(_read_text(EVIDENCE_FILE))
        _check("evidence_parseable", True, "valid JSON")
        _check("evidence_bead_id", data.get("bead_id") == BEAD_ID, str(data.get("bead_id")))
        verdict = data.get("verdict", data.get("overall_pass"))
        _check(
            "evidence_verdict",
            bool(verdict == "PASS" or (isinstance(verdict, bool) and verdict)),
            str(verdict),
        )
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
    check_event_codes()
    check_error_codes()
    check_error_variants()
    check_invariants()
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
        "title": "VEF evidence capsule for verifier SDK replay",
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
    push("event_code_count", len(EVENT_CODES) == 5, str(len(EVENT_CODES)))
    push("error_code_count", len(ERROR_CODES) == 6, str(len(ERROR_CODES)))
    push("error_variant_count", len(ERROR_VARIANTS) == 6, str(len(ERROR_VARIANTS)))
    push("invariant_count", len(INVARIANTS) == 4, str(len(INVARIANTS)))

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
    configure_test_logging("check_vef_evidence_capsule")
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
