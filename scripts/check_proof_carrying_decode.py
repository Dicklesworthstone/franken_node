#!/usr/bin/env python3
"""Verification script for bd-20uo: Proof-carrying repair artifacts.

Usage:
    python3 scripts/check_proof_carrying_decode.py          # human-readable
    python3 scripts/check_proof_carrying_decode.py --json    # machine-readable
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "repair" / "proof_carrying_decode.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "repair" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-20uo_contract.md"
GOLDEN_VECTORS = ROOT / "artifacts" / "10.14" / "repair_proof_samples.json"

REQUIRED_TYPES = [
    "pub struct RepairProof",
    "pub struct ProofCarryingDecoder",
    "pub struct ProofVerificationApi",
    "pub struct Fragment",
    "pub struct AlgorithmId",
    "pub struct Attestation",
    "pub enum VerificationResult",
    "pub enum ProofMode",
    "pub struct DecodeResult",
    "pub struct ProofAuditEvent",
    "pub enum ProofCarryingDecodeError",
]

REQUIRED_METHODS = [
    "fn decode(",
    "fn verify(",
    "fn check_proof_presence(",
    "fn set_mode(",
    "fn register_algorithm(",
]

EVENT_CODES = [
    "REPAIR_PROOF_EMITTED",
    "REPAIR_PROOF_VERIFIED",
    "REPAIR_PROOF_MISSING",
    "REPAIR_PROOF_INVALID",
]

INVARIANTS = [
    "INV-REPAIR-PROOF-COMPLETE",
    "INV-REPAIR-PROOF-BINDING",
    "INV-REPAIR-PROOF-DETERMINISTIC",
]

REQUIRED_TESTS = [
    "test_fragment_hash_deterministic",
    "test_fragment_hash_different_data",
    "test_algorithm_id_display",
    "test_decode_success",
    "test_decode_emits_proof",
    "test_decode_audit_event",
    "test_decode_unregistered_algorithm",
    "test_decode_empty_fragments",
    "test_decode_output_is_concatenation",
    "test_decode_proof_id_format",
    "test_decode_timestamp_propagated",
    "test_decode_trace_id_propagated",
    "test_mode_mandatory",
    "test_mode_advisory",
    "test_mode_switch",
    "test_register_algorithm",
    "test_register_duplicate_algorithm",
    "test_verify_valid_proof",
    "test_verify_tampered_fragment_hash",
    "test_verify_wrong_algorithm",
    "test_verify_output_hash_mismatch",
    "test_verify_invalid_signature",
    "test_presence_mandatory_with_proof",
    "test_presence_mandatory_without_proof",
    "test_presence_advisory_without_proof",
    "test_verification_result_event_codes",
    "test_repair_proof_roundtrip",
    "test_decode_result_roundtrip",
    "test_proof_mode_roundtrip",
    "test_error_display_missing",
    "test_error_display_invalid",
    "test_error_display_reconstruction",
    "test_proof_deterministic",
    "test_multiple_decodes_audit_log",
    "test_decode_single_fragment",
]


def check_file(path, label):
    exists = path.exists()
    if exists:
        try:
            rel = str(path.relative_to(ROOT))
        except ValueError:
            rel = str(path)
    else:
        rel = str(path)
    return {
        "check": f"file: {label}",
        "pass": exists,
        "detail": f"exists: {rel}" if exists else f"missing: {rel}",
    }


def check_content(path, patterns, category):
    results = []
    try:
        text = path.read_text()
    except FileNotFoundError:
        for p in patterns:
            results.append({
                "check": f"{category}: {p}",
                "pass": False,
                "detail": f"file not found: {path}",
            })
        return results
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else f"not found in {path.name}",
        })
    return results


def check_module_registered():
    try:
        text = MOD_RS.read_text()
        found = "pub mod proof_carrying_decode;" in text
    except FileNotFoundError:
        found = False
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "not found",
    }


def check_test_count():
    try:
        text = IMPL.read_text()
        count = len(re.findall(r"#\[test\]", text))
    except FileNotFoundError:
        count = 0
    return {
        "check": "unit test count",
        "pass": count >= 25,
        "detail": f"{count} tests (minimum 25)",
    }


def check_serde_derives():
    try:
        text = IMPL.read_text()
        has_serialize = "Serialize" in text and "Deserialize" in text
    except FileNotFoundError:
        has_serialize = False
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_serialize,
        "detail": "found" if has_serialize else "not found",
    }


def check_sha256_usage():
    try:
        text = IMPL.read_text()
        has_sha = "Sha256" in text
    except FileNotFoundError:
        has_sha = False
    return {
        "check": "SHA-256 hashing",
        "pass": has_sha,
        "detail": "found" if has_sha else "not found",
    }


def check_golden_vectors():
    if not GOLDEN_VECTORS.is_file():
        return {
            "check": "golden vectors artifact",
            "pass": False,
            "detail": "missing",
        }
    try:
        data = json.loads(GOLDEN_VECTORS.read_text())
        samples = data.get("samples", data.get("proofs", []))
        count = len(samples)
        ok = count >= 3
        return {
            "check": "golden vectors artifact",
            "pass": ok,
            "detail": f"{count} samples (minimum 3)",
        }
    except (json.JSONDecodeError, KeyError) as exc:
        return {
            "check": "golden vectors artifact",
            "pass": False,
            "detail": f"JSON error: {exc}",
        }


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(GOLDEN_VECTORS, "golden vectors"))
    checks.append(check_golden_vectors())
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.append(check_sha256_usage())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = len(checks) - passing

    try:
        text = IMPL.read_text()
        test_count = len(re.findall(r"#\[test\]", text))
    except FileNotFoundError:
        test_count = 0

    return {
        "bead_id": "bd-20uo",
        "title": "Proof-carrying repair artifacts for decode/reconstruction paths",
        "section": "10.14",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": test_count,
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    return result["overall_pass"], result["checks"]


if __name__ == "__main__":
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        v = result["verdict"]
        s = result["summary"]
        print(f"bd-20uo proof_carrying_decode: {v} ({s['passing']}/{s['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
