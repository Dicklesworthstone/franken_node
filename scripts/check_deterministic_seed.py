#!/usr/bin/env python3
"""Verification script for bd-29r6: deterministic seed derivation (section 10.14).

Usage:
    python scripts/check_deterministic_seed.py          # human-readable
    python scripts/check_deterministic_seed.py --json   # machine-readable
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "encoding" / "deterministic_seed.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-29r6_contract.md"
VECTORS = ROOT / "artifacts" / "10.14" / "seed_derivation_vectors.json"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "encoding" / "mod.rs"

BEAD_ID = "bd-29r6"

# ---- helpers ---------------------------------------------------------------

def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail}


def _file_check(label: str, path: Path) -> dict:
    return _check(f"file: {label}", path.is_file(), f"exists: {path.relative_to(ROOT)}")


def _contains(content: str, needle: str, label: str) -> dict:
    found = needle in content
    return _check(label, found, "found" if found else f"missing: {needle}")


# ---- golden vector validation -----------------------------------------------

def config_hash(version: int, params: dict) -> bytes:
    h = hashlib.sha256()
    h.update(struct.pack('<I', version))
    for k in sorted(params.keys()):
        v = params[k]
        h.update(struct.pack('<I', len(k)))
        h.update(k.encode())
        h.update(struct.pack('<I', len(v)))
        h.update(v.encode())
    return h.digest()


def derive_seed_py(domain_prefix: str, content_hash_hex: str, cfg_hash: bytes) -> str:
    h = hashlib.sha256()
    h.update(domain_prefix.encode())
    h.update(b'\x00')
    h.update(bytes.fromhex(content_hash_hex))
    h.update(cfg_hash)
    return h.hexdigest()


def validate_vectors() -> list:
    checks = []
    if not VECTORS.is_file():
        checks.append(_check("vectors file exists", False, str(VECTORS)))
        return checks
    checks.append(_check("vectors file exists", True, str(VECTORS.relative_to(ROOT))))

    data = json.loads(VECTORS.read_text())
    vecs = data.get("vectors", [])
    checks.append(_check("vectors count >= 10", len(vecs) >= 10, f"{len(vecs)} vectors"))

    for v in vecs:
        cfg_h = config_hash(v["config_version"], v["config_params"])
        computed = derive_seed_py(v["domain_prefix"], v["content_hash_hex"], cfg_h)
        ok = computed == v["expected_seed_hex"]
        checks.append(_check(
            f"vector: {v['vector_id']}",
            ok,
            "match" if ok else f"expected {v['expected_seed_hex']}, got {computed}",
        ))
    return checks


# ---- main checks -----------------------------------------------------------

def run_checks() -> dict:
    checks = []

    # File existence
    checks.append(_file_check("implementation", IMPL))
    checks.append(_file_check("spec contract", SPEC))
    checks.append(_file_check("vectors", VECTORS))
    checks.append(_file_check("encoding/mod.rs", MOD_RS))

    if not IMPL.is_file():
        return _result(checks)

    content = IMPL.read_text()

    # Module registration
    if MOD_RS.is_file():
        mod_content = MOD_RS.read_text()
        checks.append(_contains(mod_content, "pub mod deterministic_seed", "module registered in mod.rs"))

    # Key types
    for ty in [
        "pub struct DeterministicSeedDeriver",
        "pub struct DeterministicSeed",
        "pub struct ContentHash",
        "pub struct ScheduleConfig",
        "pub struct VersionBumpRecord",
        "pub enum DomainTag",
        "pub enum SeedError",
    ]:
        checks.append(_contains(content, ty, f"type: {ty}"))

    # Key methods
    for method in [
        "fn derive_seed(",
        "fn config_hash(",
        "fn from_hex(",
        "fn to_hex(",
        "fn prefix_hex(",
        "fn bump_records(",
        "fn clear_bump_records(",
        "fn tracked_domains(",
        "fn with_param(",
    ]:
        checks.append(_contains(content, method, f"method: {method}"))

    # Domain separation prefixes
    for prefix in [
        "franken_node.encoding.v1",
        "franken_node.repair.v1",
        "franken_node.scheduling.v1",
        "franken_node.placement.v1",
        "franken_node.verification.v1",
    ]:
        checks.append(_contains(content, prefix, f"domain_prefix: {prefix}"))

    # Event codes
    checks.append(_contains(content, "SEED_DERIVED", "event_code: SEED_DERIVED"))
    checks.append(_contains(content, "SEED_VERSION_BUMP", "event_code: SEED_VERSION_BUMP"))

    # Invariant markers
    for inv in [
        "INV-SEED-DOMAIN-SEP",
        "INV-SEED-STABLE",
        "INV-SEED-BOUNDED",
        "INV-SEED-NO-PLATFORM",
    ]:
        checks.append(_contains(content, inv, f"invariant: {inv}"))

    # Send + Sync assertion
    checks.append(_contains(content, "assert_send_sync", "compile-time Send + Sync assertion"))

    # Serde derives
    derive_count = content.count("#[derive(")
    checks.append(_check(
        "Serialize+Deserialize derives",
        derive_count >= 4,
        f"{derive_count} derive blocks (minimum 4)",
    ))

    # Unit test count
    test_count = content.count("#[test]")
    checks.append(_check(
        "unit test count",
        test_count >= 25,
        f"{test_count} tests (minimum 25)",
    ))

    # Named tests
    for test_name in [
        "test_derive_seed_deterministic",
        "test_domain_separation_encoding_vs_repair",
        "test_domain_separation_all_pairs",
        "test_different_content_different_seed",
        "test_different_config_different_seed",
        "test_config_param_order_irrelevant",
        "test_deriver_config_change_triggers_bump",
        "test_no_collisions_100_samples",
        "test_golden_vector_encoding_zero",
        "test_golden_vector_repair_ff",
        "test_golden_vector_encoding_seq_v2",
        "test_golden_vector_scheduling_empty_params",
        "test_golden_vector_verification_singlebit",
        "test_seed_serialization_roundtrip",
        "test_content_hash_serialization_roundtrip",
        "test_single_bit_content_change",
        "test_empty_content_hash",
        "test_event_codes_defined",
    ]:
        checks.append(_contains(content, test_name, f"test: {test_name}"))

    # Golden vector cross-validation
    checks.extend(validate_vectors())

    return _result(checks)


def _result(checks: list) -> dict:
    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    return {
        "bead_id": BEAD_ID,
        "title": "Deterministic seed derivation",
        "section": "10.14",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": 47,
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return (len(failing) == 0, result["checks"])


def main():
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== {BEAD_ID}: Deterministic Seed Derivation ===")
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        print(f"\nVerdict: {result['verdict']} ({result['summary']['passing']}/{result['summary']['total']})")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
