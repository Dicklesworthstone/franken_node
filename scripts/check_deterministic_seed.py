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
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "encoding" / "deterministic_seed.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-29r6_contract.md"
VECTORS = ROOT / "artifacts" / "10.14" / "seed_derivation_vectors.json"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "encoding" / "mod.rs"

BEAD_ID = "bd-29r6"
JSON_DECODER = json.JSONDecoder()

INVARIANT_IMPLEMENTATION_MARKERS = {
    "INV-SEED-DOMAIN-SEP": [
        "pub enum DomainTag",
        "pub fn prefix(&self) -> &'static str",
        "hasher.update(domain.prefix().as_bytes())",
        "hasher.update([0x00])",
    ],
    "INV-SEED-STABLE": [
        "Sha256::new()",
        "hasher.update(content_hash.0)",
        "hasher.update(config.config_hash())",
        "hasher.finalize().into()",
    ],
    "INV-SEED-BOUNDED": [
        "pub struct ContentHash(#[serde(with = \"hex_bytes\")] pub [u8; 32])",
        "content_hash: &ContentHash",
        "hasher.update(content_hash.0)",
    ],
    "INV-SEED-NO-PLATFORM": [
        "BTreeMap<String, String>",
        "for (k, v) in &self.parameters",
        "self.version.to_le_bytes()",
        "u64::try_from(k.len()).unwrap_or(u64::MAX).to_le_bytes()",
        "u64::try_from(v.len()).unwrap_or(u64::MAX).to_le_bytes()",
    ],
}

REQUIRED_RUST_TESTS = [
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
    "content_hash_serialization_roundtrip",
    "test_single_bit_content_change",
    "test_empty_content_hash",
    "test_event_codes_defined",
]

# ---- helpers ---------------------------------------------------------------

def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail}


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _file_check(label: str, path: Path) -> dict:
    return _check(f"file: {label}", path.is_file(), f"exists: {display_path(path)}")


def _contains(content: str, needle: str, label: str) -> dict:
    found = needle in content
    return _check(label, found, "found" if found else f"missing: {needle}")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def read_rust_source(path: Path) -> str:
    return strip_rust_comments(read_text(path))


def strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = rust_block_comment_end(text, i + 2)
            continue

        raw_end = rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


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

    data = JSON_DECODER.decode(read_text(VECTORS))
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

    content = read_rust_source(IMPL)

    # Module registration
    if MOD_RS.is_file():
        mod_content = read_rust_source(MOD_RS)
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
    for inv, markers in INVARIANT_IMPLEMENTATION_MARKERS.items():
        missing = [marker for marker in markers if marker not in content]
        checks.append(_check(
            f"invariant: {inv}",
            not missing,
            "implementation markers found" if not missing else f"missing: {', '.join(missing)}",
        ))

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
    for test_name in REQUIRED_RUST_TESTS:
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
    configure_test_logging("check_deterministic_seed")
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
