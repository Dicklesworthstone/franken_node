#!/usr/bin/env python3
"""bd-206h: Verification script for idempotency dedupe store.

Usage:
    python3 scripts/check_idempotency_store.py            # human-readable
    python3 scripts/check_idempotency_store.py --json      # machine-readable
    python3 scripts/check_idempotency_store.py --self-test  # internal consistency
"""
# ruff: noqa: E402

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/remote/idempotency_store.rs"
MOD_FILE = ROOT / "crates/franken-node/src/remote/mod.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_14/bd-206h_contract.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_14/bd-206h/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_14/bd-206h/verification_summary.md"

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_EVENT_CODES = [
    "ID_ENTRY_NEW",
    "ID_ENTRY_DUPLICATE",
    "ID_ENTRY_CONFLICT",
    "ID_ENTRY_EXPIRED",
    "ID_STORE_RECOVERY",
    "ID_INFLIGHT_RESOLVED",
    "ID_SWEEP_COMPLETE",
]

REQUIRED_INVARIANTS = [
    "INV-IDS-AT-MOST-ONCE",
    "INV-IDS-CONFLICT-DETECT",
    "INV-IDS-TTL-BOUND",
    "INV-IDS-CRASH-SAFE",
    "INV-IDS-AUDITABLE",
]

REQUIRED_CORE_TYPES = [
    "DedupeResult",
    "DedupeEntry",
    "IdempotencyDedupeStore",
    "CachedOutcome",
    "EntryStatus",
]

REQUIRED_OPERATIONS = [
    "check_or_insert",
    "complete",
    "sweep_expired",
    "recover_inflight",
    "export_audit_log_jsonl",
    "content_hash",
    "stats",
    "entry_count",
]

# ── Helpers ────────────────────────────────────────────────────────────────

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _read_json(path: Path) -> tuple[dict | None, str]:
    try:
        data = json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "missing"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"
    if not isinstance(data, dict):
        return None, "top-level JSON must be an object"
    return data, "valid JSON object"


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _content_hash_block() -> str:
    src = _read(IMPL_FILE)
    match = re.search(
        r"pub fn content_hash\(&self\) -> String \{(?P<body>.*?)\n    \}\n\n    /// Return",
        src,
        re.S,
    )
    return match.group("body") if match else ""


# ── Check groups ───────────────────────────────────────────────────────────

def check_source_exists() -> list:
    checks = []
    checks.append(_check("SOURCE_EXISTS", IMPL_FILE.exists(), str(IMPL_FILE)))
    return checks


def check_file_existence() -> list:
    checks = []
    checks.append(_check("mod.rs wires idempotency_store",
                         "pub mod idempotency_store;" in _read(MOD_FILE)))
    checks.append(_check("contract spec exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("evidence artifact exists", EVIDENCE_FILE.exists(), str(EVIDENCE_FILE)))
    checks.append(_check("summary artifact exists", SUMMARY_FILE.exists(), str(SUMMARY_FILE)))
    return checks


def check_event_codes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for ec in REQUIRED_EVENT_CODES:
        checks.append(_check(f"event code {ec}", ec in src))
    checks.append(_check("EVENT_CODES all 7 present",
                         all(ec in src for ec in REQUIRED_EVENT_CODES),
                         f"{sum(1 for ec in REQUIRED_EVENT_CODES if ec in src)}/7"))
    return checks


def check_invariants() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(f"invariant {inv}", inv in src))
    checks.append(_check("INVARIANTS all 5 present",
                         all(inv in src for inv in REQUIRED_INVARIANTS),
                         f"{sum(1 for inv in REQUIRED_INVARIANTS if inv in src)}/5"))
    return checks


def check_core_types() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for t in REQUIRED_CORE_TYPES:
        found = f"pub enum {t}" in src or f"pub struct {t}" in src
        checks.append(_check(f"core type {t}", found))
    return checks


def check_conflict_error() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("CONFLICT_ERROR code",
                         "ERR_IDEMPOTENCY_CONFLICT" in src))
    return checks


def check_ttl_expiration() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("TTL_EXPIRATION: DEFAULT_TTL_SECS defined",
                         "DEFAULT_TTL_SECS" in src))
    checks.append(_check("TTL_EXPIRATION: is_expired method",
                         "fn is_expired" in src))
    checks.append(_check("TTL_EXPIRATION: 604_800 seconds (7 days)",
                         "604_800" in src))
    return checks


def check_crash_recovery() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("CRASH_RECOVERY: recover_inflight",
                         "fn recover_inflight" in src))
    checks.append(_check("CRASH_RECOVERY: Abandoned variant",
                         "Abandoned" in src))
    checks.append(_check("CRASH_RECOVERY: init constructor",
                         "fn init" in src))
    return checks


def check_audit_trail() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("AUDIT_TRAIL: export_audit_log_jsonl",
                         "fn export_audit_log_jsonl" in src))
    checks.append(_check("AUDIT_TRAIL: IdsAuditRecord type",
                         "pub struct IdsAuditRecord" in src))
    checks.append(_check("AUDIT_TRAIL: trace_id field",
                         "trace_id" in src))
    return checks


def check_operations() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for op in REQUIRED_OPERATIONS:
        checks.append(_check(f"operation {op}", f"fn {op}" in src))
    return checks


def check_content_hash_surface() -> list:
    block = _content_hash_block()
    checks = []
    checks.append(_check("CONTENT_HASH: function located", bool(block)))
    checks.append(_check("CONTENT_HASH: created_at_secs participates",
                         "entry.created_at_secs" in block))
    checks.append(_check("CONTENT_HASH: ttl_secs participates",
                         "entry.ttl_secs" in block))
    checks.append(_check("CONTENT_HASH: completed_at_secs participates",
                         "outcome.completed_at_secs" in block))
    checks.append(_check("CONTENT_HASH: result_data participates",
                         "outcome.result_data" in block))
    checks.append(_check("CONTENT_HASH: outcome presence is encoded",
                         "hasher.update([1])" in block and "hasher.update([0])" in block))
    return checks


def check_test_coverage() -> list:
    src = _read(IMPL_FILE)
    checks = []
    test_count = len(re.findall(r"#\[test\]", src))
    checks.append(_check(f"TEST_COVERAGE: {test_count} tests (>= 12)",
                         test_count >= 12, f"{test_count} tests"))
    return checks


def check_serde() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("Serde Serialize derive", "Serialize" in src))
    checks.append(_check("Serde Deserialize derive", "Deserialize" in src))
    return checks


def check_upstream() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("imports IdempotencyKey",
                         "IdempotencyKey" in src))
    checks.append(_check("uses sha2::Sha256",
                         "Sha256" in src))
    checks.append(_check("hash_payload helper",
                         "fn hash_payload" in src))
    return checks


def check_schema_version() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("SCHEMA_VERSION ids-v1.0",
                         "ids-v1.0" in src))
    return checks


def check_dedupe_result_variants() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("DedupeResult::New variant", "New" in src and "DedupeResult" in src))
    checks.append(_check("DedupeResult::Duplicate variant", "Duplicate" in src))
    checks.append(_check("DedupeResult::Conflict variant with fields",
                         "Conflict" in src and "key_hex" in src and "expected_hash" in src))
    checks.append(_check("DedupeResult::InFlight variant", "InFlight" in src))
    return checks


# ── Evidence analysis ──────────────────────────────────────────────────────

def analyze_dedupe_store_evidence(evidence_path: Path = EVIDENCE_FILE) -> dict:
    evidence, detail = _read_json(evidence_path)
    src = _read(IMPL_FILE)

    if evidence is None:
        return {
            "valid_evidence": False,
            "detail": detail,
            "verdict_ok": False,
            "rust_test_count": 0,
            "python_test_count": 0,
            "event_codes_match": False,
            "invariants_covered": False,
            "core_variants_covered": False,
            "ttl_expiration_verified": False,
            "conflict_detection_verified": False,
            "content_hash_determinism_verified": False,
            "schema_version_matches": False,
            "default_ttl_matches": False,
            "hash_payload_test_present": False,
            "ttl_boundary_test_present": False,
            "ttl_live_window_test_present": False,
        }

    capabilities = evidence.get("capabilities_verified", {})
    dedupe_results = set(capabilities.get("dedupe_results", []))
    invariants = set(evidence.get("invariants_verified", []))

    return {
        "valid_evidence": True,
        "detail": detail,
        "verdict_ok": evidence.get("verdict") == "PASS",
        "rust_test_count": int(evidence.get("rust_test_count", 0)),
        "python_test_count": int(evidence.get("python_test_count", 0)),
        "event_codes_match": evidence.get("event_codes_defined") == len(REQUIRED_EVENT_CODES),
        "invariants_covered": set(REQUIRED_INVARIANTS).issubset(invariants),
        "core_variants_covered": {"New", "Duplicate", "Conflict", "InFlight"}.issubset(
            dedupe_results
        ),
        "ttl_expiration_verified": bool(capabilities.get("ttl_expiration")),
        "conflict_detection_verified": bool(capabilities.get("conflict_detection")),
        "content_hash_determinism_verified": bool(
            capabilities.get("content_hash_determinism")
        ),
        "schema_version_matches": evidence.get("schema_version") == "ids-v1.0",
        "default_ttl_matches": evidence.get("default_ttl_secs") == 604_800,
        "hash_payload_test_present": "fn test_hash_payload_deterministic()" in src,
        "ttl_boundary_test_present": "fn entry_expired_at_exact_ttl_boundary()" in src
        and "entry.is_expired(1100)" in src
        and "entry.is_expired(1099)" in src,
        "ttl_live_window_test_present": "fn test_sweep_leaves_unexpired()" in src
        and "sweep_expired(1101" in src,
    }


# ── Main check runner ──────────────────────────────────────────────────────

def _checks() -> list:
    checks = []
    checks.extend(check_source_exists())
    checks.extend(check_file_existence())
    checks.extend(check_event_codes())
    checks.extend(check_invariants())
    checks.extend(check_core_types())
    checks.extend(check_conflict_error())
    checks.extend(check_ttl_expiration())
    checks.extend(check_crash_recovery())
    checks.extend(check_audit_trail())
    checks.extend(check_operations())
    checks.extend(check_content_hash_surface())
    checks.extend(check_test_coverage())
    checks.extend(check_serde())
    checks.extend(check_upstream())
    checks.extend(check_schema_version())
    checks.extend(check_dedupe_result_variants())

    evidence = analyze_dedupe_store_evidence()
    checks.append(_check("evidence: verification artifact loads", evidence["valid_evidence"], evidence["detail"]))
    checks.append(_check("evidence: pass verdict", evidence["verdict_ok"]))
    checks.append(_check("evidence: rust tests recorded", evidence["rust_test_count"] >= 20))
    checks.append(_check("evidence: python tests recorded", evidence["python_test_count"] >= 28))
    checks.append(_check("evidence: 7 event codes recorded", evidence["event_codes_match"]))
    checks.append(_check("evidence: 5 invariants covered", evidence["invariants_covered"]))
    checks.append(_check("evidence: dedupe result variants covered", evidence["core_variants_covered"]))
    checks.append(_check("evidence: TTL expiration verified", evidence["ttl_expiration_verified"]))
    checks.append(_check("evidence: conflict detection verified", evidence["conflict_detection_verified"]))
    checks.append(_check("evidence: content hash determinism verified", evidence["content_hash_determinism_verified"]))
    checks.append(_check("evidence: schema version matches", evidence["schema_version_matches"]))
    checks.append(_check("evidence: default TTL matches", evidence["default_ttl_matches"]))
    checks.append(_check("source test: hash payload deterministic", evidence["hash_payload_test_present"]))
    checks.append(_check("source test: exact TTL boundary", evidence["ttl_boundary_test_present"]))
    checks.append(_check("source test: unexpired sweep window", evidence["ttl_live_window_test_present"]))

    return checks


def run_checks() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["pass"])
    failed = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-206h",
        "title": "Idempotency dedupe store with at-most-once execution guarantee",
        "section": "10.14",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def run_all() -> dict:
    return run_checks()


def self_test() -> tuple:
    checks = []
    checks.append(_check("REQUIRED_EVENT_CODES count", len(REQUIRED_EVENT_CODES) == 7))
    checks.append(_check("REQUIRED_INVARIANTS count", len(REQUIRED_INVARIANTS) == 5))
    checks.append(_check("REQUIRED_CORE_TYPES count", len(REQUIRED_CORE_TYPES) == 5))
    checks.append(_check("REQUIRED_OPERATIONS count", len(REQUIRED_OPERATIONS) >= 8))

    evidence = analyze_dedupe_store_evidence()
    checks.append(_check("evidence analysis returns dict", isinstance(evidence, dict)))
    checks.append(_check("evidence analysis pass verdict", evidence["verdict_ok"]))
    checks.append(_check("evidence analysis TTL boundary test", evidence["ttl_boundary_test_present"]))
    checks.append(_check("evidence analysis hash payload test", evidence["hash_payload_test_present"]))

    result = run_checks()
    checks.append(_check("run_checks has bead_id", result.get("bead_id") == "bd-206h"))
    checks.append(_check("run_checks has section", result.get("section") == "10.14"))
    checks.append(_check("run_checks has verdict", result.get("verdict") in ("PASS", "FAIL")))

    h1 = _sha256_hex(b"self-test")
    h2 = _sha256_hex(b"self-test")
    checks.append(_check("sha256 deterministic", h1 == h2))

    ok = all(c["pass"] for c in checks)
    return (ok, checks)


def main():
    configure_test_logging("check_idempotency_store")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        passed = sum(1 for c in checks if c["pass"])
        for c in checks:
            print(f"  [{'PASS' if c['pass'] else 'FAIL'}] {c['check']}")
        print(f"\nself-test: {passed}/{len(checks)} {'PASS' if ok else 'FAIL'}")
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            print(f"  [{'PASS' if c['pass'] else 'FAIL'}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
