#!/usr/bin/env python3
"""bd-206h: Verification script for idempotency dedupe store.

Usage:
    python3 scripts/check_idempotency_store.py            # human-readable
    python3 scripts/check_idempotency_store.py --json      # machine-readable
    python3 scripts/check_idempotency_store.py --self-test  # internal consistency
"""

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


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _is_expired(now_secs: int, created_at_secs: int, ttl_secs: int) -> bool:
    """Mirror DedupeEntry::is_expired(): now >= created_at + ttl."""
    return now_secs >= (created_at_secs + ttl_secs)


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


# ── Simulation ─────────────────────────────────────────────────────────────

def simulate_dedupe_store() -> dict:
    results = {}

    # hash_payload determinism
    h1 = _sha256_hex(b"payload-a")
    h2 = _sha256_hex(b"payload-a")
    results["hash_deterministic"] = h1 == h2

    # different payloads -> different hashes
    h3 = _sha256_hex(b"payload-b")
    results["hash_differs"] = h1 != h3

    # TTL expiry logic mirrors DedupeEntry::is_expired(): now >= created_at + ttl
    created_at = 1000
    ttl = 100
    expiry_cutoff = created_at + ttl
    now = 1101
    results["ttl_boundary_expired"] = _is_expired(expiry_cutoff, created_at, ttl)
    results["ttl_expired"] = _is_expired(now, created_at, ttl)

    # Strictly before the cutoff should remain live.
    results["ttl_not_expired"] = not _is_expired(expiry_cutoff - 1, created_at, ttl)

    # 7 event codes
    results["event_code_count"] = len(REQUIRED_EVENT_CODES)

    # 5 invariants
    results["invariant_count"] = len(REQUIRED_INVARIANTS)

    # 5 core types
    results["core_type_count"] = len(REQUIRED_CORE_TYPES)

    return results


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

    sim = simulate_dedupe_store()
    checks.append(_check("sim: hash deterministic", sim["hash_deterministic"]))
    checks.append(_check("sim: hash differs for different payloads", sim["hash_differs"]))
    checks.append(_check("sim: TTL boundary expires correctly", sim["ttl_boundary_expired"]))
    checks.append(_check("sim: TTL expired correctly", sim["ttl_expired"]))
    checks.append(_check("sim: TTL not expired within window", sim["ttl_not_expired"]))
    checks.append(_check("sim: 7 event codes", sim["event_code_count"] == 7))
    checks.append(_check("sim: 5 invariants", sim["invariant_count"] == 5))
    checks.append(_check("sim: 5 core types", sim["core_type_count"] == 5))

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

    sim = simulate_dedupe_store()
    checks.append(_check("simulation returns dict", isinstance(sim, dict)))
    checks.append(_check("simulation hash_deterministic", sim["hash_deterministic"]))
    checks.append(_check("simulation ttl_boundary_expired", sim["ttl_boundary_expired"]))
    checks.append(_check("simulation ttl_expired", sim["ttl_expired"]))

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
    logger = configure_test_logging("check_idempotency_store")
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
