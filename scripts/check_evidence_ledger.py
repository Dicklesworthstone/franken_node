#!/usr/bin/env python3
"""bd-2e73: Verify bounded evidence ledger ring buffer implementation.

Checks:
  1. evidence_ledger.rs exists with required types and methods
  2. Event codes EVD-LEDGER-001 through 004
  3. Ring buffer capacity configuration
  4. FIFO eviction semantics
  5. Lab spill mode
  6. Send + Sync compile-time assertion
  7. Unit tests cover all required scenarios

Usage:
  python3 scripts/check_evidence_ledger.py          # human-readable
  python3 scripts/check_evidence_ledger.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "observability" / "evidence_ledger.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-2e73_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "observability" / "mod.rs"

REQUIRED_TYPES = [
    "pub struct EvidenceLedger",
    "pub struct EvidenceEntry",
    "pub struct LedgerCapacity",
    "pub struct LedgerSnapshot",
    "pub struct SharedEvidenceLedger",
    "pub struct LabSpillMode",
    "pub struct EntryId",
    "pub enum DecisionKind",
    "pub enum LedgerError",
]

REQUIRED_METHODS = [
    "fn append(",
    "fn iter_recent(",
    "fn iter_all(",
    "fn snapshot(",
    "fn evict_oldest(",
    "fn estimated_size(",
    "fn with_file(",
]

EVENT_CODES = [
    "EVD-LEDGER-001",
    "EVD-LEDGER-002",
    "EVD-LEDGER-003",
    "EVD-LEDGER-004",
]

REQUIRED_TESTS = [
    "new_ledger_is_empty",
    "append_single_entry",
    "evicts_oldest_when_max_entries_exceeded",
    "eviction_is_fifo",
    "evicts_when_max_bytes_exceeded",
    "rejects_entry_larger_than_max_bytes",
    "max_bytes_enforced_independently_of_max_entries",
    "iter_recent_returns_last_n",
    "iter_recent_on_empty_ledger",
    "snapshot_is_consistent",
    "snapshot_after_eviction",
    "identical_sequences_produce_identical_snapshots",
    "evidence_entry_serialization_roundtrip",
    "lab_spill_to_tempfile",
    "lab_spill_eviction_still_works",
    "shared_ledger_basic_operations",
    "steady_state_load_100_entries",
    "spill_determinism_two_runs_identical",
    "capacity_one",
    "decision_kind_labels",
]


def check_file(path, label):
    ok = path.is_file()
    rel = str(path.relative_to(ROOT)) if ok else str(path)
    return {"check": f"file: {label}", "pass": ok,
            "detail": f"exists: {rel}" if ok else f"MISSING: {rel}"}


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = path.read_text()
    for p in patterns:
        found = p in content
        results.append({"check": f"{category}: {p}", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"check": "module registered", "pass": False, "detail": "mod.rs missing"}
    content = MOD_RS.read_text()
    found = "evidence_ledger" in content
    return {"check": "module registered in mod.rs", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_send_sync():
    if not IMPL.is_file():
        return {"check": "Send + Sync assertion", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "assert_send_sync" in content and "SharedEvidenceLedger" in content
    return {"check": "compile-time Send + Sync assertion", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_test_count(path):
    if not path.is_file():
        return {"check": "test count", "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "unit test count", "pass": count >= 25,
            "detail": f"{count} tests (minimum 25)"}


def check_serde():
    if not IMPL.is_file():
        return {"check": "serde derives", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    count = content.count("Serialize, Deserialize")
    ok = count >= 5
    return {"check": "Serialize+Deserialize derives", "pass": ok,
            "detail": f"{count} derive blocks (minimum 5)"}


def self_test():
    result = run_checks()
    all_pass = result["verdict"] == "PASS"
    return all_pass, result["checks"]


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_module_registered())
    checks.append(check_send_sync())
    checks.append(check_serde())
    checks.append(check_test_count(IMPL))
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-2e73",
        "title": "Bounded evidence ledger ring buffer",
        "section": "10.14",
        "overall_pass": passed == total,
        "verdict": "PASS" if passed == total else "FAIL",
        "test_count": len(re.findall(r"#\[test\]", IMPL.read_text())) if IMPL.is_file() else 0,
        "summary": {"passing": passed, "failing": total - passed, "total": total},
        "checks": checks,
    }


def main():
    if "--self-test" in sys.argv:
        ok, results = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'}")
        return

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== bd-2e73: Evidence Ledger Ring Buffer Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing']}/{s['total']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
