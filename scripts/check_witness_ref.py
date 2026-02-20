#!/usr/bin/env python3
"""bd-1oof: Verify trace-witness reference implementation.

Checks:
  1. witness_ref.rs exists with required types and methods
  2. Event codes EVD-WITNESS-001 through 004
  3. Invariant doc comments
  4. High-impact classification predicate
  5. WitnessValidator with validation and integrity checking
  6. Unit tests cover required scenarios

Usage:
  python3 scripts/check_witness_ref.py          # human-readable
  python3 scripts/check_witness_ref.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "observability" / "witness_ref.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-1oof_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "observability" / "mod.rs"

REQUIRED_TYPES = [
    "pub struct WitnessId",
    "pub enum WitnessKind",
    "pub struct WitnessRef",
    "pub struct WitnessSet",
    "pub struct WitnessValidator",
    "pub struct WitnessAudit",
    "pub enum WitnessValidationError",
]

REQUIRED_METHODS = [
    "fn is_high_impact(",
    "fn validate(",
    "fn verify_integrity(",
    "fn coverage_audit(",
    "fn hash_hex(",
    "fn with_locator(",
    "fn has_duplicates(",
    "fn high_impact_kinds(",
    "fn is_complete(",
]

EVENT_CODES = [
    "EVD-WITNESS-001",
    "EVD-WITNESS-002",
    "EVD-WITNESS-003",
    "EVD-WITNESS-004",
]

INVARIANTS = [
    "INV-WITNESS-PRESENCE",
    "INV-WITNESS-INTEGRITY",
    "INV-WITNESS-RESOLVABLE",
]

WITNESS_KINDS = [
    "Telemetry",
    "StateSnapshot",
    "ProofArtifact",
    "ExternalSignal",
]

ERROR_CODES = [
    "ERR_MISSING_WITNESSES",
    "ERR_INTEGRITY_HASH_MISMATCH",
    "ERR_UNRESOLVABLE_LOCATOR",
    "ERR_DUPLICATE_WITNESS_ID",
]

REQUIRED_TESTS = [
    "witness_id_display",
    "witness_kind_labels",
    "witness_kind_all_four_variants",
    "witness_ref_creation",
    "witness_ref_with_locator",
    "witness_ref_hash_hex",
    "witness_set_empty",
    "witness_set_add",
    "witness_set_no_duplicates",
    "witness_set_detects_duplicates",
    "quarantine_is_high_impact",
    "release_is_high_impact",
    "escalate_is_high_impact",
    "admit_is_not_high_impact",
    "deny_is_not_high_impact",
    "all_decision_kinds_classified",
    "high_impact_with_witnesses_passes",
    "high_impact_without_witnesses_rejected",
    "non_high_impact_without_witnesses_passes",
    "duplicate_witness_ids_rejected",
    "strict_mode_requires_locator",
    "strict_mode_with_locator_passes",
    "integrity_hash_matches",
    "integrity_hash_mismatch_rejected",
    "coverage_audit_complete",
    "coverage_audit_incomplete",
    "multiple_witnesses_preserves_ordering",
    "validator_counters_accumulate",
    "all_high_impact_kinds_require_witnesses",
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
    found = "witness_ref" in content
    return {"check": "module registered in mod.rs", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_test_count():
    if not IMPL.is_file():
        return {"check": "test count", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "unit test count", "pass": count >= 25,
            "detail": f"{count} tests (minimum 25)"}


def check_upstream_import():
    if not IMPL.is_file():
        return {"check": "imports evidence_ledger types", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "DecisionKind" in content and "EvidenceEntry" in content
    return {"check": "imports DecisionKind + EvidenceEntry", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def self_test():
    result = run_checks()
    all_pass = result["verdict"] == "PASS"
    return all_pass, result["checks"]


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_module_registered())
    checks.append(check_upstream_import())
    checks.append(check_test_count())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, WITNESS_KINDS, "witness_kind"))
    checks.extend(check_content(IMPL, ERROR_CODES, "error_code"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    test_count = len(re.findall(r"#\[test\]", IMPL.read_text())) if IMPL.is_file() else 0
    return {
        "bead_id": "bd-1oof",
        "title": "Trace-witness references for high-impact ledger entries",
        "section": "10.14",
        "overall_pass": passed == total,
        "verdict": "PASS" if passed == total else "FAIL",
        "test_count": test_count,
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
        print(f"=== bd-1oof: Trace-Witness Reference Verification ===")
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
