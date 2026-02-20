#!/usr/bin/env python3
"""bd-oolt: Verify mandatory evidence emission for policy-driven actions.

Checks:
  1. evidence_emission.rs exists with required types and methods
  2. Event codes EVD-POLICY-001 through 003
  3. All four PolicyAction variants covered
  4. Conformance checker rejects missing evidence
  5. Action/evidence linkage validation
  6. Unit tests cover required scenarios

Usage:
  python3 scripts/check_evidence_emission.py          # human-readable
  python3 scripts/check_evidence_emission.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "evidence_emission.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-oolt_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
LEDGER_RS = ROOT / "crates" / "franken-node" / "src" / "observability" / "evidence_ledger.rs"

REQUIRED_TYPES = [
    "pub enum PolicyAction",
    "pub struct ActionId",
    "pub struct EvidenceRequirement",
    "pub enum PolicyActionOutcome",
    "pub struct EvidenceConformanceChecker",
    "pub enum ConformanceError",
    "pub struct CoverageEntry",
]

REQUIRED_METHODS = [
    "fn verify_and_execute(",
    "fn expected_decision_kind(",
    "fn coverage_check(",
    "fn coverage_matrix(",
    "fn action_log(",
    "fn executed_count(",
    "fn rejected_count(",
    "fn build_evidence_entry(",
    "fn for_action(",
    "fn all_requirements(",
]

EVENT_CODES = [
    "EVD-POLICY-001",
    "EVD-POLICY-002",
    "EVD-POLICY-003",
]

INVARIANTS = [
    "INV-EVIDENCE-MANDATORY",
    "INV-EVIDENCE-LINKAGE",
    "INV-EVIDENCE-COMPLETE",
]

ACTION_VARIANTS = [
    "Commit",
    "Abort",
    "Quarantine",
    "Release",
]

ERROR_CODES = [
    "ERR_MISSING_EVIDENCE",
    "ERR_DECISION_KIND_MISMATCH",
    "ERR_ACTION_ID_MISMATCH",
    "ERR_MALFORMED_EVIDENCE",
    "ERR_LEDGER_APPEND_FAILED",
]

REQUIRED_TESTS = [
    "action_id_display",
    "policy_action_all_four_variants",
    "policy_action_labels",
    "policy_action_decision_kind_mapping",
    "evidence_requirement_for_each_action",
    "all_requirements_covers_all_actions",
    "conformance_error_codes",
    "outcome_executed",
    "outcome_rejected",
    "commit_with_evidence_executes",
    "abort_with_evidence_executes",
    "quarantine_with_evidence_executes",
    "release_with_evidence_executes",
    "commit_without_evidence_rejected",
    "abort_without_evidence_rejected",
    "quarantine_without_evidence_rejected",
    "release_without_evidence_rejected",
    "wrong_decision_kind_rejected",
    "wrong_action_id_rejected",
    "empty_decision_id_rejected",
    "coverage_check_all_four_actions",
    "coverage_matrix_all_actions",
    "action_log_accumulates",
    "full_lifecycle_all_four_actions_with_evidence",
    "full_lifecycle_all_four_without_evidence",
    "build_evidence_entry_sets_correct_fields",
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
    found = "evidence_emission" in content
    return {"check": "module registered in mod.rs", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_upstream_ledger():
    ok = LEDGER_RS.is_file()
    return {"check": "upstream: evidence_ledger.rs", "pass": ok,
            "detail": "exists" if ok else "MISSING"}


def check_uses_evidence_ledger():
    if not IMPL.is_file():
        return {"check": "imports EvidenceLedger", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "EvidenceLedger" in content and "DecisionKind" in content and "EvidenceEntry" in content
    return {"check": "imports EvidenceLedger + DecisionKind + EvidenceEntry",
            "pass": found, "detail": "found" if found else "NOT FOUND"}


def check_test_count(path):
    if not path.is_file():
        return {"check": "test count", "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "unit test count", "pass": count >= 25,
            "detail": f"{count} tests (minimum 25)"}


def self_test():
    result = run_checks()
    all_pass = result["verdict"] == "PASS"
    return all_pass, result["checks"]


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_module_registered())
    checks.append(check_upstream_ledger())
    checks.append(check_uses_evidence_ledger())
    checks.append(check_test_count(IMPL))
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, ACTION_VARIANTS, "action"))
    checks.extend(check_content(IMPL, ERROR_CODES, "error_code"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-oolt",
        "title": "Mandatory evidence emission for policy-driven actions",
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
        print(f"=== bd-oolt: Evidence Emission Conformance Verification ===")
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
