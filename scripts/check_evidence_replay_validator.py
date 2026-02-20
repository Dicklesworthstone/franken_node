#!/usr/bin/env python3
"""bd-2ona: Verify evidence-ledger replay validator.

Checks:
  1. evidence_replay_validator.rs exists with required types, methods, tests
  2. Event codes EVD-REPLAY-001 through 004
  3. All 7 DecisionKind variants have replay coverage
  4. Deterministic replay: identical inputs → identical results
  5. Batch validation and summary report
  6. Module registration in tools/mod.rs and main.rs

Usage:
  python3 scripts/check_evidence_replay_validator.py          # human-readable
  python3 scripts/check_evidence_replay_validator.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "tools" / "evidence_replay_validator.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-2ona_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
MAIN_RS = ROOT / "crates" / "franken-node" / "src" / "main.rs"
LEDGER_RS = ROOT / "crates" / "franken-node" / "src" / "observability" / "evidence_ledger.rs"

REQUIRED_TYPES = [
    "pub struct EvidenceReplayValidator",
    "pub struct ReplayContext",
    "pub enum ReplayResult",
    "pub struct ReplayDiff",
    "pub struct DiffField",
    "pub struct ActionRef",
    "pub struct Candidate",
    "pub struct Constraint",
    "pub struct ReplaySummary",
]

REQUIRED_METHODS = [
    "fn validate(",
    "fn validate_batch(",
    "fn summary_report(",
    "fn replay_decision(",
    "fn matching_context(",
    "fn test_replay_entry(",
    "fn is_valid(",
    "fn is_match(",
    "fn is_mismatch(",
    "fn is_unresolvable(",
    "fn all_match(",
    "fn from_entry(",
    "fn event_code(",
]

EVENT_CODES = [
    "EVD-REPLAY-001",
    "EVD-REPLAY-002",
    "EVD-REPLAY-003",
    "EVD-REPLAY-004",
]

INVARIANTS = [
    "INV-REPLAY-DETERMINISTIC",
    "INV-REPLAY-COMPLETE",
    "INV-REPLAY-INDEPENDENT",
]

DECISION_KINDS = [
    "DecisionKind::Admit",
    "DecisionKind::Deny",
    "DecisionKind::Quarantine",
    "DecisionKind::Release",
    "DecisionKind::Rollback",
    "DecisionKind::Throttle",
    "DecisionKind::Escalate",
]

REQUIRED_TESTS = [
    "action_ref_from_entry",
    "action_ref_display",
    "replay_diff_empty",
    "replay_diff_single_field",
    "replay_diff_multiple_fields",
    "replay_result_match",
    "replay_result_mismatch",
    "replay_result_unresolvable",
    "replay_result_display",
    "replay_context_valid",
    "replay_context_invalid_empty_candidates",
    "replay_context_invalid_empty_snapshot",
    "validate_admit_match",
    "validate_deny_match",
    "validate_quarantine_match",
    "validate_release_match",
    "validate_rollback_match",
    "validate_throttle_match",
    "validate_escalate_match",
    "validate_decision_kind_mismatch",
    "validate_decision_id_mismatch",
    "validate_invalid_context_unresolvable",
    "validate_epoch_mismatch_unresolvable",
    "determinism_identical_runs",
    "determinism_100_runs",
    "validate_batch",
    "summary_report",
    "summary_not_all_match",
    "summary_display",
    "results_log_accumulates",
    "validator_default",
    "candidate_fields",
    "constraint_satisfied",
    "all_decision_kinds_covered",
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
    results = []
    if not MOD_RS.is_file():
        results.append({"check": "module in tools/mod.rs", "pass": False, "detail": "mod.rs missing"})
    else:
        content = MOD_RS.read_text()
        found = "evidence_replay_validator" in content
        results.append({"check": "module in tools/mod.rs", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})

    if not MAIN_RS.is_file():
        results.append({"check": "tools module in main.rs", "pass": False, "detail": "main.rs missing"})
    else:
        content = MAIN_RS.read_text()
        found = "pub mod tools" in content
        results.append({"check": "tools module in main.rs", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})
    return results


def check_upstream_ledger():
    ok = LEDGER_RS.is_file()
    return {"check": "upstream: evidence_ledger.rs", "pass": ok,
            "detail": "exists" if ok else "MISSING"}


def check_imports_ledger():
    if not IMPL.is_file():
        return {"check": "imports DecisionKind + EvidenceEntry", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "DecisionKind" in content and "EvidenceEntry" in content
    return {"check": "imports DecisionKind + EvidenceEntry",
            "pass": found, "detail": "found" if found else "NOT FOUND"}


def check_test_count(path):
    if not path.is_file():
        return {"check": "test count", "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "unit test count", "pass": count >= 30,
            "detail": f"{count} tests (minimum 30)"}


def self_test():
    result = run_checks()
    all_pass = result["verdict"] == "PASS"
    return all_pass, result["checks"]


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.extend(check_module_registered())
    checks.append(check_upstream_ledger())
    checks.append(check_imports_ledger())
    checks.append(check_test_count(IMPL))
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, DECISION_KINDS, "decision_kind"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-2ona",
        "title": "Evidence-ledger replay validator",
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
        print(f"=== bd-2ona: Evidence Replay Validator Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing']}/{s['total']}")
        print()
        for check in result["checks"]:
            tag = "PASS" if check["pass"] else "FAIL"
            print(f"  [{tag}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
