#!/usr/bin/env python3
"""bd-b9b6: Verify durability contract violation diagnostic implementation.

Checks:
  1. durability_violation.rs exists with required types and methods
  2. Event codes EVD-VIOLATION-001 through 004
  3. Invariant doc comments
  4. CausalEventType variants (5 variants)
  5. HaltPolicy variants and halt management
  6. DurabilityViolationDetector with bundle generation
  7. Unit tests cover required scenarios

Usage:
  python3 scripts/check_durability_violation.py          # human-readable
  python3 scripts/check_durability_violation.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "observability" / "durability_violation.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-b9b6_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "observability" / "mod.rs"

REQUIRED_TYPES = [
    "pub struct BundleId",
    "pub struct CausalEvent",
    "pub enum CausalEventType",
    "pub struct FailedArtifact",
    "pub struct ProofContext",
    "pub enum HaltPolicy",
    "pub struct ViolationBundle",
    "pub struct ViolationContext",
    "pub struct DurabilityViolationDetector",
    "pub struct DurabilityHaltedError",
]

REQUIRED_METHODS = [
    "fn generate_bundle(",
    "fn check_durable_op(",
    "fn clear_halt(",
    "fn is_halted(",
    "fn is_scope_halted(",
    "fn halt_policy(",
    "fn bundle_count(",
    "fn to_json(",
    "fn all_failed(",
    "fn event_count(",
    "fn artifact_count(",
]

EVENT_CODES = [
    "EVD-VIOLATION-001",
    "EVD-VIOLATION-002",
    "EVD-VIOLATION-003",
    "EVD-VIOLATION-004",
]

INVARIANTS = [
    "INV-VIOLATION-DETERMINISTIC",
    "INV-VIOLATION-CAUSAL",
    "INV-VIOLATION-HALT",
]

CAUSAL_EVENT_TYPES = [
    "GuardrailRejection",
    "HardeningEscalation",
    "RepairFailed",
    "IntegrityCheckFailed",
    "ArtifactUnverifiable",
]

HALT_POLICIES = [
    "HaltAll",
    "HaltScope",
    "WarnOnly",
]

ERROR_CODES = [
    "DurabilityHaltedError",
]

REQUIRED_TESTS = [
    "bundle_id_display",
    "causal_event_type_labels",
    "causal_event_type_all",
    "causal_event_type_display",
    "proof_context_empty",
    "proof_context_all_failed",
    "proof_context_not_all_failed",
    "halt_policy_labels",
    "halt_policy_display",
    "generate_bundle_from_context",
    "bundle_determinism",
    "bundle_determinism_100_runs",
    "different_context_different_bundle_id",
    "causal_events_ordering_preserved",
    "empty_context_produces_valid_bundle",
    "bundle_to_json",
    "detector_defaults",
    "detector_generates_bundle_and_halts",
    "detector_halt_all_blocks_all_scopes",
    "detector_halt_scope_blocks_only_matching",
    "detector_warn_only_never_blocks",
    "detector_clear_halt",
    "detector_op_before_violation_allowed",
    "halted_error_contains_bundle_id",
    "failed_artifact_hash_mismatch",
    "multiple_bundles_accumulate",
    "bundle_includes_proof_context",
    "is_scope_halted_with_halt_all",
    "is_scope_halted_with_matching_scope",
    "is_scope_halted_with_warn_only",
]


def check_file(path, label):
    ok = path.is_file()
    if ok:
        try:
            rel = str(path.relative_to(ROOT))
        except ValueError:
            rel = str(path)
    else:
        rel = str(path)
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
        return {"check": "module registered in mod.rs", "pass": False, "detail": "mod.rs missing"}
    content = MOD_RS.read_text()
    found = "durability_violation" in content
    return {"check": "module registered in mod.rs", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_test_count():
    if not IMPL.is_file():
        return {"check": "unit test count", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
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
    checks.append(check_test_count())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, CAUSAL_EVENT_TYPES, "causal_event_type"))
    checks.extend(check_content(IMPL, HALT_POLICIES, "halt_policy"))
    checks.extend(check_content(IMPL, ERROR_CODES, "error_type"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    test_count = len(re.findall(r"#\[test\]", IMPL.read_text())) if IMPL.is_file() else 0
    return {
        "bead_id": "bd-b9b6",
        "title": "Durability contract violation diagnostic bundles",
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
        print(f"=== bd-b9b6: Durability Violation Diagnostic Verification ===")
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
