#!/usr/bin/env python3
"""bd-bq4p: Verify controller boundary checks rejecting correctness-semantic mutations.

Checks:
  1. controller_boundary_checks.rs exists with required types
  2. ErrorClass has 3 variants with stable labels
  3. BoundaryViolation struct with required fields
  4. RejectedMutationRecord struct with required fields
  5. ControllerBoundaryChecker with check_proposal, audit trail methods
  6. Event codes EVD-BOUNDARY-001 through 004
  7. Invariant markers present
  8. Unit tests cover all 12 invariants, fail-closed, audit, lifecycle

Usage:
  python3 scripts/check_controller_boundary.py          # human-readable
  python3 scripts/check_controller_boundary.py --json    # machine-readable
  python3 scripts/check_controller_boundary.py --self-test
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "controller_boundary_checks.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-bq4p_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
ENVELOPE = ROOT / "crates" / "franken-node" / "src" / "policy" / "correctness_envelope.rs"

REQUIRED_TYPES = [
    "pub enum ErrorClass",
    "pub struct BoundaryViolation",
    "pub struct RejectedMutationRecord",
    "pub struct ControllerBoundaryChecker",
]

ERROR_CLASS_VARIANTS = [
    "CorrectnessSemanticMutation",
    "EnvelopeBypass",
    "UnknownInvariantTarget",
]

BOUNDARY_VIOLATION_FIELDS = [
    "violated_invariant",
    "proposal_summary",
    "rejection_reason",
    "stable_error_class",
]

REJECTED_RECORD_FIELDS = [
    "timestamp",
    "proposal_summary",
    "violated_invariant",
    "controller_id",
    "error_class",
    "epoch_id",
]

REQUIRED_METHODS = [
    "fn check_proposal(",
    "fn rejected_mutations(",
    "fn rejection_count(",
    "fn rejection_report(",
    "fn record_rejection(",
    "fn checks_passed(",
    "fn checks_rejected(",
    "fn serialize_audit_trail(",
    "fn restore_audit_trail(",
]

EVENT_CODES = [
    "EVD-BOUNDARY-001",
    "EVD-BOUNDARY-002",
    "EVD-BOUNDARY-003",
    "EVD-BOUNDARY-004",
]

INVARIANT_MARKERS = [
    "INV-BOUNDARY-MANDATORY",
    "INV-BOUNDARY-AUDITABLE",
    "INV-BOUNDARY-STABLE-ERRORS",
    "INV-BOUNDARY-FAIL-CLOSED",
]

# Tests that cover each of the 12 canonical invariants
INVARIANT_REJECTION_TESTS = [
    "rejects_hardening_direction_mutation",
    "rejects_evidence_suppression",
    "rejects_seed_algorithm_change",
    "rejects_integrity_bypass",
    "rejects_ring_buffer_overflow_change",
    "rejects_epoch_decrement",
    "rejects_witness_hash_change",
    "rejects_guardrail_precedence_override",
    "rejects_object_class_mutation",
    "rejects_network_bypass",
    "rejects_marker_stream_rewrite",
    "rejects_receipt_chain_truncation",
]

OTHER_REQUIRED_TESTS = [
    "checker_starts_empty",
    "valid_proposal_passes_check",
    "rejects_empty_proposal",
    "rejects_malformed_proposal_empty_id",
    "rejection_creates_audit_record",
    "multiple_rejections_accumulate_in_audit_trail",
    "valid_proposals_do_not_add_to_audit_trail",
    "mixed_proposals_track_both_counts",
    "rejection_report_contains_per_invariant_counts",
    "rejection_report_contains_error_class_distribution",
    "error_class_label_round_trip",
    "boundary_violation_serialization_round_trip",
    "rejected_mutation_record_serialization_round_trip",
    "audit_trail_serialize_and_restore",
    "rapid_sequential_submissions_all_tracked",
    "mixed_changes_proposal_rejected_on_first_violation",
    "rejects_sub_field_of_immutable_prefix",
    "full_lifecycle_check_reject_check_report",
    "default_creates_empty_checker",
]


def check_file(path, label):
    ok = path.is_file()
    rel = str(path.relative_to(ROOT)) if ok else str(path)
    return {
        "id": f"CBC-FILE-{label.upper().replace(' ', '-')}",
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {rel}" if ok else f"MISSING: {rel}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({
                "id": f"CBC-{category.upper()}-MISSING",
                "check": f"{category}: {p}",
                "pass": False,
                "detail": "file missing",
            })
        return results
    content = path.read_text()
    for p in patterns:
        found = p in content
        short = p[:30].upper().replace(" ", "-").replace("(", "").replace(")", "")
        results.append({
            "id": f"CBC-{category.upper()}-{short}",
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.is_file():
        return {"id": "CBC-MOD-REG", "check": "module registered",
                "pass": False, "detail": "mod.rs missing"}
    content = MOD_RS.read_text()
    found = "controller_boundary_checks" in content
    return {
        "id": "CBC-MOD-REG",
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_upstream_dependency():
    """Verify that the implementation imports from correctness_envelope."""
    if not IMPL.is_file():
        return {"id": "CBC-UPSTREAM-DEP", "check": "upstream dependency",
                "pass": False, "detail": "impl missing"}
    content = IMPL.read_text()
    found = "correctness_envelope" in content and "CorrectnessEnvelope" in content
    return {
        "id": "CBC-UPSTREAM-DEP",
        "check": "imports from correctness_envelope (bd-sddz)",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_test_count(path):
    if not path.is_file():
        return {"id": "CBC-TEST-COUNT", "check": "test count",
                "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {
        "id": "CBC-TEST-COUNT",
        "check": "unit test count",
        "pass": count >= 30,
        "detail": f"{count} tests (minimum 30)",
    }


def check_uses_envelope_api():
    """Verify the checker uses is_within_envelope from the envelope."""
    if not IMPL.is_file():
        return {"id": "CBC-ENVELOPE-API", "check": "uses envelope API",
                "pass": False, "detail": "impl missing"}
    content = IMPL.read_text()
    found = "is_within_envelope" in content
    return {
        "id": "CBC-ENVELOPE-API",
        "check": "calls is_within_envelope from CorrectnessEnvelope",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_serde_derives():
    """Verify all public types derive Serialize + Deserialize."""
    if not IMPL.is_file():
        return {"id": "CBC-SERDE", "check": "serde derives",
                "pass": False, "detail": "impl missing"}
    content = IMPL.read_text()
    # Count Serialize + Deserialize derives — should appear at least 4 times
    count = content.count("Serialize, Deserialize")
    ok = count >= 4
    return {
        "id": "CBC-SERDE",
        "check": "Serialize+Deserialize derives on public types",
        "pass": ok,
        "detail": f"{count} derive blocks (minimum 4)" if ok else f"only {count} derive blocks",
    }


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(ENVELOPE, "upstream envelope"))
    checks.append(check_module_registered())
    checks.append(check_upstream_dependency())
    checks.append(check_uses_envelope_api())
    checks.append(check_serde_derives())

    # Types
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))

    # ErrorClass variants
    checks.extend(check_content(IMPL, ERROR_CLASS_VARIANTS, "error_class"))

    # BoundaryViolation fields
    checks.extend(check_content(IMPL, BOUNDARY_VIOLATION_FIELDS, "violation_field"))

    # RejectedMutationRecord fields
    checks.extend(check_content(IMPL, REJECTED_RECORD_FIELDS, "record_field"))

    # Methods
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))

    # Event codes
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))

    # Invariant markers
    checks.extend(check_content(IMPL, INVARIANT_MARKERS, "invariant"))

    # Test count
    checks.append(check_test_count(IMPL))

    # Invariant rejection tests (12)
    checks.extend(check_content(IMPL, INVARIANT_REJECTION_TESTS, "inv_test"))

    # Other required tests
    checks.extend(check_content(IMPL, OTHER_REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)

    return {
        "bead": "bd-bq4p",
        "title": "Controller boundary checks rejecting correctness-semantic mutations",
        "section": "10.14",
        "verdict": "PASS" if passed == total else "FAIL",
        "summary": {
            "passing_checks": passed,
            "failing_checks": total - passed,
            "total_checks": total,
        },
        "checks": checks,
    }


def self_test():
    result = run_checks()
    assert isinstance(result, dict)
    assert result["bead"] == "bd-bq4p"
    assert "checks" in result
    assert len(result["checks"]) > 0
    print(f"self_test passed: {result['summary']['passing_checks']}/{result['summary']['total_checks']} checks")
    return result


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== bd-bq4p: Controller Boundary Checks Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing_checks']}/{s['total_checks']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
