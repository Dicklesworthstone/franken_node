#!/usr/bin/env python3
"""Verification script for bd-15j6: mandatory evidence emission for control decisions.

Usage:
    python scripts/check_control_evidence.py          # human-readable
    python scripts/check_control_evidence.py --json    # machine-readable
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "control_evidence.rs"
SPEC = ROOT / "docs" / "integration" / "control_evidence_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
SAMPLES = ROOT / "artifacts" / "10.15" / "control_evidence_samples.jsonl"
CONFORMANCE_TEST = ROOT / "tests" / "conformance" / "control_policy_evidence_required.rs"
POLICY_EVIDENCE_REQUIRED_SENTINEL = "policy_evidence_required"

REQUIRED_TYPES = [
    "pub enum DecisionType",
    "pub enum DecisionKind",
    "pub enum DecisionOutcome",
    "pub struct ControlEvidenceEntry",
    "pub enum ConformanceError",
    "pub struct ControlEvidenceEvent",
    "pub struct ControlEvidenceEmitter",
]

REQUIRED_METHODS = [
    "fn emit_evidence(",
    "fn execute_with_evidence(",
    "fn verify_ordering(",
    "fn uncovered_types(",
    "fn entries(",
    "fn events(",
    "fn take_events(",
    "fn to_jsonl(",
    "fn validate(",
    "fn map_decision_kind(",
    "fn ordering_key(",
    "fn label(",
    "fn all(",
]

EVENT_CODES = [
    "EVD-001",
    "EVD-002",
    "EVD-003",
    "EVD-004",
    "EVD-005",
]

INVARIANTS = [
    "INV-CE-MANDATORY",
    "INV-CE-SCHEMA",
    "INV-CE-DETERMINISTIC",
    "INV-CE-FAIL-CLOSED",
]

DECISION_TYPES = [
    "HealthGateEval",
    "RolloutTransition",
    "QuarantineAction",
    "FencingDecision",
    "MigrationDecision",
]

REQUIRED_TESTS = [
    "test_decision_type_all",
    "test_decision_type_labels",
    "test_decision_type_display",
    "test_decision_kind_labels",
    "test_decision_kind_display",
    "test_map_health_gate_pass",
    "test_map_health_gate_fail",
    "test_map_rollout_go",
    "test_map_rollout_nogo",
    "test_map_quarantine_promote",
    "test_map_quarantine_demote",
    "test_map_fencing_grant",
    "test_map_fencing_deny",
    "test_map_migration_proceed",
    "test_map_migration_abort",
    "test_entry_validate_valid",
    "test_entry_validate_bad_schema_version",
    "test_entry_validate_empty_decision_id",
    "test_entry_validate_empty_trace_id",
    "test_entry_validate_empty_action",
    "test_emit_valid_evidence",
    "test_emit_invalid_evidence_rejected",
    "test_emit_emits_evd001_event",
    "test_emit_emits_evd003_event",
    "test_emit_invalid_emits_evd004_event",
    "test_execute_with_evidence_success",
    "test_execute_without_evidence_fails",
    "test_execute_without_evidence_emits_evd002",
    "test_execute_with_wrong_type_fails",
    "test_ordering_valid",
    "test_ordering_violation_detected",
    "test_ordering_violation_emits_evd005",
    "test_coverage_starts_empty",
    "test_coverage_tracks_emitted_types",
    "test_full_coverage",
    "test_deterministic_entries",
    "test_deterministic_jsonl",
    "test_jsonl_export",
    "test_jsonl_multiple_entries",
    "test_take_events_drains",
    "test_conformance_error_display_missing",
    "test_conformance_error_display_schema",
    "test_conformance_error_display_ordering",
    "test_conformance_error_display_mismatch",
    "test_entry_serde_roundtrip",
    "test_decision_type_serde_roundtrip",
    "test_conformance_error_serde_roundtrip",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_default_emitter",
    "test_all_types_can_emit",
]

REQUIRED_CONFORMANCE_TESTS = [
    POLICY_EVIDENCE_REQUIRED_SENTINEL,
    "policy_evidence_required_for_every_policy_influenced_decision",
    "policy_evidence_required_missing_entry_fails_closed",
    "policy_evidence_required_rejects_malformed_schema",
    "policy_evidence_required_ordering_is_deterministic",
    "policy_evidence_required_detects_ordering_violation",
]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.exists():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.exists():
        return {"check": "module registered in mod.rs", "pass": False, "detail": "mod.rs missing"}
    text = MOD_RS.read_text()
    found = "pub mod control_evidence;" in text
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_test_count():
    if not IMPL.exists():
        return {"check": "unit test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 40
    return {
        "check": "unit test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 40)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_samples_jsonl():
    results = []
    if not SAMPLES.exists():
        results.append({"check": "samples JSONL exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "samples JSONL exists", "pass": True, "detail": "found"})
    lines = [l for l in SAMPLES.read_text().strip().split("\n") if l.strip()]
    ok = len(lines) >= 10
    results.append({
        "check": "samples JSONL: entry count",
        "pass": ok,
        "detail": f"{len(lines)} entries (minimum 10)",
    })
    # Check all 5 decision types are represented
    types_found = set()
    for line in lines:
        try:
            entry = json.loads(line)
            types_found.add(entry.get("decision_type", ""))
        except json.JSONDecodeError:
            pass
    all_types = len(types_found) >= 5
    results.append({
        "check": "samples JSONL: all decision types",
        "pass": all_types,
        "detail": f"found {len(types_found)} types" if all_types else f"only {len(types_found)} types",
    })
    return results


def check_spec_content():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec: decision types listed", "pass": False, "detail": "spec missing"})
        return results
    text = SPEC.read_text()
    for dt in DECISION_TYPES:
        found = dt in text
        results.append({
            "check": f"spec: {dt} documented",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def run_checks():
    checks = []

    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.append(check_file(SAMPLES, "evidence samples JSONL"))
    checks.append(check_file(CONFORMANCE_TEST, "policy evidence required conformance test"))
    checks.extend(check_samples_jsonl())
    checks.extend(check_spec_content())
    checks.append(check_module_registered())
    checks.append(check_test_count())
    checks.append(check_serde_derives())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))
    checks.extend(check_content(CONFORMANCE_TEST, REQUIRED_CONFORMANCE_TESTS, "conformance_test"))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-15j6",
        "title": "Mandatory evidence emission for policy-influenced control decisions",
        "section": "10.15",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": check_test_count()["detail"].split()[0] if IMPL.exists() else 0,
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    logger = configure_test_logging("check_control_evidence")
    logger.info("starting %s verification", "check_control_evidence")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-15j6 verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
