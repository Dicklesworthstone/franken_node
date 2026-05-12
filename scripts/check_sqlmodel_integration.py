#!/usr/bin/env python3
"""Verification script for bd-1v65: sqlmodel_rust integration.

Usage:
    python scripts/check_sqlmodel_integration.py          # human-readable
    python scripts/check_sqlmodel_integration.py --json    # machine-readable
"""

import csv
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

IMPL = ROOT / "tests" / "conformance" / "sqlmodel_contracts.rs"
CSV_FILE = ROOT / "artifacts" / "10.16" / "sqlmodel_integration_domains.csv"
POLICY = ROOT / "artifacts" / "10.16" / "sqlmodel_policy_matrix.json"
SPEC = ROOT / "docs" / "specs" / "section_10_16" / "bd-1v65_contract.md"

MODEL_NAMES = [
    "FencingLeaseRecord", "LeaseServiceRecord", "LeaseQuorumRecord",
    "RolloutStateRecord", "HealthGatePolicyRecord", "ControlChannelStateRecord",
    "ArtifactJournalRecord", "TieredTrustArtifactRecord", "CanonicalStateRootRecord",
    "DurabilityModeRecord", "DurableClaimAuditRecord", "SchemaMigrationRecord",
    "SnapshotPolicyRecord", "CrdtMergeStateRecord", "QuarantineEntryRecord",
    "QuarantinePromotionRecord", "RetentionPolicyRecord", "RepairCycleAuditRecord",
    "LeaseConflictAuditRecord", "OfflineCoverageMetricRecord",
    "LifecycleTransitionCacheRecord",
]

EVENT_CODES = [
    "SQLMODEL_SCHEMA_DRIFT_DETECTED",
    "SQLMODEL_ROUND_TRIP_PASS",
    "SQLMODEL_ROUND_TRIP_FAIL",
    "SQLMODEL_MODEL_REGISTERED",
    "SQLMODEL_VERSION_COMPAT_FAIL",
]

INVARIANTS = [
    "INV-SMI-DRIFT",
    "INV-SMI-ROUNDTRIP",
    "INV-SMI-MANDATORY",
    "INV-SMI-OWNERSHIP",
]

REQUIRED_TYPES = [
    "pub enum ModelClassification",
    "pub enum ModelSource",
    "pub struct TypedModel",
    "pub struct DriftResult",
    "pub struct RoundTripResult",
    "pub struct SqlmodelEvent",
    "pub struct SqlmodelIntegrationGate",
    "pub struct IntegrationSummary",
]

REQUIRED_METHODS = [
    "fn register_model(",
    "fn check_drift(",
    "fn check_round_trip(",
    "fn gate_pass(",
    "fn summary(",
    "fn models(",
    "fn events(",
    "fn take_events(",
    "fn to_report(",
    "fn all(",
    "fn label(",
    "fn is_mandatory(",
]

REQUIRED_TESTS = [
    "test_classification_all_count",
    "test_classification_labels",
    "test_classification_is_mandatory",
    "test_classification_display",
    "test_classification_serde_roundtrip",
    "test_model_source_labels",
    "test_model_source_display",
    "test_model_source_serde_roundtrip",
    "test_canonical_total_count",
    "test_canonical_mandatory_count",
    "test_canonical_should_use_count",
    "test_canonical_optional_count",
    "test_canonical_unique_model_names",
    "test_canonical_unique_domains",
    "test_canonical_all_versioned",
    "test_gate_empty_fails",
    "test_gate_all_registered_all_pass",
    "test_gate_drift_failure_fails",
    "test_gate_round_trip_failure_mandatory_fails",
    "test_gate_round_trip_failure_optional_passes",
    "test_register_model_emits_registered_event",
    "test_check_drift_no_drift_no_event",
    "test_check_drift_detected_emits_event",
    "test_check_round_trip_pass_emits_pass_event",
    "test_check_round_trip_fail_emits_fail_event",
    "test_take_events_drains",
    "test_event_has_model_name",
    "test_summary_counts",
    "test_summary_drift_failures",
    "test_summary_round_trip_failures",
    "test_report_structure",
    "test_report_pass_verdict",
    "test_report_fail_verdict_empty",
    "test_report_models_count",
    "test_invariant_constants_defined",
    "test_event_code_constants_defined",
    "test_determinism_same_input_same_report",
    "test_typed_model_serde_roundtrip",
    "test_drift_result_serde_roundtrip",
    "test_round_trip_result_serde_roundtrip",
    "test_sqlmodel_event_serde_roundtrip",
    "test_integration_summary_serde_roundtrip",
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


def check_impl_test_count():
    if not IMPL.exists():
        return {"check": "conformance test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 35
    return {"check": "conformance test count", "pass": ok, "detail": f"{count} tests (minimum 35)"}


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_ser = "Serialize" in text and "Deserialize" in text
    return {"check": "Serialize/Deserialize derives", "pass": has_ser, "detail": "found" if has_ser else "NOT FOUND"}


def check_csv():
    results = []
    if not CSV_FILE.exists():
        results.append({"check": "CSV: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "CSV: exists", "pass": True, "detail": "found"})
    with open(CSV_FILE) as f:
        rows = list(csv.DictReader(f))
    results.append({"check": "CSV: row count", "pass": len(rows) == 21, "detail": f"{len(rows)} rows"})
    all_pass_drift = all(r.get("schema_drift_status") == "pass" for r in rows)
    results.append({"check": "CSV: all drift pass", "pass": all_pass_drift, "detail": "all pass" if all_pass_drift else "failures found"})
    all_pass_rt = all(r.get("round_trip_status") == "pass" for r in rows)
    results.append({"check": "CSV: all round-trip pass", "pass": all_pass_rt, "detail": "all pass" if all_pass_rt else "failures found"})
    mandatory = [r for r in rows if r.get("classification") == "mandatory"]
    results.append({"check": "CSV: mandatory count = 12", "pass": len(mandatory) == 12, "detail": f"{len(mandatory)}"})
    should_use = [r for r in rows if r.get("classification") == "should_use"]
    results.append({"check": "CSV: should_use count = 7", "pass": len(should_use) == 7, "detail": f"{len(should_use)}"})
    csv_models = {r.get("model_struct_name", "") for r in rows}
    for name in MODEL_NAMES:
        found = name in csv_models
        results.append({"check": f"CSV: model {name}", "pass": found, "detail": "found" if found else "NOT FOUND"})
    return results


def check_spec():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec doc: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "spec doc: exists", "pass": True, "detail": "found"})
    text = SPEC.read_text()
    for section in ["Types", "Methods", "Event Codes", "Invariants", "Acceptance Criteria"]:
        found = section in text
        results.append({"check": f"spec doc: section '{section}'", "pass": found, "detail": "found" if found else "NOT FOUND"})
    return results


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "conformance test"))
    checks.append(check_file(CSV_FILE, "integration domains CSV"))
    checks.append(check_file(POLICY, "policy matrix"))
    checks.append(check_file(SPEC, "spec doc"))
    checks.append(check_impl_test_count())
    checks.append(check_serde_derives())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))
    checks.extend(check_csv())
    checks.extend(check_spec())
    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    return {
        "bead_id": "bd-1v65",
        "title": "sqlmodel_rust integration",
        "section": "10.16",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": check_impl_test_count()["detail"].split()[0] if IMPL.exists() else 0,
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    logger = configure_test_logging("check_sqlmodel_integration")
    logger.info("starting sqlmodel integration verification")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-1v65 verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
