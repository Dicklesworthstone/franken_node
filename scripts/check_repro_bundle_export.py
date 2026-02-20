#!/usr/bin/env python3
"""bd-2808: Verify deterministic repro bundle export implementation.

Usage:
  python3 scripts/check_repro_bundle_export.py          # human-readable
  python3 scripts/check_repro_bundle_export.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "tools" / "repro_bundle_export.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-2808_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"

REQUIRED_TYPES = [
    "pub struct TraceEvent",
    "pub enum TraceEventType",
    "pub struct EvidenceRef",
    "pub struct FailureContext",
    "pub enum FailureType",
    "pub struct ConfigSnapshot",
    "pub struct ReproBundle",
    "pub struct ExportContext",
    "pub enum ReplayOutcome",
    "pub enum SchemaError",
    "pub struct ReproBundleExporter",
]

REQUIRED_METHODS = [
    "fn generate_repro_bundle(",
    "fn replay_bundle(",
    "fn validate_bundle(",
    "fn event_count(",
    "fn evidence_count(",
    "fn is_portable(",
    "fn to_json(",
    "fn export(",
    "fn find_bundle(",
    "fn bundle_count(",
    "fn should_auto_export(",
    "fn export_for_range",
    "fn with_entry(",
    "fn label(",
]

EVENT_CODES = [
    "REPRO_BUNDLE_EXPORTED",
    "REPRO_BUNDLE_REPLAY_START",
    "REPRO_BUNDLE_REPLAY_COMPLETE",
    "REPRO_BUNDLE_REPLAY_DIVERGENCE",
]

INVARIANTS = [
    "INV-REPRO-DETERMINISTIC",
    "INV-REPRO-COMPLETE",
    "INV-REPRO-VERSIONED",
]

TRACE_EVENT_TYPES = [
    "EpochTransition",
    "BarrierEvent",
    "PolicyEvaluation",
    "MarkerIntegrityCheck",
    "ConfigChange",
    "ExternalSignal",
]

FAILURE_TYPES = [
    "EpochTransitionTimeout",
    "BarrierTimeout",
    "PolicyViolation",
    "MarkerIntegrityBreak",
]

REPLAY_VARIANTS = [
    "Match",
    "Divergence",
]

SCHEMA_ERROR_VARIANTS = [
    "MissingField",
    "InvalidVersion",
    "NonPortablePath",
    "EmptyEventTrace",
]

REQUIRED_TESTS = [
    "trace_event_type_labels",
    "trace_event_type_all_six",
    "trace_event_type_display",
    "failure_type_labels",
    "failure_type_all_four",
    "failure_type_display",
    "config_snapshot_empty",
    "config_snapshot_with_entries",
    "config_snapshot_not_portable",
    "evidence_ref_portable",
    "evidence_ref_not_portable_unix",
    "evidence_ref_display",
    "generate_bundle_from_context",
    "bundle_determinism",
    "bundle_determinism_100_runs",
    "different_context_different_id",
    "event_trace_ordering_preserved",
    "empty_trace_produces_valid_bundle",
    "bundle_is_portable",
    "bundle_to_json",
    "replay_produces_match",
    "replay_deterministic_100_runs",
    "replay_wrong_schema_version",
    "replay_misordered_events_diverge",
    "replay_outcome_display",
    "valid_bundle_passes_schema",
    "empty_bundle_id_rejected",
    "wrong_version_rejected",
    "empty_error_message_rejected",
    "non_portable_path_rejected",
    "schema_error_display",
    "exporter_defaults",
    "exporter_custom_triggers",
    "exporter_exports_bundle",
    "exporter_multiple_bundles",
    "exporter_find_missing_bundle",
    "exporter_time_range_query",
    "json_round_trip_preserves_key_fields",
    "config_snapshot_in_bundle",
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
    found = "repro_bundle_export" in content
    return {"check": "module registered in mod.rs", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_test_count():
    if not IMPL.is_file():
        return {"check": "unit test count", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "unit test count", "pass": count >= 25,
            "detail": f"{count} tests (minimum 25)"}


def check_schema_version():
    if not IMPL.is_file():
        return {"check": "schema version constant", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "SCHEMA_VERSION" in content and "schema_version" in content
    return {"check": "schema version constant", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def check_default_hasher():
    if not IMPL.is_file():
        return {"check": "DefaultHasher for determinism", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "DefaultHasher" in content
    return {"check": "DefaultHasher for determinism", "pass": found,
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
    checks.append(check_test_count())
    checks.append(check_schema_version())
    checks.append(check_default_hasher())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, TRACE_EVENT_TYPES, "trace_event_type"))
    checks.extend(check_content(IMPL, FAILURE_TYPES, "failure_type"))
    checks.extend(check_content(IMPL, REPLAY_VARIANTS, "replay_variant"))
    checks.extend(check_content(IMPL, SCHEMA_ERROR_VARIANTS, "schema_error"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    test_count = len(re.findall(r"#\[test\]", IMPL.read_text())) if IMPL.is_file() else 0
    return {
        "bead_id": "bd-2808",
        "title": "Deterministic repro bundle export for control-plane failures",
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
        print(f"=== bd-2808: Repro Bundle Export Verification ===")
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
