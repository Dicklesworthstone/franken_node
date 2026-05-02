#!/usr/bin/env python3
"""Verification script for bd-1xtf: frankentui surface migration.

Usage:
    python scripts/check_frankentui_migration.py          # human-readable
    python scripts/check_frankentui_migration.py --json    # machine-readable
"""

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

IMPL = ROOT / "tests" / "integration" / "frankentui_surface_migration.rs"
INVENTORY_CSV = ROOT / "artifacts" / "10.16" / "frankentui_surface_inventory.csv"
CONTRACT = ROOT / "docs" / "specs" / "frankentui_integration_contract.md"
SPEC = ROOT / "docs" / "specs" / "section_10_16" / "bd-1xtf_contract.md"

# From the bd-34ll contract
CONTRACT_MODULES = [
    "src/cli.rs",
    "src/main.rs",
    "src/policy/correctness_envelope.rs",
    "src/policy/controller_boundary_checks.rs",
    "src/policy/evidence_emission.rs",
    "src/observability/evidence_ledger.rs",
    "src/tools/evidence_replay_validator.rs",
]

FRANKENTUI_COMPONENTS = [
    "CommandSurface",
    "Panel",
    "Table",
    "StatusBar",
    "AlertBanner",
    "DiffPanel",
    "LogStreamPanel",
]

EVENT_CODES = [
    "FRANKENTUI_SURFACE_MIGRATED",
    "FRANKENTUI_RAW_OUTPUT_DETECTED",
    "FRANKENTUI_MIGRATION_INCOMPLETE",
]

INVARIANTS = [
    "INV-FTM-COMPLETE",
    "INV-FTM-NO-RAW",
    "INV-FTM-MAPPED",
    "INV-FTM-SNAPSHOT",
]

REQUIRED_TYPES = [
    "pub enum FrankentuiComponent",
    "pub enum MigrationStatus",
    "pub enum BoundaryType",
    "pub struct SurfaceEntry",
    "pub struct MigrationEvent",
    "pub struct FrankentuiMigrationGate",
    "pub struct MigrationSummary",
]

REQUIRED_METHODS = [
    "fn register_surface(",
    "fn register_raw_output(",
    "fn gate_pass(",
    "fn summary(",
    "fn surfaces(",
    "fn events(",
    "fn take_events(",
    "fn to_report(",
    "fn all(",
    "fn label(",
    "fn is_complete(",
]

REQUIRED_TESTS = [
    "test_component_all_count",
    "test_component_labels",
    "test_component_display",
    "test_component_serde_roundtrip",
    "test_status_complete_is_complete",
    "test_status_in_progress_not_complete",
    "test_status_not_started_not_complete",
    "test_status_labels",
    "test_status_display",
    "test_status_serde_roundtrip",
    "test_boundary_type_labels",
    "test_boundary_type_display",
    "test_gate_empty_fails",
    "test_gate_all_complete_passes",
    "test_gate_incomplete_surface_fails",
    "test_gate_raw_output_detected_fails",
    "test_gate_canonical_surfaces_count",
    "test_gate_canonical_all_complete",
    "test_summary_all_complete",
    "test_summary_with_incomplete",
    "test_summary_with_raw_violations",
    "test_register_complete_emits_migrated_event",
    "test_register_incomplete_emits_incomplete_event",
    "test_raw_output_emits_detected_event",
    "test_take_events_drains",
    "test_event_has_surface_name",
    "test_report_structure",
    "test_report_pass_verdict",
    "test_report_fail_verdict",
    "test_report_surfaces_count",
    "test_invariant_constants_defined",
    "test_event_code_constants_defined",
    "test_canonical_covers_all_components",
    "test_determinism_same_input_same_report",
    "test_surface_entry_serde_roundtrip",
    "test_migration_event_serde_roundtrip",
    "test_canonical_has_all_boundary_types",
    "test_canonical_covers_cli_module",
    "test_canonical_covers_main_module",
    "test_canonical_covers_correctness_envelope",
    "test_canonical_covers_controller_boundary",
    "test_canonical_covers_evidence_emission",
    "test_canonical_covers_evidence_ledger",
    "test_canonical_covers_replay_validator",
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
    text = path.read_text(encoding="utf-8")
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
        return {"check": "integration test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text(encoding="utf-8")
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 35
    return {
        "check": "integration test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 35)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text(encoding="utf-8")
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_inventory_csv():
    results = []
    if not INVENTORY_CSV.exists():
        results.append({"check": "inventory CSV: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "inventory CSV: exists", "pass": True, "detail": "found"})

    with INVENTORY_CSV.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Check row count
    has_rows = len(rows) >= 12
    results.append({
        "check": "inventory CSV: row count",
        "pass": has_rows,
        "detail": f"{len(rows)} rows (minimum 12)",
    })

    # Check all complete
    all_complete = all(r.get("migration_status") == "complete" for r in rows)
    results.append({
        "check": "inventory CSV: all complete",
        "pass": all_complete,
        "detail": "all complete" if all_complete else "incomplete surfaces found",
    })

    # Check all contract modules covered
    csv_modules = {r.get("module_path", "") for r in rows}
    for mod in CONTRACT_MODULES:
        found = mod in csv_modules
        results.append({
            "check": f"inventory CSV: module {mod}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # Check all frankentui components used
    csv_components = {r.get("frankentui_component", "") for r in rows}
    for comp in FRANKENTUI_COMPONENTS:
        found = comp in csv_components
        results.append({
            "check": f"inventory CSV: component {comp}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    # Check required columns
    if rows:
        for col in ["module_path", "surface_name", "migration_status", "frankentui_component", "notes"]:
            found = col in rows[0]
            results.append({
                "check": f"inventory CSV: column {col}",
                "pass": found,
                "detail": "found" if found else "NOT FOUND",
            })

    return results


def check_spec():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec doc: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "spec doc: exists", "pass": True, "detail": "found"})
    text = SPEC.read_text(encoding="utf-8")

    for section in ["Types", "Methods", "Event Codes", "Invariants", "Acceptance Criteria"]:
        found = section in text
        results.append({
            "check": f"spec doc: section '{section}'",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })

    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "integration test"))
    checks.append(check_file(INVENTORY_CSV, "surface inventory CSV"))
    checks.append(check_file(SPEC, "spec doc"))

    # Test count
    checks.append(check_impl_test_count())

    # Serde derives
    checks.append(check_serde_derives())

    # Implementation content
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    # Inventory CSV
    checks.extend(check_inventory_csv())

    # Spec doc
    checks.extend(check_spec())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-1xtf",
        "title": "Frankentui surface migration",
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
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-1xtf verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
