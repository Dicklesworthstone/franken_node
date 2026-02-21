#!/usr/bin/env python3
"""Verification script for bd-f2y: incident bundle retention and export policy.

Usage:
    python3 scripts/check_incident_bundles.py              # human-readable
    python3 scripts/check_incident_bundles.py --json        # machine-readable JSON
    python3 scripts/check_incident_bundles.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

# --- File paths -----------------------------------------------------------

SPEC = ROOT / "docs" / "specs" / "section_10_8" / "bd-f2y_contract.md"
POLICY = ROOT / "docs" / "policy" / "incident_bundle_retention.md"
IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "incident_bundle_retention.rs"
CONNECTOR_MOD = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"

# Upstream dependencies
RETENTION_POLICY = ROOT / "crates" / "franken-node" / "src" / "connector" / "retention_policy.rs"
REPLAY_BUNDLE = ROOT / "crates" / "franken-node" / "src" / "tools" / "replay_bundle.rs"
CONFIG_RS = ROOT / "crates" / "franken-node" / "src" / "config.rs"
HEALTH_GATE = ROOT / "crates" / "franken-node" / "src" / "connector" / "health_gate.rs"

# --- Constants -------------------------------------------------------------

EVENT_CODES = ["IBR-001", "IBR-002", "IBR-003", "IBR-004"]

INVARIANTS = [
    "INV-IBR-COMPLETE",
    "INV-IBR-RETENTION",
    "INV-IBR-EXPORT",
    "INV-IBR-INTEGRITY",
]

EXPORT_FORMATS = ["JSON", "CSV", "SARIF"]

RETENTION_TIERS = ["hot", "cold", "archive"]

SEVERITY_LEVELS = ["critical", "high", "medium", "low"]

REQUIRED_IMPL_TYPES = [
    "pub enum Severity",
    "pub enum RetentionTier",
    "pub enum ExportFormat",
    "pub struct BundleMetadata",
    "pub struct IncidentBundle",
    "pub struct RetentionConfig",
    "pub struct RetentionDecision",
    "pub struct IncidentBundleStore",
    "pub enum IncidentBundleError",
]

REQUIRED_IMPL_FUNCTIONS = [
    "pub fn compute_integrity_hash(",
    "pub fn validate_bundle_complete(",
    "pub fn export_csv_row(",
    "pub fn csv_header(",
    "pub fn export_sarif(",
]

RETENTION_DEFAULTS = {
    "hot_days": "90",
    "cold_days": "365",
    "archive_days": "2555",
}

# --- Results accumulator ---------------------------------------------------

RESULTS: list[dict[str, Any]] = []


# --- Helpers ---------------------------------------------------------------

def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    """Return a relative path string, guarding against non-ROOT paths."""
    s_path = str(path)
    s_root = str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file_exists: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _file_contains(path: Path, keyword: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: '{keyword}'", False, "file missing")
    content = path.read_text(encoding="utf-8")
    found = keyword in content
    return _check(
        f"{label}: '{keyword}'",
        found,
        "found" if found else "not found in file",
    )


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_spec_exists() -> dict[str, Any]:
    """C01: Spec contract file exists."""
    return _file_exists(SPEC, "spec contract")


def check_policy_exists() -> dict[str, Any]:
    """C02: Policy document exists."""
    return _file_exists(POLICY, "policy document")


def check_impl_exists() -> dict[str, Any]:
    """C03: Implementation file exists."""
    return _file_exists(IMPL, "incident bundle retention impl")


def check_upstream_retention_policy() -> dict[str, Any]:
    """C04: Upstream retention_policy.rs exists."""
    return _file_exists(RETENTION_POLICY, "upstream retention policy (10.13)")


def check_upstream_replay_bundle() -> dict[str, Any]:
    """C05: Upstream replay_bundle.rs exists."""
    return _file_exists(REPLAY_BUNDLE, "upstream replay bundle (10.5)")


def check_upstream_config() -> dict[str, Any]:
    """C06: Config system exists."""
    return _file_exists(CONFIG_RS, "config system")


def check_upstream_health_gate() -> dict[str, Any]:
    """C07: Health gate exists."""
    return _file_exists(HEALTH_GATE, "health gate")


def check_module_wiring() -> dict[str, Any]:
    """C08: Module is wired in connector/mod.rs."""
    return _file_contains(CONNECTOR_MOD, "pub mod incident_bundle_retention;", "module_wiring")


def check_spec_event_codes() -> dict[str, Any]:
    """C09: Spec defines all four IBR event codes."""
    if not SPEC.is_file():
        return _check("spec_event_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes present" if passed else f"missing: {missing}"
    return _check("spec_event_codes", passed, detail)


def check_spec_invariants() -> dict[str, Any]:
    """C10: Spec defines all four INV-IBR invariants."""
    if not SPEC.is_file():
        return _check("spec_invariants", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants present" if passed else f"missing: {missing}"
    return _check("spec_invariants", passed, detail)


def check_spec_export_formats() -> dict[str, Any]:
    """C11: Spec documents all three export formats."""
    if not SPEC.is_file():
        return _check("spec_export_formats", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [f for f in EXPORT_FORMATS if f not in content]
    passed = len(missing) == 0
    detail = "all 3 export formats documented" if passed else f"missing: {missing}"
    return _check("spec_export_formats", passed, detail)


def check_spec_retention_tiers() -> dict[str, Any]:
    """C12: Spec documents all three retention tiers."""
    if not SPEC.is_file():
        return _check("spec_retention_tiers", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8").lower()
    # Check for tier mentions in context of retention
    missing = [t for t in RETENTION_TIERS if t not in content]
    passed = len(missing) == 0
    detail = "all 3 retention tiers documented" if passed else f"missing: {missing}"
    return _check("spec_retention_tiers", passed, detail)


def check_spec_retention_periods() -> dict[str, Any]:
    """C13: Spec documents default retention periods (90/365/2555 days)."""
    if not SPEC.is_file():
        return _check("spec_retention_periods", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    has_90 = "90 days" in content or "90" in content
    has_365 = "365 days" in content or "1 year" in content
    has_2555 = "2555 days" in content or "7 years" in content
    passed = has_90 and has_365 and has_2555
    detail = "all retention periods documented" if passed else "some periods missing"
    return _check("spec_retention_periods", passed, detail)


def check_spec_bundle_format() -> dict[str, Any]:
    """C14: Spec documents bundle format fields."""
    if not SPEC.is_file():
        return _check("spec_bundle_format", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    fields = ["bundle_id", "incident_id", "created_at", "severity",
              "retention_tier", "metadata", "logs", "traces",
              "metrics_snapshots", "evidence_refs", "integrity_hash"]
    missing = [f for f in fields if f not in content]
    passed = len(missing) == 0
    detail = f"all {len(fields)} bundle fields documented" if passed else f"missing: {missing}"
    return _check("spec_bundle_format", passed, detail)


def check_spec_dependencies() -> dict[str, Any]:
    """C15: Spec documents upstream dependencies."""
    return _file_contains(SPEC, "Dependencies", "spec_section")


def check_spec_acceptance_criteria() -> dict[str, Any]:
    """C16: Spec documents acceptance criteria."""
    return _file_contains(SPEC, "Acceptance Criteria", "spec_section")


def check_policy_retention_schedule() -> dict[str, Any]:
    """C17: Policy defines retention schedule."""
    return _file_contains(POLICY, "Retention Schedule", "policy_section")


def check_policy_export_procedures() -> dict[str, Any]:
    """C18: Policy defines export procedures."""
    return _file_contains(POLICY, "Export Procedures", "policy_section")


def check_policy_compliance() -> dict[str, Any]:
    """C19: Policy defines compliance requirements."""
    return _file_contains(POLICY, "Compliance Requirements", "policy_section")


def check_policy_governance() -> dict[str, Any]:
    """C20: Policy defines governance section."""
    return _file_contains(POLICY, "Governance", "policy_section")


def check_policy_event_codes() -> dict[str, Any]:
    """C21: Policy references all four IBR event codes."""
    if not POLICY.is_file():
        return _check("policy_event_codes", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes in policy" if passed else f"missing: {missing}"
    return _check("policy_event_codes", passed, detail)


def check_policy_invariants() -> dict[str, Any]:
    """C22: Policy references all four INV-IBR invariants."""
    if not POLICY.is_file():
        return _check("policy_invariants", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants in policy" if passed else f"missing: {missing}"
    return _check("policy_invariants", passed, detail)


def check_policy_automated_cleanup() -> dict[str, Any]:
    """C23: Policy defines automated cleanup."""
    return _file_contains(POLICY, "Automated Cleanup", "policy_section")


def check_policy_audit_trail() -> dict[str, Any]:
    """C24: Policy defines audit trail requirements."""
    return _file_contains(POLICY, "Audit Trail", "policy_section")


def check_impl_types() -> dict[str, Any]:
    """C25: Implementation has all required types."""
    if not IMPL.is_file():
        return _check("impl_types", False, "impl file missing")
    content = IMPL.read_text(encoding="utf-8")
    missing = [t for t in REQUIRED_IMPL_TYPES if t not in content]
    passed = len(missing) == 0
    detail = f"all {len(REQUIRED_IMPL_TYPES)} types present" if passed else f"missing: {missing}"
    return _check("impl_types", passed, detail)


def check_impl_functions() -> dict[str, Any]:
    """C26: Implementation has all required functions."""
    if not IMPL.is_file():
        return _check("impl_functions", False, "impl file missing")
    content = IMPL.read_text(encoding="utf-8")
    missing = [f for f in REQUIRED_IMPL_FUNCTIONS if f not in content]
    passed = len(missing) == 0
    detail = f"all {len(REQUIRED_IMPL_FUNCTIONS)} functions present" if passed else f"missing: {missing}"
    return _check("impl_functions", passed, detail)


def check_impl_event_codes() -> dict[str, Any]:
    """C27: Implementation defines all four event codes."""
    if not IMPL.is_file():
        return _check("impl_event_codes", False, "impl file missing")
    content = IMPL.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes in impl" if passed else f"missing: {missing}"
    return _check("impl_event_codes", passed, detail)


def check_impl_invariant_comments() -> dict[str, Any]:
    """C28: Implementation references invariants in doc comments."""
    if not IMPL.is_file():
        return _check("impl_invariant_comments", False, "impl file missing")
    content = IMPL.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants referenced in impl" if passed else f"missing: {missing}"
    return _check("impl_invariant_comments", passed, detail)


def check_impl_retention_defaults() -> dict[str, Any]:
    """C29: Implementation has correct retention defaults."""
    if not IMPL.is_file():
        return _check("impl_retention_defaults", False, "impl file missing")
    content = IMPL.read_text(encoding="utf-8")
    missing = []
    for key, val in RETENTION_DEFAULTS.items():
        if f"{key}: {val}" not in content:
            missing.append(f"{key}={val}")
    passed = len(missing) == 0
    detail = "all retention defaults correct" if passed else f"missing: {missing}"
    return _check("impl_retention_defaults", passed, detail)


def check_impl_has_tests() -> dict[str, Any]:
    """C30: Implementation has test module."""
    return _file_contains(IMPL, "#[cfg(test)]", "impl_tests")


def check_impl_severity_enum() -> dict[str, Any]:
    """C31: Implementation defines all severity levels."""
    if not IMPL.is_file():
        return _check("impl_severity_levels", False, "impl file missing")
    content = IMPL.read_text(encoding="utf-8")
    missing = [s.capitalize() for s in SEVERITY_LEVELS if s.capitalize() not in content]
    passed = len(missing) == 0
    detail = "all 4 severity levels present" if passed else f"missing: {missing}"
    return _check("impl_severity_levels", passed, detail)


def check_impl_export_formats() -> dict[str, Any]:
    """C32: Implementation defines all export formats."""
    if not IMPL.is_file():
        return _check("impl_export_formats", False, "impl file missing")
    content = IMPL.read_text(encoding="utf-8")
    variants = ["Json", "Csv", "Sarif"]
    missing = [v for v in variants if v not in content]
    passed = len(missing) == 0
    detail = "all 3 export format variants present" if passed else f"missing: {missing}"
    return _check("impl_export_formats", passed, detail)


def check_impl_archive_protection() -> dict[str, Any]:
    """C33: Implementation has archive protection logic."""
    return _file_contains(IMPL, "ArchiveProtected", "impl_archive_protection")


def check_impl_integrity_verification() -> dict[str, Any]:
    """C34: Implementation verifies integrity hash on store and export."""
    if not IMPL.is_file():
        return _check("impl_integrity_verification", False, "impl file missing")
    content = IMPL.read_text(encoding="utf-8")
    has_store_check = "IntegrityFailure" in content
    has_hash_compute = "compute_integrity_hash" in content
    passed = has_store_check and has_hash_compute
    detail = "integrity verification present" if passed else "missing integrity checks"
    return _check("impl_integrity_verification", passed, detail)


# ---------------------------------------------------------------------------
# Validation helpers (exported for test use)
# ---------------------------------------------------------------------------

def validate_retention_period(tier: str, days: int) -> dict[str, Any]:
    """Validate that a retention period matches policy requirements."""
    defaults = {"hot": 90, "cold": 365, "archive": 2555}
    expected = defaults.get(tier)
    if expected is None:
        return {"name": f"retention_{tier}", "passed": False, "detail": f"unknown tier: {tier}"}
    ok = days >= expected
    return {
        "name": f"retention_{tier}",
        "passed": ok,
        "detail": f"{tier}: {days} days (min={expected})",
    }


def validate_bundle_fields(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate that a bundle dict has all required fields."""
    required = [
        "bundle_id", "incident_id", "created_at", "severity",
        "retention_tier", "metadata", "logs", "traces",
        "metrics_snapshots", "evidence_refs", "integrity_hash",
    ]
    results = []
    for field in required:
        ok = field in bundle and bundle[field] is not None
        results.append({
            "name": f"bundle_field_{field}",
            "passed": ok,
            "detail": f"{field}: present" if ok else f"{field}: missing",
        })
    return results


def validate_severity(severity: str) -> dict[str, Any]:
    """Validate severity value."""
    ok = severity in SEVERITY_LEVELS
    return {
        "name": "severity_valid",
        "passed": ok,
        "detail": f"severity={severity}",
    }


def validate_retention_tier(tier: str) -> dict[str, Any]:
    """Validate retention tier value."""
    ok = tier in RETENTION_TIERS
    return {
        "name": "retention_tier_valid",
        "passed": ok,
        "detail": f"tier={tier}",
    }


def validate_export_format(fmt: str) -> dict[str, Any]:
    """Validate export format value."""
    ok = fmt.lower() in ["json", "csv", "sarif"]
    return {
        "name": "export_format_valid",
        "passed": ok,
        "detail": f"format={fmt}",
    }


# ---------------------------------------------------------------------------
# All check functions
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_impl_exists,
    check_upstream_retention_policy,
    check_upstream_replay_bundle,
    check_upstream_config,
    check_upstream_health_gate,
    check_module_wiring,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_export_formats,
    check_spec_retention_tiers,
    check_spec_retention_periods,
    check_spec_bundle_format,
    check_spec_dependencies,
    check_spec_acceptance_criteria,
    check_policy_retention_schedule,
    check_policy_export_procedures,
    check_policy_compliance,
    check_policy_governance,
    check_policy_event_codes,
    check_policy_invariants,
    check_policy_automated_cleanup,
    check_policy_audit_trail,
    check_impl_types,
    check_impl_functions,
    check_impl_event_codes,
    check_impl_invariant_comments,
    check_impl_retention_defaults,
    check_impl_has_tests,
    check_impl_severity_enum,
    check_impl_export_formats,
    check_impl_archive_protection,
    check_impl_integrity_verification,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    """Run all checks and return structured result."""
    global RESULTS
    RESULTS = []

    for fn in ALL_CHECKS:
        fn()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-f2y",
        "title": "Incident bundle retention and export policy",
        "section": "10.8",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    """Run self-test: execute all checks and report pass/fail."""
    report = run_all()
    total = report["total"]
    passed = report["passed"]
    failed = report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-f2y: incident bundle retention and export policy"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    report = run_all()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{report['passed']}/{report['total']} checks pass (verdict={report['verdict']})")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
