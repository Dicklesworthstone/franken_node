#!/usr/bin/env python3
"""Verification script for bd-3q9: release rollback bundles with deterministic restoration.

Usage:
    python scripts/check_rollback_bundles.py           # human-readable
    python scripts/check_rollback_bundles.py --json     # machine-readable
    python scripts/check_rollback_bundles.py --self-test # self-test mode
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_6" / "bd-3q9_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "release_rollback_bundles.md"
RUST_IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "rollback_bundle.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"

EVIDENCE_DIR = ROOT / "artifacts" / "section_10_6" / "bd-3q9"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

RESULTS: list[dict[str, Any]] = []

# ---------------------------------------------------------------------------
# Required patterns
# ---------------------------------------------------------------------------

REQUIRED_EVENT_CODES = [
    "RRB-001",
    "RRB-002",
    "RRB-003",
    "RRB-004",
]

REQUIRED_INVARIANTS = [
    "INV-RRB-DETERM",
    "INV-RRB-IDEMPOT",
    "INV-RRB-HEALTH",
    "INV-RRB-MANIFEST",
]

REQUIRED_ERROR_CODES = [
    "ERR-RRB-MANIFEST-INVALID",
    "ERR-RRB-CHECKSUM-MISMATCH",
    "ERR-RRB-HEALTH-FAILED",
    "ERR-RRB-VERSION-MISMATCH",
]

REQUIRED_RUST_TYPES = [
    "pub struct RollbackBundle",
    "pub struct BundleStore",
    "pub struct BundleComponent",
    "pub struct RestoreManifest",
    "pub struct ManifestComponent",
    "pub struct CompatibilityProof",
    "pub struct StateSnapshot",
    "pub struct HealthCheckResult",
    "pub struct RollbackResult",
    "pub struct RollbackAction",
    "pub struct RollbackAuditEntry",
    "pub enum RollbackBundleError",
    "pub enum HealthCheckKind",
    "pub enum RollbackMode",
]

REQUIRED_RUST_METHODS = [
    "pub fn sha256_hex(",
    "pub fn new(",
    "pub fn verify_checksum(",
    "pub fn verify_integrity(",
    "pub fn check_compatibility(",
    "pub fn ordered_components(",
    "pub fn create_bundle(",
    "pub fn apply_rollback(",
    "pub fn get_bundle(",
    "pub fn list_bundles(",
    "pub fn prune(",
    "pub fn set_state(",
    "pub fn current_state(",
    "pub fn take_events(",
    "pub fn events(",
    "pub fn audit_log(",
    "pub fn integrity_hash(",
    "pub fn canonical_bytes(",
    "pub fn snapshot_hash(",
    "pub fn diff(",
    "pub fn to_json(",
    "pub fn label(",
    "pub fn all(",
]

REQUIRED_RUST_TESTS = [
    "test_sha256_hex_deterministic",
    "test_sha256_hex_different_input",
    "test_bundle_component_new",
    "test_bundle_component_checksum_verification",
    "test_bundle_component_tampered_data",
    "test_compatibility_proof_serde",
    "test_health_check_kind_all",
    "test_health_check_kind_labels",
    "test_health_check_kind_display",
    "test_health_check_kind_serde",
    "test_restore_manifest_integrity_hash_deterministic",
    "test_state_snapshot_hash_deterministic",
    "test_state_snapshot_hash_changes_on_version",
    "test_state_snapshot_diff_identical",
    "test_state_snapshot_diff_version",
    "test_create_bundle",
    "test_bundle_integrity_valid",
    "test_bundle_integrity_tampered",
    "test_bundle_component_tampered_in_bundle",
    "test_bundle_compatibility_pass",
    "test_bundle_compatibility_fail",
    "test_ordered_components",
    "test_apply_rollback_success",
    "test_apply_rollback_idempotent",
    "test_dry_run_no_state_change",
    "test_rollback_version_mismatch",
    "test_rollback_emits_events",
    "test_rollback_failure_emits_rrb004",
    "test_health_check_binary_version",
    "test_health_check_config_schema",
    "test_health_check_state_integrity",
    "test_health_check_smoke_test",
    "test_bundle_store_list_bundles",
    "test_bundle_store_get_bundle",
    "test_bundle_store_prune",
    "test_audit_log_on_creation",
    "test_audit_log_on_rollback",
    "test_rollback_result_to_json",
    "test_rollback_mode_serde",
    "test_error_display_manifest_invalid",
    "test_error_display_checksum_mismatch",
    "test_error_display_health_failed",
    "test_error_display_version_mismatch",
    "test_error_serde_roundtrip",
    "test_manifest_canonical_bytes_deterministic",
    "test_bundle_store_default",
    "test_event_codes_defined",
    "test_invariant_constants_defined",
    "test_health_check_result_serde",
    "test_rollback_action_serde",
    "test_rollback_audit_entry_serde",
    "test_apply_rollback_actions_count",
    "test_dry_run_actions_not_applied",
    "test_manifest_health_checks_populated",
    "test_bundle_timestamp",
    "test_state_snapshot_serde_roundtrip",
    "test_restore_manifest_serde_roundtrip",
    "test_bundle_component_serde_roundtrip",
    "test_rollback_bundle_serde_roundtrip",
    "test_set_and_get_state",
]

REQUIRED_HEALTH_CHECKS = [
    "BinaryVersion",
    "ConfigSchema",
    "StateIntegrity",
    "SmokeTest",
]

REQUIRED_SPEC_SECTIONS = [
    "Rollback Bundle Structure",
    "Event Codes",
    "Invariants",
    "Error Codes",
    "Health Check Sequence",
    "Restore Manifest Format",
    "Quantitative Targets",
]

REQUIRED_POLICY_SECTIONS = [
    "Bundle Generation",
    "Rollback Procedure",
    "Dry-Run Mode",
    "Error Handling",
    "Audit Trail",
    "Time Ceiling",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_rel(path: Path) -> str:
    """Return relative path string, falling back to absolute if outside ROOT."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _file_contains(path: Path, pattern: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: {pattern}", False, "file missing")
    content = path.read_text(encoding="utf-8")
    found = pattern in content
    return _check(
        f"{label}: {pattern}",
        found,
        "found" if found else "not found in file",
    )


def _check_content(path: Path, patterns: list[str], category: str) -> list[dict[str, Any]]:
    results = []
    if not path.is_file():
        for p in patterns:
            results.append(_check(f"{category}: {p}", False, "file missing"))
        return results
    text = path.read_text(encoding="utf-8")
    for p in patterns:
        found = p in text
        results.append(_check(
            f"{category}: {p}",
            found,
            "found" if found else "not found",
        ))
    return results


def check_module_registered() -> dict[str, Any]:
    if not MOD_RS.is_file():
        return _check("module registered in mod.rs", False, "mod.rs missing")
    text = MOD_RS.read_text(encoding="utf-8")
    found = "pub mod rollback_bundle;" in text
    return _check(
        "module registered in mod.rs",
        found,
        "found" if found else "NOT FOUND",
    )


def check_impl_test_count() -> dict[str, Any]:
    if not RUST_IMPL.is_file():
        return _check("impl unit test count", False, "impl missing")
    text = RUST_IMPL.read_text(encoding="utf-8")
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 40
    return _check(
        "impl unit test count",
        ok,
        f"{count} tests (minimum 40)",
    )


def check_serde_derives() -> dict[str, Any]:
    if not RUST_IMPL.is_file():
        return _check("Serialize/Deserialize derives", False, "impl missing")
    text = RUST_IMPL.read_text(encoding="utf-8")
    has_ser = "Serialize" in text and "Deserialize" in text
    return _check(
        "Serialize/Deserialize derives",
        has_ser,
        "found" if has_ser else "NOT FOUND",
    )


def check_sha256_usage() -> dict[str, Any]:
    if not RUST_IMPL.is_file():
        return _check("SHA-256 usage", False, "impl missing")
    text = RUST_IMPL.read_text(encoding="utf-8")
    has_sha = "Sha256" in text and "sha2" in text
    return _check(
        "SHA-256 usage",
        has_sha,
        "found" if has_sha else "NOT FOUND",
    )


def check_idempotency_test() -> dict[str, Any]:
    if not RUST_IMPL.is_file():
        return _check("idempotency test", False, "impl missing")
    text = RUST_IMPL.read_text(encoding="utf-8")
    found = "test_apply_rollback_idempotent" in text
    return _check(
        "idempotency test",
        found,
        "found" if found else "NOT FOUND",
    )


def check_dry_run_test() -> dict[str, Any]:
    if not RUST_IMPL.is_file():
        return _check("dry-run test", False, "impl missing")
    text = RUST_IMPL.read_text(encoding="utf-8")
    found = "test_dry_run_no_state_change" in text and "DryRun" in text
    return _check(
        "dry-run test",
        found,
        "found" if found else "NOT FOUND",
    )


def check_deterministic_restore() -> dict[str, Any]:
    if not RUST_IMPL.is_file():
        return _check("deterministic restore logic", False, "impl missing")
    text = RUST_IMPL.read_text(encoding="utf-8")
    has_snapshot = "StateSnapshot" in text
    has_diff = "fn diff(" in text
    has_hash = "fn snapshot_hash(" in text
    ok = has_snapshot and has_diff and has_hash
    return _check(
        "deterministic restore logic",
        ok,
        "StateSnapshot+diff+hash present" if ok else "missing components",
    )


def check_health_check_kinds() -> list[dict[str, Any]]:
    results = []
    if not RUST_IMPL.is_file():
        for hc in REQUIRED_HEALTH_CHECKS:
            results.append(_check(f"health_check: {hc}", False, "impl missing"))
        return results
    text = RUST_IMPL.read_text(encoding="utf-8")
    for hc in REQUIRED_HEALTH_CHECKS:
        found = hc in text
        results.append(_check(
            f"health_check: {hc}",
            found,
            "found" if found else "NOT FOUND",
        ))
    return results


def check_spec_sections() -> list[dict[str, Any]]:
    results = []
    if not SPEC_PATH.is_file():
        for s in REQUIRED_SPEC_SECTIONS:
            results.append(_check(f"spec: {s}", False, "spec missing"))
        return results
    text = SPEC_PATH.read_text(encoding="utf-8")
    for s in REQUIRED_SPEC_SECTIONS:
        found = s in text
        results.append(_check(
            f"spec: {s}",
            found,
            "found" if found else "NOT FOUND",
        ))
    return results


def check_policy_sections() -> list[dict[str, Any]]:
    results = []
    if not POLICY_PATH.is_file():
        for s in REQUIRED_POLICY_SECTIONS:
            results.append(_check(f"policy: {s}", False, "policy missing"))
        return results
    text = POLICY_PATH.read_text(encoding="utf-8")
    for s in REQUIRED_POLICY_SECTIONS:
        found = s in text
        results.append(_check(
            f"policy: {s}",
            found,
            "found" if found else "NOT FOUND",
        ))
    return results


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------


def run_all() -> dict[str, Any]:
    """Run all checks and return structured evidence."""
    global RESULTS
    RESULTS = []
    timestamp = datetime.now(timezone.utc).isoformat()

    # File existence checks
    _file_exists(SPEC_PATH, "spec contract")
    _file_exists(POLICY_PATH, "policy document")
    _file_exists(RUST_IMPL, "Rust implementation")
    _file_exists(MOD_RS, "connector mod.rs")

    # Module registration
    check_module_registered()

    # Rust types
    _check_content(RUST_IMPL, REQUIRED_RUST_TYPES, "type")

    # Rust methods
    _check_content(RUST_IMPL, REQUIRED_RUST_METHODS, "method")

    # Event codes in impl
    _check_content(RUST_IMPL, REQUIRED_EVENT_CODES, "impl_event_code")

    # Invariants in impl
    _check_content(RUST_IMPL, REQUIRED_INVARIANTS, "impl_invariant")

    # Error codes in impl
    _check_content(RUST_IMPL, REQUIRED_ERROR_CODES, "impl_error_code")

    # Rust tests
    _check_content(RUST_IMPL, REQUIRED_RUST_TESTS, "rust_test")

    # Test count
    check_impl_test_count()

    # Serde derives
    check_serde_derives()

    # SHA-256 usage
    check_sha256_usage()

    # Idempotency test
    check_idempotency_test()

    # Dry-run test
    check_dry_run_test()

    # Deterministic restore logic
    check_deterministic_restore()

    # Health check kinds
    check_health_check_kinds()

    # Event codes in spec
    _check_content(SPEC_PATH, REQUIRED_EVENT_CODES, "spec_event_code")

    # Invariants in spec
    _check_content(SPEC_PATH, REQUIRED_INVARIANTS, "spec_invariant")

    # Error codes in spec
    _check_content(SPEC_PATH, REQUIRED_ERROR_CODES, "spec_error_code")

    # Spec sections
    check_spec_sections()

    # Policy sections
    check_policy_sections()

    passing = sum(1 for c in RESULTS if c["pass"])
    failing = sum(1 for c in RESULTS if not c["pass"])
    total = len(RESULTS)

    return {
        "bead_id": "bd-3q9",
        "section": "10.6",
        "title": "Release rollback bundles with deterministic restoration",
        "timestamp": timestamp,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "overall_pass": failing == 0,
        "total": total,
        "passed": passing,
        "failed": failing,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": total,
        },
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    """Run self-test verifying the check harness returns expected shape."""
    report = run_all()
    assert isinstance(report, dict), "run_all must return dict"
    assert report["bead_id"] == "bd-3q9", "bead_id must be bd-3q9"
    assert report["section"] == "10.6", "section must be 10.6"
    assert "checks" in report, "must have checks"
    assert "summary" in report, "must have summary"
    assert isinstance(report["checks"], list), "checks must be a list"
    assert report["summary"]["total"] > 0, "must have at least one check"
    assert all("check" in c and "pass" in c for c in report["checks"]), "each check must have check+pass"
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-3q9 release rollback bundles implementation"
    )
    parser.add_argument("--json", action="store_true", help="Output JSON evidence")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    report = run_all()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
        s = report["summary"]
        print(
            f"\nbd-3q9 verification: {report['verdict']} "
            f"({s['passing']}/{s['total']} checks pass)"
        )

    sys.exit(0 if report["overall_pass"] else 1)


if __name__ == "__main__":
    main()
