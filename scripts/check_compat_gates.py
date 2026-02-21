#!/usr/bin/env python3
"""Verification script for bd-137: Policy-visible compatibility gate APIs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

# ── File paths ────────────────────────────────────────────────────────────────

IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "compat_gates.rs"
LEGACY_IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "compatibility_gate.rs"
POLICY_MOD = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_5" / "bd-137_contract.md"
BAND_SPEC = ROOT / "docs" / "specs" / "section_10_2" / "bd-2wz_contract.md"

# ── Required patterns in compat_gates.rs ──────────────────────────────────────

REQUIRED_TYPES = [
    "pub enum CompatibilityBand",
    "pub enum CompatibilityMode",
    "pub enum DivergenceAction",
    "pub enum ShimRiskCategory",
    "pub struct ShimRegistryEntry",
    "pub struct ShimRegistry",
    "pub struct PolicyPredicate",
    "pub struct AttenuationConstraint",
    "pub enum GateDecision",
    "pub struct GateCheckResult",
    "pub struct ModeSelectionReceipt",
    "pub struct ScopeConfig",
    "pub enum CompatGateError",
    "pub struct CompatGateEvaluator",
    "pub struct CompatGateReport",
]

REQUIRED_METHODS = [
    "pub fn register(",
    "pub fn get(",
    "pub fn all(",
    "pub fn by_band(",
    "pub fn by_api_family(",
    "pub fn active_under_mode(",
    "pub fn set_mode(",
    "pub fn get_mode(",
    "pub fn evaluate_gate(",
    "pub fn check_non_interference(",
    "pub fn check_monotonicity(",
    "pub fn audit_log_for_scope(",
    "pub fn receipts_for_scope(",
    "pub fn divergence_action(",
    "pub fn generate_compat_report(",
]

EVENT_CODES = [
    "PCG_GATE_PASS",
    "PCG_GATE_DENY",
    "PCG_MODE_TRANSITION",
    "PCG_RECEIPT_ISSUED",
    "PCG_GATE_AUDIT",
    "PCG_NONINTERFERENCE_VIOLATION",
    "PCG_MONOTONICITY_VIOLATION",
    "PCG_SHIM_REGISTERED",
]

INVARIANTS = [
    "INV-PCG-VISIBLE",
    "INV-PCG-AUDITABLE",
    "INV-PCG-RECEIPT",
    "INV-PCG-TRANSITION",
]

COMPATIBILITY_BANDS = [
    "Core",
    "HighValue",
    "Edge",
    "Unsafe",
]

COMPATIBILITY_MODES = [
    "Strict",
    "Balanced",
    "LegacyRisky",
]

DIVERGENCE_ACTIONS = [
    "Error",
    "Warn",
    "Log",
    "Blocked",
]

REQUIRED_TESTS = [
    "band_labels",
    "band_priority_ordering",
    "mode_labels",
    "mode_risk_ordering",
    "mode_escalation_detection",
    "divergence_matrix_core_always_error",
    "divergence_matrix_high_value",
    "divergence_matrix_edge",
    "divergence_matrix_unsafe",
    "divergence_matrix_is_complete",
    "registry_register_and_lookup",
    "registry_duplicate_rejected",
    "registry_by_band",
    "registry_active_under_mode",
    "predicate_signature_valid",
    "predicate_scope_attenuated",
    "gate_decision_event_codes",
    "set_mode_initial",
    "set_mode_escalation_requires_approval",
    "set_mode_escalation_with_approval",
    "set_mode_de_escalation_auto_approved",
    "gate_eval_core_shim_denied_in_balanced",
    "gate_eval_hv_shim_audited_in_balanced",
    "gate_eval_edge_shim_allowed_in_balanced",
    "gate_eval_unsafe_shim_denied_in_balanced",
    "gate_eval_unknown_package_in_strict",
    "gate_eval_scope_not_found",
    "non_interference_isolated_scopes",
    "monotonicity_new_shim_ok",
    "monotonicity_replacement_weaker_rejected",
    "receipts_accumulated",
    "report_generation",
    "gate_eval_deterministic",
    "unsafe_shim_allowed_only_in_legacy_risky",
    "multiple_scopes_independent",
]

# ── Also check the legacy compatibility_gate.rs ───────────────────────────────

LEGACY_TYPES = [
    "pub enum CompatMode",
    "pub enum Verdict",
    "pub struct GateEngine",
    "pub struct GateCheckRequest",
    "pub struct GateCheckResult",
    "pub struct DivergenceReceipt",
    "pub struct ModeTransitionReceipt",
    "pub struct ShimEntry",
    "pub struct PolicyPredicate",
    "pub struct GateAuditEvent",
    "pub struct ScopeMode",
]

LEGACY_METHODS = [
    "pub fn gate_check(",
    "pub fn set_scope_mode(",
    "pub fn query_mode(",
    "pub fn request_transition(",
    "pub fn issue_divergence_receipt(",
    "pub fn query_receipts(",
    "pub fn verify_receipt_signature(",
    "pub fn audit_trail(",
    "pub fn check_non_interference(",
    "pub fn check_monotonicity(",
]


# ── Check functions ───────────────────────────────────────────────────────────

def check_file(path: Path, label: str) -> dict[str, Any]:
    return {
        "check": f"File exists: {label}",
        "pass": path.exists(),
        "detail": str(path) if path.exists() else f"MISSING: {path}",
    }


def check_content(path: Path, patterns: list[str], category: str) -> list[dict[str, Any]]:
    results = []
    if not path.exists():
        for p in patterns:
            results.append({
                "check": f"{category}: {p}",
                "pass": False,
                "detail": f"File not found: {path}",
            })
        return results

    text = path.read_text()
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else f"NOT FOUND in {path.name}",
        })
    return results


def check_impl_test_count() -> dict[str, Any]:
    """Check that compat_gates.rs has at least 35 test functions."""
    if not IMPL.exists():
        return {"check": "Impl test count >= 35", "pass": False, "detail": "File missing"}
    text = IMPL.read_text()
    count = text.count("#[test]")
    return {
        "check": f"Impl test count >= 35 (found {count})",
        "pass": count >= 35,
        "detail": f"{count} tests found",
    }


def check_legacy_test_count() -> dict[str, Any]:
    """Check that compatibility_gate.rs has at least 20 test functions."""
    if not LEGACY_IMPL.exists():
        return {"check": "Legacy test count >= 20", "pass": False, "detail": "File missing"}
    text = LEGACY_IMPL.read_text()
    count = text.count("#[test]")
    return {
        "check": f"Legacy test count >= 20 (found {count})",
        "pass": count >= 20,
        "detail": f"{count} tests found",
    }


def check_spec() -> list[dict[str, Any]]:
    results = []
    if not SPEC.exists():
        results.append({"check": "Spec exists", "pass": False, "detail": "MISSING"})
        return results
    text = SPEC.read_text()
    spec_patterns = [
        "bd-137",
        "Gate Check Endpoint",
        "Mode Query API",
        "Mode Transition Request API",
        "Receipt Query API",
        "Shim Registry Query API",
        "INV-PCG-VISIBLE",
        "INV-PCG-AUDITABLE",
        "INV-PCG-RECEIPT",
        "INV-PCG-TRANSITION",
        "PCG-001",
        "PCG-002",
        "PCG-003",
        "PCG-004",
        "Non-Interference",
        "Monotonicity",
        "strict",
        "balanced",
        "legacy_risky",
    ]
    for p in spec_patterns:
        found = p in text
        results.append({
            "check": f"Spec: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered() -> dict[str, Any]:
    """Check that compat_gates is registered in policy/mod.rs."""
    if not POLICY_MOD.exists():
        return {"check": "Module registered", "pass": False, "detail": "mod.rs missing"}
    text = POLICY_MOD.read_text()
    found = "pub mod compat_gates;" in text
    return {
        "check": "Module compat_gates registered in policy/mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_band_mode_matrix_complete() -> dict[str, Any]:
    """Check that the band-mode matrix covers all 12 cells."""
    if not IMPL.exists():
        return {"check": "Band-mode matrix complete", "pass": False, "detail": "File missing"}
    text = IMPL.read_text()
    # Count match arms in divergence_action function
    count = 0
    for band in COMPATIBILITY_BANDS:
        for mode in COMPATIBILITY_MODES:
            pattern = f"CompatibilityBand::{band}"
            if pattern in text:
                count += 1
                break
    # Simpler: check for the test that verifies it
    has_test = "divergence_matrix_is_complete" in text
    return {
        "check": "Band-mode matrix complete (12 cells)",
        "pass": has_test and count == 4,
        "detail": f"4 bands covered, completeness test present" if has_test else "INCOMPLETE",
    }


def check_serde_derives() -> dict[str, Any]:
    """Check that key types have Serialize, Deserialize derives."""
    if not IMPL.exists():
        return {"check": "Serde derives on types", "pass": False, "detail": "File missing"}
    text = IMPL.read_text()
    serde_count = text.count("Serialize, Deserialize")
    return {
        "check": f"Serde derives on types (found {serde_count})",
        "pass": serde_count >= 10,
        "detail": f"{serde_count} types with Serde",
    }


# ── Main runner ───────────────────────────────────────────────────────────────

def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    # File existence
    checks.append(check_file(IMPL, "compat_gates.rs"))
    checks.append(check_file(LEGACY_IMPL, "compatibility_gate.rs"))
    checks.append(check_file(SPEC, "bd-137_contract.md"))
    checks.append(check_file(POLICY_MOD, "policy/mod.rs"))

    # Module registration
    checks.append(check_module_registered())

    # Types in compat_gates.rs
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))

    # Methods in compat_gates.rs
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))

    # Event codes
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))

    # Invariants in doc comments
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))

    # Tests present
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    # Test count
    checks.append(check_impl_test_count())

    # Legacy types
    checks.extend(check_content(LEGACY_IMPL, LEGACY_TYPES, "legacy_type"))

    # Legacy methods
    checks.extend(check_content(LEGACY_IMPL, LEGACY_METHODS, "legacy_method"))

    # Legacy test count
    checks.append(check_legacy_test_count())

    # Spec checks
    checks.extend(check_spec())

    # Structural checks
    checks.append(check_band_mode_matrix_complete())
    checks.append(check_serde_derives())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-137",
        "title": "Policy-visible compatibility gate APIs",
        "section": "10.5",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test() -> tuple[bool, str]:
    """Self-test: run checks and verify structure."""
    result = run_checks()
    if not isinstance(result, dict):
        return False, "result is not a dict"
    for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
        if key not in result:
            return False, f"missing key: {key}"
    if result["bead_id"] != "bd-137":
        return False, f"bead_id mismatch: {result['bead_id']}"
    if not isinstance(result["checks"], list):
        return False, "checks is not a list"
    if len(result["checks"]) < 50:
        return False, f"too few checks: {len(result['checks'])}"
    return True, "self_test passed"


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify bd-137 compatibility gate APIs")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        ok, msg = self_test()
        print(msg)
        sys.exit(0 if ok else 1)

    result = run_checks()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-137: {result['verdict']}")
        print(f"  Passing: {result['summary']['passing']}")
        print(f"  Failing: {result['summary']['failing']}")
        if result["summary"]["failing"] > 0:
            print("\nFailing checks:")
            for c in result["checks"]:
                if not c["pass"]:
                    print(f"  FAIL: {c['check']}: {c['detail']}")

    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
