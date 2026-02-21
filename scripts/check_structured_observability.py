#!/usr/bin/env python3
"""Verification script for bd-3o6: structured observability adoption across operational surfaces.

Usage:
    python3 scripts/check_structured_observability.py              # human-readable
    python3 scripts/check_structured_observability.py --json        # machine-readable JSON
    python3 scripts/check_structured_observability.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

# --- File paths -----------------------------------------------------------

SPEC = ROOT / "docs" / "specs" / "section_10_8" / "bd-3o6_contract.md"
POLICY = ROOT / "docs" / "policy" / "structured_observability.md"

# Upstream 10.13 contracts
TELEMETRY_NS_IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "telemetry_namespace.rs"
ERROR_REG_IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "error_code_registry.rs"
TRACE_CTX_IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "trace_context.rs"
TELEMETRY_NS_SPEC = ROOT / "docs" / "specs" / "section_10_13" / "bd-1ugy_contract.md"
ERROR_REG_SPEC = ROOT / "docs" / "specs" / "section_10_13" / "bd-novi_contract.md"

# Operational surface source files
CLI_IMPL = ROOT / "crates" / "franken-node" / "src" / "cli.rs"
MAIN_IMPL = ROOT / "crates" / "franken-node" / "src" / "main.rs"
HEALTH_GATE = ROOT / "crates" / "franken-node" / "src" / "connector" / "health_gate.rs"
CONNECTOR_MOD = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
OBSERVABILITY_MOD = ROOT / "crates" / "franken-node" / "src" / "observability" / "mod.rs"
DASHBOARD_DOC = ROOT / "docs" / "observability" / "asupersync_control_dashboards.md"
CONTROL_EVIDENCE = ROOT / "crates" / "franken-node" / "src" / "connector" / "control_evidence.rs"

# --- Constants -------------------------------------------------------------

EVENT_CODES = ["SOB-001", "SOB-002", "SOB-003", "SOB-004"]

INVARIANTS = [
    "INV-SOB-METRIC-CANONICAL",
    "INV-SOB-ERROR-REGISTERED",
    "INV-SOB-TRACE-CONTEXT",
    "INV-SOB-DASHBOARD-VALID",
]

OPERATIONAL_SURFACES = [
    "OPS-CLI",
    "OPS-API",
    "OPS-HEALTH",
    "OPS-DASH",
    "OPS-LOG",
    "OPS-CONTROL",
]

RECOVERY_HINT_ACTIONS = ["retry", "escalate", "reconfigure", "rollback", "ignore"]

SEVERITY_LEVELS = ["Fatal", "Degraded", "Transient"]

CANONICAL_PREFIXES = [
    "franken.protocol.",
    "franken.capability.",
    "franken.egress.",
    "franken.security.",
]

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


def check_upstream_telemetry_ns() -> dict[str, Any]:
    """C03: Upstream telemetry namespace implementation exists."""
    return _file_exists(TELEMETRY_NS_IMPL, "telemetry namespace impl (10.13)")


def check_upstream_error_registry() -> dict[str, Any]:
    """C04: Upstream error code registry implementation exists."""
    return _file_exists(ERROR_REG_IMPL, "error code registry impl (10.13)")


def check_upstream_trace_context() -> dict[str, Any]:
    """C05: Upstream trace context implementation exists."""
    return _file_exists(TRACE_CTX_IMPL, "trace context impl")


def check_spec_event_codes() -> dict[str, Any]:
    """C06: Spec defines all four SOB event codes."""
    if not SPEC.is_file():
        return _check("spec_event_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes present" if passed else f"missing: {missing}"
    return _check("spec_event_codes", passed, detail)


def check_spec_invariants() -> dict[str, Any]:
    """C07: Spec defines all four INV-SOB invariants."""
    if not SPEC.is_file():
        return _check("spec_invariants", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants present" if passed else f"missing: {missing}"
    return _check("spec_invariants", passed, detail)


def check_spec_operational_surfaces() -> dict[str, Any]:
    """C08: Spec enumerates all six operational surfaces."""
    if not SPEC.is_file():
        return _check("spec_operational_surfaces", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [s for s in OPERATIONAL_SURFACES if s not in content]
    passed = len(missing) == 0
    detail = "all 6 surfaces listed" if passed else f"missing: {missing}"
    return _check("spec_operational_surfaces", passed, detail)


def check_spec_recovery_hint_schema() -> dict[str, Any]:
    """C09: Spec defines recovery hint schema with action/target/confidence."""
    if not SPEC.is_file():
        return _check("spec_recovery_hint_schema", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    keywords = ["action", "target", "confidence", "escalation_path"]
    found = [k for k in keywords if k in content]
    passed = len(found) == len(keywords)
    detail = f"all {len(keywords)} hint fields documented" if passed else f"found {len(found)}/{len(keywords)}"
    return _check("spec_recovery_hint_schema", passed, detail)


def check_spec_backward_compatibility() -> dict[str, Any]:
    """C10: Spec documents backward compatibility / deprecation cycle."""
    return _file_contains(SPEC, "Backward Compatibility", "spec_section")


def check_spec_adoption_checklist() -> dict[str, Any]:
    """C11: Spec includes adoption checklist."""
    return _file_contains(SPEC, "Adoption Checklist", "spec_section")


def check_policy_canonical_log_format() -> dict[str, Any]:
    """C12: Policy defines canonical log format."""
    return _file_contains(POLICY, "Canonical Log Format", "policy_section")


def check_policy_error_taxonomy() -> dict[str, Any]:
    """C13: Policy defines error taxonomy section."""
    return _file_contains(POLICY, "Error Taxonomy", "policy_section")


def check_policy_severity_levels() -> dict[str, Any]:
    """C14: Policy defines all three severity levels."""
    if not POLICY.is_file():
        return _check("policy_severity_levels", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [s for s in SEVERITY_LEVELS if s not in content]
    passed = len(missing) == 0
    detail = "all 3 severity levels present" if passed else f"missing: {missing}"
    return _check("policy_severity_levels", passed, detail)


def check_policy_trace_ids() -> dict[str, Any]:
    """C15: Policy documents trace ID format and requirements."""
    return _file_contains(POLICY, "trace_id", "policy_field")


def check_policy_recovery_hints() -> dict[str, Any]:
    """C16: Policy defines recovery hint actions."""
    if not POLICY.is_file():
        return _check("policy_recovery_hints", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [a for a in RECOVERY_HINT_ACTIONS if a not in content]
    passed = len(missing) == 0
    detail = "all 5 recovery actions documented" if passed else f"missing: {missing}"
    return _check("policy_recovery_hints", passed, detail)


def check_policy_surface_inventory() -> dict[str, Any]:
    """C17: Policy includes operational surface inventory."""
    return _file_contains(POLICY, "Operational Surface Inventory", "policy_section")


def check_policy_enforcement_event_codes() -> dict[str, Any]:
    """C18: Policy references all four SOB event codes."""
    if not POLICY.is_file():
        return _check("policy_event_codes", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes in policy" if passed else f"missing: {missing}"
    return _check("policy_event_codes", passed, detail)


def check_policy_invariants() -> dict[str, Any]:
    """C19: Policy references all four INV-SOB invariants."""
    if not POLICY.is_file():
        return _check("policy_invariants", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants in policy" if passed else f"missing: {missing}"
    return _check("policy_invariants", passed, detail)


def check_policy_deprecation_cycle() -> dict[str, Any]:
    """C20: Policy documents deprecation cycle requirements."""
    return _file_contains(POLICY, "Deprecation Cycle", "policy_section")


def check_policy_governance() -> dict[str, Any]:
    """C21: Policy defines governance section."""
    return _file_contains(POLICY, "Governance", "policy_section")


def check_upstream_telemetry_ns_spec() -> dict[str, Any]:
    """C22: Upstream telemetry namespace spec exists."""
    return _file_exists(TELEMETRY_NS_SPEC, "telemetry namespace spec (10.13)")


def check_upstream_error_registry_spec() -> dict[str, Any]:
    """C23: Upstream error code registry spec exists."""
    return _file_exists(ERROR_REG_SPEC, "error code registry spec (10.13)")


def check_telemetry_ns_has_schema_registry() -> dict[str, Any]:
    """C24: Telemetry namespace impl has SchemaRegistry type."""
    return _file_contains(TELEMETRY_NS_IMPL, "struct SchemaRegistry", "telemetry_ns")


def check_error_reg_has_recovery_info() -> dict[str, Any]:
    """C25: Error code registry impl has RecoveryInfo type."""
    return _file_contains(ERROR_REG_IMPL, "struct RecoveryInfo", "error_registry")


def check_trace_ctx_has_trace_context() -> dict[str, Any]:
    """C26: Trace context impl has TraceContext type."""
    return _file_contains(TRACE_CTX_IMPL, "struct TraceContext", "trace_ctx")


def check_cli_has_json_flag() -> dict[str, Any]:
    """C27: CLI surface supports --json flag for structured output."""
    return _file_contains(CLI_IMPL, "pub json: bool", "cli_surface")


def check_spec_canonical_prefixes() -> dict[str, Any]:
    """C28: Spec references all four canonical metric namespace prefixes."""
    if not SPEC.is_file():
        return _check("spec_canonical_prefixes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [p for p in CANONICAL_PREFIXES if p not in content]
    passed = len(missing) == 0
    detail = "all 4 canonical prefixes documented" if passed else f"missing: {missing}"
    return _check("spec_canonical_prefixes", passed, detail)


def check_policy_canonical_prefixes() -> dict[str, Any]:
    """C29: Policy references canonical metric namespace prefixes."""
    if not POLICY.is_file():
        return _check("policy_canonical_prefixes", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    # Check at least the pattern is referenced
    found = "franken.protocol." in content or "franken.{plane}." in content
    return _check("policy_canonical_prefixes", found,
                   "canonical prefix pattern found" if found else "not found")


def check_spec_dependencies_documented() -> dict[str, Any]:
    """C30: Spec documents upstream dependencies."""
    return _file_contains(SPEC, "Dependencies", "spec_section")


# ---------------------------------------------------------------------------
# Validation helpers (exported for test use)
# ---------------------------------------------------------------------------

def validate_recovery_hint(hint: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate a recovery hint object against the canonical schema."""
    results: list[dict[str, Any]] = []

    action = hint.get("action")
    ok = isinstance(action, str) and action in RECOVERY_HINT_ACTIONS
    results.append({
        "name": "hint_action_valid",
        "passed": ok,
        "detail": f"action={action}",
    })

    target = hint.get("target")
    ok = isinstance(target, str) and len(target) > 0
    results.append({
        "name": "hint_target_present",
        "passed": ok,
        "detail": f"target={target}" if ok else "missing or empty",
    })

    confidence = hint.get("confidence")
    ok = isinstance(confidence, (int, float)) and 0.0 <= confidence <= 1.0
    results.append({
        "name": "hint_confidence_range",
        "passed": ok,
        "detail": f"confidence={confidence}",
    })

    # escalation_path is optional
    ep = hint.get("escalation_path")
    if ep is not None:
        ok = isinstance(ep, str)
        results.append({
            "name": "hint_escalation_path_type",
            "passed": ok,
            "detail": f"escalation_path={ep}" if ok else "not a string",
        })

    return results


def validate_structured_log_entry(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate a structured log entry against the canonical format."""
    results: list[dict[str, Any]] = []

    # trace_id required
    trace_id = entry.get("trace_id")
    ok = isinstance(trace_id, str) and len(trace_id) == 32
    results.append({
        "name": "log_trace_id",
        "passed": ok,
        "detail": f"trace_id length={len(trace_id) if isinstance(trace_id, str) else 'missing'}",
    })

    # span_id required
    span_id = entry.get("span_id")
    ok = isinstance(span_id, str) and len(span_id) == 16
    results.append({
        "name": "log_span_id",
        "passed": ok,
        "detail": f"span_id length={len(span_id) if isinstance(span_id, str) else 'missing'}",
    })

    # level required
    level = entry.get("level")
    ok = isinstance(level, str) and level in ("error", "warn", "info", "debug")
    results.append({
        "name": "log_level_valid",
        "passed": ok,
        "detail": f"level={level}",
    })

    # surface required
    surface = entry.get("surface")
    ok = isinstance(surface, str) and surface in OPERATIONAL_SURFACES
    results.append({
        "name": "log_surface_valid",
        "passed": ok,
        "detail": f"surface={surface}",
    })

    # error_code if error/warn level
    if level in ("error", "warn"):
        error_code = entry.get("error_code")
        ok = isinstance(error_code, str) and error_code.startswith("FRANKEN_")
        results.append({
            "name": "log_error_code_canonical",
            "passed": ok,
            "detail": f"error_code={error_code}" if ok else "missing or non-canonical",
        })

    return results


def is_canonical_metric_name(name: str) -> bool:
    """Check if a metric name uses a canonical namespace prefix."""
    return any(name.startswith(p) for p in CANONICAL_PREFIXES)


# ---------------------------------------------------------------------------
# All check functions
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_upstream_telemetry_ns,
    check_upstream_error_registry,
    check_upstream_trace_context,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_operational_surfaces,
    check_spec_recovery_hint_schema,
    check_spec_backward_compatibility,
    check_spec_adoption_checklist,
    check_policy_canonical_log_format,
    check_policy_error_taxonomy,
    check_policy_severity_levels,
    check_policy_trace_ids,
    check_policy_recovery_hints,
    check_policy_surface_inventory,
    check_policy_enforcement_event_codes,
    check_policy_invariants,
    check_policy_deprecation_cycle,
    check_policy_governance,
    check_upstream_telemetry_ns_spec,
    check_upstream_error_registry_spec,
    check_telemetry_ns_has_schema_registry,
    check_error_reg_has_recovery_info,
    check_trace_ctx_has_trace_context,
    check_cli_has_json_flag,
    check_spec_canonical_prefixes,
    check_policy_canonical_prefixes,
    check_spec_dependencies_documented,
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
        "bead_id": "bd-3o6",
        "title": "Structured observability adoption across operational surfaces",
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
        description="Verify bd-3o6: structured observability adoption"
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
