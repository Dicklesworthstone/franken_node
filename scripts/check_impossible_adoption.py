#!/usr/bin/env python3
"""Verification script for bd-1xao: impossible-by-default adoption success criterion.

Checks that the spec contract, policy document, event codes, invariants,
capability states, adoption tiers, quantitative targets, and artifacts are
complete and consistent.

Usage:
    python3 scripts/check_impossible_adoption.py [--json] [--self-test]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-1xao_contract.md"
POLICY = ROOT / "docs" / "policy" / "impossible_by_default_adoption.md"
EVIDENCE = ROOT / "artifacts" / "section_13" / "bd-1xao" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_13" / "bd-1xao" / "verification_summary.md"

EVENT_CODES = ["IBD-001", "IBD-002", "IBD-003", "IBD-004"]

INVARIANTS = [
    "INV-IBD-DEFAULT",
    "INV-IBD-AUTH",
    "INV-IBD-AUDIT",
    "INV-IBD-COVERAGE",
]

ADOPTION_TIERS = ["A0", "A1", "A2", "A3", "A4"]

CAPABILITY_STATES = ["BLOCKED", "AUTHORIZED", "ACTIVE", "REVOKED"]

DANGEROUS_OP_CATEGORIES = [
    "Credential management",
    "Network exposure",
    "Data exfiltration paths",
    "Privilege escalation",
    "Configuration override",
]

QUANTITATIVE_TARGETS = {
    "capability_coverage": {"operator": ">=", "value": 95, "unit": "percent"},
    "bypass_detection_rate": {"operator": "==", "value": 100, "unit": "percent"},
    "authorization_audit_completeness": {"operator": "==", "value": 100, "unit": "percent"},
    "operator_adoption_rate": {"operator": ">=", "value": 90, "unit": "percent"},
    "mean_time_to_authorize": {"operator": "<=", "value": 24, "unit": "hours"},
    "revocation_latency": {"operator": "<=", "value": 1, "unit": "hour"},
}

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    """Record a single check result."""
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    """Return a relative path string, safe even if path is outside ROOT."""
    s_path, s_root = str(path), str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


def _file_contains(path: Path, needle: str, label: str) -> dict[str, Any]:
    """Check that a file exists and contains the needle string."""
    if not path.is_file():
        return _check(f"{label}: {needle}", False, f"file missing: {_safe_rel(path)}")
    content = path.read_text(encoding="utf-8")
    found = needle in content
    return _check(
        f"{label}: {needle}",
        found,
        "found" if found else "not found in file",
    )


def validate_adoption_metrics(metrics: dict[str, Any]) -> list[str]:
    """Validate an adoption metrics object.

    Expected fields:
        - coverage_pct: float, 0-100
        - bypass_attempts: int, >= 0
        - audit_completeness_pct: float, 0-100
        - tier: str, one of ADOPTION_TIERS
        - gated_operations: int, >= 0
        - total_operations: int, >= 1

    Returns a list of error strings (empty if valid).
    """
    errors: list[str] = []

    if "coverage_pct" not in metrics:
        errors.append("missing coverage_pct")
    elif not isinstance(metrics["coverage_pct"], (int, float)):
        errors.append("coverage_pct must be numeric")
    elif not (0 <= metrics["coverage_pct"] <= 100):
        errors.append(f"coverage_pct out of range: {metrics['coverage_pct']}")

    if "bypass_attempts" not in metrics:
        errors.append("missing bypass_attempts")
    elif not isinstance(metrics["bypass_attempts"], int):
        errors.append("bypass_attempts must be int")
    elif metrics["bypass_attempts"] < 0:
        errors.append(f"bypass_attempts negative: {metrics['bypass_attempts']}")

    if "audit_completeness_pct" not in metrics:
        errors.append("missing audit_completeness_pct")
    elif not isinstance(metrics["audit_completeness_pct"], (int, float)):
        errors.append("audit_completeness_pct must be numeric")
    elif not (0 <= metrics["audit_completeness_pct"] <= 100):
        errors.append(f"audit_completeness_pct out of range: {metrics['audit_completeness_pct']}")

    if "tier" not in metrics:
        errors.append("missing tier")
    elif metrics["tier"] not in ADOPTION_TIERS:
        errors.append(f"invalid tier: {metrics['tier']}")

    if "gated_operations" not in metrics:
        errors.append("missing gated_operations")
    elif not isinstance(metrics["gated_operations"], int):
        errors.append("gated_operations must be int")
    elif metrics["gated_operations"] < 0:
        errors.append(f"gated_operations negative: {metrics['gated_operations']}")

    if "total_operations" not in metrics:
        errors.append("missing total_operations")
    elif not isinstance(metrics["total_operations"], int):
        errors.append("total_operations must be int")
    elif metrics["total_operations"] < 1:
        errors.append(f"total_operations must be >= 1: {metrics['total_operations']}")

    # Cross-field: gated <= total
    if (
        "gated_operations" in metrics
        and "total_operations" in metrics
        and isinstance(metrics["gated_operations"], int)
        and isinstance(metrics["total_operations"], int)
        and metrics["gated_operations"] > metrics["total_operations"]
    ):
        errors.append("gated_operations exceeds total_operations")

    # Cross-field: tier matches coverage
    if (
        "coverage_pct" in metrics
        and "tier" in metrics
        and isinstance(metrics["coverage_pct"], (int, float))
        and metrics["tier"] in ADOPTION_TIERS
    ):
        expected_tier = coverage_to_tier(metrics["coverage_pct"])
        if expected_tier != metrics["tier"]:
            errors.append(f"tier mismatch: coverage {metrics['coverage_pct']}% should be {expected_tier}, got {metrics['tier']}")

    return errors


def coverage_to_tier(coverage_pct: float) -> str:
    """Map a coverage percentage to an adoption tier.

    Args:
        coverage_pct: Coverage percentage (0-100).

    Returns:
        Tier string: A0, A1, A2, A3, or A4.
    """
    if coverage_pct >= 95:
        return "A4"
    if coverage_pct >= 90:
        return "A3"
    if coverage_pct >= 75:
        return "A2"
    if coverage_pct >= 50:
        return "A1"
    return "A0"


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_spec_exists() -> dict[str, Any]:
    """Verify the spec contract document exists."""
    exists = SPEC.is_file()
    return _check(
        "file: spec contract",
        exists,
        f"exists: {_safe_rel(SPEC)}" if exists else f"missing: {_safe_rel(SPEC)}",
    )


def check_policy_exists() -> dict[str, Any]:
    """Verify the policy document exists."""
    exists = POLICY.is_file()
    return _check(
        "file: policy document",
        exists,
        f"exists: {_safe_rel(POLICY)}" if exists else f"missing: {_safe_rel(POLICY)}",
    )


def check_event_codes_in_spec() -> list[dict[str, Any]]:
    """Verify all event codes are documented in the spec."""
    results = []
    for code in EVENT_CODES:
        results.append(_file_contains(SPEC, code, "spec event_code"))
    return results


def check_event_codes_in_policy() -> list[dict[str, Any]]:
    """Verify all event codes are documented in the policy."""
    results = []
    for code in EVENT_CODES:
        results.append(_file_contains(POLICY, code, "policy event_code"))
    return results


def check_invariants_in_spec() -> list[dict[str, Any]]:
    """Verify all invariants are documented in the spec."""
    results = []
    for inv in INVARIANTS:
        results.append(_file_contains(SPEC, inv, "spec invariant"))
    return results


def check_invariants_in_policy() -> list[dict[str, Any]]:
    """Verify all invariants are documented in the policy."""
    results = []
    for inv in INVARIANTS:
        results.append(_file_contains(POLICY, inv, "policy invariant"))
    return results


def check_capability_states_in_spec() -> list[dict[str, Any]]:
    """Verify all capability states are documented in the spec."""
    results = []
    for state in CAPABILITY_STATES:
        results.append(_file_contains(SPEC, state, "spec capability_state"))
    return results


def check_capability_states_in_policy() -> list[dict[str, Any]]:
    """Verify all capability states are documented in the policy."""
    results = []
    for state in CAPABILITY_STATES:
        results.append(_file_contains(POLICY, state, "policy capability_state"))
    return results


def check_adoption_tiers_in_spec() -> list[dict[str, Any]]:
    """Verify all adoption tiers are documented in the spec."""
    results = []
    for tier in ADOPTION_TIERS:
        results.append(_file_contains(SPEC, tier, "spec adoption_tier"))
    return results


def check_adoption_tiers_in_policy() -> list[dict[str, Any]]:
    """Verify all adoption tiers are documented in the policy."""
    results = []
    for tier in ADOPTION_TIERS:
        results.append(_file_contains(POLICY, tier, "policy adoption_tier"))
    return results


def check_dangerous_op_categories() -> list[dict[str, Any]]:
    """Verify dangerous operation categories are documented in the spec."""
    results = []
    for cat in DANGEROUS_OP_CATEGORIES:
        results.append(_file_contains(SPEC, cat, "spec dangerous_op"))
    return results


def check_quantitative_targets_in_spec() -> list[dict[str, Any]]:
    """Verify quantitative targets are documented in the spec."""
    results = []
    for metric_name in QUANTITATIVE_TARGETS:
        results.append(_file_contains(SPEC, metric_name, "spec quant_target"))
    return results


def check_coverage_threshold() -> dict[str, Any]:
    """Verify the >= 95% coverage target is in the spec."""
    if not SPEC.is_file():
        return _check("coverage threshold >= 95%", False, "spec missing")
    content = SPEC.read_text(encoding="utf-8")
    found = ">= 95%" in content or ">= 95" in content
    return _check(
        "coverage threshold >= 95%",
        found,
        "found" if found else "target not found",
    )


def check_bypass_detection_target() -> dict[str, Any]:
    """Verify the 100% bypass detection target is in the spec."""
    if not SPEC.is_file():
        return _check("bypass detection rate 100%", False, "spec missing")
    content = SPEC.read_text(encoding="utf-8")
    found = "bypass_detection_rate" in content and "100%" in content
    return _check(
        "bypass detection rate 100%",
        found,
        "found" if found else "target not found",
    )


def check_audit_completeness_target() -> dict[str, Any]:
    """Verify the 100% authorization audit completeness target is in the spec."""
    if not SPEC.is_file():
        return _check("audit completeness 100%", False, "spec missing")
    content = SPEC.read_text(encoding="utf-8")
    found = "authorization_audit_completeness" in content and "100%" in content
    return _check(
        "audit completeness 100%",
        found,
        "found" if found else "target not found",
    )


def check_release_gate_threshold() -> dict[str, Any]:
    """Verify the release gate threshold (A3 or higher) is in the spec."""
    if not SPEC.is_file():
        return _check("release gate A3", False, "spec missing")
    content = SPEC.read_text(encoding="utf-8")
    found = "A3" in content and "release gate" in content.lower()
    return _check(
        "release gate A3 threshold",
        found,
        "found" if found else "threshold not found",
    )


def check_state_machine_in_spec() -> dict[str, Any]:
    """Verify the state transition diagram is documented in spec."""
    if not SPEC.is_file():
        return _check("state machine documented", False, "spec missing")
    content = SPEC.read_text(encoding="utf-8")
    has_transitions = "BLOCKED -> AUTHORIZED" in content and "AUTHORIZED -> ACTIVE" in content
    return _check(
        "state machine documented",
        has_transitions,
        "found" if has_transitions else "state transitions not found",
    )


def check_authorization_workflow() -> dict[str, Any]:
    """Verify the authorization workflow is documented in spec."""
    return _file_contains(SPEC, "Authorization Workflow", "spec")


def check_acceptance_criteria() -> dict[str, Any]:
    """Verify the acceptance criteria section is in spec."""
    return _file_contains(SPEC, "## Acceptance Criteria", "spec")


def check_artifacts_table() -> dict[str, Any]:
    """Verify the artifacts table is in spec."""
    return _file_contains(SPEC, "## Artifacts", "spec")


def check_policy_risk_description() -> dict[str, Any]:
    """Verify risk description is in policy."""
    return _file_contains(POLICY, "## Risk Description", "policy")


def check_policy_impact() -> dict[str, Any]:
    """Verify impact section is in policy."""
    return _file_contains(POLICY, "### Impact", "policy")


def check_policy_monitoring() -> list[dict[str, Any]]:
    """Verify monitoring section and metrics in policy."""
    results = []
    results.append(_file_contains(POLICY, "Monitoring", "policy"))
    results.append(_file_contains(POLICY, "ibd_capability_coverage_pct", "policy metric"))
    results.append(_file_contains(POLICY, "ibd_bypass_attempts_count", "policy metric"))
    results.append(_file_contains(POLICY, "ibd_authorization_audit_completeness", "policy metric"))
    results.append(_file_contains(POLICY, "ibd_active_authorizations_count", "policy metric"))
    results.append(_file_contains(POLICY, "ibd_mean_time_to_authorize_hours", "policy metric"))
    results.append(_file_contains(POLICY, "ibd_revocation_latency_minutes", "policy metric"))
    return results


def check_policy_escalation() -> list[dict[str, Any]]:
    """Verify escalation procedures in policy."""
    results = []
    results.append(_file_contains(POLICY, "Escalation Procedures", "policy"))
    results.append(_file_contains(POLICY, "Bypass Attempt Detected", "policy escalation"))
    results.append(_file_contains(POLICY, "Coverage Below Release Gate", "policy escalation"))
    results.append(_file_contains(POLICY, "Authorization Audit Incomplete", "policy escalation"))
    results.append(_file_contains(POLICY, "Revocation Latency Exceeded", "policy escalation"))
    return results


def check_policy_evidence_requirements() -> dict[str, Any]:
    """Verify evidence requirements section in policy."""
    return _file_contains(POLICY, "Evidence Requirements", "policy")


def check_verification_evidence() -> dict[str, Any]:
    """Verify the evidence JSON artifact exists and has correct structure."""
    if not EVIDENCE.is_file():
        return _check(
            "verification evidence",
            False,
            f"missing: {_safe_rel(EVIDENCE)}",
        )
    try:
        data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _check("verification evidence", False, f"parse error: {exc}")
    has_bead = data.get("bead_id") == "bd-1xao"
    has_section = data.get("section") == "13"
    has_status = data.get("status") == "pass"
    ok = has_bead and has_section and has_status
    return _check(
        "verification evidence",
        ok,
        "valid" if ok else f"bead={has_bead} section={has_section} status={has_status}",
    )


def check_verification_summary() -> dict[str, Any]:
    """Verify the summary markdown exists and contains PASS."""
    if not SUMMARY.is_file():
        return _check(
            "verification summary",
            False,
            f"missing: {_safe_rel(SUMMARY)}",
        )
    content = SUMMARY.read_text(encoding="utf-8")
    has_pass = "PASS" in content
    has_bead = "bd-1xao" in content
    ok = has_pass and has_bead
    return _check(
        "verification summary",
        ok,
        "valid" if ok else f"PASS={has_pass} bead={has_bead}",
    )


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_event_codes_in_spec,
    check_event_codes_in_policy,
    check_invariants_in_spec,
    check_invariants_in_policy,
    check_capability_states_in_spec,
    check_capability_states_in_policy,
    check_adoption_tiers_in_spec,
    check_adoption_tiers_in_policy,
    check_dangerous_op_categories,
    check_quantitative_targets_in_spec,
    check_coverage_threshold,
    check_bypass_detection_target,
    check_audit_completeness_target,
    check_release_gate_threshold,
    check_state_machine_in_spec,
    check_authorization_workflow,
    check_acceptance_criteria,
    check_artifacts_table,
    check_policy_risk_description,
    check_policy_impact,
    check_policy_monitoring,
    check_policy_escalation,
    check_policy_evidence_requirements,
    check_verification_evidence,
    check_verification_summary,
]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def run_all() -> dict[str, Any]:
    """Run all checks and return structured report."""
    global RESULTS
    RESULTS = []

    for fn in ALL_CHECKS:
        result = fn()
        # Some checks return lists; individual items already added via _check
        # Nothing to do here since _check appends to RESULTS

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-1xao",
        "title": "Impossible-by-default adoption success criterion",
        "section": "13",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    """Run self-test: verify the script's own constants are consistent."""
    errors: list[str] = []

    # Event codes must be 4
    if len(EVENT_CODES) != 4:
        errors.append(f"Expected 4 event codes, got {len(EVENT_CODES)}")

    # All event codes must start with IBD-
    for code in EVENT_CODES:
        if not code.startswith("IBD-"):
            errors.append(f"Event code {code} does not start with IBD-")

    # Invariants must be 4
    if len(INVARIANTS) != 4:
        errors.append(f"Expected 4 invariants, got {len(INVARIANTS)}")

    # All invariants must start with INV-IBD-
    for inv in INVARIANTS:
        if not inv.startswith("INV-IBD-"):
            errors.append(f"Invariant {inv} does not start with INV-IBD-")

    # Adoption tiers must be 5
    if len(ADOPTION_TIERS) != 5:
        errors.append(f"Expected 5 adoption tiers, got {len(ADOPTION_TIERS)}")

    # Capability states must be 4
    if len(CAPABILITY_STATES) != 4:
        errors.append(f"Expected 4 capability states, got {len(CAPABILITY_STATES)}")

    # Dangerous op categories must be >= 5
    if len(DANGEROUS_OP_CATEGORIES) < 5:
        errors.append(f"Expected >= 5 dangerous op categories, got {len(DANGEROUS_OP_CATEGORIES)}")

    # Quantitative targets must have all required metrics
    expected_metrics = {
        "capability_coverage",
        "bypass_detection_rate",
        "authorization_audit_completeness",
        "operator_adoption_rate",
        "mean_time_to_authorize",
        "revocation_latency",
    }
    actual_metrics = set(QUANTITATIVE_TARGETS.keys())
    if actual_metrics != expected_metrics:
        errors.append(f"Metric mismatch: expected {expected_metrics}, got {actual_metrics}")

    # SPEC, POLICY, EVIDENCE, SUMMARY paths must be under ROOT
    for label, path in [("SPEC", SPEC), ("POLICY", POLICY), ("EVIDENCE", EVIDENCE), ("SUMMARY", SUMMARY)]:
        s_path, s_root = str(path), str(ROOT)
        if not s_path.startswith(s_root):
            errors.append(f"{label} path {path} is not under ROOT {ROOT}")

    # coverage_to_tier must return correct tiers
    tier_tests = [
        (0, "A0"), (49.9, "A0"), (50, "A1"), (74.9, "A1"),
        (75, "A2"), (89.9, "A2"), (90, "A3"), (94.9, "A3"),
        (95, "A4"), (100, "A4"),
    ]
    for pct, expected_tier in tier_tests:
        actual_tier = coverage_to_tier(pct)
        if actual_tier != expected_tier:
            errors.append(f"coverage_to_tier({pct}) = {actual_tier}, expected {expected_tier}")

    # validate_adoption_metrics must accept a valid object
    valid_metrics = {
        "coverage_pct": 96.0,
        "bypass_attempts": 0,
        "audit_completeness_pct": 100.0,
        "tier": "A4",
        "gated_operations": 48,
        "total_operations": 50,
    }
    metric_errors = validate_adoption_metrics(valid_metrics)
    if metric_errors:
        errors.append(f"validate_adoption_metrics rejected valid input: {metric_errors}")

    # validate_adoption_metrics must reject invalid object
    invalid_metrics = {"coverage_pct": 150}
    metric_errors = validate_adoption_metrics(invalid_metrics)
    if not metric_errors:
        errors.append("validate_adoption_metrics accepted invalid input")

    # run_all must return dict with required keys
    report = run_all()
    required_keys = {"bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"}
    missing_keys = required_keys - set(report.keys())
    if missing_keys:
        errors.append(f"run_all missing keys: {missing_keys}")
    if report.get("bead_id") != "bd-1xao":
        errors.append(f"run_all bead_id mismatch: {report.get('bead_id')}")
    if report.get("section") != "13":
        errors.append(f"run_all section mismatch: {report.get('section')}")

    # ALL_CHECKS must be non-empty
    if not ALL_CHECKS:
        errors.append("ALL_CHECKS is empty")

    if errors:
        for err in errors:
            print(f"  SELF-TEST FAIL: {err}", file=sys.stderr)
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-1xao: impossible-by-default adoption success criterion"
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
