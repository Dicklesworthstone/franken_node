#!/usr/bin/env python3
"""Verification script for bd-pga7: deterministic incident containment/explanation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-pga7_contract.md"
POLICY = ROOT / "docs" / "policy" / "deterministic_incident_containment.md"
EVIDENCE = ROOT / "artifacts" / "section_13" / "bd-pga7" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_13" / "bd-pga7" / "verification_summary.md"

EVENT_CODES = ["DIC-001", "DIC-002", "DIC-003", "DIC-004"]

INVARIANTS = [
    "INV-DIC-CONTAIN",
    "INV-DIC-EXPLAIN",
    "INV-DIC-BOUND",
    "INV-DIC-COMPLETE",
]

CONTAINMENT_ACTIONS = [
    "isolate_component",
    "shed_load",
    "revoke_credentials",
    "disable_extension",
    "snapshot_state",
    "emit_alert",
]

QUANTITATIVE_TARGETS = {
    "blast_radius": {"operator": "<=", "value": 3, "unit": "components"},
    "time_to_contain": {"operator": "<=", "value": 60, "unit": "seconds"},
    "evidence_completeness": {"operator": ">=", "value": 95, "unit": "percent"},
    "explanation_reproducibility": {"operator": "==", "value": 100, "unit": "percent"},
}

EXPLANATION_DIMENSIONS = [
    "evidence_completeness",
    "root_cause_reproducibility",
    "explanation_latency",
]

CONTAINMENT_DIMENSIONS = [
    "blast_radius_bound",
    "time_to_contain",
    "automated_actions",
]

ACCEPTANCE_CRITERIA = [
    "Spec contract exists",
    "Policy document exists",
    "event codes",
    "invariants",
    "blast_radius",
    "time_to_contain",
    "evidence_completeness",
    "explanation_reproducibility",
    "Containment determinism",
    "Explanation determinism",
    "Verification script passes",
    "Evidence artifact",
]


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = os.path.relpath(path, ROOT)
    return _check(
        f"file: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _file_contains(path: Path, needle: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: {needle}", False, "file missing")
    content = path.read_text(encoding="utf-8")
    found = needle in content
    return _check(
        f"{label}: {needle}",
        found,
        "found" if found else "not found in file",
    )


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_spec_exists() -> dict[str, Any]:
    """Verify the spec contract document exists."""
    return _file_exists(SPEC, "spec contract")


def check_policy_exists() -> dict[str, Any]:
    """Verify the policy document exists."""
    return _file_exists(POLICY, "policy document")


def check_containment_documented() -> list[dict[str, Any]]:
    """Verify containment dimensions are documented in the spec."""
    results = []
    for dim in CONTAINMENT_DIMENSIONS:
        results.append(_file_contains(SPEC, dim, "spec containment"))
    for action in CONTAINMENT_ACTIONS:
        results.append(_file_contains(SPEC, action, "spec action"))
    return results


def check_explanation_documented() -> list[dict[str, Any]]:
    """Verify explanation dimensions are documented in the spec."""
    results = []
    for dim in EXPLANATION_DIMENSIONS:
        results.append(_file_contains(SPEC, dim, "spec explanation"))
    return results


def check_blast_radius() -> dict[str, Any]:
    """Verify blast_radius target is specified in spec."""
    if not SPEC.is_file():
        return _check("blast_radius target", False, "spec missing")
    content = SPEC.read_text(encoding="utf-8")
    found = "<= 3" in content or "<= 3 components" in content
    return _check(
        "blast_radius target <= 3 components",
        found,
        "found" if found else "target not found",
    )


def check_time_to_contain() -> dict[str, Any]:
    """Verify time_to_contain target is specified in spec."""
    if not SPEC.is_file():
        return _check("time_to_contain target", False, "spec missing")
    content = SPEC.read_text(encoding="utf-8")
    found = "<= 60" in content or "<= 60 seconds" in content
    return _check(
        "time_to_contain target <= 60s",
        found,
        "found" if found else "target not found",
    )


def check_evidence_completeness() -> dict[str, Any]:
    """Verify evidence_completeness target is specified in spec."""
    if not SPEC.is_file():
        return _check("evidence_completeness target", False, "spec missing")
    content = SPEC.read_text(encoding="utf-8")
    found = ">= 95" in content or ">= 95%" in content
    return _check(
        "evidence_completeness target >= 95%",
        found,
        "found" if found else "target not found",
    )


def check_event_codes() -> list[dict[str, Any]]:
    """Verify all event codes are documented in spec and policy."""
    results = []
    for code in EVENT_CODES:
        results.append(_file_contains(SPEC, code, "spec event_code"))
        results.append(_file_contains(POLICY, code, "policy event_code"))
    return results


def check_invariants() -> list[dict[str, Any]]:
    """Verify all invariants are documented in the spec."""
    results = []
    for inv in INVARIANTS:
        results.append(_file_contains(SPEC, inv, "spec invariant"))
    return results


def check_quantitative_targets() -> list[dict[str, Any]]:
    """Verify quantitative targets table exists in spec."""
    results = []
    if not SPEC.is_file():
        results.append(_check("quantitative targets table", False, "spec missing"))
        return results
    content = SPEC.read_text(encoding="utf-8")
    results.append(_check(
        "quantitative targets: blast_radius",
        "blast_radius" in content and "<= 3" in content,
        "found" if ("blast_radius" in content and "<= 3" in content) else "missing",
    ))
    results.append(_check(
        "quantitative targets: time_to_contain",
        "time_to_contain" in content and "<= 60" in content,
        "found" if ("time_to_contain" in content and "<= 60" in content) else "missing",
    ))
    results.append(_check(
        "quantitative targets: evidence_completeness",
        "evidence_completeness" in content and ">= 95" in content,
        "found" if ("evidence_completeness" in content and ">= 95" in content) else "missing",
    ))
    results.append(_check(
        "quantitative targets: explanation_reproducibility",
        "explanation_reproducibility" in content and "100%" in content,
        "found" if ("explanation_reproducibility" in content and "100%" in content) else "missing",
    ))
    return results


def check_acceptance_criteria() -> list[dict[str, Any]]:
    """Verify acceptance criteria section exists in spec."""
    results = []
    if not SPEC.is_file():
        results.append(_check("acceptance criteria section", False, "spec missing"))
        return results
    content = SPEC.read_text(encoding="utf-8")
    results.append(_check(
        "acceptance criteria section",
        "## Acceptance Criteria" in content,
        "found" if "## Acceptance Criteria" in content else "section missing",
    ))
    for criterion in ACCEPTANCE_CRITERIA:
        results.append(_check(
            f"acceptance: {criterion}",
            criterion in content,
            "found" if criterion in content else "not found",
        ))
    return results


def check_verification_evidence() -> dict[str, Any]:
    """Verify the evidence JSON artifact exists and has correct structure."""
    if not EVIDENCE.is_file():
        return _check("verification evidence", False, f"missing: {os.path.relpath(EVIDENCE, ROOT)}")
    try:
        data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _check("verification evidence", False, f"parse error: {exc}")
    has_bead = data.get("bead_id") == "bd-pga7"
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
        return _check("verification summary", False, f"missing: {os.path.relpath(SUMMARY, ROOT)}")
    content = SUMMARY.read_text(encoding="utf-8")
    has_pass = "PASS" in content
    has_bead = "bd-pga7" in content
    ok = has_pass and has_bead
    return _check(
        "verification summary",
        ok,
        "valid" if ok else f"PASS={has_pass} bead={has_bead}",
    )


def check_policy_containment_contract() -> list[dict[str, Any]]:
    """Verify the policy documents the containment contract."""
    results = []
    results.append(_file_contains(POLICY, "Blast Radius", "policy containment"))
    results.append(_file_contains(POLICY, "Time Bounds", "policy containment"))
    results.append(_file_contains(POLICY, "Automated Actions", "policy containment"))
    return results


def check_policy_explanation_contract() -> list[dict[str, Any]]:
    """Verify the policy documents the explanation contract."""
    results = []
    results.append(_file_contains(POLICY, "Evidence Capture", "policy explanation"))
    results.append(_file_contains(POLICY, "Reproducibility", "policy explanation"))
    results.append(_file_contains(POLICY, "Latency", "policy explanation"))
    return results


def check_policy_escalation() -> list[dict[str, Any]]:
    """Verify the policy documents escalation procedures."""
    results = []
    results.append(_file_contains(POLICY, "Escalation Procedures", "policy"))
    results.append(_file_contains(POLICY, "Containment Divergence", "policy escalation"))
    results.append(_file_contains(POLICY, "Explanation Divergence", "policy escalation"))
    results.append(_file_contains(POLICY, "Blast Radius Exceeded", "policy escalation"))
    results.append(_file_contains(POLICY, "Evidence Completeness Below", "policy escalation"))
    return results


def check_policy_monitoring() -> list[dict[str, Any]]:
    """Verify the policy documents monitoring dashboards."""
    results = []
    results.append(_file_contains(POLICY, "Monitoring", "policy"))
    results.append(_file_contains(POLICY, "dic_containment_time_p99", "policy metric"))
    results.append(_file_contains(POLICY, "dic_blast_radius_max", "policy metric"))
    results.append(_file_contains(POLICY, "dic_explanation_time_p99", "policy metric"))
    results.append(_file_contains(POLICY, "dic_evidence_completeness_min", "policy metric"))
    results.append(_file_contains(POLICY, "dic_containment_divergence_count", "policy metric"))
    results.append(_file_contains(POLICY, "dic_explanation_divergence_count", "policy metric"))
    return results


def check_policy_evidence_requirements() -> dict[str, Any]:
    """Verify the policy documents evidence requirements for review."""
    return _file_contains(POLICY, "Evidence Requirements", "policy")


def check_determinism_contracts() -> list[dict[str, Any]]:
    """Verify determinism contracts are documented in the spec."""
    results = []
    results.append(_file_contains(SPEC, "Containment Determinism", "spec"))
    results.append(_file_contains(SPEC, "Explanation Determinism", "spec"))
    results.append(_file_contains(SPEC, "pure function", "spec determinism"))
    return results


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    """Run all checks and return structured report."""
    checks: list[dict[str, Any]] = []

    # File existence
    checks.append(check_spec_exists())
    checks.append(check_policy_exists())

    # Containment documentation
    checks.extend(check_containment_documented())

    # Explanation documentation
    checks.extend(check_explanation_documented())

    # Quantitative thresholds
    checks.append(check_blast_radius())
    checks.append(check_time_to_contain())
    checks.append(check_evidence_completeness())

    # Event codes in spec and policy
    checks.extend(check_event_codes())

    # Invariants in spec
    checks.extend(check_invariants())

    # Quantitative targets table
    checks.extend(check_quantitative_targets())

    # Acceptance criteria
    checks.extend(check_acceptance_criteria())

    # Policy sub-checks
    checks.extend(check_policy_containment_contract())
    checks.extend(check_policy_explanation_contract())
    checks.extend(check_policy_escalation())
    checks.extend(check_policy_monitoring())
    checks.append(check_policy_evidence_requirements())

    # Determinism contracts
    checks.extend(check_determinism_contracts())

    # Artifacts
    checks.append(check_verification_evidence())
    checks.append(check_verification_summary())

    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing

    return {
        "bead_id": "bd-pga7",
        "title": "Deterministic incident containment and explanation",
        "section": "13",
        "verdict": "PASS" if failing == 0 else "FAIL",
        "overall_pass": failing == 0,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": total,
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, str]:
    """Run self-test: verify the script's own constants are consistent."""
    errors: list[str] = []

    # Event codes must be 4
    if len(EVENT_CODES) != 4:
        errors.append(f"Expected 4 event codes, got {len(EVENT_CODES)}")

    # Invariants must be 4
    if len(INVARIANTS) != 4:
        errors.append(f"Expected 4 invariants, got {len(INVARIANTS)}")

    # All event codes must start with DIC-
    for code in EVENT_CODES:
        if not code.startswith("DIC-"):
            errors.append(f"Event code {code} does not start with DIC-")

    # All invariants must start with INV-DIC-
    for inv in INVARIANTS:
        if not inv.startswith("INV-DIC-"):
            errors.append(f"Invariant {inv} does not start with INV-DIC-")

    # Containment actions must be >= 5
    if len(CONTAINMENT_ACTIONS) < 5:
        errors.append(f"Expected >= 5 containment actions, got {len(CONTAINMENT_ACTIONS)}")

    # Quantitative targets must include all 4 metrics
    expected_metrics = {"blast_radius", "time_to_contain", "evidence_completeness", "explanation_reproducibility"}
    actual_metrics = set(QUANTITATIVE_TARGETS.keys())
    if actual_metrics != expected_metrics:
        errors.append(f"Metric mismatch: expected {expected_metrics}, got {actual_metrics}")

    # SPEC, POLICY, EVIDENCE, SUMMARY paths must be under ROOT
    for label, path in [("SPEC", SPEC), ("POLICY", POLICY), ("EVIDENCE", EVIDENCE), ("SUMMARY", SUMMARY)]:
        try:
            path.relative_to(ROOT)
        except ValueError:
            errors.append(f"{label} path {path} is not under ROOT {ROOT}")

    # Explanation dimensions must be 3
    if len(EXPLANATION_DIMENSIONS) != 3:
        errors.append(f"Expected 3 explanation dimensions, got {len(EXPLANATION_DIMENSIONS)}")

    # Containment dimensions must be 3
    if len(CONTAINMENT_DIMENSIONS) != 3:
        errors.append(f"Expected 3 containment dimensions, got {len(CONTAINMENT_DIMENSIONS)}")

    # run_all must return dict with required keys
    report = run_all()
    required_keys = {"bead_id", "title", "section", "verdict", "overall_pass", "summary", "checks"}
    missing_keys = required_keys - set(report.keys())
    if missing_keys:
        errors.append(f"run_all missing keys: {missing_keys}")
    if report.get("bead_id") != "bd-pga7":
        errors.append(f"run_all bead_id mismatch: {report.get('bead_id')}")
    if report.get("section") != "13":
        errors.append(f"run_all section mismatch: {report.get('section')}")

    ok = len(errors) == 0
    msg = "all self-test assertions pass" if ok else "; ".join(errors)
    return ok, msg


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-pga7: deterministic incident containment/explanation"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok, msg = self_test()
        if args.json:
            print(json.dumps({"ok": ok, "message": msg}, indent=2))
        else:
            print(f"self_test: {'PASS' if ok else 'FAIL'} - {msg}")
        sys.exit(0 if ok else 1)

    report = run_all()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for check in report["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
        print(
            f"\n{report['summary']['passing']}/{report['summary']['total']} checks pass "
            f"(verdict={report['verdict']})"
        )

    sys.exit(0 if report["overall_pass"] else 1)


if __name__ == "__main__":
    main()
