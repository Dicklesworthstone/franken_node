#!/usr/bin/env python3
"""Verification script for bd-3e74: benchmark/verifier external usage.

Checks that the spec contract, policy document, and all required content
(event codes, invariants, adoption tiers, metric dimensions, gate thresholds,
provenance requirements, packaging formats, tracking channels, and evidence
artifacts) are present and correct.

Usage:
    python3 scripts/check_benchmark_external.py           # human-readable
    python3 scripts/check_benchmark_external.py --json    # machine-readable
    python3 scripts/check_benchmark_external.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-3e74_contract.md"
POLICY = ROOT / "docs" / "policy" / "benchmark_verifier_external_usage.md"

EVENT_CODES = ["BVE-001", "BVE-002", "BVE-003", "BVE-004"]
INVARIANTS = ["INV-BVE-PACKAGE", "INV-BVE-GUIDE", "INV-BVE-TRACK", "INV-BVE-REPORT"]
ADOPTION_TIERS = ["U0", "U1", "U2", "U3", "U4"]

METRIC_TARGETS = {
    "external_project_adoption": 3,
    "external_validation_parties": 2,
    "external_citations": 1,
    "packaging_formats": 1,
    "getting_started_time": 15,
    "tracking_channels": 2,
}

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {"check": name, "pass": bool(passed), "detail": detail or ("found" if passed else "NOT FOUND")}
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    s_path, s_root = str(path), str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# File existence checks
# ---------------------------------------------------------------------------

def check_spec_exists() -> None:
    """Spec contract file must exist."""
    _check("spec_exists", SPEC.is_file(), f"spec at {_safe_rel(SPEC)}")


def check_policy_exists() -> None:
    """Policy document must exist."""
    _check("policy_exists", POLICY.is_file(), f"policy at {_safe_rel(POLICY)}")


# ---------------------------------------------------------------------------
# Spec content checks
# ---------------------------------------------------------------------------

def check_spec_event_codes() -> None:
    """Spec must define all four BVE event codes."""
    if not SPEC.is_file():
        _check("spec_event_codes", False, "spec missing")
        return
    text = SPEC.read_text()
    for code in EVENT_CODES:
        _check(f"spec_event_code:{code}", code in text, code)


def check_spec_invariants() -> None:
    """Spec must define all four INV-BVE invariants."""
    if not SPEC.is_file():
        _check("spec_invariants", False, "spec missing")
        return
    text = SPEC.read_text()
    for inv in INVARIANTS:
        _check(f"spec_invariant:{inv}", inv in text, inv)


def check_spec_adoption_tiers() -> None:
    """Spec must define all five adoption tiers U0-U4."""
    if not SPEC.is_file():
        _check("spec_adoption_tiers", False, "spec missing")
        return
    text = SPEC.read_text()
    for tier in ADOPTION_TIERS:
        _check(f"spec_tier:{tier}", tier in text, tier)


def check_spec_quantitative_targets() -> None:
    """Spec must contain concrete quantitative targets."""
    if not SPEC.is_file():
        _check("spec_quantitative_targets", False, "spec missing")
        return
    text = SPEC.read_text()
    targets = {
        "adoption_ge_3": r">=?\s*3",
        "validation_ge_2": r">=?\s*2",
        "citations_ge_1": r">=?\s*1",
        "time_le_15": r"<=?\s*15\s*min",
    }
    for label, pattern in targets.items():
        found = bool(re.search(pattern, text))
        _check(f"spec_target:{label}", found, label)


def check_spec_metric_dimensions() -> None:
    """Spec must define all six metric dimensions."""
    if not SPEC.is_file():
        _check("spec_metric_dimensions", False, "spec missing")
        return
    text = SPEC.read_text().lower()
    dimensions = [
        "external project adoption",
        "external validation parties",
        "external citations",
        "packaging formats",
        "getting started guide",
        "usage tracking channels",
    ]
    for dim in dimensions:
        _check(f"spec_dimension:{dim}", dim in text, dim)


def check_spec_gate_thresholds() -> None:
    """Spec must define alpha (U2) and beta (U3) gate thresholds."""
    if not SPEC.is_file():
        _check("spec_gate_thresholds", False, "spec missing")
        return
    text = SPEC.read_text().lower()
    _check("spec_gate:alpha", "alpha" in text and "u2" in text, "alpha gate at U2")
    _check("spec_gate:beta", "beta" in text and "u3" in text, "beta gate at U3")


def check_spec_provenance() -> None:
    """Spec must define provenance requirements."""
    if not SPEC.is_file():
        _check("spec_provenance", False, "spec missing")
        return
    text = SPEC.read_text().lower()
    keywords = ["sha-256", "correlation id", "environment", "timestamp"]
    for kw in keywords:
        _check(f"spec_provenance:{kw}", kw in text, f"provenance: {kw}")


def check_spec_packaging_formats() -> None:
    """Spec must define packaging formats with distribution channels."""
    if not SPEC.is_file():
        _check("spec_packaging", False, "spec missing")
        return
    text = SPEC.read_text().lower()
    formats = ["npm", "docker", "binary"]
    for fmt in formats:
        _check(f"spec_format:{fmt}", fmt in text, f"format: {fmt}")


def check_spec_tracking_channels() -> None:
    """Spec must define at least 6 tracking channels."""
    if not SPEC.is_file():
        _check("spec_tracking_channels", False, "spec missing")
        return
    text = SPEC.read_text().lower()
    channels = ["npm downloads", "docker pulls", "github stars", "github forks", "citations", "usage reports"]
    for ch in channels:
        _check(f"spec_channel:{ch}", ch in text, f"channel: {ch}")


def check_spec_report_schema() -> None:
    """Spec must define external usage report schema."""
    if not SPEC.is_file():
        _check("spec_report_schema", False, "spec missing")
        return
    text = SPEC.read_text().lower()
    fields = ["download_counts", "known_external_users", "citations", "usage_tier", "tracking_channels_active"]
    for field in fields:
        _check(f"spec_report_field:{field}", field in text, f"report field: {field}")


# ---------------------------------------------------------------------------
# Policy content checks
# ---------------------------------------------------------------------------

def check_policy_event_codes() -> None:
    """Policy must reference all four BVE event codes."""
    if not POLICY.is_file():
        _check("policy_event_codes", False, "policy missing")
        return
    text = POLICY.read_text()
    for code in EVENT_CODES:
        _check(f"policy_event_code:{code}", code in text, code)


def check_policy_invariants() -> None:
    """Policy must reference all four INV-BVE invariants."""
    if not POLICY.is_file():
        _check("policy_invariants", False, "policy missing")
        return
    text = POLICY.read_text()
    for inv in INVARIANTS:
        _check(f"policy_invariant:{inv}", inv in text, inv)


def check_policy_adoption_tiers() -> None:
    """Policy must define all five adoption tiers."""
    if not POLICY.is_file():
        _check("policy_adoption_tiers", False, "policy missing")
        return
    text = POLICY.read_text()
    for tier in ADOPTION_TIERS:
        _check(f"policy_tier:{tier}", tier in text, tier)


def check_policy_metric_definitions() -> None:
    """Policy must define all six metric dimensions."""
    if not POLICY.is_file():
        _check("policy_metric_definitions", False, "policy missing")
        return
    text = POLICY.read_text().lower()
    dimensions = [
        "external project adoption",
        "external validation parties",
        "external citations",
        "packaging formats",
        "getting started time",
        "tracking channels",
    ]
    for dim in dimensions:
        _check(f"policy_dimension:{dim}", dim in text, dim)


def check_policy_sybil_defense() -> None:
    """Policy must define Sybil defense measures."""
    if not POLICY.is_file():
        _check("policy_sybil_defense", False, "policy missing")
        return
    text = POLICY.read_text().lower()
    keywords = ["sybil", "verifiable identit", "manual review"]
    for kw in keywords:
        _check(f"policy_sybil:{kw}", kw in text, f"sybil defense: {kw}")


def check_policy_ci_integration() -> None:
    """Policy must define CI integration with --json flag."""
    if not POLICY.is_file():
        _check("policy_ci_integration", False, "policy missing")
        return
    text = POLICY.read_text()
    _check("policy_ci:json_flag", "--json" in text, "CI --json flag")
    _check("policy_ci:exit_code", "exit code" in text.lower(), "CI exit code")


def check_policy_escalation() -> None:
    """Policy must define escalation procedures."""
    if not POLICY.is_file():
        _check("policy_escalation", False, "policy missing")
        return
    text = POLICY.read_text().lower()
    keywords = ["escalation", "block release", "investigate"]
    for kw in keywords:
        _check(f"policy_escalation:{kw}", kw in text, f"escalation: {kw}")


def check_policy_provenance() -> None:
    """Policy must define provenance requirements."""
    if not POLICY.is_file():
        _check("policy_provenance", False, "policy missing")
        return
    text = POLICY.read_text().lower()
    keywords = ["sha-256", "correlation id", "environment fingerprint", "timestamp"]
    for kw in keywords:
        _check(f"policy_provenance:{kw}", kw in text, f"provenance: {kw}")


def check_policy_risk_impact() -> None:
    """Policy must define risk and impact sections."""
    if not POLICY.is_file():
        _check("policy_risk_impact", False, "policy missing")
        return
    text = POLICY.read_text().lower()
    _check("policy_section:risk", "## risk" in text, "risk section")
    _check("policy_section:impact", "## impact" in text, "impact section")


def check_policy_monitoring() -> None:
    """Policy must define monitoring and alerting."""
    if not POLICY.is_file():
        _check("policy_monitoring", False, "policy missing")
        return
    text = POLICY.read_text().lower()
    keywords = ["dashboard", "alert", "weekly"]
    for kw in keywords:
        _check(f"policy_monitoring:{kw}", kw in text, f"monitoring: {kw}")


# ---------------------------------------------------------------------------
# Evidence artifact checks
# ---------------------------------------------------------------------------

def check_evidence_artifacts() -> None:
    """Evidence directory must contain verification_evidence.json and summary."""
    ev_dir = ROOT / "artifacts" / "section_13" / "bd-3e74"
    ev_json = ev_dir / "verification_evidence.json"
    ev_md = ev_dir / "verification_summary.md"
    _check("evidence:json", ev_json.is_file(), f"evidence.json at {_safe_rel(ev_json)}")
    _check("evidence:summary", ev_md.is_file(), f"summary.md at {_safe_rel(ev_md)}")


# ---------------------------------------------------------------------------
# Helpers: validate_external_metrics and metrics_to_tier
# ---------------------------------------------------------------------------

def validate_external_metrics(metrics: dict[str, Any]) -> list[str]:
    """Validate a metrics dict against the required dimensions.

    Returns a list of error strings. Empty list means valid.
    """
    errors: list[str] = []
    required_keys = list(METRIC_TARGETS.keys())
    for key in required_keys:
        if key not in metrics:
            errors.append(f"missing metric: {key}")
        elif not isinstance(metrics[key], (int, float)):
            errors.append(f"non-numeric value for {key}: {metrics[key]}")
    return errors


def metrics_to_tier(metrics: dict[str, Any]) -> str:
    """Map a metrics dict to an adoption tier string (U0-U4).

    Returns the highest tier whose criteria are fully met.
    Tiers are evaluated from highest to lowest.
    """
    adoption = metrics.get("external_project_adoption", 0)
    validation = metrics.get("external_validation_parties", 0)
    citations = metrics.get("external_citations", 0)

    # U4: >= 1 external citation
    if adoption >= 3 and validation >= 2 and citations >= 1:
        return "U4"
    # U3: >= 3 external projects adopt
    if adoption >= 3:
        return "U3"
    # U2: >= 2 external validation parties
    if validation >= 2:
        return "U2"
    # U1: >= 1 external user, < 3 project adoptions
    if adoption >= 1:
        return "U1"
    # U0: No external usage
    return "U0"


# ---------------------------------------------------------------------------
# ALL_CHECKS list
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_adoption_tiers,
    check_spec_quantitative_targets,
    check_spec_metric_dimensions,
    check_spec_gate_thresholds,
    check_spec_provenance,
    check_spec_packaging_formats,
    check_spec_tracking_channels,
    check_spec_report_schema,
    check_policy_event_codes,
    check_policy_invariants,
    check_policy_adoption_tiers,
    check_policy_metric_definitions,
    check_policy_sybil_defense,
    check_policy_ci_integration,
    check_policy_escalation,
    check_policy_provenance,
    check_policy_risk_impact,
    check_policy_monitoring,
    check_evidence_artifacts,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    global RESULTS
    RESULTS = []
    for fn in ALL_CHECKS:
        fn()
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    return {
        "bead_id": "bd-3e74",
        "title": "benchmark/verifier external usage",
        "section": "13",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test() -> bool:
    report = run_all()
    total, passed, failed = report["total"], report["passed"], report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Verify bd-3e74: benchmark/verifier external usage")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
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
