#!/usr/bin/env python3
"""Verification script for bd-13yn: signal poisoning and Sybil risk control.

Checks that the risk control artefacts for Signal Poisoning and Sybil
attacks are present, complete, and internally consistent.

Usage:
    python3 scripts/check_signal_sybil.py            # human-readable
    python3 scripts/check_signal_sybil.py --json      # machine-readable
    python3 scripts/check_signal_sybil.py --self-test  # smoke-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "specs" / "section_12" / "bd-13yn_contract.md"
POLICY = ROOT / "docs" / "policy" / "risk_signal_poisoning_sybil.md"

EVENT_CODES = ["SPS-001", "SPS-002", "SPS-003", "SPS-004"]
INVARIANTS = [
    "INV-SPS-AGGREGATION",
    "INV-SPS-STAKE",
    "INV-SPS-SYBIL",
    "INV-SPS-ADVERSARIAL",
]
ERROR_CODES = [
    "ERR_SPS_POISONED_SIGNAL",
    "ERR_SPS_SYBIL_DETECTED",
    "ERR_SPS_INSUFFICIENT_STAKE",
    "ERR_SPS_AGGREGATION_FAILED",
]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    s_path, s_root = str(path), str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_spec_exists() -> None:
    """Spec contract file must exist."""
    ok = SPEC.is_file()
    _check(
        "spec_exists",
        ok,
        f"found: {_safe_rel(SPEC)}" if ok else f"MISSING: {_safe_rel(SPEC)}",
    )


def check_policy_exists() -> None:
    """Risk policy file must exist."""
    ok = POLICY.is_file()
    _check(
        "policy_exists",
        ok,
        f"found: {_safe_rel(POLICY)}" if ok else f"MISSING: {_safe_rel(POLICY)}",
    )


def check_spec_bead_id() -> None:
    """Spec must reference bd-13yn."""
    if not SPEC.is_file():
        _check("spec_bead_id", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "bd-13yn" in text
    _check("spec_bead_id", ok, "found" if ok else "NOT FOUND")


def check_spec_section() -> None:
    """Spec must reference section 12."""
    if not SPEC.is_file():
        _check("spec_section_12", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "12" in text and ("Risk Control" in text or "Risk" in text)
    _check("spec_section_12", ok, "found" if ok else "NOT FOUND")


def check_spec_event_codes() -> None:
    """Spec must contain all event codes."""
    if not SPEC.is_file():
        for code in EVENT_CODES:
            _check(f"spec_event_code_{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"spec_event_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_spec_invariants() -> None:
    """Spec must contain all invariants."""
    if not SPEC.is_file():
        for inv in INVARIANTS:
            _check(f"spec_invariant_{inv}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"spec_invariant_{inv}", ok, "found" if ok else "NOT FOUND")


def check_spec_error_codes() -> None:
    """Spec must contain all error codes."""
    if not SPEC.is_file():
        for code in ERROR_CODES:
            _check(f"spec_error_code_{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in ERROR_CODES:
        ok = code in text
        _check(f"spec_error_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_spec_thresholds() -> None:
    """Spec must document quantitative thresholds."""
    if not SPEC.is_file():
        _check("spec_thresholds", False, "spec file missing")
        return
    text = SPEC.read_text()
    has_5pct = "5%" in text
    has_1pct = "1%" in text
    has_10_scenarios = "10" in text
    ok = has_5pct and has_1pct and has_10_scenarios
    _check(
        "spec_thresholds",
        ok,
        "5%, 1%, and 10-scenario thresholds present"
        if ok
        else "missing quantitative thresholds",
    )


def check_spec_countermeasures() -> None:
    """Spec must document all four countermeasures."""
    if not SPEC.is_file():
        _check("spec_countermeasures", False, "spec file missing")
        return
    text = SPEC.read_text().lower()
    has_aggregation = "robust aggregation" in text or "trimmed-mean" in text
    has_stake = "stake" in text and "weight" in text
    has_sybil = "sybil" in text and ("detection" in text or "resistance" in text)
    has_adversarial = "adversarial" in text and "test" in text
    ok = has_aggregation and has_stake and has_sybil and has_adversarial
    _check(
        "spec_countermeasures",
        ok,
        "all four countermeasures documented"
        if ok
        else "missing countermeasure documentation",
    )


def check_spec_acceptance_criteria() -> None:
    """Spec must have acceptance criteria."""
    if not SPEC.is_file():
        _check("spec_acceptance_criteria", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Acceptance Criteria" in text
    _check("spec_acceptance_criteria", ok, "found" if ok else "NOT FOUND")


def check_spec_test_scenarios() -> None:
    """Spec must have test scenarios."""
    if not SPEC.is_file():
        _check("spec_test_scenarios", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Test Scenario" in text or "Scenario" in text
    _check("spec_test_scenarios", ok, "found" if ok else "NOT FOUND")


def check_policy_risk_description() -> None:
    """Policy must document the risk description."""
    if not POLICY.is_file():
        _check("policy_risk_description", False, "policy file missing")
        return
    text = POLICY.read_text()
    has_desc = "Signal Poisoning" in text and "Sybil" in text
    has_section = "Risk Description" in text
    ok = has_desc and has_section
    _check(
        "policy_risk_description",
        ok,
        "risk description with signal poisoning and Sybil documented"
        if ok
        else "missing risk description",
    )


def check_policy_impact() -> None:
    """Policy must document impact assessment."""
    if not POLICY.is_file():
        _check("policy_impact", False, "policy file missing")
        return
    text = POLICY.read_text()
    ok = "Impact" in text and "Critical" in text
    _check("policy_impact", ok, "found" if ok else "NOT FOUND")


def check_policy_likelihood() -> None:
    """Policy must document likelihood assessment."""
    if not POLICY.is_file():
        _check("policy_likelihood", False, "policy file missing")
        return
    text = POLICY.read_text()
    ok = "Likelihood" in text and "High" in text
    _check("policy_likelihood", ok, "found" if ok else "NOT FOUND")


def check_policy_countermeasures() -> None:
    """Policy must document countermeasure details."""
    if not POLICY.is_file():
        _check("policy_countermeasures", False, "policy file missing")
        return
    text = POLICY.read_text()
    has_agg = "Robust Aggregation" in text
    has_stake = "Stake" in text
    has_sybil = "Sybil Detection" in text or "Sybil Resistance" in text
    has_adv = "Adversarial" in text
    ok = has_agg and has_stake and has_sybil and has_adv
    _check(
        "policy_countermeasures",
        ok,
        "all four countermeasures documented"
        if ok
        else "missing countermeasure documentation",
    )


def check_policy_escalation() -> None:
    """Policy must document escalation procedures."""
    if not POLICY.is_file():
        _check("policy_escalation", False, "policy file missing")
        return
    text = POLICY.read_text()
    ok = "Escalation" in text and "60 second" in text.lower()
    _check(
        "policy_escalation",
        ok,
        "escalation procedures with 60s SLA documented"
        if ok
        else "escalation procedures missing or incomplete",
    )


def check_policy_evidence_requirements() -> None:
    """Policy must document evidence requirements for review."""
    if not POLICY.is_file():
        _check("policy_evidence_requirements", False, "policy file missing")
        return
    text = POLICY.read_text()
    ok = "Evidence" in text and "review" in text.lower()
    _check(
        "policy_evidence_requirements",
        ok,
        "evidence requirements for review documented"
        if ok
        else "evidence requirements missing",
    )


def check_policy_thresholds() -> None:
    """Policy must document quantitative thresholds."""
    if not POLICY.is_file():
        _check("policy_thresholds", False, "policy file missing")
        return
    text = POLICY.read_text()
    has_5pct = "5%" in text
    has_1pct = "1%" in text
    has_60s = "60 second" in text.lower()
    ok = has_5pct and has_1pct and has_60s
    _check(
        "policy_thresholds",
        ok,
        "quantitative thresholds (5%, 1%, 60s) present"
        if ok
        else "missing quantitative thresholds",
    )


def check_policy_invariants() -> None:
    """Policy must reference all invariants."""
    if not POLICY.is_file():
        for inv in INVARIANTS:
            _check(f"policy_invariant_{inv}", False, "policy file missing")
        return
    text = POLICY.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"policy_invariant_{inv}", ok, "found" if ok else "NOT FOUND")


def check_policy_event_codes() -> None:
    """Policy must reference all event codes."""
    if not POLICY.is_file():
        for code in EVENT_CODES:
            _check(f"policy_event_code_{code}", False, "policy file missing")
        return
    text = POLICY.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"policy_event_code_{code}", ok, "found" if ok else "NOT FOUND")


def validate_signal_provenance() -> None:
    """Validate that signal provenance verification is documented."""
    if not POLICY.is_file():
        _check("signal_provenance_coverage", False, "policy file missing")
        return
    text = POLICY.read_text()
    # Signal provenance = robust aggregation + stake weighting = 100% coverage
    has_coverage = "100%" in text
    has_aggregation = "aggregation" in text.lower()
    ok = has_coverage and has_aggregation
    _check(
        "signal_provenance_coverage",
        ok,
        "signal provenance with 100% coverage documented"
        if ok
        else "signal provenance coverage incomplete",
    )


def validate_sybil_resistance() -> None:
    """Validate that Sybil resistance mechanisms are documented."""
    if not POLICY.is_file():
        _check("sybil_resistance_mechanisms", False, "policy file missing")
        return
    text = POLICY.read_text()
    has_detection = "detect" in text.lower() and "cluster" in text.lower()
    has_attenuation = "attenuate" in text.lower() or "attenuation" in text.lower()
    has_influence = "100" in text and "influence" in text.lower()
    ok = has_detection and has_attenuation and has_influence
    _check(
        "sybil_resistance_mechanisms",
        ok,
        "Sybil detection, attenuation, and influence limits documented"
        if ok
        else "Sybil resistance mechanisms incomplete",
    )


def check_verification_evidence() -> None:
    """Verification evidence artifact must exist and be valid."""
    p = ROOT / "artifacts" / "section_12" / "bd-13yn" / "verification_evidence.json"
    if not p.is_file():
        _check("verification_evidence", False, f"MISSING: {_safe_rel(p)}")
        return
    try:
        data = json.loads(p.read_text())
        ok = data.get("bead_id") == "bd-13yn" and data.get("status") == "pass"
        _check(
            "verification_evidence",
            ok,
            f"valid: {_safe_rel(p)}"
            if ok
            else "evidence has incorrect bead_id or status",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"parse error: {exc}")


def check_verification_summary() -> None:
    """Verification summary artifact must exist."""
    p = ROOT / "artifacts" / "section_12" / "bd-13yn" / "verification_summary.md"
    ok = p.is_file()
    _check(
        "verification_summary",
        ok,
        f"found: {_safe_rel(p)}" if ok else f"MISSING: {_safe_rel(p)}",
    )


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_spec_bead_id,
    check_spec_section,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_error_codes,
    check_spec_thresholds,
    check_spec_countermeasures,
    check_spec_acceptance_criteria,
    check_spec_test_scenarios,
    check_policy_risk_description,
    check_policy_impact,
    check_policy_likelihood,
    check_policy_countermeasures,
    check_policy_escalation,
    check_policy_evidence_requirements,
    check_policy_thresholds,
    check_policy_invariants,
    check_policy_event_codes,
    validate_signal_provenance,
    validate_sybil_resistance,
    check_verification_evidence,
    check_verification_summary,
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
        "bead_id": "bd-13yn",
        "title": "signal poisoning and Sybil risk control",
        "section": "12",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    report = run_all()
    total, passed, failed = report["total"], report["passed"], report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-13yn: signal poisoning and Sybil"
    )
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
        print(
            f"\n{report['passed']}/{report['total']} checks pass"
            f" (verdict={report['verdict']})"
        )
    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
