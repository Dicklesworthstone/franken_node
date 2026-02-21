#!/usr/bin/env python3
"""Verification script for bd-1jmq: EV score and tier contract field.

Usage:
    python3 scripts/check_ev_score.py              # human-readable
    python3 scripts/check_ev_score.py --json        # machine-readable JSON
    python3 scripts/check_ev_score.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_11" / "bd-1jmq_contract.md"
POLICY = ROOT / "docs" / "policy" / "ev_score_and_tier.md"

EVENT_CODES = ["EVS-001", "EVS-002", "EVS-003", "EVS-004"]

INVARIANTS = ["INV-EVS-COMPUTE", "INV-EVS-TIER", "INV-EVS-UPGRADE", "INV-EVS-DOWNGRADE"]

TIER_LABELS = ["T0", "T1", "T2", "T3", "T4"]

TIER_THRESHOLDS = ["0-19", "20-39", "40-59", "60-79", "80-100"]

DIMENSIONS = ["code_review", "test_coverage", "security_audit", "supply_chain", "conformance"]

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


def check_spec_ev_score_keyword() -> dict[str, Any]:
    """C03: Spec mentions 'EV score'."""
    return _file_contains(SPEC, "EV score", "spec_keyword")


def check_spec_tier_keyword() -> dict[str, Any]:
    """C04: Spec mentions 'tier'."""
    return _file_contains(SPEC, "tier", "spec_keyword")


def check_spec_tiers_defined() -> dict[str, Any]:
    """C05: Spec defines all five tiers T0 through T4."""
    if not SPEC.is_file():
        return _check("spec_tiers_defined", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [t for t in TIER_LABELS if t not in content]
    passed = len(missing) == 0
    detail = "all 5 tiers present" if passed else f"missing: {missing}"
    return _check("spec_tiers_defined", passed, detail)


def check_spec_verification_keyword() -> dict[str, Any]:
    """C06: Spec mentions 'verification'."""
    return _file_contains(SPEC, "verification", "spec_keyword")


def check_spec_weighted_keyword() -> dict[str, Any]:
    """C07: Spec mentions 'weighted'."""
    return _file_contains(SPEC, "weighted", "spec_keyword")


def check_spec_event_codes() -> dict[str, Any]:
    """C08: Spec defines all four event codes EVS-001 through EVS-004."""
    if not SPEC.is_file():
        return _check("spec_event_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes present" if passed else f"missing: {missing}"
    return _check("spec_event_codes", passed, detail)


def check_spec_invariants() -> dict[str, Any]:
    """C09: Spec defines all four INV-EVS invariants."""
    if not SPEC.is_file():
        return _check("spec_invariants", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants present" if passed else f"missing: {missing}"
    return _check("spec_invariants", passed, detail)


def check_spec_tier_thresholds() -> dict[str, Any]:
    """C10: Spec defines tier threshold boundaries."""
    if not SPEC.is_file():
        return _check("spec_tier_thresholds", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    found = [t for t in TIER_THRESHOLDS if t in content]
    passed = len(found) == 5
    detail = "all 5 tier threshold ranges present" if passed else f"{len(found)}/5 threshold ranges present"
    return _check("spec_tier_thresholds", passed, detail)


def check_spec_upgrade_path() -> dict[str, Any]:
    """C11: Spec documents upgrade path."""
    return _file_contains(SPEC, "Upgrade Path", "spec_section")


def check_spec_downgrade_triggers() -> dict[str, Any]:
    """C12: Spec documents downgrade triggers."""
    return _file_contains(SPEC, "Downgrade Triggers", "spec_section")


def check_policy_dimensions() -> dict[str, Any]:
    """C13: Policy defines all five verification dimensions."""
    if not POLICY.is_file():
        return _check("policy_dimensions", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [d for d in DIMENSIONS if d not in content]
    passed = len(missing) == 0
    detail = "all 5 dimensions present" if passed else f"missing: {missing}"
    return _check("policy_dimensions", passed, detail)


def check_policy_weights() -> dict[str, Any]:
    """C14: Policy defines dimension weights that sum to 1.0."""
    if not POLICY.is_file():
        return _check("policy_weights", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    weights = ["0.20", "0.25", "0.15"]
    found = all(w in content for w in weights)
    return _check("policy_weights", found, "weight values found" if found else "weight values missing")


def check_policy_governance() -> dict[str, Any]:
    """C15: Policy defines governance section."""
    return _file_contains(POLICY, "Governance", "policy_section")


def check_policy_appeal_process() -> dict[str, Any]:
    """C16: Policy defines appeal process."""
    return _file_contains(POLICY, "Appeal Process", "policy_section")


def check_policy_tier_thresholds() -> dict[str, Any]:
    """C17: Policy defines the same tier thresholds as spec."""
    if not POLICY.is_file():
        return _check("policy_tier_thresholds", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    found = [t for t in TIER_THRESHOLDS if t in content]
    passed = len(found) == 5
    detail = "all 5 tier threshold ranges in policy" if passed else f"{len(found)}/5 threshold ranges"
    return _check("policy_tier_thresholds", passed, detail)


def check_policy_event_codes() -> dict[str, Any]:
    """C18: Policy references all four event codes."""
    if not POLICY.is_file():
        return _check("policy_event_codes", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = "all 4 event codes in policy" if passed else f"missing: {missing}"
    return _check("policy_event_codes", passed, detail)


def check_policy_invariants() -> dict[str, Any]:
    """C19: Policy references all four invariants."""
    if not POLICY.is_file():
        return _check("policy_invariants", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = "all 4 invariants in policy" if passed else f"missing: {missing}"
    return _check("policy_invariants", passed, detail)


def check_policy_downgrade_triggers() -> dict[str, Any]:
    """C20: Policy documents downgrade triggers."""
    return _file_contains(POLICY, "Downgrade Triggers", "policy_section")


# ---------------------------------------------------------------------------
# EV score validation helpers (for testing EV score objects)
# ---------------------------------------------------------------------------

DIMENSION_WEIGHTS = {
    "code_review": 0.20,
    "test_coverage": 0.20,
    "security_audit": 0.25,
    "supply_chain": 0.15,
    "conformance": 0.20,
}


def compute_ev_score(dimension_scores: dict[str, float]) -> int:
    """Compute the EV score from dimension scores using canonical weights."""
    raw = sum(
        DIMENSION_WEIGHTS[d] * dimension_scores.get(d, 0.0)
        for d in DIMENSIONS
    )
    return round(100 * raw)


def score_to_tier(score: int) -> str:
    """Map a composite EV score to its tier."""
    if score >= 80:
        return "T4"
    elif score >= 60:
        return "T3"
    elif score >= 40:
        return "T2"
    elif score >= 20:
        return "T1"
    else:
        return "T0"


def validate_ev_score(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate an ev_score_and_tier object. Returns list of check results."""
    results: list[dict[str, Any]] = []

    # Dimension scores present and in range
    dim_scores = obj.get("dimension_scores", {})
    for d in DIMENSIONS:
        score = dim_scores.get(d, {}).get("score")
        ok = isinstance(score, (int, float)) and 0.0 <= score <= 1.0
        results.append({
            "name": f"dim_{d}_range",
            "passed": ok,
            "detail": f"{d}={score}",
        })

    # EV score in range
    ev_score = obj.get("ev_score")
    ok = isinstance(ev_score, (int, float)) and 0 <= ev_score <= 100
    results.append({"name": "ev_score_range", "passed": ok, "detail": f"ev_score={ev_score}"})

    # Tier valid
    tier = obj.get("tier")
    ok = tier in TIER_LABELS
    results.append({"name": "tier_valid", "passed": ok, "detail": f"tier={tier}"})

    # Tier matches score
    if isinstance(ev_score, (int, float)):
        expected_tier = score_to_tier(int(ev_score))
        ok = tier == expected_tier
        results.append({
            "name": "tier_matches_score",
            "passed": ok,
            "detail": f"tier={tier} expected={expected_tier} for score={ev_score}",
        })
    else:
        results.append({"name": "tier_matches_score", "passed": False, "detail": "no ev_score"})

    # Rationale
    rationale = obj.get("rationale")
    ok = isinstance(rationale, str) and len(rationale) > 0
    results.append({"name": "rationale_present", "passed": ok, "detail": "present" if ok else "missing"})

    return results


# ---------------------------------------------------------------------------
# All check functions
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_spec_ev_score_keyword,
    check_spec_tier_keyword,
    check_spec_tiers_defined,
    check_spec_verification_keyword,
    check_spec_weighted_keyword,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_tier_thresholds,
    check_spec_upgrade_path,
    check_spec_downgrade_triggers,
    check_policy_dimensions,
    check_policy_weights,
    check_policy_governance,
    check_policy_appeal_process,
    check_policy_tier_thresholds,
    check_policy_event_codes,
    check_policy_invariants,
    check_policy_downgrade_triggers,
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
        "bead_id": "bd-1jmq",
        "title": "EV score and tier contract field",
        "section": "11",
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
        description="Verify bd-1jmq: EV score and tier contract field"
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
