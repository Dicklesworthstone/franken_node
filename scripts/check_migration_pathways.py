#!/usr/bin/env python3
"""Verification script for bd-2f43: Low-Risk Migration Pathways.

Validates that the migration-pathway success criterion is fully specified,
that risk-scoring thresholds are quantitative, that rollout stages and
rollback safety are defined, and that all event codes and invariants are
present.

Usage:
    python scripts/check_migration_pathways.py          # human-readable
    python scripts/check_migration_pathways.py --json   # machine-readable
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

BEAD_ID = "bd-2f43"

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"name": name, "passed": passed, "detail": detail})


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_spec_exists() -> None:
    """Spec contract file must exist."""
    spec = ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
    _check(
        "spec_exists",
        spec.is_file(),
        f"Spec file {'found' if spec.is_file() else 'MISSING'}: {spec.relative_to(ROOT)}",
    )


def check_policy_exists() -> None:
    """Policy document must exist."""
    pol = ROOT / "docs" / "policy" / "migration_pathways.md"
    _check(
        "policy_exists",
        pol.is_file(),
        f"Policy file {'found' if pol.is_file() else 'MISSING'}: {pol.relative_to(ROOT)}",
    )


def check_quantitative_targets() -> None:
    """Spec must contain all four quantitative targets with concrete numbers."""
    spec = ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
    if not spec.is_file():
        _check("quantitative_targets", False, "Spec file missing")
        return
    text = spec.read_text()
    targets = {
        "success_rate_90": r">=?\s*90\s*%",
        "rollback_time_5min": r"<\s*5\s*min",
        "zero_data_loss": r"[Zz]ero.{0,5}data.{0,5}loss",
        "risk_threshold_030": r"<=?\s*0\.30",
    }
    missing = []
    for label, pattern in targets.items():
        if not re.search(pattern, text):
            missing.append(label)
    passed = len(missing) == 0
    detail = "All targets present" if passed else f"Missing targets: {', '.join(missing)}"
    _check("quantitative_targets", passed, detail)


def check_pathway_requirements() -> None:
    """Spec must define all four pathway requirements."""
    spec = ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
    if not spec.is_file():
        _check("pathway_requirements", False, "Spec file missing")
        return
    text = spec.read_text()
    requirements = [
        "Automated Analysis",
        "Risk Scoring",
        "Staged Rollout",
        "Rollback Safety",
    ]
    missing = [r for r in requirements if r not in text]
    passed = len(missing) == 0
    detail = "All requirements present" if passed else f"Missing: {', '.join(missing)}"
    _check("pathway_requirements", passed, detail)


def check_risk_scoring() -> None:
    """Policy must define three risk sub-dimensions with weights summing to 1.0."""
    pol = ROOT / "docs" / "policy" / "migration_pathways.md"
    if not pol.is_file():
        _check("risk_scoring", False, "Policy file missing")
        return
    text = pol.read_text()
    dimensions = ["Compatibility Risk", "Dependency Risk", "Operational Risk"]
    weights = [0.40, 0.35, 0.25]
    found_dims = [d for d in dimensions if d.lower().replace(" ", "") in text.lower().replace(" ", "")]
    weight_sum_ok = all(f"{w}" in text for w in weights)
    passed = len(found_dims) == 3 and weight_sum_ok
    detail = (
        f"Dimensions: {len(found_dims)}/3, weights present: {weight_sum_ok}"
    )
    _check("risk_scoring", passed, detail)


def check_rollout_stages() -> None:
    """Policy must define canary, progressive, and full stages."""
    pol = ROOT / "docs" / "policy" / "migration_pathways.md"
    if not pol.is_file():
        _check("rollout_stages", False, "Policy file missing")
        return
    text = pol.read_text().lower()
    stages = ["canary", "progressive", "full"]
    found = [s for s in stages if s in text]
    passed = len(found) == 3
    detail = f"Stages found: {', '.join(found)}" if found else "No stages found"
    _check("rollout_stages", passed, detail)


def check_rollback_requirements() -> None:
    """Policy must specify rollback time < 5 min and zero-data-loss."""
    pol = ROOT / "docs" / "policy" / "migration_pathways.md"
    if not pol.is_file():
        _check("rollback_requirements", False, "Policy file missing")
        return
    text = pol.read_text()
    has_time = bool(re.search(r"[<Uu]nder\s*5\s*min|<\s*5\s*min", text))
    has_zero_loss = bool(re.search(r"[Zz]ero.{0,10}[Dd]ata.{0,10}[Ll]oss", text))
    passed = has_time and has_zero_loss
    detail = f"Time constraint: {has_time}, zero-loss: {has_zero_loss}"
    _check("rollback_requirements", passed, detail)


def check_event_codes() -> None:
    """Spec must define MIG-001 through MIG-004."""
    spec = ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
    if not spec.is_file():
        _check("event_codes", False, "Spec file missing")
        return
    text = spec.read_text()
    codes = ["MIG-001", "MIG-002", "MIG-003", "MIG-004"]
    missing = [c for c in codes if c not in text]
    passed = len(missing) == 0
    detail = "All event codes present" if passed else f"Missing: {', '.join(missing)}"
    _check("event_codes", passed, detail)


def check_invariants() -> None:
    """Spec must define all four invariants."""
    spec = ROOT / "docs" / "specs" / "section_13" / "bd-2f43_contract.md"
    if not spec.is_file():
        _check("invariants", False, "Spec file missing")
        return
    text = spec.read_text()
    invariants = [
        "INV-MIG-PATHWAY",
        "INV-MIG-RISK",
        "INV-MIG-ROLLBACK",
        "INV-MIG-EVIDENCE",
    ]
    missing = [inv for inv in invariants if inv not in text]
    passed = len(missing) == 0
    detail = "All invariants present" if passed else f"Missing: {', '.join(missing)}"
    _check("invariants", passed, detail)


def check_evidence_artifacts() -> None:
    """Evidence directory must contain verification_evidence.json and summary."""
    ev_dir = ROOT / "artifacts" / "section_13" / "bd-2f43"
    ev_json = ev_dir / "verification_evidence.json"
    ev_md = ev_dir / "verification_summary.md"
    json_ok = ev_json.is_file()
    md_ok = ev_md.is_file()
    passed = json_ok and md_ok
    detail = f"evidence.json: {json_ok}, summary.md: {md_ok}"
    _check("evidence_artifacts", passed, detail)


def check_cohort_strategy() -> None:
    """Policy must reference Node and Bun cohorts."""
    pol = ROOT / "docs" / "policy" / "migration_pathways.md"
    if not pol.is_file():
        _check("cohort_strategy", False, "Policy file missing")
        return
    text = pol.read_text()
    has_node = "Node" in text or "node" in text
    has_bun = "Bun" in text or "bun" in text
    passed = has_node and has_bun
    detail = f"Node referenced: {has_node}, Bun referenced: {has_bun}"
    _check("cohort_strategy", passed, detail)


def check_ci_gate() -> None:
    """Policy must define a CI gate section."""
    pol = ROOT / "docs" / "policy" / "migration_pathways.md"
    if not pol.is_file():
        _check("ci_gate", False, "Policy file missing")
        return
    text = pol.read_text()
    has_gate = "CI Gate" in text or "ci gate" in text.lower()
    has_json_flag = "--json" in text
    passed = has_gate and has_json_flag
    detail = f"CI gate section: {has_gate}, --json flag: {has_json_flag}"
    _check("ci_gate", passed, detail)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_quantitative_targets,
    check_pathway_requirements,
    check_risk_scoring,
    check_rollout_stages,
    check_rollback_requirements,
    check_event_codes,
    check_invariants,
    check_evidence_artifacts,
    check_cohort_strategy,
    check_ci_gate,
]


def run_all() -> dict:
    """Execute every check and return a summary dict."""
    RESULTS.clear()
    for fn in ALL_CHECKS:
        fn()
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["passed"])
    return {
        "bead_id": BEAD_ID,
        "section": "13",
        "title": "Low-Risk Migration Pathways",
        "total_checks": total,
        "passed": passed,
        "failed": total - passed,
        "overall_passed": passed == total,
        "checks": RESULTS,
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test() -> None:
    """Smoke test the verification machinery itself."""
    RESULTS.clear()
    _check("self_test_true", True, "always passes")
    _check("self_test_false", False, "always fails")
    _expect(len(RESULTS) == 2, "self_test expected two synthetic checks")
    _expect(bool(RESULTS[0]["passed"]), "self_test true check did not pass")
    _expect(not bool(RESULTS[1]["passed"]), "self_test false check did not fail")
    RESULTS.clear()

    result = run_all()
    _expect(result["bead_id"] == BEAD_ID, "self_test bead id mismatch")
    _expect(result["total_checks"] == len(ALL_CHECKS), "self_test check count mismatch")
    _expect(
        result["passed"] + result["failed"] == result["total_checks"],
        "self_test summary counts do not add up",
    )
    _expect(isinstance(result["overall_passed"], bool), "self_test overall_passed is not bool")
    _expect(isinstance(result["checks"], list), "self_test checks is not a list")
    for check in result["checks"]:
        _expect("name" in check, f"self_test check missing name: {check!r}")
        _expect("passed" in check, f"self_test check missing passed: {check!r}")
        _expect("detail" in check, f"self_test check missing detail: {check!r}")
    print("self_test: ALL PASSED")


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

def main() -> None:
    configure_test_logging("check_migration_pathways")
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-2f43 Migration Pathways — {result['passed']}/{result['total_checks']} checks passed")
        print("=" * 60)
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['name']}: {c['detail']}")
        print("=" * 60)
        overall = "PASSED" if result["overall_passed"] else "FAILED"
        print(f"Overall: {overall}")

    sys.exit(0 if result["overall_passed"] else 1)


if __name__ == "__main__":
    main()
