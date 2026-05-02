#!/usr/bin/env python3
"""Verification script for bd-38ri: Risk Control — Scope Explosion.

Checks that the risk control artefacts for the Scope Explosion risk
are present, complete, and internally consistent.

Usage:
    python scripts/check_scope_explosion.py          # human-readable
    python scripts/check_scope_explosion.py --json    # machine-readable
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"name": name, "passed": passed, "detail": detail})


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_json(path: Path) -> dict:
    return json.JSONDecoder().decode(_read_text(path))


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_spec_exists() -> None:
    p = ROOT / "docs" / "specs" / "section_12" / "bd-38ri_contract.md"
    _check("spec_exists", p.is_file(), f"Spec file {'found' if p.is_file() else 'MISSING'}: {p}")


def check_risk_policy_exists() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    _check("risk_policy_exists", p.is_file(), f"Risk policy {'found' if p.is_file() else 'MISSING'}: {p}")


def check_risk_documented() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    if not p.is_file():
        _check("risk_documented", False, "Risk policy file missing")
        return
    text = _read_text(p)
    has_description = "Scope Explosion" in text
    has_impact = "Impact" in text
    has_likelihood = "Likelihood" in text
    ok = has_description and has_impact and has_likelihood
    _check("risk_documented", ok, "Risk description, impact, and likelihood documented" if ok else "Missing risk documentation sections")


def check_capability_gates() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    if not p.is_file():
        _check("capability_gates", False, "Risk policy file missing")
        return
    text = _read_text(p)
    has_cap_gates = "capability gate" in text.lower() or "Capability Gate" in text
    has_max = "maximum capability count" in text.lower() or "max" in text.lower()
    has_approval = "approval" in text.lower()
    ok = has_cap_gates and has_max and has_approval
    _check("capability_gates", ok, "Capability gates documented with limits and approval" if ok else "Capability gate documentation incomplete")


def check_artifact_gates() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    if not p.is_file():
        _check("artifact_gates", False, "Risk policy file missing")
        return
    text = _read_text(p)
    has_artifact = "artifact-gated" in text.lower() or "Artifact-Gated" in text
    has_chain = "artifact chain" in text.lower()
    has_six = "verification_evidence" in text and "verification_summary" in text
    ok = has_artifact and has_chain and has_six
    _check("artifact_gates", ok, "Artifact-gated delivery documented with full chain" if ok else "Artifact gate documentation incomplete")


def check_scope_budgets() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    if not p.is_file():
        _check("scope_budgets", False, "Risk policy file missing")
        return
    text = _read_text(p)
    has_budget = "scope budget" in text.lower() or "bead count limit" in text.lower() or "per-track" in text.lower()
    has_80 = "80%" in text
    has_95 = "95%" in text
    ok = has_budget and has_80 and has_95
    _check("scope_budgets", ok, "Scope budgets documented with 80% and 95% thresholds" if ok else "Scope budget documentation incomplete")


def check_countermeasures() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    if not p.is_file():
        _check("countermeasures", False, "Risk policy file missing")
        return
    text = _read_text(p)
    has_cap = "capability gate" in text.lower()
    has_artifact = "artifact-gated" in text.lower()
    has_budget = "scope budget" in text.lower() or "bead count" in text.lower()
    has_monitoring = "monitoring" in text.lower() or "dashboard" in text.lower()
    ok = has_cap and has_artifact and has_budget and has_monitoring
    _check("countermeasures", ok, "All countermeasures documented" if ok else "Missing countermeasure documentation")


def check_event_codes() -> None:
    p = ROOT / "docs" / "specs" / "section_12" / "bd-38ri_contract.md"
    if not p.is_file():
        _check("event_codes", False, "Spec file missing")
        return
    text = _read_text(p)
    codes = ["RSE-001", "RSE-002", "RSE-003", "RSE-004"]
    missing = [c for c in codes if c not in text]
    ok = len(missing) == 0
    _check("event_codes", ok, "All event codes present" if ok else f"Missing event codes: {missing}")


def check_invariants() -> None:
    p = ROOT / "docs" / "specs" / "section_12" / "bd-38ri_contract.md"
    if not p.is_file():
        _check("invariants", False, "Spec file missing")
        return
    text = _read_text(p)
    invariants = ["INV-RSE-GATE", "INV-RSE-BUDGET", "INV-RSE-ARTIFACT", "INV-RSE-TRACK"]
    missing = [i for i in invariants if i not in text]
    ok = len(missing) == 0
    _check("invariants", ok, "All invariants present" if ok else f"Missing invariants: {missing}")


def check_spec_keywords() -> None:
    p = ROOT / "docs" / "specs" / "section_12" / "bd-38ri_contract.md"
    if not p.is_file():
        _check("spec_keywords", False, "Spec file missing")
        return
    text = _read_text(p)
    keywords = ["Scope Explosion", "capability gate", "artifact-gated", "scope budget", "bd-38ri"]
    missing = [k for k in keywords if k.lower() not in text.lower()]
    ok = len(missing) == 0
    _check("spec_keywords", ok, "All spec keywords present" if ok else f"Missing keywords: {missing}")


def check_escalation() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    if not p.is_file():
        _check("escalation", False, "Risk policy file missing")
        return
    text = _read_text(p)
    ok = "escalation" in text.lower() or "Escalation" in text
    _check("escalation", ok, "Escalation procedures documented" if ok else "Escalation procedures missing")


def check_evidence_requirements() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    if not p.is_file():
        _check("evidence_requirements", False, "Risk policy file missing")
        return
    text = _read_text(p)
    ok = "evidence" in text.lower() and "review" in text.lower()
    _check("evidence_requirements", ok, "Evidence requirements for review documented" if ok else "Evidence requirements missing")


def check_monitoring() -> None:
    p = ROOT / "docs" / "policy" / "risk_scope_explosion.md"
    if not p.is_file():
        _check("monitoring", False, "Risk policy file missing")
        return
    text = _read_text(p)
    has_dashboard = "dashboard" in text.lower()
    has_velocity = "velocity" in text.lower()
    ok = has_dashboard and has_velocity
    _check("monitoring", ok, "Monitoring with dashboards and velocity metrics documented" if ok else "Monitoring documentation incomplete")


def check_verification_evidence() -> None:
    p = ROOT / "artifacts" / "section_12" / "bd-38ri" / "verification_evidence.json"
    if not p.is_file():
        _check("verification_evidence", False, f"Evidence file MISSING: {p}")
        return
    try:
        data = _read_json(p)
        ok = isinstance(data, dict) and data.get("bead_id") == "bd-38ri" and data.get("status") == "pass"
        _check("verification_evidence", ok, "Evidence file valid" if ok else "Evidence file has incorrect bead_id or status")
    except (json.JSONDecodeError, OSError) as exc:
        _check("verification_evidence", False, f"Evidence file parse error: {exc}")


def check_verification_summary() -> None:
    p = ROOT / "artifacts" / "section_12" / "bd-38ri" / "verification_summary.md"
    _check("verification_summary", p.is_file(), f"Summary file {'found' if p.is_file() else 'MISSING'}: {p}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_risk_policy_exists,
    check_risk_documented,
    check_capability_gates,
    check_artifact_gates,
    check_scope_budgets,
    check_countermeasures,
    check_event_codes,
    check_invariants,
    check_spec_keywords,
    check_escalation,
    check_evidence_requirements,
    check_monitoring,
    check_verification_evidence,
    check_verification_summary,
]


def run_all() -> dict:
    RESULTS.clear()
    for fn in ALL_CHECKS:
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    total = len(RESULTS)
    return {
        "bead_id": "bd-38ri",
        "section": "12",
        "title": "Risk Control — Scope Explosion",
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
        "checks": list(RESULTS),
    }


def self_test() -> None:
    """Smoke-test: run all checks and assert the structure is valid."""
    result = run_all()
    if not isinstance(result, dict):
        raise RuntimeError("self-test result must be a dict")
    if result["bead_id"] != "bd-38ri":
        raise RuntimeError("self-test bead_id mismatch")
    if result["section"] != "12":
        raise RuntimeError("self-test section mismatch")
    if not isinstance(result["checks"], list):
        raise RuntimeError("self-test checks must be a list")
    if result["total"] != len(ALL_CHECKS):
        raise RuntimeError("self-test total must match ALL_CHECKS")
    if result["passed"] > result["total"]:
        raise RuntimeError("self-test passed count cannot exceed total")
    if not isinstance(result["all_passed"], bool):
        raise RuntimeError("self-test all_passed must be bool")
    for check in result["checks"]:
        if "name" not in check:
            raise RuntimeError("self-test check missing name")
        if "passed" not in check:
            raise RuntimeError("self-test check missing passed")
        if "detail" not in check:
            raise RuntimeError("self-test check missing detail")
    print("self_test passed")


def main() -> None:
    configure_test_logging("check_scope_explosion")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("bd-38ri: Risk Control — Scope Explosion")
        print(f"{'=' * 55}")
        for check in result["checks"]:
            mark = "PASS" if check["passed"] else "FAIL"
            print(f"  [{mark}] {check['name']}: {check['detail']}")
        print(f"\n  {result['passed']}/{result['total']} checks passed")
        if not result["all_passed"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
