#!/usr/bin/env python3
"""Verification script for bd-kiqr: Risk Control — Trust-System Complexity.

Checks that the risk control artefacts for the Trust-System Complexity risk
are present, complete, and internally consistent.

Usage:
    python3 scripts/check_trust_complexity.py              # human-readable
    python3 scripts/check_trust_complexity.py --json        # machine-readable
    python3 scripts/check_trust_complexity.py --self-test   # smoke-test
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_12" / "bd-kiqr_contract.md"
POLICY = ROOT / "docs" / "policy" / "risk_trust_complexity.md"
EVIDENCE = ROOT / "artifacts" / "section_12" / "bd-kiqr" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_12" / "bd-kiqr" / "verification_summary.md"

EVENT_CODES = ["RTC-001", "RTC-002", "RTC-003", "RTC-004"]
INVARIANTS = ["INV-RTC-REPLAY", "INV-RTC-DEGRADED", "INV-RTC-BUDGET", "INV-RTC-AUDIT"]

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"name": name, "passed": passed, "detail": detail})


def _safe_rel(path: Path) -> str:
    """Return a display-friendly relative path, falling back to str(path)."""
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# -- Checks ------------------------------------------------------------------

def check_spec_exists() -> None:
    ok = SPEC.is_file()
    _check("spec_exists", ok,
           f"Spec file {'found' if ok else 'MISSING'}: {_safe_rel(SPEC)}")


def check_risk_policy_exists() -> None:
    ok = POLICY.is_file()
    _check("risk_policy_exists", ok,
           f"Risk policy {'found' if ok else 'MISSING'}: {_safe_rel(POLICY)}")


def check_risk_documented() -> None:
    if not POLICY.is_file():
        _check("risk_documented", False, "Risk policy file missing")
        return
    text = POLICY.read_text()
    ok = all(k in text for k in ["Trust-System Complexity", "Impact", "Likelihood"])
    _check("risk_documented", ok,
           "Risk description, impact, and likelihood documented" if ok else "Missing sections")


def check_replay_mechanism() -> None:
    if not POLICY.is_file():
        _check("replay_mechanism", False, "Risk policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "replay" in text and "deterministic" in text
    _check("replay_mechanism", ok,
           "Deterministic replay mechanism documented" if ok else "Replay mechanism missing")


def check_degraded_mode() -> None:
    if not POLICY.is_file():
        _check("degraded_mode", False, "Risk policy file missing")
        return
    text = POLICY.read_text()
    text_lower = text.lower()
    ok = "degraded" in text_lower and "300s" in text and "safe-mode" in text_lower
    _check("degraded_mode", ok,
           "Degraded-mode contract with duration and safe-mode documented" if ok else "Incomplete")


def check_complexity_budget() -> None:
    if not POLICY.is_file():
        _check("complexity_budget", False, "Risk policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "complexity budget" in text and "depth" in text
    _check("complexity_budget", ok,
           "Complexity budget with depth limits documented" if ok else "Missing budget")


def check_countermeasures() -> None:
    if not POLICY.is_file():
        _check("countermeasures", False, "Risk policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = all(k in text for k in ["replay", "degraded", "budget", "dashboard"])
    _check("countermeasures", ok,
           "All countermeasures documented" if ok else "Missing countermeasures")


def check_event_codes() -> None:
    if not SPEC.is_file():
        _check("event_codes", False, "Spec file missing")
        return
    text = SPEC.read_text()
    missing = [c for c in EVENT_CODES if c not in text]
    ok = len(missing) == 0
    _check("event_codes", ok,
           "All event codes present" if ok else f"Missing: {missing}")


def check_invariants() -> None:
    if not SPEC.is_file():
        _check("invariants", False, "Spec file missing")
        return
    text = SPEC.read_text()
    missing = [i for i in INVARIANTS if i not in text]
    ok = len(missing) == 0
    _check("invariants", ok,
           "All invariants present" if ok else f"Missing: {missing}")


def check_spec_keywords() -> None:
    if not SPEC.is_file():
        _check("spec_keywords", False, "Spec file missing")
        return
    text = SPEC.read_text().lower()
    keywords = ["complexity", "trust", "budget", "audit", "threshold"]
    missing = [k for k in keywords if k not in text]
    ok = len(missing) == 0
    _check("spec_keywords", ok,
           "All spec keywords present" if ok else f"Missing keywords: {missing}")


def check_threshold() -> None:
    if not SPEC.is_file():
        _check("threshold", False, "Spec file missing")
        return
    text = SPEC.read_text()
    ok = "replay divergence" in text.lower() and "0" in text
    _check("threshold", ok,
           "Zero-divergence threshold present" if ok else "Missing threshold")


def check_alert_pipeline() -> None:
    if not SPEC.is_file():
        _check("alert_pipeline", False, "Spec file missing")
        return
    text = SPEC.read_text().lower()
    ok = "alert" in text and ("pipeline" in text or "escalation" in text)
    _check("alert_pipeline", ok,
           "Alert pipeline documented" if ok else "Alert pipeline missing")


def check_escalation() -> None:
    if not POLICY.is_file():
        _check("escalation", False, "Risk policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "escalation" in text
    _check("escalation", ok,
           "Escalation procedures documented" if ok else "Missing escalation")


def check_evidence_requirements() -> None:
    if not POLICY.is_file():
        _check("evidence_requirements", False, "Risk policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "evidence" in text and "review" in text
    _check("evidence_requirements", ok,
           "Evidence requirements for review documented" if ok else "Missing evidence reqs")


def check_monitoring() -> None:
    if not POLICY.is_file():
        _check("monitoring", False, "Risk policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "dashboard" in text and "velocity" in text
    _check("monitoring", ok,
           "Monitoring with dashboards and velocity metrics documented" if ok else "Incomplete")


def check_verification_evidence() -> None:
    if not EVIDENCE.is_file():
        _check("verification_evidence", False,
               f"Evidence file MISSING: {_safe_rel(EVIDENCE)}")
        return
    try:
        data = json.loads(EVIDENCE.read_text())
        ok = data.get("bead_id") == "bd-kiqr" and data.get("status") == "pass"
        _check("verification_evidence", ok,
               "Evidence file valid" if ok else "Evidence has incorrect bead_id or status")
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"Evidence parse error: {exc}")


def check_verification_summary() -> None:
    ok = SUMMARY.is_file()
    _check("verification_summary", ok,
           f"Summary file {'found' if ok else 'MISSING'}: {_safe_rel(SUMMARY)}")


# -- Runner ------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_risk_policy_exists,
    check_risk_documented,
    check_replay_mechanism,
    check_degraded_mode,
    check_complexity_budget,
    check_countermeasures,
    check_event_codes,
    check_invariants,
    check_spec_keywords,
    check_threshold,
    check_alert_pipeline,
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
    failed = total - passed
    return {
        "bead_id": "bd-kiqr",
        "section": "12",
        "title": "Risk Control — Trust-System Complexity",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "status": "pass" if failed == 0 else "fail",
        "passed": passed,
        "failed": failed,
        "total": total,
        "all_passed": failed == 0,
        "checks": list(RESULTS),
    }


def self_test() -> None:
    """Smoke-test: run all checks and assert the structure is valid."""
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == "bd-kiqr"
    assert result["section"] == "12"
    assert isinstance(result["checks"], list)
    assert result["total"] == len(ALL_CHECKS)
    assert result["passed"] <= result["total"]
    assert result["failed"] == result["total"] - result["passed"]
    assert result["verdict"] in ("PASS", "FAIL")
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
    print("self_test passed")


def main() -> None:
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("bd-kiqr: Risk Control — Trust-System Complexity")
        print("=" * 55)
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")
        print(f"\n  {result['passed']}/{result['total']} checks passed"
              f" (verdict={result['verdict']})")
        if result["verdict"] != "PASS":
            sys.exit(1)


if __name__ == "__main__":
    main()
