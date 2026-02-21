#!/usr/bin/env python3
"""Verification script for bd-1n1t: topology blind spots risk control.

Checks that the risk control artefacts for the Topology Blind Spots risk
are present, complete, and internally consistent.

Usage:
    python3 scripts/check_topology_blind_spots.py              # human-readable
    python3 scripts/check_topology_blind_spots.py --json        # machine-readable
    python3 scripts/check_topology_blind_spots.py --self-test   # smoke-test
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_12" / "bd-1n1t_contract.md"
POLICY = ROOT / "docs" / "policy" / "risk_topology_blind_spots.md"
EVIDENCE = ROOT / "artifacts" / "section_12" / "bd-1n1t" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_12" / "bd-1n1t" / "verification_summary.md"

# Spec uses TBS-101..105 event codes for dependency-graph topology analysis.
SPEC_EVENT_CODES = ["TBS-101", "TBS-102", "TBS-103", "TBS-104", "TBS-105"]
SPEC_INVARIANTS = [
    "INV-TBS-GRAPH-INGEST",
    "INV-TBS-METRICS-BASELINE",
    "INV-TBS-DRIFT-REVIEW",
    "INV-TBS-CHOKEPOINT",
    "INV-TBS-CYCLE-HANDLING",
]

# Policy uses TBS-001..004 event codes for monitoring-layer coverage.
POLICY_EVENT_CODES = ["TBS-001", "TBS-002", "TBS-003", "TBS-004"]
POLICY_INVARIANTS = [
    "INV-TBS-COVERAGE",
    "INV-TBS-OBSERVE",
    "INV-TBS-DETECT",
    "INV-TBS-REMEDIATE",
]

COUNTERMEASURES = [
    "Trust Graph Coverage Audit",
    "Control Plane Observability Contract",
    "Dead Zone Detection",
    "Blind Spot Remediation SLA",
]

THRESHOLDS = {
    "coverage": 95,
    "event_latency_s": 5,
    "dead_zone_window_h": 24,
    "remediation_sla_h": 72,
}

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"name": name, "passed": bool(passed), "detail": detail})


def _safe_rel(path: Path) -> str:
    """Return a display-friendly relative path, falling back to str(path)."""
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def validate_topology_audit(audit: dict[str, Any]) -> list[str]:
    """Validate a topology audit result dict.  Returns list of error strings."""
    errors: list[str] = []
    required = [
        "timestamp",
        "total_nodes",
        "monitored_nodes",
        "coverage_percent",
        "unmonitored",
    ]
    for f in required:
        if f not in audit:
            errors.append(f"missing field: {f}")
    if "total_nodes" in audit:
        if not isinstance(audit["total_nodes"], int) or audit["total_nodes"] < 0:
            errors.append("total_nodes must be non-negative int")
    if "monitored_nodes" in audit:
        if not isinstance(audit["monitored_nodes"], int) or audit["monitored_nodes"] < 0:
            errors.append("monitored_nodes must be non-negative int")
    if (
        isinstance(audit.get("total_nodes"), int)
        and isinstance(audit.get("monitored_nodes"), int)
        and audit["monitored_nodes"] > audit["total_nodes"]
    ):
        errors.append("monitored_nodes exceeds total_nodes")
    if "coverage_percent" in audit:
        cp = audit["coverage_percent"]
        if not isinstance(cp, (int, float)) or cp < 0 or cp > 100:
            errors.append("coverage_percent must be 0-100")
    if "unmonitored" in audit:
        if not isinstance(audit["unmonitored"], list):
            errors.append("unmonitored must be a list")
    return errors


# -- Checks ------------------------------------------------------------------


def check_spec_exists() -> None:
    ok = SPEC.is_file()
    _check(
        "spec_exists",
        ok,
        f"Spec file {'found' if ok else 'MISSING'}: {_safe_rel(SPEC)}",
    )


def check_policy_exists() -> None:
    ok = POLICY.is_file()
    _check(
        "policy_exists",
        ok,
        f"Policy file {'found' if ok else 'MISSING'}: {_safe_rel(POLICY)}",
    )


def check_spec_event_codes() -> None:
    if not SPEC.is_file():
        _check("spec_event_codes", False, "Spec file missing")
        return
    text = SPEC.read_text()
    missing = [c for c in SPEC_EVENT_CODES if c not in text]
    ok = len(missing) == 0
    _check(
        "spec_event_codes",
        ok,
        "All spec event codes present" if ok else f"Missing: {missing}",
    )


def check_spec_invariants() -> None:
    if not SPEC.is_file():
        _check("spec_invariants", False, "Spec file missing")
        return
    text = SPEC.read_text()
    missing = [i for i in SPEC_INVARIANTS if i not in text]
    ok = len(missing) == 0
    _check(
        "spec_invariants",
        ok,
        "All spec invariants present" if ok else f"Missing: {missing}",
    )


def check_spec_countermeasures() -> None:
    if not SPEC.is_file():
        _check("spec_countermeasures", False, "Spec file missing")
        return
    text = SPEC.read_text()
    # Spec uses different countermeasure names: Graph Ingestion, Metric Baselines,
    # Choke-Point Alerts, Cycle Handling
    spec_cms = ["Graph Ingestion", "Metric Baselines", "Choke-Point"]
    missing = [cm for cm in spec_cms if cm not in text]
    ok = len(missing) == 0
    _check(
        "spec_countermeasures",
        ok,
        "All spec countermeasures present" if ok else f"Missing: {missing}",
    )


def check_spec_threshold_drift() -> None:
    if not SPEC.is_file():
        _check("spec_threshold_drift", False, "Spec file missing")
        return
    text = SPEC.read_text()
    ok = "20%" in text
    _check(
        "spec_threshold_drift",
        ok,
        "Drift threshold 20% present" if ok else "Drift threshold missing",
    )


def check_spec_threshold_chokepoint() -> None:
    if not SPEC.is_file():
        _check("spec_threshold_chokepoint", False, "Spec file missing")
        return
    text = SPEC.read_text()
    ok = "50%" in text
    _check(
        "spec_threshold_chokepoint",
        ok,
        "Choke-point threshold >50% present" if ok else "Choke-point threshold missing",
    )


def check_spec_keywords() -> None:
    if not SPEC.is_file():
        _check("spec_keywords", False, "Spec file missing")
        return
    text = SPEC.read_text().lower()
    keywords = ["topology", "blind spot", "transitive", "depth", "remediation"]
    missing = [k for k in keywords if k not in text]
    ok = len(missing) == 0
    _check(
        "spec_keywords",
        ok,
        "All spec keywords present" if ok else f"Missing keywords: {missing}",
    )


def check_spec_scenarios() -> None:
    if not SPEC.is_file():
        _check("spec_scenarios", False, "Spec file missing")
        return
    text = SPEC.read_text()
    scenarios = ["Scenario A", "Scenario B", "Scenario C", "Scenario D"]
    missing = [s for s in scenarios if s not in text]
    ok = len(missing) == 0
    _check(
        "spec_scenarios",
        ok,
        "All scenarios A-D present" if ok else f"Missing: {missing}",
    )


def check_policy_event_codes() -> None:
    if not POLICY.is_file():
        _check("policy_event_codes", False, "Policy file missing")
        return
    text = POLICY.read_text()
    missing = [c for c in POLICY_EVENT_CODES if c not in text]
    ok = len(missing) == 0
    _check(
        "policy_event_codes",
        ok,
        "All policy event codes present" if ok else f"Missing: {missing}",
    )


def check_policy_invariants() -> None:
    if not POLICY.is_file():
        _check("policy_invariants", False, "Policy file missing")
        return
    text = POLICY.read_text()
    missing = [i for i in POLICY_INVARIANTS if i not in text]
    ok = len(missing) == 0
    _check(
        "policy_invariants",
        ok,
        "All policy invariants present" if ok else f"Missing: {missing}",
    )


def check_policy_sections() -> None:
    if not POLICY.is_file():
        _check("policy_sections", False, "Policy file missing")
        return
    text = POLICY.read_text()
    sections = [
        "Escalation Procedures",
        "Evidence Requirements",
        "Countermeasure Details",
        "Impact",
        "Likelihood",
    ]
    missing = [s for s in sections if s not in text]
    ok = len(missing) == 0
    _check(
        "policy_sections",
        ok,
        "All policy sections present" if ok else f"Missing sections: {missing}",
    )


def check_policy_allowlist() -> None:
    if not POLICY.is_file():
        _check("policy_allowlist", False, "Policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "allowlist" in text
    _check(
        "policy_allowlist",
        ok,
        "Allowlist for silent subsystems documented" if ok else "Allowlist missing",
    )


def check_policy_remediation_register() -> None:
    if not POLICY.is_file():
        _check("policy_remediation_register", False, "Policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "remediation register" in text
    _check(
        "policy_remediation_register",
        ok,
        "Remediation register documented" if ok else "Remediation register missing",
    )


def check_policy_risk_description() -> None:
    if not POLICY.is_file():
        _check("policy_risk_description", False, "Policy file missing")
        return
    text = POLICY.read_text()
    ok = "Topology Blind Spots" in text and "Risk Description" in text
    _check(
        "policy_risk_description",
        ok,
        "Risk description documented" if ok else "Risk description missing",
    )


def check_policy_dead_zone_detection() -> None:
    if not POLICY.is_file():
        _check("policy_dead_zone_detection", False, "Policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "dead zone" in text and "24" in POLICY.read_text()
    _check(
        "policy_dead_zone_detection",
        ok,
        "Dead zone detection documented with 24h window"
        if ok
        else "Dead zone detection missing",
    )


def check_policy_escalation() -> None:
    if not POLICY.is_file():
        _check("policy_escalation", False, "Policy file missing")
        return
    text = POLICY.read_text().lower()
    ok = "escalation" in text and "72" in POLICY.read_text()
    _check(
        "policy_escalation",
        ok,
        "Escalation procedures with 72h SLA documented"
        if ok
        else "Escalation or SLA missing",
    )


def check_policy_countermeasures() -> None:
    if not POLICY.is_file():
        _check("policy_countermeasures", False, "Policy file missing")
        return
    text = POLICY.read_text()
    cm_keywords = [
        "Trust Graph Coverage Audit",
        "Observability Contract",
        "Dead Zone Detection",
        "Remediation SLA",
    ]
    missing = [k for k in cm_keywords if k not in text]
    ok = len(missing) == 0
    _check(
        "policy_countermeasures",
        ok,
        "All countermeasure subsections present in policy"
        if ok
        else f"Missing: {missing}",
    )


def check_verification_evidence() -> None:
    if not EVIDENCE.is_file():
        _check(
            "verification_evidence",
            False,
            f"Evidence file MISSING: {_safe_rel(EVIDENCE)}",
        )
        return
    try:
        data = json.loads(EVIDENCE.read_text())
        ok = data.get("bead_id") == "bd-1n1t" and data.get("status") == "pass"
        _check(
            "verification_evidence",
            ok,
            "Evidence file valid" if ok else "Evidence has incorrect bead_id or status",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"Evidence parse error: {exc}")


def check_verification_summary() -> None:
    ok = SUMMARY.is_file()
    _check(
        "verification_summary",
        ok,
        f"Summary file {'found' if ok else 'MISSING'}: {_safe_rel(SUMMARY)}",
    )


# -- Runner ------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_countermeasures,
    check_spec_threshold_drift,
    check_spec_threshold_chokepoint,
    check_spec_keywords,
    check_spec_scenarios,
    check_policy_event_codes,
    check_policy_invariants,
    check_policy_sections,
    check_policy_allowlist,
    check_policy_remediation_register,
    check_policy_risk_description,
    check_policy_dead_zone_detection,
    check_policy_escalation,
    check_policy_countermeasures,
    check_verification_evidence,
    check_verification_summary,
]


def run_all() -> dict[str, Any]:
    RESULTS.clear()
    for fn in ALL_CHECKS:
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    total = len(RESULTS)
    failed = total - passed
    return {
        "bead_id": "bd-1n1t",
        "section": "12",
        "title": "Risk Control — Topology Blind Spots",
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
    assert result["bead_id"] == "bd-1n1t"
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
        print("bd-1n1t: Risk Control — Topology Blind Spots")
        print("=" * 55)
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")
        print(
            f"\n  {result['passed']}/{result['total']} checks passed"
            f" (verdict={result['verdict']})"
        )
        if result["verdict"] != "PASS":
            sys.exit(1)


if __name__ == "__main__":
    main()
