#!/usr/bin/env python3
"""Verification script for bd-3jc1: migration friction persistence guardrails.

Usage:
    python scripts/check_migration_friction_persistence.py          # human-readable
    python scripts/check_migration_friction_persistence.py --json   # machine-readable
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-3jc1"
SECTION = "12"

CONTRACT = ROOT / "docs" / "specs" / "section_12" / "bd-3jc1_contract.md"
REPORT = ROOT / "artifacts" / "12" / "migration_friction_report.json"

REQUIRED_EVENT_CODES = ["MFP-001", "MFP-002", "MFP-003", "MFP-004", "MFP-005"]
REQUIRED_CONTRACT_TERMS = [
    "INV-MFP-AUTOPILOT",
    "INV-MFP-CONFIDENCE-REPORT",
    "INV-MFP-CALIBRATION",
    "INV-MFP-MIXED-MODE",
    "Scenario A",
    "Scenario B",
    "Scenario C",
]


def check_file(path: Path, label: str) -> dict:
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def load_report() -> tuple[dict | None, list[dict]]:
    checks = []
    if not REPORT.exists():
        checks.append({"check": "report: exists", "pass": False, "detail": "MISSING"})
        return None, checks

    checks.append({"check": "report: exists", "pass": True, "detail": "found"})

    try:
        data = json.loads(REPORT.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        checks.append({"check": "report: valid json", "pass": False, "detail": "invalid"})
        return None, checks

    checks.append({"check": "report: valid json", "pass": True, "detail": "valid"})
    return data, checks


def check_contract() -> list[dict]:
    checks = []
    if not CONTRACT.exists():
        checks.append({"check": "contract: exists", "pass": False, "detail": "MISSING"})
        return checks

    text = CONTRACT.read_text(encoding="utf-8")
    checks.append({"check": "contract: exists", "pass": True, "detail": "found"})

    for term in REQUIRED_CONTRACT_TERMS:
        present = term in text
        checks.append({
            "check": f"contract: term {term}",
            "pass": present,
            "detail": "present" if present else "MISSING",
        })

    return checks


def autopilot_coverage_pct(projects: list[dict]) -> float:
    total_steps = sum(int(p.get("autopilot_steps_total", 0)) for p in projects)
    auto_steps = sum(int(p.get("autopilot_steps_auto", 0)) for p in projects)
    if total_steps == 0:
        return 0.0
    return round((auto_steps / total_steps) * 100.0, 1)


def high_confidence_success_rate(projects: list[dict], threshold: int = 80) -> float:
    high = [p for p in projects if int(p.get("confidence_score", -1)) >= threshold]
    if not high:
        return 0.0
    success = sum(1 for p in high if bool(p.get("migration_success", False)))
    return round((success / len(high)) * 100.0, 1)


def check_report(data: dict | None) -> list[dict]:
    if data is None:
        return []

    checks = []

    projects = data.get("projects", [])
    aggregate = data.get("aggregate", {})

    checks.append({
        "check": "report: cohort size",
        "pass": len(projects) == 10,
        "detail": f"{len(projects)} projects",
    })

    coverage = autopilot_coverage_pct(projects)
    checks.append({
        "check": "autopilot: coverage >= 80%",
        "pass": coverage >= 80.0,
        "detail": f"coverage={coverage}%",
    })

    no_manual = all(int(p.get("manual_interventions", 0)) == 0 for p in projects)
    checks.append({
        "check": "autopilot: zero manual interventions",
        "pass": no_manual,
        "detail": "all zero" if no_manual else "manual interventions detected",
    })

    confidence_reports_complete = True
    for project in projects:
        has_score = isinstance(project.get("confidence_score"), int)
        has_blockers = isinstance(project.get("ranked_blockers"), list)
        in_range = has_score and 0 <= int(project["confidence_score"]) <= 100
        confidence_reports_complete = confidence_reports_complete and has_score and has_blockers and in_range
    checks.append({
        "check": "confidence: report generated for every attempt",
        "pass": confidence_reports_complete,
        "detail": "all projects have score and ranked blockers" if confidence_reports_complete else "missing score/blockers",
    })

    predicted_rate = high_confidence_success_rate(projects, 80)
    checks.append({
        "check": "confidence: score>=80 predicts >=90% success",
        "pass": predicted_rate >= 90.0,
        "detail": f"observed={predicted_rate}%",
    })

    scenario_a = next((p for p in projects if p.get("scenario") == "A"), None)
    a_ok = (
        scenario_a is not None
        and scenario_a.get("name") == "express-starter"
        and int(scenario_a.get("confidence_score", 0)) >= 90
        and bool(scenario_a.get("migration_success", False))
        and int(scenario_a.get("manual_interventions", 0)) == 0
    )
    checks.append({
        "check": "scenario A: express starter",
        "pass": a_ok,
        "detail": "validated" if a_ok else "scenario A invariant failed",
    })

    scenario_b = next((p for p in projects if p.get("scenario") == "B"), None)
    blockers_b = [str(x).lower() for x in (scenario_b or {}).get("blockers", [])]
    b_ok = (
        scenario_b is not None
        and int(scenario_b.get("confidence_score", 100)) < 50
        and any("native addon" in b for b in blockers_b)
    )
    checks.append({
        "check": "scenario B: native addon blocker",
        "pass": b_ok,
        "detail": "validated" if b_ok else "scenario B invariant failed",
    })

    scenario_c = next((p for p in projects if p.get("scenario") == "C"), None)
    mixed = (scenario_c or {}).get("mixed_mode", {})
    c_ok = (
        scenario_c is not None
        and int(mixed.get("migrated_module_pct", 0)) == 50
        and bool(mixed.get("franken_node_runtime_ok", False))
        and bool(mixed.get("legacy_runtime_ok", False))
        and bool(mixed.get("bridge_calls_ok", False))
    )
    checks.append({
        "check": "scenario C: mixed-mode partial migration",
        "pass": c_ok,
        "detail": "validated" if c_ok else "scenario C invariant failed",
    })

    report_codes = data.get("event_codes", [])
    for code in REQUIRED_EVENT_CODES:
        checks.append({
            "check": f"events: {code}",
            "pass": code in report_codes,
            "detail": "present" if code in report_codes else "MISSING",
        })

    trace_ok = isinstance(data.get("trace_id"), str) and len(data.get("trace_id", "")) > 0
    checks.append({
        "check": "logs: trace id present",
        "pass": trace_ok,
        "detail": data.get("trace_id", "MISSING"),
    })

    aggregate_matches = abs(float(aggregate.get("autopilot_coverage_pct", -1.0)) - coverage) < 0.11
    checks.append({
        "check": "aggregate: coverage matches recomputation",
        "pass": aggregate_matches,
        "detail": f"reported={aggregate.get('autopilot_coverage_pct')} computed={coverage}",
    })

    calibration_matches = (
        abs(float(aggregate.get("high_confidence_success_rate_pct", -1.0)) - predicted_rate) < 0.11
    )
    checks.append({
        "check": "aggregate: calibration matches recomputation",
        "pass": calibration_matches,
        "detail": f"reported={aggregate.get('high_confidence_success_rate_pct')} computed={predicted_rate}",
    })

    deterministic = (
        autopilot_coverage_pct(list(projects)) == autopilot_coverage_pct(list(reversed(projects)))
        and high_confidence_success_rate(list(projects), 80)
        == high_confidence_success_rate(list(reversed(projects)), 80)
    )
    checks.append({
        "check": "determinism: order-insensitive aggregate metrics",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable aggregation",
    })

    adversarial_projects = [dict(p) for p in projects]
    for p in adversarial_projects:
        if int(p.get("confidence_score", 0)) >= 80:
            p["migration_success"] = False
            break
    adversarial_rate = high_confidence_success_rate(adversarial_projects, 80)
    adversarial_sensitive = adversarial_rate < 90.0
    checks.append({
        "check": "determinism: adversarial perturbation flips calibration gate",
        "pass": adversarial_sensitive,
        "detail": f"adversarial_rate={adversarial_rate}%",
    })

    return checks


def run_checks() -> dict:
    checks = []

    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(REPORT, "migration friction report"))

    checks.extend(check_contract())
    data, report_checks = load_report()
    checks.extend(report_checks)
    checks.extend(check_report(data))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": BEAD_ID,
        "title": "Risk control: migration friction persistence",
        "section": SECTION,
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict]]:
    result = run_checks()
    failed = [c for c in result["checks"] if not c["pass"]]
    return len(failed) == 0, result["checks"]


if __name__ == "__main__":
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(
            f"{BEAD_ID} verification: {status} "
            f"({result['summary']['passing']}/{result['summary']['total']})"
        )
        for check in result["checks"]:
            mark = "PASS" if check["pass"] else "FAIL"
            print(f"  [{mark}] {check['check']}: {check['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
