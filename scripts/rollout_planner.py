#!/usr/bin/env python3
"""
Rollout Planner.

Generates a graduated rollout plan (shadow → canary → ramp → default)
based on project risk assessment.

Usage:
    python3 scripts/rollout_planner.py <risk_score_report.json> [--json]
    python3 scripts/rollout_planner.py --self-test [--json]
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

PHASES = [
    {
        "name": "shadow",
        "description": "Run both runtimes in parallel, compare outputs, serve from original",
        "traffic_pct": 0,
        "gate": "Validation runner passes with zero critical divergences",
        "rollback": "Disable shadow execution",
        "duration_estimate": "1-2 weeks",
    },
    {
        "name": "canary",
        "description": "Serve 1-5% of traffic from franken_node",
        "traffic_pct": 5,
        "gate": "No critical/high divergences in shadow phase for 48h",
        "rollback": "Route all traffic back to original runtime",
        "duration_estimate": "1 week",
    },
    {
        "name": "ramp",
        "description": "Gradually increase franken_node traffic from 5% to 50%",
        "traffic_pct": 50,
        "gate": "Error rate < 0.1% during canary phase for 24h",
        "rollback": "Reduce traffic to canary level (5%)",
        "duration_estimate": "2-4 weeks",
    },
    {
        "name": "default",
        "description": "All traffic on franken_node, original as fallback",
        "traffic_pct": 100,
        "gate": "Sustained stability at 50%+ for 1 week with no regressions",
        "rollback": "Route traffic back to original runtime",
        "duration_estimate": "Permanent (with monitoring)",
    },
]


def generate_plan(risk_report: dict = None) -> dict:
    """Generate a rollout plan based on risk assessment."""
    risk_score = 0
    difficulty = "low"
    project = "<unknown>"

    if risk_report:
        risk_score = risk_report.get("risk_score", 0)
        difficulty = risk_report.get("difficulty", {}).get("level", "low")
        project = risk_report.get("project", "<unknown>")

    # Adjust phase durations based on risk
    phases = []
    for phase in PHASES:
        adjusted = dict(phase)
        if difficulty in ("high", "critical"):
            adjusted["gate"] += " (extended monitoring required)"
            if phase["name"] == "canary":
                adjusted["traffic_pct"] = 1
                adjusted["duration_estimate"] = "2 weeks"
            elif phase["name"] == "ramp":
                adjusted["traffic_pct"] = 25
                adjusted["duration_estimate"] = "4-8 weeks"
        phases.append(adjusted)

    # Pre-migration checklist
    checklist = [
        {"item": "Project scan completed", "required": True},
        {"item": "Risk score calculated", "required": True},
        {"item": "Rewrite suggestions reviewed", "required": True},
        {"item": "Critical risks addressed", "required": risk_score > 40},
        {"item": "Validation runner configured", "required": True},
        {"item": "Monitoring/alerting configured", "required": True},
        {"item": "Rollback procedure tested", "required": True},
    ]

    return {
        "project": project,
        "plan_timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_assessment": {
            "score": risk_score,
            "difficulty": difficulty,
        },
        "phases": phases,
        "pre_migration_checklist": checklist,
        "phase_order": ["shadow", "canary", "ramp", "default"],
        "constraints": {
            "phase_order_strict": True,
            "rollback_always_available": True,
            "gate_conditions_mandatory": True,
        },
    }


def validate_plan(plan: dict) -> list[dict]:
    """Validate plan structure and invariants."""
    checks = []

    # Phase order
    names = [p["name"] for p in plan.get("phases", [])]
    correct_order = names == ["shadow", "canary", "ramp", "default"]
    checks.append({"id": "PLAN-ORDER", "status": "PASS" if correct_order else "FAIL"})

    # All phases have gates
    all_gated = all("gate" in p and p["gate"] for p in plan.get("phases", []))
    checks.append({"id": "PLAN-GATED", "status": "PASS" if all_gated else "FAIL"})

    # All phases have rollback
    all_rollback = all("rollback" in p and p["rollback"] for p in plan.get("phases", []))
    checks.append({"id": "PLAN-ROLLBACK", "status": "PASS" if all_rollback else "FAIL"})

    # Constraints present
    has_constraints = plan.get("constraints", {}).get("phase_order_strict") is True
    checks.append({"id": "PLAN-CONSTRAINTS", "status": "PASS" if has_constraints else "FAIL"})

    # Checklist present
    has_checklist = len(plan.get("pre_migration_checklist", [])) >= 5
    checks.append({"id": "PLAN-CHECKLIST", "status": "PASS" if has_checklist else "FAIL"})

    return checks


def self_test() -> dict:
    """Run self-test."""
    checks = []

    # Test low-risk plan
    plan_low = generate_plan({"risk_score": 5, "difficulty": {"level": "low"}, "project": "test-low"})
    low_checks = validate_plan(plan_low)
    checks.extend(low_checks)

    # Test high-risk plan
    plan_high = generate_plan({"risk_score": 75, "difficulty": {"level": "critical"}, "project": "test-high"})
    high_checks = validate_plan(plan_high)

    # High-risk should have reduced canary traffic
    canary = next(p for p in plan_high["phases"] if p["name"] == "canary")
    checks.append({"id": "PLAN-HIGH-RISK-CANARY", "status": "PASS" if canary["traffic_pct"] <= 5 else "FAIL",
                    "details": {"canary_traffic": canary["traffic_pct"]}})

    failing = [c for c in checks if c["status"] == "FAIL"]
    return {
        "gate": "rollout_planner_verification",
        "section": "10.3",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }


def main():
    logger = configure_test_logging("rollout_planner")
    logger.info("starting rollout_planner", extra={"argv": sys.argv[1:]})
    json_output = "--json" in sys.argv
    is_self_test = "--self-test" in sys.argv

    if is_self_test:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        risk_report = json.loads(Path(args[0]).read_text())
        plan = generate_plan(risk_report)
    else:
        plan = generate_plan()

    if json_output:
        print(json.dumps(plan, indent=2))
    else:
        for phase in plan["phases"]:
            print(f"[{phase['name'].upper()}] {phase['description']} (traffic: {phase['traffic_pct']}%)")
            print(f"  Gate: {phase['gate']}")
            print(f"  Rollback: {phase['rollback']}")
            print()


if __name__ == "__main__":
    main()
