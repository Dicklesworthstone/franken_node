#!/usr/bin/env python3
"""Verification script for bd-paui: topological choke-point false positives.

Usage:
    python3 scripts/check_chokepoint_false_positives.py
    python3 scripts/check_chokepoint_false_positives.py --json
    python3 scripts/check_chokepoint_false_positives.py --self-test --json
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-paui"
SECTION = "12"
TITLE = "Risk control: topological choke-point false positives"

CONTRACT = ROOT / "docs" / "specs" / "section_12" / "bd-paui_contract.md"
REPORT = ROOT / "artifacts" / "12" / "chokepoint_false_positive_report.json"

REQUIRED_EVENT_CODES = ["CFP-001", "CFP-002", "CFP-003", "CFP-004", "CFP-005"]
REQUIRED_CONTRACT_TERMS = [
    "INV-CFP-SIMULATION",
    "INV-CFP-FP-GATE",
    "INV-CFP-EV-GATE",
    "INV-CFP-STAGED",
    "INV-CFP-ROLLBACK",
    "Scenario A",
    "Scenario B",
    "Scenario C",
    "Scenario D",
]


def check_file(path: Path, label: str) -> dict:
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


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


def rule_lookup(data: dict, rule_id: str) -> dict | None:
    for rule in data.get("rules", []):
        if rule.get("rule_id") == rule_id:
            return rule
    return None


def simulation_ok(rule: dict) -> bool:
    return int(rule.get("counterfactual", {}).get("historical_operations_replayed", 0)) >= 1000


def rollout_stages_ok(rule: dict) -> bool:
    stages = rule.get("rollout", {}).get("stages", [])
    names = [s.get("stage") for s in stages]
    if "audit" not in names or "warn" not in names:
        return False
    if rule.get("status") == "enforced" and "enforce" not in names:
        return False
    return all(int(s.get("duration_hours", 0)) >= 24 for s in stages)


def evaluate_rules(data: dict) -> dict:
    rules = data.get("rules", [])
    enforced = [r for r in rules if r.get("status") == "enforced"]
    enforced_fp = [float(r.get("counterfactual", {}).get("false_positive_rate_pct", 999.0)) for r in enforced]
    max_enforced_fp = max(enforced_fp) if enforced_fp else 0.0
    all_enforced_net_positive = all(bool(r.get("expected_loss", {}).get("net_positive", False)) for r in enforced)
    all_staged = all(rollout_stages_ok(r) for r in rules)
    all_simulated = all(simulation_ok(r) for r in rules)

    return {
        "rules_total": len(rules),
        "rules_enforced": len(enforced),
        "rules_rejected": sum(1 for r in rules if r.get("status") == "rejected"),
        "max_enforced_fp": round(max_enforced_fp, 3),
        "all_enforced_net_positive": all_enforced_net_positive,
        "all_stage_durations_min_24h": all_staged,
        "all_rules_simulated_ge_1000": all_simulated,
    }


def check_report(data: dict | None) -> list[dict]:
    if data is None:
        return []

    checks = []
    rules = data.get("rules", [])
    aggregate = data.get("aggregate", {})

    checks.append({
        "check": "rules: at least one rule exists",
        "pass": len(rules) > 0,
        "detail": f"rules={len(rules)}",
    })

    sim_ok = all(simulation_ok(rule) for rule in rules)
    checks.append({
        "check": "simulation: every rule replayed on >=1000 operations",
        "pass": sim_ok,
        "detail": "all rules satisfy replay minimum" if sim_ok else "replay minimum violated",
    })

    enforced_rules = [r for r in rules if r.get("status") == "enforced"]
    enforced_fp_ok = all(
        float(r.get("counterfactual", {}).get("false_positive_rate_pct", 999.0)) <= 1.0
        for r in enforced_rules
    )
    checks.append({
        "check": "false-positive gate: enforced rules <=1%",
        "pass": enforced_fp_ok,
        "detail": "all enforced rules within threshold" if enforced_fp_ok else "enforced FP threshold violated",
    })

    ev_ok = all(
        bool(r.get("expected_loss", {}).get("net_positive", False))
        for r in enforced_rules
    )
    checks.append({
        "check": "expected-loss gate: enforced rules net-positive",
        "pass": ev_ok,
        "detail": "all enforced rules net positive" if ev_ok else "net-negative enforced rule detected",
    })

    staged_ok = all(rollout_stages_ok(r) for r in rules)
    checks.append({
        "check": "staged rollout: audit->warn->enforce with >=24h stage duration",
        "pass": staged_ok,
        "detail": "all rules follow staged rollout policy" if staged_ok else "staged rollout policy violated",
    })

    audit_no_block_ok = True
    for rule in rules:
        for stage in rule.get("rollout", {}).get("stages", []):
            if stage.get("stage") == "audit" and int(stage.get("blocked_operations", -1)) != 0:
                audit_no_block_ok = False
    checks.append({
        "check": "audit mode: logs violations without blocking",
        "pass": audit_no_block_ok,
        "detail": "audit stages have zero blocked operations" if audit_no_block_ok else "audit stage blocked operations detected",
    })

    scenario_a = next((s for s in data.get("scenarios", []) if s.get("scenario") == "A"), None)
    scenario_a_ok = (
        scenario_a is not None
        and scenario_a.get("rule_id") == "rule-overhard-05"
        and bool(scenario_a.get("rejected_before_enforce", False))
    )
    checks.append({
        "check": "scenario A: 5% legitimate-block rule rejected",
        "pass": scenario_a_ok,
        "detail": "validated" if scenario_a_ok else "scenario A invariant failed",
    })

    scenario_b = next((s for s in data.get("scenarios", []) if s.get("scenario") == "B"), None)
    scenario_b_ok = (
        scenario_b is not None
        and int(scenario_b.get("audit_mode_blocks", -1)) == 0
        and int(scenario_b.get("audit_mode_logs", 0)) > 0
    )
    checks.append({
        "check": "scenario B: audit mode logs-only behavior",
        "pass": scenario_b_ok,
        "detail": "validated" if scenario_b_ok else "scenario B invariant failed",
    })

    scenario_c = next((s for s in data.get("scenarios", []) if s.get("scenario") == "C"), None)
    scenario_c_ok = (
        scenario_c is not None
        and float(scenario_c.get("false_positive_rate_pct", 999.0)) <= 1.0
        and bool(scenario_c.get("promotion_allowed", False))
    )
    checks.append({
        "check": "scenario C: promotion allowed only for <=1% FP",
        "pass": scenario_c_ok,
        "detail": "validated" if scenario_c_ok else "scenario C invariant failed",
    })

    scenario_d = next((s for s in data.get("scenarios", []) if s.get("scenario") == "D"), None)
    scenario_d_ok = (
        scenario_d is not None
        and float(scenario_d.get("false_positive_cost_usd_per_day", 0.0)) > float(scenario_d.get("blocked_threat_value_usd_per_day", 0.0))
        and bool(scenario_d.get("flagged_net_negative", False))
    )
    checks.append({
        "check": "scenario D: expected-loss net-negative rule flagged",
        "pass": scenario_d_ok,
        "detail": "validated" if scenario_d_ok else "scenario D invariant failed",
    })

    report_codes = data.get("event_codes", [])
    for code in REQUIRED_EVENT_CODES:
        checks.append({
            "check": f"events: {code}",
            "pass": code in report_codes,
            "detail": "present" if code in report_codes else "MISSING",
        })

    trace_ok = isinstance(data.get("trace_id"), str) and len(data.get("trace_id", "").strip()) > 0
    checks.append({
        "check": "logs: trace id present",
        "pass": trace_ok,
        "detail": data.get("trace_id", "MISSING"),
    })

    eval_out = evaluate_rules(data)
    checks.append({
        "check": "aggregate: rules_total matches recomputation",
        "pass": int(aggregate.get("rules_total", -1)) == eval_out["rules_total"],
        "detail": f"reported={aggregate.get('rules_total')} computed={eval_out['rules_total']}",
    })
    checks.append({
        "check": "aggregate: rules_enforced matches recomputation",
        "pass": int(aggregate.get("rules_enforced", -1)) == eval_out["rules_enforced"],
        "detail": f"reported={aggregate.get('rules_enforced')} computed={eval_out['rules_enforced']}",
    })
    checks.append({
        "check": "aggregate: rules_rejected matches recomputation",
        "pass": int(aggregate.get("rules_rejected", -1)) == eval_out["rules_rejected"],
        "detail": f"reported={aggregate.get('rules_rejected')} computed={eval_out['rules_rejected']}",
    })
    checks.append({
        "check": "aggregate: min replay operations >=1000",
        "pass": int(aggregate.get("min_replay_operations", 0)) >= 1000,
        "detail": f"reported={aggregate.get('min_replay_operations')}",
    })
    checks.append({
        "check": "aggregate: max enforced FP matches recomputation",
        "pass": abs(float(aggregate.get("max_false_positive_rate_enforced_pct", -1.0)) - eval_out["max_enforced_fp"]) < 0.01,
        "detail": f"reported={aggregate.get('max_false_positive_rate_enforced_pct')} computed={eval_out['max_enforced_fp']}",
    })
    checks.append({
        "check": "aggregate: enforced net-positive flag matches recomputation",
        "pass": bool(aggregate.get("all_enforced_net_positive", False)) == eval_out["all_enforced_net_positive"],
        "detail": f"reported={aggregate.get('all_enforced_net_positive')} computed={eval_out['all_enforced_net_positive']}",
    })
    checks.append({
        "check": "aggregate: stage-duration flag matches recomputation",
        "pass": bool(aggregate.get("all_stage_durations_min_24h", False)) == eval_out["all_stage_durations_min_24h"],
        "detail": f"reported={aggregate.get('all_stage_durations_min_24h')} computed={eval_out['all_stage_durations_min_24h']}",
    })

    deterministic = evaluate_rules({"rules": list(rules)}) == evaluate_rules({"rules": list(reversed(rules))})
    checks.append({
        "check": "determinism: order-insensitive aggregate evaluation",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable",
    })

    adversarial = json.loads(json.dumps(data))
    safe_rule = rule_lookup(adversarial, "rule-safe-chokepoint-01")
    if safe_rule:
        safe_rule["counterfactual"]["false_positive_rate_pct"] = 2.0
    adv_eval = evaluate_rules(adversarial)
    adversarial_sensitive = adv_eval["max_enforced_fp"] > 1.0
    checks.append({
        "check": "adversarial: enforced FP >1% is detected",
        "pass": adversarial_sensitive,
        "detail": f"adversarial_max_enforced_fp={adv_eval['max_enforced_fp']}",
    })

    return checks


def run_checks() -> dict:
    checks = []
    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(REPORT, "chokepoint FP report"))
    checks.extend(check_contract())
    data, load_checks = load_report()
    checks.extend(load_checks)
    checks.extend(check_report(data))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "section": SECTION,
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": len(checks),
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict]]:
    sample_rule = {
        "rule_id": "r",
        "status": "enforced",
        "counterfactual": {"historical_operations_replayed": 1000, "false_positive_rate_pct": 0.5},
        "expected_loss": {"net_positive": True},
        "rollout": {
            "stages": [
                {"stage": "audit", "duration_hours": 24, "blocked_operations": 0},
                {"stage": "warn", "duration_hours": 24, "blocked_operations": 0},
                {"stage": "enforce", "duration_hours": 24, "blocked_operations": 1}
            ]
        }
    }
    checks = []
    checks.append({"check": "self: simulation_ok", "pass": simulation_ok(sample_rule)})
    checks.append({"check": "self: rollout_stages_ok", "pass": rollout_stages_ok(sample_rule)})
    checks.append({"check": "self: evaluate_rules", "pass": evaluate_rules({"rules": [sample_rule]})["rules_enforced"] == 1})
    return all(c["pass"] for c in checks), checks


def main() -> int:
    as_json = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv

    if run_self_test:
        ok, checks = self_test()
        result = {
            "self_test_passed": ok,
            "checks_total": len(checks),
            "checks_passing": sum(1 for c in checks if c["pass"]),
            "checks_failing": sum(1 for c in checks if not c["pass"]),
        }
        if as_json:
            print(json.dumps(result, indent=2))
        else:
            print("PASS" if ok else "FAIL")
            for check in checks:
                status = "PASS" if check["pass"] else "FAIL"
                print(f"[{status}] {check['check']}")
        return 0 if ok else 1

    result = run_checks()
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        verdict = result["verdict"]
        summary = result["summary"]
        print(f"{verdict}: {result['title']} ({summary['passing']}/{summary['total']} checks passed)")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
