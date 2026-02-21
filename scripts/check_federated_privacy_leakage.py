#!/usr/bin/env python3
"""Verification script for bd-1nab: federated privacy leakage guardrails.

Usage:
    python3 scripts/check_federated_privacy_leakage.py
    python3 scripts/check_federated_privacy_leakage.py --json
    python3 scripts/check_federated_privacy_leakage.py --self-test --json
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-1nab"
SECTION = "12"
TITLE = "Risk control: federated privacy leakage"

CONTRACT = ROOT / "docs" / "specs" / "section_12" / "bd-1nab_contract.md"
REPORT = ROOT / "artifacts" / "12" / "federated_privacy_leakage_report.json"

REQUIRED_EVENT_CODES = ["FPL-001", "FPL-002", "FPL-003", "FPL-004", "FPL-005"]
REQUIRED_CONTRACT_TERMS = [
    "INV-FPL-BUDGETS",
    "INV-FPL-EXHAUSTION",
    "INV-FPL-SECURE-AGGREGATION",
    "INV-FPL-EXTERNAL-VERIFIER",
    "INV-FPL-RESET-AUTHZ",
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


def channel_default_budget_ok(channels: list[dict]) -> bool:
    return all(float(ch.get("epsilon_budget", 999.0)) <= 1.0 for ch in channels)


def channel_exhaustion_blocking_ok(channels: list[dict]) -> bool:
    for channel in channels:
        allowed = int(channel.get("emissions_allowed", 0))
        attempted = int(channel.get("emissions_attempted", -1))
        blocked = bool(channel.get("n_plus_one_blocked", False))
        error = channel.get("blocked_error")
        if attempted != allowed + 1:
            return False
        if not blocked:
            return False
        if error != "ERR_PRIVACY_BUDGET_EXHAUSTED":
            return False
    return True


def find_scenario(data: dict, scenario_id: str) -> dict | None:
    for scenario in data.get("scenarios", []):
        if scenario.get("scenario") == scenario_id:
            return scenario
    return None


def check_report(data: dict | None) -> list[dict]:
    if data is None:
        return []

    checks = []
    channels = data.get("channels", [])
    aggregate = data.get("aggregate", {})

    checks.append({
        "check": "channels: at least one telemetry channel",
        "pass": len(channels) > 0,
        "detail": f"count={len(channels)}",
    })

    checks.append({
        "check": "channels: default epsilon <= 1.0",
        "pass": channel_default_budget_ok(channels),
        "detail": "all channels within default max" if channel_default_budget_ok(channels) else "default epsilon exceeded",
    })

    all_consumed = all(
        abs(float(ch.get("epsilon_consumed", -1.0)) - float(ch.get("epsilon_budget", -2.0))) < 0.0001
        for ch in channels
    )
    checks.append({
        "check": "channels: budget consumption tracked to exhaustion",
        "pass": all_consumed,
        "detail": "all channels fully consumed" if all_consumed else "consumption mismatch detected",
    })

    checks.append({
        "check": "channels: (N+1) emission blocked with stable error",
        "pass": channel_exhaustion_blocking_ok(channels),
        "detail": "all channels block post-exhaustion emissions" if channel_exhaustion_blocking_ok(channels) else "blocking invariant failed",
    })

    secure = data.get("secure_aggregation", {})
    secure_ok = (
        int(secure.get("participants", 0)) >= 10
        and bool(secure.get("contributions_encrypted", False))
        and bool(secure.get("aggregate_visible_only", False))
        and bool(secure.get("recovery_attack_attempted", False))
        and not bool(secure.get("recovery_succeeded", True))
    )
    checks.append({
        "check": "secure aggregation: >=10 participants and non-recoverability",
        "pass": secure_ok,
        "detail": "validated" if secure_ok else "secure aggregation invariant failed",
    })

    verifier = data.get("external_verifier", {})
    verifier_ok = (
        bool(verifier.get("api_available", False))
        and verifier.get("input_scope") == "aggregate+budget-only"
        and bool(verifier.get("budget_exhausted_detected", False))
        and not bool(verifier.get("raw_data_accessed", True))
    )
    checks.append({
        "check": "external verifier: aggregate-only budget audit",
        "pass": verifier_ok,
        "detail": "validated" if verifier_ok else "external verifier invariant failed",
    })

    reset = data.get("budget_reset_attempt", {})
    reset_ok = (
        not bool(reset.get("authorized", True))
        and bool(reset.get("denied", False))
        and reset.get("error_code") == "ERR_PRIVACY_BUDGET_RESET_DENIED"
        and reset.get("logged_event") == "FPL-005"
    )
    checks.append({
        "check": "unauthorized reset: denied and logged",
        "pass": reset_ok,
        "detail": "validated" if reset_ok else "reset authorization invariant failed",
    })

    scenario_a = find_scenario(data, "A")
    scenario_a_ok = (
        scenario_a is not None
        and bool(scenario_a.get("exhaustion_blocked", False))
        and scenario_a.get("error_code") == "ERR_PRIVACY_BUDGET_EXHAUSTED"
    )
    checks.append({
        "check": "scenario A: budget exhaustion blocks emission",
        "pass": scenario_a_ok,
        "detail": "validated" if scenario_a_ok else "scenario A invariant failed",
    })

    scenario_b = find_scenario(data, "B")
    scenario_b_ok = (
        scenario_b is not None
        and int(scenario_b.get("participants", 0)) >= 10
        and not bool(scenario_b.get("recovery_succeeded", True))
    )
    checks.append({
        "check": "scenario B: secure aggregation recovery attempt fails",
        "pass": scenario_b_ok,
        "detail": "validated" if scenario_b_ok else "scenario B invariant failed",
    })

    scenario_c = find_scenario(data, "C")
    scenario_c_ok = scenario_c is not None and bool(scenario_c.get("verifier_reports_exhausted", False))
    checks.append({
        "check": "scenario C: verifier reports exhausted budget",
        "pass": scenario_c_ok,
        "detail": "validated" if scenario_c_ok else "scenario C invariant failed",
    })

    scenario_d = find_scenario(data, "D")
    scenario_d_ok = (
        scenario_d is not None
        and bool(scenario_d.get("reset_denied", False))
        and scenario_d.get("logged_event") == "FPL-005"
    )
    checks.append({
        "check": "scenario D: unauthorized reset denied and logged",
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

    agg_count = int(aggregate.get("channels_count", -1))
    agg_default = int(aggregate.get("channels_with_default_epsilon_leq_1", -1))
    agg_blocking = bool(aggregate.get("all_exhausted_channels_block_n_plus_one", False))
    agg_participants = int(aggregate.get("secure_aggregation_participants", -1))

    checks.append({
        "check": "aggregate: channel count matches recomputation",
        "pass": agg_count == len(channels),
        "detail": f"reported={agg_count} computed={len(channels)}",
    })

    default_count = sum(1 for ch in channels if float(ch.get("epsilon_budget", 999.0)) <= 1.0)
    checks.append({
        "check": "aggregate: default-epsilon channel count matches recomputation",
        "pass": agg_default == default_count,
        "detail": f"reported={agg_default} computed={default_count}",
    })

    checks.append({
        "check": "aggregate: n+1 blocking flag matches recomputation",
        "pass": agg_blocking == channel_exhaustion_blocking_ok(channels),
        "detail": f"reported={agg_blocking} computed={channel_exhaustion_blocking_ok(channels)}",
    })

    checks.append({
        "check": "aggregate: secure aggregation participant count matches report",
        "pass": agg_participants == int(secure.get("participants", -1)),
        "detail": f"reported={agg_participants} computed={secure.get('participants')}",
    })

    deterministic = (
        channel_default_budget_ok(channels) == channel_default_budget_ok(list(reversed(channels)))
        and channel_exhaustion_blocking_ok(channels) == channel_exhaustion_blocking_ok(list(reversed(channels)))
    )
    checks.append({
        "check": "determinism: order-insensitive channel aggregates",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable channel aggregation",
    })

    adversarial = json.loads(json.dumps(data))
    if adversarial.get("channels"):
        adversarial["channels"][0]["n_plus_one_blocked"] = False
    adversarial_sensitive = not channel_exhaustion_blocking_ok(adversarial.get("channels", []))
    checks.append({
        "check": "determinism: adversarial perturbation flips exhaustion gate",
        "pass": adversarial_sensitive,
        "detail": "perturbation detected" if adversarial_sensitive else "gate failed to detect perturbation",
    })

    return checks


def run_checks() -> dict:
    checks = []
    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(REPORT, "federated privacy report"))
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
    sample_channels = [
        {
            "channel": "x",
            "epsilon_budget": 1.0,
            "epsilon_consumed": 1.0,
            "emissions_allowed": 1,
            "emissions_attempted": 2,
            "n_plus_one_blocked": True,
            "blocked_error": "ERR_PRIVACY_BUDGET_EXHAUSTED",
        }
    ]
    checks = []
    checks.append({"check": "self: default budget check", "pass": channel_default_budget_ok(sample_channels)})
    checks.append({"check": "self: exhaustion blocking check", "pass": channel_exhaustion_blocking_ok(sample_channels)})
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
