#!/usr/bin/env python3
"""Verification script for bd-2w4u: hardening perf regression guardrails.

Usage:
    python3 scripts/check_hardening_perf_regression.py
    python3 scripts/check_hardening_perf_regression.py --json
    python3 scripts/check_hardening_perf_regression.py --self-test --json
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-2w4u"
SECTION = "12"
TITLE = "Risk control: hardening perf regression"

CONTRACT = ROOT / "docs" / "specs" / "section_12" / "bd-2w4u_contract.md"
REPORT = ROOT / "artifacts" / "12" / "hardening_perf_regression_report.json"

REQUIRED_EVENT_CODES = ["HPR-001", "HPR-002", "HPR-003", "HPR-004", "HPR-005"]
REQUIRED_CONTRACT_TERMS = [
    "INV-HPR-PROFILES",
    "INV-HPR-P99-GATE",
    "INV-HPR-THROUGHPUT-GATE",
    "INV-HPR-RUNTIME-SWITCH",
    "INV-HPR-CI-REGRESSION",
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


def find_profile(data: dict, name: str) -> dict | None:
    profiles = data.get("profiles", [])
    for profile in profiles:
        if profile.get("name") == name:
            return profile
    return None


def p99_overhead_pct(data: dict, profile_name: str) -> float:
    baseline = find_profile(data, "unhardened")
    profile = find_profile(data, profile_name)
    if not baseline or not profile:
        return 0.0

    baseline_p99 = float(baseline.get("p99_latency_ms", 0.0))
    profile_p99 = float(profile.get("p99_latency_ms", 0.0))
    if baseline_p99 <= 0:
        return 0.0
    return round(((profile_p99 - baseline_p99) / baseline_p99) * 100.0, 1)


def throughput_retention_pct(data: dict, profile_name: str) -> float:
    baseline = find_profile(data, "unhardened")
    profile = find_profile(data, profile_name)
    if not baseline or not profile:
        return 0.0

    baseline_tput = float(baseline.get("throughput_rps", 0.0))
    profile_tput = float(profile.get("throughput_rps", 0.0))
    if baseline_tput <= 0:
        return 0.0
    return round((profile_tput / baseline_tput) * 100.0, 1)


def check_benchmark_blocking(ci_runs: list[dict]) -> tuple[bool, str]:
    for run in ci_runs:
        regression = float(run.get("regression_pct", 0.0))
        blocked = bool(run.get("blocked_merge", False))
        if regression > 5.0 and not blocked:
            return False, f"regression {regression}% not blocked in {run.get('pr')}"
    return True, "all regressions >5% blocked"


def scenario_by_id(data: dict, scenario_id: str) -> dict | None:
    for scenario in data.get("scenarios", []):
        if scenario.get("scenario") == scenario_id:
            return scenario
    return None


def check_report(data: dict | None) -> list[dict]:
    if data is None:
        return []

    checks = []
    profiles = data.get("profiles", [])
    aggregate = data.get("aggregate", {})

    baseline = find_profile(data, "unhardened")
    strict = find_profile(data, "strict")
    balanced = find_profile(data, "balanced")
    permissive = find_profile(data, "permissive")

    checks.append({
        "check": "profiles: baseline exists",
        "pass": baseline is not None,
        "detail": "found" if baseline else "MISSING baseline profile",
    })
    checks.append({
        "check": "profiles: strict exists",
        "pass": strict is not None,
        "detail": "found" if strict else "MISSING strict profile",
    })
    checks.append({
        "check": "profiles: balanced exists",
        "pass": balanced is not None,
        "detail": "found" if balanced else "MISSING balanced profile",
    })
    checks.append({
        "check": "profiles: permissive exists",
        "pass": permissive is not None,
        "detail": "found" if permissive else "MISSING permissive profile",
    })

    hardening_profiles = [p for p in profiles if p.get("name") in {"strict", "balanced", "permissive"}]
    checks.append({
        "check": "profiles: at least 3 hardening profiles",
        "pass": len(hardening_profiles) >= 3,
        "detail": f"count={len(hardening_profiles)}",
    })

    tradeoffs_documented = all(
        isinstance(p.get("tradeoff"), str) and len(p.get("tradeoff", "").strip()) > 0
        for p in hardening_profiles
    )
    checks.append({
        "check": "profiles: tradeoffs documented",
        "pass": tradeoffs_documented,
        "detail": "all documented" if tradeoffs_documented else "missing tradeoff docs",
    })

    balanced_p99 = p99_overhead_pct(data, "balanced")
    checks.append({
        "check": "balanced gate: p99 overhead <= 15%",
        "pass": balanced_p99 <= 15.0,
        "detail": f"overhead={balanced_p99}%",
    })

    balanced_tput = throughput_retention_pct(data, "balanced")
    checks.append({
        "check": "balanced gate: throughput >= 85%",
        "pass": balanced_tput >= 85.0,
        "detail": f"retention={balanced_tput}%",
    })

    switch = data.get("runtime_profile_switch", {})
    switch_ok = (
        bool(switch.get("runtime_reconfigurable", False))
        and not bool(switch.get("requires_restart", True))
        and int(switch.get("request_failures", 1)) == 0
    )
    checks.append({
        "check": "runtime switch: reconfigurable without restart and no failures",
        "pass": switch_ok,
        "detail": "validated" if switch_ok else "runtime switch invariant failed",
    })

    scenario_a = scenario_by_id(data, "A")
    scenario_a_ok = (
        scenario_a is not None
        and scenario_a.get("name") == "strict-profile-benchmark"
        and bool(scenario_a.get("documented", False))
        and float(scenario_a.get("overhead_pct", 0.0)) > 0.0
    )
    checks.append({
        "check": "scenario A: strict profile benchmark documented",
        "pass": scenario_a_ok,
        "detail": "validated" if scenario_a_ok else "scenario A invariant failed",
    })

    scenario_b = scenario_by_id(data, "B")
    scenario_b_ok = (
        scenario_b is not None
        and bool(scenario_b.get("p99_within_15pct", False))
        and bool(scenario_b.get("throughput_at_least_85pct", False))
    )
    checks.append({
        "check": "scenario B: balanced profile gate pass",
        "pass": scenario_b_ok,
        "detail": "validated" if scenario_b_ok else "scenario B invariant failed",
    })

    scenario_c = scenario_by_id(data, "C")
    scenario_c_ok = (
        scenario_c is not None
        and float(scenario_c.get("injected_latency_regression_pct", 0.0)) >= 20.0
        and bool(scenario_c.get("ci_blocked_merge", False))
    )
    checks.append({
        "check": "scenario C: 20% regression blocked by CI",
        "pass": scenario_c_ok,
        "detail": "validated" if scenario_c_ok else "scenario C invariant failed",
    })

    scenario_d = scenario_by_id(data, "D")
    scenario_d_ok = (
        scenario_d is not None
        and bool(scenario_d.get("switch_without_restart", False))
        and int(scenario_d.get("request_failures", 1)) == 0
    )
    checks.append({
        "check": "scenario D: runtime switch under load no failures",
        "pass": scenario_d_ok,
        "detail": "validated" if scenario_d_ok else "scenario D invariant failed",
    })

    ci_runs = data.get("ci_benchmark_runs", [])
    ci_ok, ci_detail = check_benchmark_blocking(ci_runs)
    checks.append({
        "check": "continuous benchmarking: regressions >5% block merge",
        "pass": ci_ok,
        "detail": ci_detail,
    })

    checks.append({
        "check": "continuous benchmarking: at least one blocked regression sample",
        "pass": any(float(r.get("regression_pct", 0.0)) > 5.0 and bool(r.get("blocked_merge", False)) for r in ci_runs),
        "detail": "present" if any(float(r.get("regression_pct", 0.0)) > 5.0 and bool(r.get("blocked_merge", False)) for r in ci_runs) else "MISSING blocked sample",
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

    aggregate_p99 = float(aggregate.get("balanced_p99_overhead_pct", -1.0))
    aggregate_tput = float(aggregate.get("balanced_throughput_retention_pct", -1.0))
    aggregate_profiles = int(aggregate.get("hardening_profiles_count", -1))

    checks.append({
        "check": "aggregate: balanced p99 overhead matches recomputation",
        "pass": abs(aggregate_p99 - balanced_p99) < 0.11,
        "detail": f"reported={aggregate_p99} computed={balanced_p99}",
    })
    checks.append({
        "check": "aggregate: balanced throughput retention matches recomputation",
        "pass": abs(aggregate_tput - balanced_tput) < 0.11,
        "detail": f"reported={aggregate_tput} computed={balanced_tput}",
    })
    checks.append({
        "check": "aggregate: hardening profile count matches recomputation",
        "pass": aggregate_profiles == len(hardening_profiles),
        "detail": f"reported={aggregate_profiles} computed={len(hardening_profiles)}",
    })

    deterministic = (
        p99_overhead_pct({"profiles": list(reversed(profiles))}, "balanced") == balanced_p99
        and throughput_retention_pct({"profiles": list(reversed(profiles))}, "balanced") == balanced_tput
    )
    checks.append({
        "check": "determinism: order-insensitive aggregate metrics",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable aggregation",
    })

    adversarial = json.loads(json.dumps(data))
    baseline_adv = find_profile(adversarial, "unhardened")
    balanced_adv = find_profile(adversarial, "balanced")
    if baseline_adv and balanced_adv:
        balanced_adv["p99_latency_ms"] = round(float(baseline_adv["p99_latency_ms"]) * 1.25, 1)
    adversarial_p99 = p99_overhead_pct(adversarial, "balanced")
    adversarial_sensitive = adversarial_p99 > 15.0
    checks.append({
        "check": "determinism: adversarial perturbation flips p99 gate",
        "pass": adversarial_sensitive,
        "detail": f"adversarial_overhead={adversarial_p99}%",
    })

    return checks


def run_checks() -> dict:
    checks = []
    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(REPORT, "hardening perf report"))
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
    sample = {
        "profiles": [
            {"name": "unhardened", "p99_latency_ms": 10.0, "throughput_rps": 100.0},
            {"name": "balanced", "p99_latency_ms": 11.0, "throughput_rps": 90.0},
        ],
        "ci_benchmark_runs": [{"pr": "#x", "regression_pct": 6.0, "blocked_merge": True}],
    }
    checks = []
    checks.append({"check": "self: p99 overhead calc", "pass": p99_overhead_pct(sample, "balanced") == 10.0})
    checks.append({"check": "self: throughput retention calc", "pass": throughput_retention_pct(sample, "balanced") == 90.0})
    ci_ok, _ = check_benchmark_blocking(sample["ci_benchmark_runs"])
    checks.append({"check": "self: regression blocking", "pass": ci_ok})
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
