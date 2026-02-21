#!/usr/bin/env python3
"""Verification script for bd-28sz: >=95% compatibility corpus pass gate.

Usage:
    python3 scripts/check_compatibility_corpus_pass_gate.py
    python3 scripts/check_compatibility_corpus_pass_gate.py --json
    python3 scripts/check_compatibility_corpus_pass_gate.py --self-test --json
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-28sz"
SECTION = "13"
TITLE = "Concrete target gate: >=95% compatibility corpus pass"

CONTRACT = ROOT / "docs" / "specs" / "section_13" / "bd-28sz_contract.md"
REPORT = ROOT / "artifacts" / "13" / "compatibility_corpus_results.json"

REQUIRED_EVENT_CODES = ["CCG-001", "CCG-002", "CCG-003", "CCG-004"]
REQUIRED_RISK_BANDS = {"critical", "high", "medium", "low"}
REQUIRED_BANDS = {"core", "high-value", "edge"}
REQUIRED_FAMILIES = {
    "fs",
    "http",
    "net",
    "crypto",
    "stream",
    "buffer",
    "path",
    "os",
    "child_process",
    "cluster",
    "events",
    "timers",
    "url",
    "querystring",
    "zlib",
    "tls",
}
REQUIRED_CONTRACT_TERMS = [
    "INV-CCG-OVERALL",
    "INV-CCG-BAND",
    "INV-CCG-FAMILY-FLOOR",
    "INV-CCG-CORPUS-SIZE",
    "INV-CCG-TRACKING",
    "INV-CCG-REPRODUCIBILITY",
    "INV-CCG-RATCHET",
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


def pass_rate(passed: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((passed / total) * 100.0, 2)


def aggregate_by_key(per_tests: list[dict], key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for row in per_tests:
        k = str(row.get(key, ""))
        out.setdefault(k, {"total": 0, "passed": 0})
        out[k]["total"] += 1
        if row.get("status") == "pass":
            out[k]["passed"] += 1
    for value in out.values():
        value["pass_rate_pct"] = pass_rate(value["passed"], value["total"])
    return out


def evaluate_gate(data: dict) -> dict:
    per_tests = data.get("per_test_results", [])
    prev = data.get("previous_release", {})
    thresholds = data.get("thresholds", {})

    total = len(per_tests)
    passed = sum(1 for r in per_tests if r.get("status") == "pass")
    current_rate = pass_rate(passed, total)
    prev_rate = float(prev.get("overall_pass_rate_pct", 0.0))

    overall_threshold = float(thresholds.get("overall_pass_rate_min_pct", 95.0))
    family_floor = float(thresholds.get("per_family_pass_rate_min_pct", 80.0))
    band_thresholds = thresholds.get("band_pass_rate_min_pct", {})

    family_breakdown = aggregate_by_key(per_tests, "api_family")
    band_breakdown = aggregate_by_key(per_tests, "band")

    families_ok = all(v["pass_rate_pct"] >= family_floor for v in family_breakdown.values())
    bands_ok = all(
        band_breakdown.get(band, {"pass_rate_pct": -1.0})["pass_rate_pct"] >= float(req)
        for band, req in band_thresholds.items()
    )
    threshold_met = current_rate >= overall_threshold and families_ok and bands_ok
    regression = current_rate < prev_rate

    return {
        "current_rate": current_rate,
        "previous_rate": prev_rate,
        "overall_threshold": overall_threshold,
        "threshold_met": threshold_met,
        "regression_detected": regression,
        "release_blocked": (not threshold_met) or regression,
        "family_breakdown": family_breakdown,
        "band_breakdown": band_breakdown,
    }


def check_report(data: dict | None) -> list[dict]:
    if data is None:
        return []

    checks = []
    totals = data.get("totals", {})
    per_tests = data.get("per_test_results", [])
    families = data.get("api_families", [])
    bands = data.get("bands", [])
    failures = data.get("failing_tests_tracking", [])
    ci = data.get("ci_gate", {})
    reproducibility = data.get("reproducibility", {})

    total = int(totals.get("total_test_cases", 0))
    passed = int(totals.get("passed_test_cases", 0))
    failed = int(totals.get("failed_test_cases", 0))
    errored = int(totals.get("errored_test_cases", 0))
    skipped = int(totals.get("skipped_test_cases", 0))

    checks.append({
        "check": "corpus: total test cases >= 500",
        "pass": total >= 500,
        "detail": f"total={total}",
    })

    checks.append({
        "check": "corpus: per_test_results count matches total",
        "pass": len(per_tests) == total,
        "detail": f"per_test={len(per_tests)} total={total}",
    })

    checks.append({
        "check": "totals: count partition is consistent",
        "pass": total == (passed + failed + errored + skipped),
        "detail": f"total={total} partition={passed + failed + errored + skipped}",
    })

    recomputed_overall = pass_rate(sum(1 for r in per_tests if r.get("status") == "pass"), len(per_tests))
    reported_overall = float(totals.get("overall_pass_rate_pct", -1.0))
    checks.append({
        "check": "totals: overall pass rate matches recomputation",
        "pass": abs(recomputed_overall - reported_overall) < 0.01,
        "detail": f"reported={reported_overall} computed={recomputed_overall}",
    })

    family_names = {str(f.get("family")) for f in families}
    checks.append({
        "check": "coverage: all required API families present",
        "pass": REQUIRED_FAMILIES.issubset(family_names),
        "detail": f"present={len(family_names)} required={len(REQUIRED_FAMILIES)}",
    })

    per_test_family_names = {str(r.get("api_family")) for r in per_tests}
    checks.append({
        "check": "coverage: per-test family coverage includes required set",
        "pass": REQUIRED_FAMILIES.issubset(per_test_family_names),
        "detail": f"present={len(per_test_family_names)} required={len(REQUIRED_FAMILIES)}",
    })

    tags_valid = all(
        isinstance(r.get("test_id"), str)
        and r.get("api_family") in REQUIRED_FAMILIES
        and r.get("band") in REQUIRED_BANDS
        and r.get("risk_band") in REQUIRED_RISK_BANDS
        and r.get("status") in {"pass", "fail", "error", "skip"}
        for r in per_tests
    )
    checks.append({
        "check": "per-test: required tags and enums valid",
        "pass": tags_valid,
        "detail": "valid" if tags_valid else "invalid tag/value detected",
    })

    observed_risk_bands = {r.get("risk_band") for r in per_tests}
    checks.append({
        "check": "per-test: all risk bands represented",
        "pass": REQUIRED_RISK_BANDS.issubset(observed_risk_bands),
        "detail": f"observed={sorted(observed_risk_bands)}",
    })

    gate_eval = evaluate_gate(data)
    checks.append({
        "check": "gate: overall threshold >=95 met",
        "pass": gate_eval["current_rate"] >= gate_eval["overall_threshold"],
        "detail": f"current={gate_eval['current_rate']} threshold={gate_eval['overall_threshold']}",
    })

    family_floor = float(data.get("thresholds", {}).get("per_family_pass_rate_min_pct", 80.0))
    low_families = [
        fam for fam, stat in gate_eval["family_breakdown"].items()
        if stat["pass_rate_pct"] < family_floor
    ]
    checks.append({
        "check": "gate: no family below 80%",
        "pass": len(low_families) == 0,
        "detail": "all pass" if len(low_families) == 0 else f"below-floor={low_families}",
    })

    band_thresholds = data.get("thresholds", {}).get("band_pass_rate_min_pct", {})
    for band, threshold in band_thresholds.items():
        observed = gate_eval["band_breakdown"].get(band, {}).get("pass_rate_pct", -1.0)
        checks.append({
            "check": f"gate: band {band} >= {threshold}%",
            "pass": observed >= float(threshold),
            "detail": f"observed={observed}",
        })

    failure_ids = {
        r.get("test_id") for r in per_tests if r.get("status") in {"fail", "error"}
    }
    tracking_ids = {f.get("test_id") for f in failures}
    checks.append({
        "check": "tracking: failing tests have bead tracking entries",
        "pass": failure_ids.issubset(tracking_ids),
        "detail": f"failing={len(failure_ids)} tracked={len(tracking_ids)}",
    })

    tracking_shape_ok = all(
        isinstance(f.get("investigation_bead_id"), str)
        and f.get("investigation_bead_id", "").startswith("bd-")
        and f.get("investigation_status") in {"open", "in_progress", "closed"}
        for f in failures
    )
    checks.append({
        "check": "tracking: bead ids and statuses valid",
        "pass": tracking_shape_ok,
        "detail": "valid" if tracking_shape_ok else "invalid tracking entry",
    })

    checks.append({
        "check": "ci gate: report reflects met threshold and non-blocked release",
        "pass": bool(ci.get("threshold_met", False)) and not bool(ci.get("release_blocked", True)),
        "detail": f"threshold_met={ci.get('threshold_met')} release_blocked={ci.get('release_blocked')}",
    })

    checks.append({
        "check": "regression: no pass-rate decrease vs previous release",
        "pass": not gate_eval["regression_detected"],
        "detail": f"current={gate_eval['current_rate']} previous={gate_eval['previous_rate']}",
    })

    report_codes = data.get("event_codes", [])
    for code in REQUIRED_EVENT_CODES:
        checks.append({
            "check": f"events: {code}",
            "pass": code in report_codes,
            "detail": "present" if code in report_codes else "MISSING",
        })

    repro_ok = (
        isinstance(reproducibility.get("deterministic_seed"), str)
        and bool(reproducibility.get("same_inputs_same_digest", False))
        and isinstance(reproducibility.get("external_repro_command"), str)
        and len(reproducibility.get("external_repro_command", "")) > 0
    )
    checks.append({
        "check": "reproducibility: deterministic metadata complete",
        "pass": repro_ok,
        "detail": "complete" if repro_ok else "missing deterministic fields",
    })

    recomputed_family = aggregate_by_key(list(per_tests), "api_family")
    recomputed_band = aggregate_by_key(list(per_tests), "band")
    reversed_family = aggregate_by_key(list(reversed(per_tests)), "api_family")
    reversed_band = aggregate_by_key(list(reversed(per_tests)), "band")
    deterministic = (recomputed_family == reversed_family) and (recomputed_band == reversed_band)
    checks.append({
        "check": "determinism: order-insensitive aggregates",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable",
    })

    adversarial = json.loads(json.dumps(data))
    flips = 0
    for row in adversarial.get("per_test_results", []):
        if row.get("status") == "pass":
            row["status"] = "fail"
            flips += 1
        if flips >= 30:
            break
    adv_eval = evaluate_gate(adversarial)
    checks.append({
        "check": "adversarial: threshold drop blocks release",
        "pass": adv_eval["release_blocked"] and (not adv_eval["threshold_met"]),
        "detail": f"adversarial_rate={adv_eval['current_rate']} blocked={adv_eval['release_blocked']}",
    })

    return checks


def run_checks() -> dict:
    checks = []
    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(REPORT, "compatibility corpus report"))
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
        "totals": {"total_test_cases": 10, "passed_test_cases": 10},
        "per_test_results": [
            {"test_id": "a", "api_family": "fs", "band": "core", "risk_band": "critical", "status": "pass"},
            {"test_id": "b", "api_family": "http", "band": "core", "risk_band": "critical", "status": "pass"},
            {"test_id": "c", "api_family": "querystring", "band": "edge", "risk_band": "low", "status": "pass"},
        ],
        "thresholds": {
            "overall_pass_rate_min_pct": 95.0,
            "per_family_pass_rate_min_pct": 80.0,
            "band_pass_rate_min_pct": {"core": 99.0, "high-value": 95.0, "edge": 90.0},
        },
        "previous_release": {"overall_pass_rate_pct": 90.0},
    }
    checks = []
    checks.append({"check": "self: pass_rate helper", "pass": pass_rate(95, 100) == 95.0})
    checks.append({"check": "self: evaluate gate release blocked", "pass": evaluate_gate(sample)["release_blocked"]})
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
