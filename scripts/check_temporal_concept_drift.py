#!/usr/bin/env python3
"""Verification script for bd-v4ps: temporal concept drift controls.

Usage:
    python3 scripts/check_temporal_concept_drift.py
    python3 scripts/check_temporal_concept_drift.py --json
    python3 scripts/check_temporal_concept_drift.py --self-test --json
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD_ID = "bd-v4ps"
SECTION = "12"
TITLE = "Risk control: temporal concept drift"

CONTRACT = ROOT / "docs" / "specs" / "section_12" / "bd-v4ps_contract.md"
REPORT = ROOT / "artifacts" / "12" / "temporal_concept_drift_report.json"
EVIDENCE = ROOT / "artifacts" / "section_12" / "bd-v4ps" / "verification_evidence.json"

REQUIRED_EVENT_CODES = ["TCD-001", "TCD-002", "TCD-003", "TCD-004", "TCD-005"]
REQUIRED_CONTRACT_TERMS = [
    "INV-TCD-TTL",
    "INV-TCD-STALE-BLOCK",
    "INV-TCD-DRIFT-GATE",
    "INV-TCD-RECAL-PIPELINE",
    "INV-TCD-COHORT-REPORT",
    "Scenario A",
    "Scenario B",
    "Scenario C",
    "Scenario D",
]
REQUIRED_PIPELINE_COMMANDS = [
    "python3 scripts/check_temporal_concept_drift.py --self-test --json",
    "python3 scripts/check_temporal_concept_drift.py --json",
    "python3 -m unittest tests/test_check_temporal_concept_drift.py",
]
REQUIRED_PIPELINE_SOURCE_PATHS = [
    "artifacts/12/temporal_concept_drift_report.json",
    "docs/specs/section_12/bd-v4ps_contract.md",
    "scripts/check_temporal_concept_drift.py",
    "tests/test_check_temporal_concept_drift.py",
]
PIPELINE_EXECUTION_MODE = "deterministic_fixture_replay"
COHORT_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_json(path: Path) -> dict:
    return json.JSONDecoder().decode(_read_text(path))


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

    text = _read_text(CONTRACT)
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
        data = _read_json(REPORT)
    except (json.JSONDecodeError, OSError):
        checks.append({"check": "report: valid json", "pass": False, "detail": "invalid"})
        return None, checks
    if not isinstance(data, dict):
        checks.append({"check": "report: valid json", "pass": False, "detail": "not an object"})
        return None, checks

    checks.append({"check": "report: valid json", "pass": True, "detail": "valid"})
    return data, checks


def load_evidence() -> tuple[dict | None, list[dict]]:
    checks = []
    if not EVIDENCE.exists():
        checks.append({"check": "evidence: exists", "pass": False, "detail": "MISSING"})
        return None, checks

    checks.append({"check": "evidence: exists", "pass": True, "detail": "found"})
    try:
        data = _read_json(EVIDENCE)
    except (json.JSONDecodeError, OSError):
        checks.append({"check": "evidence: valid json", "pass": False, "detail": "invalid"})
        return None, checks
    if not isinstance(data, dict):
        checks.append({"check": "evidence: valid json", "pass": False, "detail": "not an object"})
        return None, checks

    checks.append({"check": "evidence: valid json", "pass": True, "detail": "valid"})
    return data, checks


def evaluate_models(data: dict) -> dict:
    models = data.get("models", [])
    stale = [m for m in models if bool(m.get("stale", False))]
    drift_threshold = float(data.get("aggregate", {}).get("drift_threshold_pct", 5.0))
    drifted = [m for m in models if float(m.get("drift_delta_pct", 0.0)) > drift_threshold]
    stale_blocked = all(bool(m.get("deployment_blocked", False)) for m in stale)
    recal_ok = all(
        (not bool(m.get("recalibration_triggered", False))) or isinstance(m.get("recalibration_run_id"), str)
        for m in models
    )
    return {
        "models_total": len(models),
        "models_stale": len(stale),
        "stale_models_blocked": stale_blocked,
        "models_exceeding_drift_threshold": len(drifted),
        "recalibration_run_ids_valid": recal_ok,
        "drift_threshold_pct": drift_threshold,
    }


def _evidence_command_statuses(evidence: dict | None) -> dict[str, str]:
    if not isinstance(evidence, dict):
        return {}
    commands = evidence.get("commands", [])
    if not isinstance(commands, list):
        return {}
    statuses: dict[str, str] = {}
    for item in commands:
        if not isinstance(item, dict):
            continue
        command = item.get("command")
        status = item.get("status")
        if isinstance(command, str) and isinstance(status, str):
            statuses[command] = status.lower()
    return statuses


def check_recalibration_pipeline(data: dict, evidence: dict | None) -> tuple[list[dict], bool]:
    checks = []
    pipeline = data.get("recalibration_pipeline", {})
    if not isinstance(pipeline, dict):
        checks.append({
            "check": "pipeline: object present",
            "pass": False,
            "detail": "missing or invalid recalibration_pipeline",
        })
        return checks, False

    execution_mode_ok = pipeline.get("execution_mode") == PIPELINE_EXECUTION_MODE
    checks.append({
        "check": "pipeline: fixture execution mode is explicit",
        "pass": execution_mode_ok,
        "detail": str(pipeline.get("execution_mode", "MISSING")),
    })

    fixture_classification_ok = (
        bool(pipeline.get("synthetic_data_run", False))
        and bool(pipeline.get("fixture_only", False))
        and not bool(pipeline.get("live_recalibration_claimed", True))
    )
    checks.append({
        "check": "pipeline: synthetic fixture is not claimed as live recalibration",
        "pass": fixture_classification_ok,
        "detail": "fixture-only boundary explicit" if fixture_classification_ok else "missing fixture-only or live-claim guard",
    })

    completion_ok = bool(pipeline.get("completed_without_errors", False)) and float(pipeline.get("duration_seconds", 0.0)) > 0.0
    checks.append({
        "check": "pipeline: fixture replay completed without errors",
        "pass": completion_ok,
        "detail": "completed" if completion_ok else "pipeline failed/incomplete",
    })

    pipeline_evidence = pipeline.get("evidence", {})
    source_paths = pipeline_evidence.get("source_paths", []) if isinstance(pipeline_evidence, dict) else []
    required_sources_present = all(path in source_paths for path in REQUIRED_PIPELINE_SOURCE_PATHS)
    required_sources_exist = all((ROOT / path).exists() for path in REQUIRED_PIPELINE_SOURCE_PATHS)
    source_backed = required_sources_present and required_sources_exist
    checks.append({
        "check": "pipeline: fixture evidence source paths exist",
        "pass": source_backed,
        "detail": "all required source paths present" if source_backed else "missing required source path evidence",
    })

    statuses = _evidence_command_statuses(evidence)
    missing_commands = [command for command in REQUIRED_PIPELINE_COMMANDS if statuses.get(command) != "pass"]
    command_backed = not missing_commands
    checks.append({
        "check": "pipeline: verification commands are recorded as passing",
        "pass": command_backed,
        "detail": "all required commands pass" if command_backed else f"missing/failing: {', '.join(missing_commands)}",
    })

    return checks, all(check["pass"] for check in checks)


def check_report(data: dict | None, evidence: dict | None = None) -> list[dict]:
    if data is None:
        return []

    if evidence is None:
        evidence, _ = load_evidence()

    checks = []
    models = data.get("models", [])
    aggregate = data.get("aggregate", {})

    checks.append({
        "check": "models: at least one model exists",
        "pass": len(models) > 0,
        "detail": f"models={len(models)}",
    })

    ttl_fields_ok = all(
        isinstance(m.get("ttl_days"), int)
        and m.get("ttl_days") > 0
        and isinstance(m.get("last_calibrated_at"), str)
        and len(m.get("last_calibrated_at")) > 0
        for m in models
    )
    checks.append({
        "check": "models: ttl and calibration timestamp metadata present",
        "pass": ttl_fields_ok,
        "detail": "all models have TTL + timestamp" if ttl_fields_ok else "missing ttl/timestamp metadata",
    })

    stale_consistency = all(bool(m.get("stale", False)) == (int(m.get("age_days", -1)) > int(m.get("ttl_days", 0))) for m in models)
    checks.append({
        "check": "staleness: stale flag matches age > ttl",
        "pass": stale_consistency,
        "detail": "consistent" if stale_consistency else "stale mismatch detected",
    })

    stale_blocked = all(
        (not bool(m.get("stale", False))) or bool(m.get("deployment_blocked", False))
        for m in models
    )
    checks.append({
        "check": "staleness: stale models are deployment-blocked",
        "pass": stale_blocked,
        "detail": "all stale models blocked" if stale_blocked else "stale model not blocked",
    })

    drift_delta_consistency = all(
        abs(float(m.get("drift_delta_pct", 0.0)) - round(float(m.get("all_time_accuracy_pct", 0.0)) + (-float(m.get("recent_30d_accuracy_pct", 0.0))), 1)) < 0.11
        for m in models
    )
    checks.append({
        "check": "drift: reported delta matches accuracy difference",
        "pass": drift_delta_consistency,
        "detail": "consistent" if drift_delta_consistency else "drift delta mismatch",
    })

    drift_trigger_ok = all(
        (float(m.get("drift_delta_pct", 0.0)) <= 5.0) or bool(m.get("recalibration_triggered", False))
        for m in models
    )
    checks.append({
        "check": "drift: >5% delta triggers recalibration",
        "pass": drift_trigger_ok,
        "detail": "trigger policy satisfied" if drift_trigger_ok else "missing recalibration trigger",
    })

    recalibration_runs_ok = all(
        (not bool(m.get("recalibration_triggered", False))) or (
            isinstance(m.get("recalibration_run_id"), str) and len(m.get("recalibration_run_id", "")) > 0
        )
        for m in models
    )
    checks.append({
        "check": "recalibration: triggered models include run id",
        "pass": recalibration_runs_ok,
        "detail": "all triggered models have run ids" if recalibration_runs_ok else "missing run id",
    })

    improvement_ok = all(
        (m.get("recent_post_recalibration_accuracy_pct") is None)
        or (float(m.get("recent_post_recalibration_accuracy_pct", 0.0)) >= float(m.get("recent_30d_accuracy_pct", 0.0)))
        for m in models
    )
    checks.append({
        "check": "recalibration: post-recalibration recent accuracy does not regress",
        "pass": improvement_ok,
        "detail": "improvement/non-regression satisfied" if improvement_ok else "post-recalibration regression detected",
    })

    pipeline_checks, pipeline_ok = check_recalibration_pipeline(data, evidence)
    checks.extend(pipeline_checks)

    cohort = data.get("cohort_accuracy", [])
    cohort_shape_ok = len(cohort) > 0 and all(
        COHORT_MONTH_RE.match(str(c.get("cohort_month", ""))) and 0.0 <= float(c.get("accuracy_pct", -1.0)) <= 100.0
        for c in cohort
    )
    checks.append({
        "check": "cohort: monthly cohort accuracy breakdown present",
        "pass": cohort_shape_ok,
        "detail": f"cohorts={len(cohort)}" if cohort_shape_ok else "invalid cohort breakdown",
    })

    scenario_a = next((s for s in data.get("scenarios", []) if s.get("scenario") == "A"), None)
    scenario_a_ok = (
        scenario_a is not None
        and bool(scenario_a.get("staleness_alert_fired", False))
        and bool(scenario_a.get("deployment_blocked", False))
    )
    checks.append({
        "check": "scenario A: stale model triggers alert and deployment block",
        "pass": scenario_a_ok,
        "detail": "validated" if scenario_a_ok else "scenario A invariant failed",
    })

    scenario_b = next((s for s in data.get("scenarios", []) if s.get("scenario") == "B"), None)
    scenario_b_ok = (
        scenario_b is not None
        and float(scenario_b.get("drift_delta_pct", 0.0)) > 5.0
        and bool(scenario_b.get("recalibration_triggered", False))
    )
    checks.append({
        "check": "scenario B: >5% drift triggers recalibration",
        "pass": scenario_b_ok,
        "detail": "validated" if scenario_b_ok else "scenario B invariant failed",
    })

    scenario_c = next((s for s in data.get("scenarios", []) if s.get("scenario") == "C"), None)
    scenario_c_ok = (
        scenario_c is not None
        and float(scenario_c.get("post_recalibration_accuracy_pct", 0.0)) > float(scenario_c.get("pre_recalibration_accuracy_pct", 0.0))
        and bool(scenario_c.get("improved", False))
    )
    checks.append({
        "check": "scenario C: recalibration improves recent cohort accuracy",
        "pass": scenario_c_ok,
        "detail": "validated" if scenario_c_ok else "scenario C invariant failed",
    })

    scenario_d = next((s for s in data.get("scenarios", []) if s.get("scenario") == "D"), None)
    scenario_d_ok = (
        scenario_d is not None
        and int(scenario_d.get("cohorts_reported", 0)) >= 1
    )
    checks.append({
        "check": "scenario D: cohort breakdown reported",
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

    eval_out = evaluate_models(data)
    checks.append({
        "check": "aggregate: models_total matches recomputation",
        "pass": int(aggregate.get("models_total", -1)) == eval_out["models_total"],
        "detail": f"reported={aggregate.get('models_total')} computed={eval_out['models_total']}",
    })
    checks.append({
        "check": "aggregate: models_stale matches recomputation",
        "pass": int(aggregate.get("models_stale", -1)) == eval_out["models_stale"],
        "detail": f"reported={aggregate.get('models_stale')} computed={eval_out['models_stale']}",
    })
    checks.append({
        "check": "aggregate: stale_models_blocked matches recomputation",
        "pass": bool(aggregate.get("stale_models_blocked", False)) == eval_out["stale_models_blocked"],
        "detail": f"reported={aggregate.get('stale_models_blocked')} computed={eval_out['stale_models_blocked']}",
    })
    checks.append({
        "check": "aggregate: models_exceeding_drift_threshold matches recomputation",
        "pass": int(aggregate.get("models_exceeding_drift_threshold", -1)) == eval_out["models_exceeding_drift_threshold"],
        "detail": f"reported={aggregate.get('models_exceeding_drift_threshold')} computed={eval_out['models_exceeding_drift_threshold']}",
    })
    checks.append({
        "check": "aggregate: recalibration pipeline pass flag true",
        "pass": bool(aggregate.get("recalibration_pipeline_passed", False)) == pipeline_ok and pipeline_ok,
        "detail": f"reported={aggregate.get('recalibration_pipeline_passed')} computed={pipeline_ok}",
    })

    deterministic = evaluate_models({"models": list(models), "aggregate": {"drift_threshold_pct": 5.0}}) == evaluate_models({"models": list(reversed(models)), "aggregate": {"drift_threshold_pct": 5.0}})
    checks.append({
        "check": "determinism: order-insensitive model aggregation",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable",
    })

    adversarial = copy.deepcopy(data)
    for m in adversarial.get("models", []):
        if bool(m.get("stale", False)):
            m["deployment_blocked"] = False
            break
    adversarial_detected = not evaluate_models(adversarial)["stale_models_blocked"]
    checks.append({
        "check": "adversarial: stale-model unblock attempt is detected",
        "pass": adversarial_detected,
        "detail": "detected" if adversarial_detected else "not detected",
    })

    return checks


def run_checks() -> dict:
    checks = []
    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(REPORT, "temporal drift report"))
    checks.append(check_file(EVIDENCE, "verification evidence"))
    checks.extend(check_contract())
    data, load_checks = load_report()
    checks.extend(load_checks)
    evidence, evidence_checks = load_evidence()
    checks.extend(evidence_checks)
    checks.extend(check_report(data, evidence))

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
        "models": [
            {
                "ttl_days": 1,
                "age_days": 2,
                "stale": True,
                "deployment_blocked": True,
                "counterfactual": {},
                "all_time_accuracy_pct": 90.0,
                "recent_30d_accuracy_pct": 80.0,
                "drift_delta_pct": 10.0,
                "recalibration_triggered": True,
                "recalibration_run_id": "x"
            }
        ],
        "aggregate": {"drift_threshold_pct": 5.0}
    }
    pipeline_sample = {
        "recalibration_pipeline": {
            "execution_mode": PIPELINE_EXECUTION_MODE,
            "synthetic_data_run": True,
            "fixture_only": True,
            "live_recalibration_claimed": False,
            "completed_without_errors": True,
            "duration_seconds": 1,
            "evidence": {"source_paths": list(REQUIRED_PIPELINE_SOURCE_PATHS)},
        }
    }
    evidence_sample = {
        "commands": [
            {"command": command, "status": "pass"}
            for command in REQUIRED_PIPELINE_COMMANDS
        ]
    }
    live_claim_sample = copy.deepcopy(pipeline_sample)
    live_claim_sample["recalibration_pipeline"]["live_recalibration_claimed"] = True
    checks = []
    checks.append({"check": "self: evaluate_models", "pass": evaluate_models(sample)["models_stale"] == 1})
    checks.append({"check": "self: stale blocked", "pass": evaluate_models(sample)["stale_models_blocked"]})
    checks.append({
        "check": "self: fixture pipeline accepted",
        "pass": check_recalibration_pipeline(pipeline_sample, evidence_sample)[1],
    })
    checks.append({
        "check": "self: live-claiming fixture rejected",
        "pass": not check_recalibration_pipeline(live_claim_sample, evidence_sample)[1],
    })
    return all(c["pass"] for c in checks), checks


def main() -> int:
    configure_test_logging("check_temporal_concept_drift")
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
