#!/usr/bin/env python3
"""Verification script for bd-35m7: trajectory-gaming camouflage.

Usage:
    python3 scripts/check_trajectory_gaming_camouflage.py
    python3 scripts/check_trajectory_gaming_camouflage.py --json
    python3 scripts/check_trajectory_gaming_camouflage.py --self-test --json
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD_ID = "bd-35m7"
SECTION = "12"
TITLE = "Risk control: trajectory-gaming camouflage"

CONTRACT = ROOT / "docs" / "specs" / "section_12" / "bd-35m7_contract.md"
REPORT = ROOT / "artifacts" / "12" / "trajectory_gaming_camouflage_report.json"

REQUIRED_EVENT_CODES = ["TGC-001", "TGC-002", "TGC-003", "TGC-004", "TGC-005"]
REQUIRED_CONTRACT_TERMS = [
    "INV-TGC-MIMICRY-CORPUS",
    "INV-TGC-RECALL",
    "INV-TGC-HYBRID-FUSION",
    "INV-TGC-RANDOMIZATION",
    "INV-TGC-ADAPTIVE",
    "Scenario A",
    "Scenario B",
    "Scenario C",
    "Scenario D",
    "Scenario E",
]
RUST_INTEGRATION_SYMBOLS = [
    (
        "trajectory runtime contract",
        ROOT / "crates" / "franken-node" / "src" / "security" / "trajectory_gaming.rs",
        ["CamouflageHint", "ingest_verifier_hints", "export_runtime_trajectory"],
    ),
    (
        "in-process camouflage detector",
        ROOT / "crates" / "franken-node" / "src" / "security" / "bpet" / "camouflage_detector.rs",
        ["detect_camouflage", "DetectorConfig"],
    ),
    (
        "camouflage fixture harness",
        ROOT / "crates" / "franken-node" / "src" / "security" / "bpet" / "camouflage_fixtures.rs",
        ["load_camouflage_fixture", "evaluate_camouflage_fixture"],
    ),
    (
        "trust-card camouflage mark",
        ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "trust_card.rs",
        ["mark_camouflage_suspected", "TRUST_CARD_CAMOUFLAGE_SUSPECTED"],
    ),
    (
        "trust-card camouflage integration test",
        ROOT
        / "crates"
        / "franken-node"
        / "tests"
        / "trust_card_authoritative_state_real_inputs.rs",
        ["authoritative_registry_marks_camouflage_hints_on_signed_card"],
    ),
    (
        "camouflage detector integration test",
        ROOT / "tests" / "security" / "camouflage_detector.rs",
        ["evaluate_camouflage_fixture", "fixture_phase_shift_clear_emits_phase_shift_hint"],
    ),
]

RUNTIME_EXPORT_FORBIDDEN_TOKENS = [
    "export_for_verifier",
    "tgc-runtime-placeholder",
    "Sub-task 1 of bd-35m7 only establishes the contract",
    "Sub-tasks 2-4 will replace placeholders",
    '"pattern_count": 0',
    '"scenarios": []',
]


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


def check_rust_integration() -> list[dict]:
    checks = []
    for label, path, symbols in RUST_INTEGRATION_SYMBOLS:
        exists = path.exists()
        checks.append({
            "check": f"rust: {label} path exists",
            "pass": exists,
            "detail": f"exists: {path.relative_to(ROOT)}" if exists else f"MISSING: {path}",
        })
        if not exists:
            for symbol in symbols:
                checks.append({
                    "check": f"rust: {label} symbol {symbol}",
                    "pass": False,
                    "detail": "MISSING file",
                })
            continue

        text = _read_text(path)
        for symbol in symbols:
            present = symbol in text
            checks.append({
                "check": f"rust: {label} symbol {symbol}",
                "pass": present,
                "detail": "present" if present else f"MISSING: {symbol}",
            })
    return checks


def check_runtime_export_truthfulness() -> list[dict]:
    path = ROOT / "crates" / "franken-node" / "src" / "security" / "trajectory_gaming.rs"
    if not path.exists():
        return [{
            "check": "rust: trajectory runtime export truthfulness",
            "pass": False,
            "detail": f"MISSING: {path}",
        }]

    text = _read_text(path)
    checks = []
    for token in RUNTIME_EXPORT_FORBIDDEN_TOKENS:
        present = token in text
        checks.append({
            "check": f"rust: trajectory runtime export forbids {token}",
            "pass": not present,
            "detail": "absent" if not present else f"FORBIDDEN token present: {token}",
        })
    checks.append({
        "check": "rust: trajectory runtime export declares non-analysis status",
        "pass": "analysis_ready" in text and "TGC_RUNTIME_TRAJECTORY_ONLY" in text,
        "detail": "present" if "analysis_ready" in text and "TGC_RUNTIME_TRAJECTORY_ONLY" in text else "missing",
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


def scenario_lookup(data: dict, scenario_id: str) -> dict | None:
    for scenario in data.get("scenarios", []):
        if scenario.get("scenario") == scenario_id:
            return scenario
    return None


def motif_subset_hashes(data: dict) -> list[str]:
    evaluations = data.get("motif_randomization", {}).get("evaluations", [])
    return [str(e.get("feature_subset_hash", "")).strip() for e in evaluations if str(e.get("feature_subset_hash", "")).strip()]


def fusion_flags_non_behavioral_failures(data: dict) -> bool:
    adjudications = data.get("hybrid_signal_fusion", {}).get("adjudications", [])
    if not adjudications:
        return False

    for item in adjudications:
        provenance_pass = bool(item.get("provenance_pass", False))
        code_pass = bool(item.get("code_analysis_pass", False))
        reputation_pass = bool(item.get("reputation_pass", False))
        flagged = bool(item.get("flagged", False))
        non_behavioral_failure = (not provenance_pass) or (not code_pass) or (not reputation_pass)
        if non_behavioral_failure and not flagged:
            return False
    return True


def evaluate_policy(data: dict) -> dict:
    corpus = data.get("mimicry_corpus", {})
    model = data.get("detection_model", {})
    motif = data.get("motif_randomization", {})

    subset_hashes = motif_subset_hashes(data)
    unique_subsets = len(subset_hashes) >= 2 and len(set(subset_hashes)) == len(subset_hashes)

    adaptive_rounds = [float(x) for x in model.get("adaptive_round_recall_pct", [])]
    adaptive_min = min(adaptive_rounds) if adaptive_rounds else 0.0

    return {
        "pattern_count": int(corpus.get("pattern_count", 0)),
        "quarterly_update_ok": int(corpus.get("update_interval_days", 999)) <= int(corpus.get("quarterly_update_required_days", 92)),
        "known_recall_pct": float(model.get("known_mimicry_recall_pct", 0.0)),
        "known_threshold_pct": float(model.get("known_mimicry_threshold_pct", 90.0)),
        "adaptive_rounds": int(model.get("adaptive_attack_rounds", 0)),
        "adaptive_min_recall_pct": adaptive_min,
        "adaptive_threshold_pct": float(model.get("adaptive_recall_threshold_pct", 80.0)),
        "motif_unique_subsets": unique_subsets and bool(motif.get("subsets_unique", False)),
        "fusion_flags_non_behavioral_failures": fusion_flags_non_behavioral_failures(data),
    }


def check_report(data: dict | None) -> list[dict]:
    if data is None:
        return []

    checks = []
    corpus = data.get("mimicry_corpus", {})
    model = data.get("detection_model", {})
    fusion = data.get("hybrid_signal_fusion", {})
    aggregate = data.get("aggregate", {})

    eval_out = evaluate_policy(data)

    checks.append({
        "check": "mimicry corpus: pattern count >=100",
        "pass": eval_out["pattern_count"] >= 100,
        "detail": f"pattern_count={eval_out['pattern_count']}",
    })

    checks.append({
        "check": "mimicry corpus: refreshed at least quarterly",
        "pass": eval_out["quarterly_update_ok"],
        "detail": (
            f"interval_days={corpus.get('update_interval_days')} required<={corpus.get('quarterly_update_required_days')}"
        ),
    })

    checks.append({
        "check": "detection: known-mimicry recall >=90%",
        "pass": eval_out["known_recall_pct"] >= eval_out["known_threshold_pct"] and eval_out["known_threshold_pct"] >= 90.0,
        "detail": f"recall={eval_out['known_recall_pct']} threshold={eval_out['known_threshold_pct']}",
    })

    checks.append({
        "check": "detection: adaptive adversary rounds == 10",
        "pass": eval_out["adaptive_rounds"] == 10,
        "detail": f"rounds={eval_out['adaptive_rounds']}",
    })

    checks.append({
        "check": "detection: adaptive minimum recall >=80%",
        "pass": eval_out["adaptive_min_recall_pct"] >= eval_out["adaptive_threshold_pct"] and eval_out["adaptive_threshold_pct"] >= 80.0,
        "detail": f"min_recall={eval_out['adaptive_min_recall_pct']} threshold={eval_out['adaptive_threshold_pct']}",
    })

    channels = set(fusion.get("channels", []))
    required_channels = {"behavioral", "provenance", "code_analysis", "reputation"}
    checks.append({
        "check": "hybrid fusion: required channels present",
        "pass": required_channels.issubset(channels),
        "detail": f"channels={sorted(channels)}",
    })

    checks.append({
        "check": "hybrid fusion: non-behavioral failures are flagged",
        "pass": eval_out["fusion_flags_non_behavioral_failures"] and bool(fusion.get("gaming_behavioral_only_flagged", False)),
        "detail": "validated" if eval_out["fusion_flags_non_behavioral_failures"] else "unflagged non-behavioral failure detected",
    })

    subset_hashes = motif_subset_hashes(data)
    checks.append({
        "check": "motif randomization: two evaluations use different subsets",
        "pass": eval_out["motif_unique_subsets"],
        "detail": f"subset_hashes={subset_hashes}",
    })

    scenario_a = scenario_lookup(data, "A")
    scenario_a_ok = (
        scenario_a is not None
        and bool(scenario_a.get("flagged", False))
        and float(scenario_a.get("confidence_pct", 0.0)) >= float(scenario_a.get("minimum_required_confidence_pct", 90.0))
    )
    checks.append({
        "check": "scenario A: known mimicry flagged >=90% confidence",
        "pass": scenario_a_ok,
        "detail": "validated" if scenario_a_ok else "scenario A invariant failed",
    })

    scenario_b = scenario_lookup(data, "B")
    scenario_b_ok = (
        scenario_b is not None
        and bool(scenario_b.get("behavioral_channel_gamed", False))
        and (not bool(scenario_b.get("provenance_pass", True)) or not bool(scenario_b.get("code_analysis_pass", True)))
        and bool(scenario_b.get("flagged", False))
    )
    checks.append({
        "check": "scenario B: behavioral gaming + suspicious provenance is flagged",
        "pass": scenario_b_ok,
        "detail": "validated" if scenario_b_ok else "scenario B invariant failed",
    })

    scenario_c = scenario_lookup(data, "C")
    scenario_c_hashes = [] if scenario_c is None else scenario_c.get("feature_subset_hashes", [])
    scenario_c_ok = (
        scenario_c is not None
        and bool(scenario_c.get("subsets_different", False))
        and len(scenario_c_hashes) >= 2
        and len(set(scenario_c_hashes)) == len(scenario_c_hashes)
    )
    checks.append({
        "check": "scenario C: same trajectory uses randomized motifs",
        "pass": scenario_c_ok,
        "detail": "validated" if scenario_c_ok else "scenario C invariant failed",
    })

    scenario_d = scenario_lookup(data, "D")
    scenario_d_ok = (
        scenario_d is not None
        and bool(scenario_d.get("new_pattern_added", False))
        and bool(scenario_d.get("retrained", False))
        and float(scenario_d.get("post_retrain_recall_pct", 0.0)) >= float(scenario_d.get("minimum_required_recall_pct", 90.0))
        and bool(model.get("retrained_after_new_pattern", False))
    )
    checks.append({
        "check": "scenario D: new pattern + retrain keeps recall >=90%",
        "pass": scenario_d_ok,
        "detail": "validated" if scenario_d_ok else "scenario D invariant failed",
    })

    scenario_e = scenario_lookup(data, "E")
    scenario_e_ok = (
        scenario_e is not None
        and int(scenario_e.get("rounds", 0)) == 10
        and float(scenario_e.get("min_round_recall_pct", 0.0)) >= float(scenario_e.get("minimum_required_recall_pct", 80.0))
        and bool(scenario_e.get("passes_threshold", False))
    )
    checks.append({
        "check": "scenario E: adaptive adversary 10-round recall >=80%",
        "pass": scenario_e_ok,
        "detail": "validated" if scenario_e_ok else "scenario E invariant failed",
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

    checks.append({
        "check": "aggregate: pattern_count matches corpus",
        "pass": int(aggregate.get("pattern_count", -1)) == eval_out["pattern_count"],
        "detail": f"reported={aggregate.get('pattern_count')} computed={eval_out['pattern_count']}",
    })

    checks.append({
        "check": "aggregate: known recall matches model",
        "pass": abs(float(aggregate.get("known_mimicry_recall_pct", -1.0)) - eval_out["known_recall_pct"]) < 0.01,
        "detail": f"reported={aggregate.get('known_mimicry_recall_pct')} computed={eval_out['known_recall_pct']}",
    })

    checks.append({
        "check": "aggregate: adaptive min recall matches model",
        "pass": abs(float(aggregate.get("adaptive_min_round_recall_pct", -1.0)) - eval_out["adaptive_min_recall_pct"]) < 0.01,
        "detail": f"reported={aggregate.get('adaptive_min_round_recall_pct')} computed={eval_out['adaptive_min_recall_pct']}",
    })

    checks.append({
        "check": "aggregate: motif uniqueness flag matches recomputation",
        "pass": bool(aggregate.get("motif_subsets_unique", False)) == eval_out["motif_unique_subsets"],
        "detail": f"reported={aggregate.get('motif_subsets_unique')} computed={eval_out['motif_unique_subsets']}",
    })

    checks.append({
        "check": "aggregate: hybrid gaming flag matches recomputation",
        "pass": bool(aggregate.get("hybrid_behavioral_gaming_flagged", False)) == eval_out["fusion_flags_non_behavioral_failures"],
        "detail": (
            f"reported={aggregate.get('hybrid_behavioral_gaming_flagged')} "
            f"computed={eval_out['fusion_flags_non_behavioral_failures']}"
        ),
    })

    checks.append({
        "check": "aggregate: update interval matches corpus",
        "pass": int(aggregate.get("update_interval_days", -1)) == int(corpus.get("update_interval_days", -2)),
        "detail": f"reported={aggregate.get('update_interval_days')} corpus={corpus.get('update_interval_days')}",
    })

    deterministic_variant = copy.deepcopy(data)
    deterministic_variant["detection_model"]["adaptive_round_recall_pct"] = list(
        reversed(deterministic_variant.get("detection_model", {}).get("adaptive_round_recall_pct", []))
    )
    deterministic = evaluate_policy(data) == evaluate_policy(deterministic_variant)
    checks.append({
        "check": "determinism: adaptive-round order-insensitive evaluation",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable",
    })

    adversarial = copy.deepcopy(data)
    evaluations = adversarial.get("motif_randomization", {}).get("evaluations", [])
    if len(evaluations) >= 2:
        evaluations[1]["feature_subset_hash"] = evaluations[0].get("feature_subset_hash", "")
    adversarial_eval = evaluate_policy(adversarial)
    adversarial_detected = not adversarial_eval["motif_unique_subsets"]
    checks.append({
        "check": "adversarial: motif-subset reuse is detected",
        "pass": adversarial_detected,
        "detail": f"adversarial_unique={adversarial_eval['motif_unique_subsets']}",
    })

    return checks


def run_checks() -> dict:
    checks = []
    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(REPORT, "trajectory-gaming camouflage report"))
    checks.extend(check_contract())
    checks.extend(check_rust_integration())
    checks.extend(check_runtime_export_truthfulness())
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
        "mimicry_corpus": {
            "pattern_count": 120,
            "update_interval_days": 30,
            "quarterly_update_required_days": 92,
        },
        "detection_model": {
            "known_mimicry_recall_pct": 92.0,
            "known_mimicry_threshold_pct": 90.0,
            "adaptive_attack_rounds": 10,
            "adaptive_round_recall_pct": [88.0, 84.0],
            "adaptive_recall_threshold_pct": 80.0,
        },
        "motif_randomization": {
            "subsets_unique": True,
            "evaluations": [
                {"feature_subset_hash": "a"},
                {"feature_subset_hash": "b"},
            ],
        },
        "hybrid_signal_fusion": {
            "adjudications": [
                {
                    "provenance_pass": False,
                    "code_analysis_pass": True,
                    "reputation_pass": True,
                    "flagged": True,
                }
            ]
        },
    }

    out = evaluate_policy(sample)
    checks = [
        {"check": "self: corpus", "pass": out["pattern_count"] >= 100},
        {"check": "self: known_recall", "pass": out["known_recall_pct"] >= 90.0},
        {"check": "self: adaptive_recall", "pass": out["adaptive_min_recall_pct"] >= 80.0},
        {"check": "self: unique_subsets", "pass": out["motif_unique_subsets"]},
        {
            "check": "self: fusion_flags_non_behavioral_failures",
            "pass": out["fusion_flags_non_behavioral_failures"],
        },
    ]
    return all(c["pass"] for c in checks), checks


def main() -> int:
    configure_test_logging("check_trajectory_gaming_camouflage")
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
        summary = result["summary"]
        print(f"{result['verdict']}: {TITLE} ({summary['passing']}/{summary['total']} checks passed)")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
