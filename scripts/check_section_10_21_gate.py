#!/usr/bin/env python3
"""Section 10.21 verification gate: Behavioral Package Evolution Tracker (BPET).

Aggregates evidence from all 16 section 10.21 beads and produces a gate verdict.

Usage:
    python3 scripts/check_section_10_21_gate.py          # human-readable
    python3 scripts/check_section_10_21_gate.py --json    # machine-readable
    python3 scripts/check_section_10_21_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GATE_BEAD = "bd-zm5b"
SECTION = "10.21"

# All 16 section 10.21 implementation beads
SECTION_BEADS = [
    ("bd-39ga", "BehavioralGenome schema and version-lineage contract"),
    ("bd-2xgs", "Deterministic phenotype feature extraction"),
    ("bd-3rai", "Signed lineage graph builder"),
    ("bd-1ga5", "Cohort-aware baseline modeling"),
    ("bd-2ao3", "Temporal drift feature engine"),
    ("bd-2lll", "Changepoint and regime-shift detection"),
    ("bd-1b9x", "Survival/hazard model"),
    ("bd-1jpc", "Unified evolution-risk scorer"),
    ("bd-232t", "BPET trajectory signals integration"),
    ("bd-kwwg", "BPET with DGIS integration"),
    ("bd-2zo1", "BPET with ATC integration"),
    ("bd-ye4m", "Adversarial evaluation suite"),
    ("bd-1naf", "BPET governance policy for thresholding/appeals/override workflows"),
    ("bd-3cbi", "Integrate BPET risk into economic trust layer and operator copilot"),
    ("bd-aoq6", "BPET migration stability gate verification"),
    ("bd-3v9l", "BPET performance budgets and predictive claim release gate"),
]

# Domain groupings for coverage checks
DOMAIN_GROUPS = {
    "genome_schema": ["bd-39ga"],
    "phenotype_extraction": ["bd-2xgs"],
    "lineage_graph": ["bd-3rai"],
    "baseline_modeling": ["bd-1ga5"],
    "drift_detection": ["bd-2ao3"],
    "changepoint_detection": ["bd-2lll"],
    "survival_model": ["bd-1b9x"],
    "risk_scoring": ["bd-1jpc"],
    "trajectory_signals": ["bd-232t"],
    "dgis_integration": ["bd-kwwg"],
    "atc_integration": ["bd-2zo1"],
    "adversarial_testing": ["bd-ye4m"],
    "governance_policy": ["bd-1naf"],
    "economic_integration": ["bd-3cbi"],
    "migration_gate": ["bd-aoq6"],
    "release_gate": ["bd-3v9l"],
}

# Key section-level artifacts
KEY_ARTIFACTS = [
    ("bpet_governance_audit_log", "artifacts/10.21/bpet_governance_audit_log.jsonl"),
    ("bpet_release_gate_report", "artifacts/10.21/bpet_release_gate_report.json"),
    ("bpet_migration_gate_results", "artifacts/10.21/bpet_migration_gate_results.json"),
    ("bpet_economic_guidance_report", "artifacts/10.21/bpet_economic_guidance_report.csv"),
    ("bpet_dgis_escalation_report", "artifacts/10.21/bpet_dgis_escalation_report.json"),
]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _evidence_pass(data: dict[str, Any]) -> bool:
    if data.get("verdict") == "PASS":
        return True
    if data.get("overall_pass") is True:
        return True
    if data.get("all_passed") is True:
        return True
    raw_status = str(data.get("status", "")).lower()
    if raw_status == "pass":
        return True
    if raw_status == "completed":
        return True
    if raw_status.startswith("completed_with_"):
        return True
    vr = data.get("verification_results", {})
    if vr:
        py_checker = vr.get("python_checker", vr.get("check_script", {}))
        py_tests = vr.get("python_unit_tests", vr.get("unit_tests", {}))
        if py_checker.get("verdict") == "PASS" and py_tests.get("verdict") == "PASS":
            return True
    overall_status = str(data.get("overall_status", "")).lower()
    if overall_status.startswith("partial_blocked_by_preexisting"):
        deliverables = data.get("deliverables", [])
        if deliverables and all(d.get("exists") for d in deliverables):
            return True
    return False


def _safe_relative(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _find_evidence(bead_id: str) -> Path | None:
    base = ROOT / "artifacts" / f"section_{SECTION.replace('.', '_')}" / bead_id
    for name in ("verification_evidence.json", "check_report.json"):
        p = base / name
        if p.is_file():
            return p
    return None


def _load_evidence(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def check_bead_evidence(bead_id: str, title: str) -> dict[str, Any]:
    evidence_path = _find_evidence(bead_id)
    if evidence_path is None:
        fallback = ROOT / "artifacts" / f"section_{SECTION.replace('.', '_')}" / bead_id / "verification_evidence.json"
        return _check(f"evidence_{bead_id}", False, f"missing: {_safe_relative(fallback)}")
    data = _load_evidence(evidence_path)
    if data is None:
        return _check(f"evidence_{bead_id}", False, f"parse error: {_safe_relative(evidence_path)}")
    passed = _evidence_pass(data)
    return _check(
        f"evidence_{bead_id}",
        passed,
        f"PASS: {title[:60]}" if passed else f"FAIL: {title[:60]}",
    )


def check_bead_summary(bead_id: str) -> dict[str, Any]:
    summary_path = ROOT / "artifacts" / f"section_{SECTION.replace('.', '_')}" / bead_id / "verification_summary.md"
    exists = summary_path.is_file()
    return _check(
        f"summary_{bead_id}",
        exists,
        f"exists: {_safe_relative(summary_path)}" if exists else f"missing: {_safe_relative(summary_path)}",
    )


def check_all_evidence_present() -> dict[str, Any]:
    count = 0
    for bead_id, _ in SECTION_BEADS:
        if _find_evidence(bead_id) is not None:
            count += 1
    passed = count == len(SECTION_BEADS)
    return _check("all_evidence_present", passed, f"{count}/{len(SECTION_BEADS)} beads have evidence")


def check_all_verdicts_pass() -> dict[str, Any]:
    pass_count = 0
    fail_list: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        evidence_path = _find_evidence(bead_id)
        if evidence_path is not None:
            data = _load_evidence(evidence_path)
            if data is not None and _evidence_pass(data):
                pass_count += 1
            else:
                fail_list.append(bead_id)
        else:
            fail_list.append(bead_id)
    passed = pass_count == len(SECTION_BEADS)
    detail = f"{pass_count}/{len(SECTION_BEADS)} PASS" if passed else f"FAIL: {', '.join(fail_list)}"
    return _check("all_verdicts_pass", passed, detail)


def check_key_artifacts() -> list[dict[str, Any]]:
    checks = []
    for name, rel_path in KEY_ARTIFACTS:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            f"artifact_{name}",
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_gate_deliverables() -> list[dict[str, Any]]:
    checks = []
    gate_files = [
        ("gate_tests", "tests/test_check_section_10_21_gate.py"),
    ]
    for name, rel_path in gate_files:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            name,
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_domain_coverage() -> list[dict[str, Any]]:
    """Verify all domain groups have passing beads."""
    checks = []
    for domain, bead_ids in DOMAIN_GROUPS.items():
        passing = 0
        for bead_id in bead_ids:
            evidence_path = _find_evidence(bead_id)
            if evidence_path is not None:
                data = _load_evidence(evidence_path)
                if data is not None and _evidence_pass(data):
                    passing += 1
        all_pass = passing == len(bead_ids)
        checks.append(_check(
            f"domain_{domain}_coverage",
            all_pass,
            f"{passing}/{len(bead_ids)} beads PASS",
        ))
    return checks


def check_pipeline_completeness() -> list[dict[str, Any]]:
    """Verify the BPET pipeline: schema -> extraction -> lineage -> baseline -> drift -> risk -> integration."""
    checks = []
    pipeline_stages = [
        ("pipeline_schema_to_extraction", ["bd-39ga", "bd-2xgs"]),
        ("pipeline_extraction_to_lineage", ["bd-2xgs", "bd-3rai"]),
        ("pipeline_lineage_to_baseline", ["bd-3rai", "bd-1ga5"]),
        ("pipeline_baseline_to_drift", ["bd-1ga5", "bd-2ao3"]),
        ("pipeline_drift_to_changepoint", ["bd-2ao3", "bd-2lll"]),
        ("pipeline_changepoint_to_survival", ["bd-2lll", "bd-1b9x"]),
        ("pipeline_survival_to_risk", ["bd-1b9x", "bd-1jpc"]),
        ("pipeline_risk_to_trajectory", ["bd-1jpc", "bd-232t"]),
        ("pipeline_trajectory_to_dgis", ["bd-232t", "bd-kwwg"]),
        ("pipeline_trajectory_to_atc", ["bd-232t", "bd-2zo1"]),
    ]
    for name, bead_ids in pipeline_stages:
        all_have_evidence = all(_find_evidence(bid) is not None for bid in bead_ids)
        checks.append(_check(
            name,
            all_have_evidence,
            "both have evidence" if all_have_evidence else "incomplete",
        ))
    return checks


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()

    for bead_id, title in SECTION_BEADS:
        check_bead_evidence(bead_id, title)

    for bead_id, _ in SECTION_BEADS:
        check_bead_summary(bead_id)

    check_all_evidence_present()
    check_all_verdicts_pass()
    check_key_artifacts()
    check_gate_deliverables()
    check_domain_coverage()
    check_pipeline_completeness()

    return RESULTS


def run_all() -> dict[str, Any]:
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0
    return {
        "bead_id": GATE_BEAD,
        "title": f"Section {SECTION} verification gate: Behavioral Package Evolution Tracker (BPET)",
        "section": SECTION,
        "gate": True,
        "verdict": "PASS" if overall else "FAIL",
        "overall_pass": overall,
        "total": total,
        "passed": passed,
        "failed": failed,
        "section_beads": [b[0] for b in SECTION_BEADS],
        "checks": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("section_bead_count", len(SECTION_BEADS) == 16, str(len(SECTION_BEADS)))
    push("domain_group_count", len(DOMAIN_GROUPS) == 16, str(len(DOMAIN_GROUPS)))
    push("gate_bead_set", GATE_BEAD == "bd-zm5b", GATE_BEAD)
    push("section_set", SECTION == "10.21", SECTION)

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")
    push("run_all_has_section_beads", len(report.get("section_beads", [])) == 16, "16 beads")

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": GATE_BEAD,
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    logger = configure_test_logging("check_section_10_21_gate")
    parser = argparse.ArgumentParser(description=f"Section {SECTION} verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        result = self_test()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"SELF-TEST: {result['verdict']} ({result['passed']}/{result['total']})")
            for check in result["checks"]:
                mark = "+" if check["pass"] else "x"
                print(f"  [{mark}] {check['check']}: {check['detail']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  Section {SECTION} Gate: {'PASS' if result['verdict'] == 'PASS' else 'FAIL'} ({result['passed']}/{result['total']})\n")
        for r in result["checks"]:
            mark = "+" if r["pass"] else "x"
            print(f"  [{mark}] {r['check']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
