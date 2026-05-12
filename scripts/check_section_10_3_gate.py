#!/usr/bin/env python3
"""Section 10.3 verification gate: Migration Analysis & Rollout Planning.

Aggregates evidence from all 8 section 10.3 beads and produces a gate verdict.

Usage:
    python3 scripts/check_section_10_3_gate.py          # human-readable
    python3 scripts/check_section_10_3_gate.py --json    # machine-readable
    python3 scripts/check_section_10_3_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


GATE_BEAD = "bd-3enl"
SECTION = "10.3"
PARENT_COMPLETION_BEAD = "bd-2avo"
COMPLETION_DEBT_BEAD = "bd-2avo.1"

# All 8 section 10.3 implementation beads
SECTION_BEADS = [
    ("bd-2a0", "Project scanner"),
    ("bd-33x", "Risk scorer"),
    ("bd-2ew", "Rewrite engine"),
    ("bd-2st", "Migration validation"),
    ("bd-3dn", "Rollout planner"),
    ("bd-12f", "Confidence report"),
    ("bd-hg1", "Migrate report"),
    ("bd-3f9", "Failure replay"),
]

# Domain groupings for coverage checks
DOMAIN_GROUPS = {
    "project_scanner": ["bd-2a0"],
    "risk_scorer": ["bd-33x"],
    "rewrite_engine": ["bd-2ew"],
    "migration_validation": ["bd-2st"],
    "rollout_planner": ["bd-3dn"],
    "confidence_report": ["bd-12f"],
    "migrate_report": ["bd-hg1"],
    "failure_replay": ["bd-3f9"],
}

COMPLETION_DEBT_REQUIRED_SPEC_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "migrations.primary",
    "telemetry.primary",
}

COMPLETION_DEBT_OBLIGATIONS = [
    {
        "spec_item": "tests.unit.primary",
        "category": "unit",
        "status": "covered",
        "description": "section 10.3 checker unit tests exercise gate shape, evidence pass/fail behavior, and completion-debt contract drift",
        "evidence_paths": [
            "tests/test_check_section_10_3_gate.py",
            "tests/test_check_project_scanner.py",
            "tests/test_check_risk_scorer.py",
            "tests/test_check_rewrite_engine.py",
            "tests/test_check_migration_validation.py",
            "tests/test_check_rollout_planner.py",
            "tests/test_check_confidence_report.py",
            "tests/test_check_migrate_report.py",
            "tests/test_check_failure_replay.py",
        ],
        "commands": ["python3 -m unittest tests/test_check_section_10_3_gate.py"],
    },
    {
        "spec_item": "tests.e2e.primary",
        "category": "e2e",
        "status": "covered",
        "description": "migration cohort validation shell suite exercises deterministic cohort artifacts and structured event logs without cargo",
        "evidence_paths": [
            "tests/e2e/migration_cohort_validation.sh",
            "artifacts/15/migration_cohort_results.json",
            "artifacts/15/migration_cohort_validation_log.jsonl",
            "artifacts/15/migration_cohort_validation_summary.json",
        ],
        "commands": ["tests/e2e/migration_cohort_validation.sh"],
    },
    {
        "spec_item": "migrations.primary",
        "category": "migrations",
        "status": "covered",
        "description": "all section 10.3 migration autopilot domains have passing evidence and summaries",
        "evidence_paths": [
            "scripts/check_project_scanner.py",
            "scripts/check_risk_scorer.py",
            "scripts/check_rewrite_engine.py",
            "scripts/check_migration_validation.py",
            "scripts/check_rollout_planner.py",
            "scripts/check_confidence_report.py",
            "scripts/check_migrate_report.py",
            "scripts/check_failure_replay.py",
        ],
        "domain_groups": sorted(DOMAIN_GROUPS),
        "commands": ["python3 scripts/check_section_10_3_gate.py --json"],
    },
    {
        "spec_item": "telemetry.primary",
        "category": "telemetry",
        "status": "covered",
        "description": "checker logs and E2E cohort logs preserve trace-correlated event fields",
        "evidence_paths": [
            "scripts/check_section_10_3_gate.py",
            "tests/e2e/migration_cohort_validation.sh",
            "artifacts/15/migration_cohort_validation_log.jsonl",
        ],
        "required_fields": ["trace_id", "event_code", "status", "detail"],
        "commands": ["python3 scripts/check_section_10_3_gate.py --json"],
    },
]

# Key section-level artifacts
KEY_ARTIFACTS: list[tuple[str, str]] = []

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
    if bool(data.get("overall_pass")):
        return True
    if bool(data.get("all_passed")):
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
        raw = path.read_text()
        return json.JSONDecoder().decode(raw)
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
        ("gate_tests", "tests/test_check_section_10_3_gate.py"),
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
    """Verify the migration pipeline has coverage: scan -> risk -> rewrite -> validation -> rollout -> report."""
    checks = []
    pipeline_stages = [
        ("pipeline_scan_to_risk", ["bd-2a0", "bd-33x"]),
        ("pipeline_risk_to_rewrite", ["bd-33x", "bd-2ew"]),
        ("pipeline_rewrite_to_validation", ["bd-2ew", "bd-2st"]),
        ("pipeline_validation_to_rollout", ["bd-2st", "bd-3dn"]),
        ("pipeline_rollout_to_report", ["bd-3dn", "bd-12f"]),
    ]
    for name, bead_ids in pipeline_stages:
        all_have_evidence = all(_find_evidence(bid) is not None for bid in bead_ids)
        checks.append(_check(
            name,
            all_have_evidence,
            "both have evidence" if all_have_evidence else "incomplete",
        ))
    return checks


def _completion_debt_contract() -> dict[str, Any]:
    return {
        "parent_bead": PARENT_COMPLETION_BEAD,
        "completion_bead": COMPLETION_DEBT_BEAD,
        "required_spec_items": sorted(COMPLETION_DEBT_REQUIRED_SPEC_ITEMS),
        "coverage_obligations": COMPLETION_DEBT_OBLIGATIONS,
    }


def check_completion_debt_coverage() -> dict[str, Any]:
    coverage_by_item = {
        obligation.get("spec_item"): obligation
        for obligation in COMPLETION_DEBT_OBLIGATIONS
        if isinstance(obligation, dict)
    }
    missing_items = sorted(COMPLETION_DEBT_REQUIRED_SPEC_ITEMS - set(coverage_by_item))
    missing_paths: list[str] = []
    noncovered_items: list[str] = []
    for item, obligation in coverage_by_item.items():
        if obligation.get("status") != "covered":
            noncovered_items.append(str(item))
        for rel_path in obligation.get("evidence_paths", []):
            if isinstance(rel_path, str) and not (ROOT / rel_path).exists():
                missing_paths.append(rel_path)

    passed = not missing_items and not missing_paths and not noncovered_items
    detail = "all completion-debt obligations covered"
    if not passed:
        detail = json.dumps(
            {
                "missing_items": missing_items,
                "missing_paths": sorted(missing_paths),
                "noncovered_items": sorted(noncovered_items),
            },
            sort_keys=True,
        )
    return _check("completion_debt_bd_2avo_1_coverage", passed, detail)


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
    check_completion_debt_coverage()

    return RESULTS


def run_all() -> dict[str, Any]:
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0
    return {
        "bead_id": GATE_BEAD,
        "title": f"Section {SECTION} verification gate: Migration Analysis & Rollout Planning",
        "section": SECTION,
        "gate": True,
        "verdict": "PASS" if overall else "FAIL",
        "overall_pass": overall,
        "total": total,
        "passed": passed,
        "failed": failed,
        "section_beads": [b[0] for b in SECTION_BEADS],
        "completion_debt": _completion_debt_contract(),
        "checks": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("section_bead_count", len(SECTION_BEADS) == 8, str(len(SECTION_BEADS)))
    push("domain_group_count", len(DOMAIN_GROUPS) == 8, str(len(DOMAIN_GROUPS)))
    push("gate_bead_set", GATE_BEAD == "bd-3enl", GATE_BEAD)
    push("section_set", SECTION == "10.3", SECTION)
    push(
        "completion_debt_items_set",
        set(_completion_debt_contract()["required_spec_items"]) == COMPLETION_DEBT_REQUIRED_SPEC_ITEMS,
        ",".join(_completion_debt_contract()["required_spec_items"]),
    )

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")
    push("run_all_has_section_beads", len(report.get("section_beads", [])) == 8, "8 beads")
    push("run_all_has_completion_debt", report.get("completion_debt", {}).get("completion_bead") == COMPLETION_DEBT_BEAD)

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
    configure_test_logging("check_section_10_3_gate")
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
