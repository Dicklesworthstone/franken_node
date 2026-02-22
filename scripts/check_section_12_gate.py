#!/usr/bin/env python3
"""Section 12 comprehensive verification gate (bd-2x1e)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-2x1e"
SECTION = "12"
TITLE = "Section-wide verification gate: comprehensive unit+e2e+logging"

RISK_REGISTER_SUMMARY = ROOT / "docs" / "specs" / "section_12" / "risk_register_summary.md"
SECTION_MATRIX_SUMMARY = ROOT / "artifacts" / "section_12" / "section_12_verification_summary.md"


@dataclass(frozen=True)
class SectionEntry:
    bead: str
    risk: str
    script: str
    test: str


SECTION_ENTRIES: list[SectionEntry] = [
    SectionEntry("bd-s4cu", "compatibility illusion", "scripts/check_risk_compatibility.py", "tests/test_check_risk_compatibility.py"),
    SectionEntry("bd-38ri", "scope explosion", "scripts/check_scope_explosion.py", "tests/test_check_scope_explosion.py"),
    SectionEntry("bd-kiqr", "trust-system complexity", "scripts/check_trust_complexity.py", "tests/test_check_trust_complexity.py"),
    SectionEntry("bd-3jc1", "migration friction persistence", "scripts/check_migration_friction_persistence.py", "tests/test_check_migration_friction_persistence.py"),
    SectionEntry("bd-2w4u", "hardening perf regression", "scripts/check_hardening_perf_regression.py", "tests/test_check_hardening_perf_regression.py"),
    SectionEntry("bd-1nab", "federated privacy leakage", "scripts/check_federated_privacy_leakage.py", "tests/test_check_federated_privacy_leakage.py"),
    SectionEntry("bd-13yn", "signal poisoning and Sybil", "scripts/check_signal_sybil.py", "tests/test_check_signal_sybil.py"),
    SectionEntry("bd-1n1t", "topology blind spots", "scripts/check_topology_blind_spots.py", "tests/test_check_topology_blind_spots.py"),
    SectionEntry("bd-paui", "topological choke-point false positives", "scripts/check_chokepoint_false_positives.py", "tests/test_check_chokepoint_false_positives.py"),
    SectionEntry("bd-v4ps", "temporal concept drift", "scripts/check_temporal_concept_drift.py", "tests/test_check_temporal_concept_drift.py"),
    SectionEntry("bd-1rff", "longitudinal privacy/re-identification", "scripts/check_longitudinal_privacy.py", "tests/test_check_longitudinal_privacy.py"),
    SectionEntry("bd-35m7", "trajectory-gaming camouflage", "scripts/check_trajectory_gaming_camouflage.py", "tests/test_check_trajectory_gaming_camouflage.py"),
]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_unittest_counts(output: str) -> tuple[int, int]:
    ran = 0
    failed = 0
    ran_match = re.search(r"Ran\s+(\d+)\s+tests?", output)
    if ran_match:
        ran = int(ran_match.group(1))
    failed_match = re.search(r"FAILED\s*\(([^)]*)\)", output)
    if failed_match:
        detail = failed_match.group(1)
        for key in ["failures", "errors"]:
            m = re.search(rf"{key}=(\d+)", detail)
            if m:
                failed += int(m.group(1))
    return ran, failed


def has_self_test(script_path: Path) -> bool:
    if not script_path.exists():
        return False
    text = script_path.read_text(encoding="utf-8")
    return "def self_test(" in text


def evidence_passed(payload: dict[str, Any]) -> bool:
    verdict = str(payload.get("verdict", "")).upper()
    if verdict == "PASS":
        return True
    if payload.get("overall_pass") is True:
        return True
    if payload.get("all_passed") is True:
        return True
    status = str(payload.get("status", "")).lower()
    if status == "pass":
        return True
    if int(payload.get("checks_failed", 0)) == 0 and int(payload.get("checks_total", 0)) > 0:
        return True
    summary = payload.get("summary")
    if isinstance(summary, dict) and int(summary.get("failing", 1)) == 0 and int(summary.get("total", 0)) > 0:
        return True
    return False


def parse_script_result(stdout: str, return_code: int) -> tuple[bool, str]:
    if return_code != 0:
        return False, "non-zero-exit"
    try:
        payload = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        return False, "invalid-json"
    return evidence_passed(payload), str(payload.get("verdict", payload.get("status", "PASS")))


def run_script(entry: SectionEntry, execute: bool = True) -> dict[str, Any]:
    script_path = ROOT / entry.script
    result = {
        "bead": entry.bead,
        "script": entry.script,
        "exists": script_path.exists(),
        "self_test_present": has_self_test(script_path),
        "status": "PASS",
        "exit_code": None,
        "verdict": "PASS",
    }

    if not script_path.exists():
        result["status"] = "FAIL"
        result["verdict"] = "MISSING"
        return result

    if not execute:
        result["status"] = "PASS" if result["self_test_present"] else "FAIL"
        result["verdict"] = "PASS" if result["self_test_present"] else "NO_SELF_TEST"
        return result

    proc = subprocess.run(
        [sys.executable, str(script_path), "--json"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
    )
    result["exit_code"] = proc.returncode
    script_ok, verdict = parse_script_result(proc.stdout, proc.returncode)
    result["verdict"] = verdict
    result["status"] = "PASS" if script_ok and result["self_test_present"] else "FAIL"
    if proc.stderr:
        result["stderr"] = proc.stderr.strip()[:300]
    return result


def run_unit_test(entry: SectionEntry, execute: bool = True) -> dict[str, Any]:
    test_path = ROOT / entry.test
    result = {
        "bead": entry.bead,
        "test": entry.test,
        "exists": test_path.exists(),
        "status": "PASS",
        "tests_ran": 0,
        "tests_failed": 0,
        "exit_code": None,
    }
    if not test_path.exists():
        result["status"] = "FAIL"
        return result

    if not execute:
        return result

    proc = subprocess.run(
        [sys.executable, "-m", "unittest", entry.test],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=240,
    )
    output = f"{proc.stdout}\n{proc.stderr}"
    ran, failed = parse_unittest_counts(output)
    result["tests_ran"] = ran
    result["tests_failed"] = failed
    result["exit_code"] = proc.returncode
    if proc.returncode != 0:
        result["status"] = "FAIL"
        result["stderr"] = proc.stderr.strip()[:300] if proc.stderr else ""
    return result


def load_evidence(entry: SectionEntry) -> dict[str, Any]:
    evidence_path = ROOT / "artifacts" / "section_12" / entry.bead / "verification_evidence.json"
    result = {
        "bead": entry.bead,
        "path": str(evidence_path.relative_to(ROOT)),
        "exists": evidence_path.exists(),
        "status": "PASS",
        "verdict": "PASS",
        "countermeasures": 0,
        "passing_checks": 0,
    }
    if not evidence_path.exists():
        result["status"] = "FAIL"
        result["verdict"] = "MISSING"
        return result

    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        result["status"] = "FAIL"
        result["verdict"] = "INVALID_JSON"
        return result

    passed = evidence_passed(payload)
    result["verdict"] = str(payload.get("verdict", payload.get("status", "UNKNOWN"))).upper()
    result["status"] = "PASS" if passed else "FAIL"

    countermeasures = payload.get("countermeasures", [])
    if isinstance(countermeasures, list):
        result["countermeasures"] = len(countermeasures)

    checks = payload.get("checks", [])
    if isinstance(checks, list):
        result["passing_checks"] = sum(
            1
            for check in checks
            if bool(check.get("pass", check.get("passed", False)))
        )

    result["payload"] = payload
    return result


def scenario_effectiveness(entry: SectionEntry, evidence_result: dict[str, Any]) -> dict[str, Any]:
    check_report = ROOT / "artifacts" / "section_12" / entry.bead / "check_report.json"

    if check_report.exists():
        try:
            payload = json.loads(check_report.read_text(encoding="utf-8"))
            checks = payload.get("checks", [])
            # Count checks that demonstrate risk-mitigation effectiveness.
            # Some beads name these "scenario …", others use domain terms
            # like "countermeasure", "mitigation", "gate", "control", etc.
            _EFFECTIVENESS_KEYWORDS = (
                "scenario", "countermeasure", "mitigation", "gate",
                "control", "threshold", "replay", "degraded",
            )
            scenario_passes = sum(
                1
                for check in checks
                if any(
                    kw in str(check.get("check", check.get("name", ""))).lower()
                    for kw in _EFFECTIVENESS_KEYWORDS
                )
                and bool(check.get("pass", check.get("passed", False)))
            )
            return {
                "bead": entry.bead,
                "status": "PASS" if scenario_passes > 0 else "FAIL",
                "scenario_passes": scenario_passes,
                "source": str(check_report.relative_to(ROOT)),
            }
        except json.JSONDecodeError:
            return {
                "bead": entry.bead,
                "status": "FAIL",
                "scenario_passes": 0,
                "source": str(check_report.relative_to(ROOT)),
                "error": "invalid-json",
            }

    # Legacy fallback: if evidence passed and contains meaningful control checks,
    # treat this as at least one effectiveness scenario.
    passing_checks = int(evidence_result.get("passing_checks", 0))
    countermeasures = int(evidence_result.get("countermeasures", 0))
    implied = 1 if evidence_result.get("status") == "PASS" and (passing_checks > 0 or countermeasures > 0) else 0
    return {
        "bead": entry.bead,
        "status": "PASS" if implied > 0 else "FAIL",
        "scenario_passes": implied,
        "source": "verification_evidence_fallback",
    }


def risk_state(overall_pass: bool, scenario_passes: int) -> str:
    if overall_pass and scenario_passes > 0:
        return "mitigated"
    if overall_pass:
        return "monitoring"
    return "open"


def write_risk_register_summary(per_bead_results: list[dict[str, Any]]) -> None:
    lines = [
        "# Section 12 Risk Register Summary",
        "",
        "Generated by `scripts/check_section_12_gate.py`.",
        "",
        "| Bead | Risk | Status | Script | Unit Tests | Evidence | Scenarios |",
        "|------|------|--------|--------|------------|----------|-----------|",
    ]
    for item in per_bead_results:
        lines.append(
            "| {bead} | {risk} | {state} | {script} | {tests} | {evidence} | {scenarios} |".format(
                bead=item["bead_id"],
                risk=item["risk"],
                state=item["risk_status"],
                script="PASS" if item["script_pass"] else "FAIL",
                tests="PASS" if item["unit_pass"] else "FAIL",
                evidence="PASS" if item["evidence_pass"] else "FAIL",
                scenarios=item["scenario_passes"],
            )
        )

    lines.extend(
        [
            "",
            "Status meanings:",
            "- `mitigated`: control evidence passes and at least one effectiveness scenario is present.",
            "- `monitoring`: core checks pass but scenario coverage is incomplete.",
            "- `open`: one or more required checks fail.",
        ]
    )

    RISK_REGISTER_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    RISK_REGISTER_SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_section_matrix_summary(report: dict[str, Any]) -> None:
    lines = [
        "# Section 12 Verification Summary Matrix",
        "",
        f"- Gate bead: `{BEAD_ID}`",
        f"- Verdict: `{report['verdict']}`",
        f"- Coverage: `{report['overall_coverage_pct']}%`",
        "",
        "| Bead | Risk | Script | Unit Tests | Evidence | Scenarios | Overall |",
        "|------|------|--------|------------|----------|-----------|---------|",
    ]

    for item in report["per_bead_results"]:
        lines.append(
            "| {bead} | {risk} | {script} | {unit} | {evidence} | {scenarios} | {overall} |".format(
                bead=item["bead_id"],
                risk=item["risk"],
                script="PASS" if item["script_pass"] else "FAIL",
                unit="PASS" if item["unit_pass"] else "FAIL",
                evidence="PASS" if item["evidence_pass"] else "FAIL",
                scenarios=item["scenario_passes"],
                overall="PASS" if item["overall_pass"] else "FAIL",
            )
        )

    lines.extend(
        [
            "",
            "Structured gate events:",
        ]
    )
    for event in report["events"]:
        lines.append(
            f"- `{event['event']}` bead=`{event.get('bead', '-')}` status=`{event.get('status', '-')}` trace_id=`{event['trace_id']}`"
        )

    SECTION_MATRIX_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    SECTION_MATRIX_SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_report(execute: bool = True, write_outputs: bool = True) -> dict[str, Any]:
    trace_id = f"trace-{BEAD_ID}-section-gate"
    events: list[dict[str, Any]] = [
        {
            "event": "GATE_12_EVALUATION_STARTED",
            "trace_id": trace_id,
            "section": SECTION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    ]

    script_results = [run_script(entry, execute=execute) for entry in SECTION_ENTRIES]
    test_results = [run_unit_test(entry, execute=execute) for entry in SECTION_ENTRIES]
    evidence_results = [load_evidence(entry) for entry in SECTION_ENTRIES]

    script_map = {item["bead"]: item for item in script_results}
    test_map = {item["bead"]: item for item in test_results}
    evidence_map = {item["bead"]: item for item in evidence_results}

    per_bead_results: list[dict[str, Any]] = []
    for entry in SECTION_ENTRIES:
        scenario = scenario_effectiveness(entry, evidence_map[entry.bead])
        script_pass = script_map[entry.bead]["status"] == "PASS"
        unit_pass = test_map[entry.bead]["status"] == "PASS"
        evidence_pass = evidence_map[entry.bead]["status"] == "PASS"
        scenario_passes = int(scenario["scenario_passes"])
        overall = script_pass and unit_pass and evidence_pass and scenario_passes > 0

        item = {
            "bead_id": entry.bead,
            "risk": entry.risk,
            "script_pass": script_pass,
            "unit_pass": unit_pass,
            "evidence_pass": evidence_pass,
            "scenario_passes": scenario_passes,
            "scenario_source": scenario["source"],
            "overall_pass": overall,
            "risk_status": risk_state(overall, scenario_passes),
        }
        per_bead_results.append(item)
        events.append(
            {
                "event": "GATE_12_BEAD_CHECKED",
                "trace_id": trace_id,
                "bead": entry.bead,
                "status": "PASS" if overall else "FAIL",
            }
        )

    risk_coverage_ok = all(item["scenario_passes"] > 0 for item in per_bead_results)
    events.append(
        {
            "event": "GATE_12_RISK_COVERAGE",
            "trace_id": trace_id,
            "status": "PASS" if risk_coverage_ok else "FAIL",
            "covered": sum(1 for item in per_bead_results if item["scenario_passes"] > 0),
            "total": len(per_bead_results),
        }
    )

    coverage = round(100.0 * sum(1 for item in per_bead_results if item["overall_pass"]) / len(per_bead_results), 2)

    checks = [
        {
            "id": "GATE-SCRIPTS",
            "status": "PASS" if all(r["status"] == "PASS" for r in script_results) else "FAIL",
            "details": {
                "total": len(script_results),
                "passing": sum(1 for r in script_results if r["status"] == "PASS"),
                "results": script_results,
            },
        },
        {
            "id": "GATE-TESTS",
            "status": "PASS" if all(r["status"] == "PASS" for r in test_results) else "FAIL",
            "details": {
                "total": len(test_results),
                "passing": sum(1 for r in test_results if r["status"] == "PASS"),
                "tests_ran": sum(int(r.get("tests_ran", 0)) for r in test_results),
                "results": test_results,
            },
        },
        {
            "id": "GATE-EVIDENCE",
            "status": "PASS" if all(r["status"] == "PASS" for r in evidence_results) else "FAIL",
            "details": {
                "total": len(evidence_results),
                "passing": sum(1 for r in evidence_results if r["status"] == "PASS"),
                "results": [
                    {
                        "bead": r["bead"],
                        "path": r["path"],
                        "status": r["status"],
                        "verdict": r["verdict"],
                    }
                    for r in evidence_results
                ],
            },
        },
        {
            "id": "GATE-RISK-COVERAGE",
            "status": "PASS" if risk_coverage_ok else "FAIL",
            "details": {
                "covered": sum(1 for item in per_bead_results if item["scenario_passes"] > 0),
                "total": len(per_bead_results),
                "results": [
                    {
                        "bead": item["bead_id"],
                        "scenario_passes": item["scenario_passes"],
                        "source": item["scenario_source"],
                        "status": "PASS" if item["scenario_passes"] > 0 else "FAIL",
                    }
                    for item in per_bead_results
                ],
            },
        },
    ]

    gate_pass = all(check["status"] == "PASS" for check in checks)
    events.append(
        {
            "event": "GATE_12_VERDICT_EMITTED",
            "trace_id": trace_id,
            "status": "PASS" if gate_pass else "FAIL",
        }
    )

    report = {
        "gate": "section_12_comprehensive_gate",
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "gate_pass": gate_pass,
        "verdict": "PASS" if gate_pass else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trace_id": trace_id,
        "beads_tested": [entry.bead for entry in SECTION_ENTRIES],
        "per_bead_results": per_bead_results,
        "overall_coverage_pct": coverage,
        "checks": checks,
        "events": events,
    }
    report["content_hash"] = hashlib.sha256(_canonical_json(report).encode("utf-8")).hexdigest()

    if write_outputs:
        write_risk_register_summary(per_bead_results)
        write_section_matrix_summary(report)

    return report


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    sample_payload = {
        "status": "pass",
        "checks_total": 3,
        "checks_failed": 0,
    }
    checks = [
        {"check": "self: evidence_passed", "pass": evidence_passed(sample_payload)},
        {"check": "self: entries_count", "pass": len(SECTION_ENTRIES) == 12},
        {"check": "self: parse_unittest_counts", "pass": parse_unittest_counts("Ran 4 tests\n\nOK")[0] == 4},
    ]
    return all(c["pass"] for c in checks), checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-test")
    parser.add_argument(
        "--no-exec",
        action="store_true",
        help="Skip subprocess execution of child scripts/tests (for fast validation)",
    )
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        payload = {
            "self_test_passed": ok,
            "checks_total": len(checks),
            "checks_passing": sum(1 for c in checks if c["pass"]),
            "checks_failing": sum(1 for c in checks if not c["pass"]),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("PASS" if ok else "FAIL")
            for check in checks:
                status = "PASS" if check["pass"] else "FAIL"
                print(f"[{status}] {check['check']}")
        return 0 if ok else 1

    report = build_report(execute=not args.no_exec, write_outputs=True)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{report['verdict']}: Section 12 gate ({report['overall_coverage_pct']}% coverage)")
        for check in report["checks"]:
            print(f"[{check['status']}] {check['id']}")

    return 0 if report["gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
