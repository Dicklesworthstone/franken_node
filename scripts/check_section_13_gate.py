#!/usr/bin/env python3
"""Section 13 comprehensive verification gate (bd-z7bt)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BEAD_ID = "bd-z7bt"
SECTION = "13"
TITLE = "Section-wide verification gate: comprehensive unit+e2e+logging"
SUMMARY_MATRIX = ROOT / "artifacts" / "section_13" / "section_13_verification_summary.md"


@dataclass(frozen=True)
class SectionEntry:
    bead: str
    criterion: str
    script: str
    test: str
    quantitative: bool
    target: str


SECTION_ENTRIES: list[SectionEntry] = [
    SectionEntry(
        "bd-2f43",
        "Success criterion: low-risk migration pathways",
        "scripts/check_migration_pathways.py",
        "tests/test_check_migration_pathways.py",
        False,
        "Measurement mechanism + evidence present",
    ),
    SectionEntry(
        "bd-1w78",
        "Success criterion: continuous lockstep validation",
        "scripts/check_lockstep_validation.py",
        "tests/test_check_lockstep_validation.py",
        False,
        "Measurement mechanism + evidence present",
    ),
    SectionEntry(
        "bd-2a4l",
        "Success criterion: externally verifiable trust/security claims",
        "scripts/check_verifiable_claims.py",
        "tests/test_check_verifiable_claims.py",
        False,
        "Measurement mechanism + evidence present",
    ),
    SectionEntry(
        "bd-pga7",
        "Success criterion: deterministic incident containment/explanation",
        "scripts/check_incident_containment.py",
        "tests/test_check_incident_containment.py",
        False,
        "Measurement mechanism + evidence present",
    ),
    SectionEntry(
        "bd-1xao",
        "Success criterion: impossible-by-default adoption",
        "scripts/check_impossible_adoption.py",
        "tests/test_check_impossible_adoption.py",
        False,
        "Measurement mechanism + evidence present",
    ),
    SectionEntry(
        "bd-3e74",
        "Success criterion: benchmark/verifier external usage",
        "scripts/check_benchmark_external.py",
        "tests/test_check_benchmark_external.py",
        False,
        "Measurement mechanism + evidence present",
    ),
    SectionEntry(
        "bd-28sz",
        "Concrete target: >=95% compatibility corpus pass",
        "scripts/check_compat_corpus_gate.py",
        "tests/test_check_compat_corpus_gate.py",
        True,
        "overall_pass_rate >= 95%",
    ),
    SectionEntry(
        "bd-3agp",
        "Concrete target: >=3x migration velocity",
        "scripts/check_migration_velocity_gate.py",
        "tests/test_check_migration_velocity_gate.py",
        True,
        "overall_velocity_ratio >= 3.0",
    ),
    SectionEntry(
        "bd-3cpa",
        "Concrete target: >=10x compromise reduction",
        "scripts/check_compromise_reduction_gate.py",
        "tests/test_check_compromise_reduction_gate.py",
        True,
        "compromise_reduction_ratio >= 10.0",
    ),
    SectionEntry(
        "bd-34d5",
        "Concrete target: friction-minimized install-to-first-safe-production",
        "scripts/check_friction_pathway.py",
        "tests/test_check_friction_pathway.py",
        True,
        "all friction pathway checks pass",
    ),
    SectionEntry(
        "bd-2l1k",
        "Concrete target: 100% replay artifact coverage",
        "scripts/check_replay_coverage_gate.py",
        "tests/test_check_replay_coverage_gate.py",
        True,
        "coverage_ratio >= 1.0",
    ),
    SectionEntry(
        "bd-whxp",
        "Concrete target: >=2 independent replications",
        "scripts/check_independent_replications_gate.py",
        "tests/test_check_independent_replications_gate.py",
        True,
        "independent_replications_passing >= 2",
    ),
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
    if payload.get("overall_passed") is True:
        return True
    if payload.get("all_passed") is True:
        return True
    status = str(payload.get("status", "")).lower()
    if status == "pass":
        return True
    checks = payload.get("checks")
    if isinstance(checks, list) and checks:
        all_true = True
        for check in checks:
            if not isinstance(check, dict):
                all_true = False
                break
            if not bool(check.get("pass", check.get("passed", False))):
                all_true = False
                break
        if all_true:
            return True
    if isinstance(checks, dict):
        total = checks.get("total")
        failed = checks.get("failed")
        if isinstance(total, int) and isinstance(failed, int) and total > 0 and failed == 0:
            return True
    if int(payload.get("failed", 0)) == 0 and int(payload.get("passed", 0)) > 0:
        return True
    gate_validation = payload.get("gate_validation")
    if isinstance(gate_validation, dict):
        gate = gate_validation.get("independent_replication_gate")
        if isinstance(gate, dict) and str(gate.get("verdict", "")).upper() == "PASS":
            return True
    overall_assessment = payload.get("overall_assessment")
    if isinstance(overall_assessment, dict):
        if str(overall_assessment.get("independent_replication_gate", "")).lower() == "pass":
            return True
    summary = payload.get("summary")
    if isinstance(summary, dict) and int(summary.get("failing", 1)) == 0 and int(summary.get("total", 0)) > 0:
        return True
    return False


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("json root must be object")
    return payload


def run_script(entry: SectionEntry, execute: bool = True) -> dict[str, Any]:
    script_path = ROOT / entry.script
    result: dict[str, Any] = {
        "bead": entry.bead,
        "script": entry.script,
        "exists": script_path.exists(),
        "self_test_present": has_self_test(script_path),
        "status": "PASS",
        "verdict": "PASS",
        "exit_code": None,
        "payload": {},
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
        timeout=3600,
    )
    result["exit_code"] = proc.returncode

    payload: dict[str, Any] = {}
    parse_err = ""
    try:
        payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        parse_err = "invalid-json"

    result["payload"] = payload
    result["verdict"] = str(payload.get("verdict", payload.get("status", "UNKNOWN")))

    script_ok = proc.returncode == 0 and parse_err == "" and evidence_passed(payload)
    result["status"] = "PASS" if script_ok and result["self_test_present"] else "FAIL"

    if parse_err:
        result["parse_error"] = parse_err
    if proc.stderr:
        result["stderr"] = proc.stderr.strip()[:300]

    return result


def run_unit_test(entry: SectionEntry, execute: bool = True) -> dict[str, Any]:
    test_path = ROOT / entry.test
    result: dict[str, Any] = {
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
        timeout=3600,
    )
    output = f"{proc.stdout}\n{proc.stderr}"
    ran, failed = parse_unittest_counts(output)

    result["tests_ran"] = ran
    result["tests_failed"] = failed
    result["exit_code"] = proc.returncode

    if proc.returncode != 0:
        result["status"] = "FAIL"
        if proc.stderr:
            result["stderr"] = proc.stderr.strip()[:300]

    return result


def load_evidence(entry: SectionEntry) -> dict[str, Any]:
    evidence_path = ROOT / "artifacts" / "section_13" / entry.bead / "verification_evidence.json"
    result: dict[str, Any] = {
        "bead": entry.bead,
        "path": str(evidence_path.relative_to(ROOT)),
        "exists": evidence_path.exists(),
        "status": "PASS",
        "verdict": "PASS",
        "has_checks": False,
        "payload": {},
    }

    if not evidence_path.exists():
        result["status"] = "FAIL"
        result["verdict"] = "MISSING"
        return result

    try:
        payload = _read_json(evidence_path)
    except Exception:
        result["status"] = "FAIL"
        result["verdict"] = "INVALID_JSON"
        return result

    result["payload"] = payload
    checks = payload.get("checks")
    has_checks_list = isinstance(checks, list) and len(checks) > 0
    has_checks_dict = isinstance(checks, dict) and int(checks.get("total", 0)) > 0
    has_method_fields = any(
        key in payload
        for key in ("artifacts", "verification_script", "gate_validation", "quantitative_targets")
    )
    result["has_checks"] = has_checks_list or has_checks_dict or has_method_fields
    result["verdict"] = str(payload.get("verdict", payload.get("status", "UNKNOWN"))).upper()
    result["status"] = "PASS" if evidence_passed(payload) else "FAIL"

    return result


def _extract_current_threshold(detail: str) -> tuple[float | None, float | None]:
    current_match = re.search(r"current=([0-9]+(?:\.[0-9]+)?)", detail)
    threshold_match = re.search(r"threshold=([0-9]+(?:\.[0-9]+)?)", detail)
    current = float(current_match.group(1)) if current_match else None
    threshold = float(threshold_match.group(1)) if threshold_match else None
    return current, threshold


def extract_quantitative_target(entry: SectionEntry, script_payload: dict[str, Any], evidence_payload: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "bead": entry.bead,
        "criterion": entry.criterion,
        "target": entry.target,
        "measured": None,
        "required": None,
        "pass": False,
        "detail": "measurement unavailable",
    }

    if entry.bead == "bd-28sz":
        corpus_path = ROOT / "artifacts" / "13" / "compatibility_corpus_results.json"
        if corpus_path.is_file():
            try:
                corpus_payload = _read_json(corpus_path)
                measured = (
                    corpus_payload.get("totals", {}).get("overall_pass_rate_pct")
                    if isinstance(corpus_payload.get("totals"), dict)
                    else None
                )
                required = (
                    corpus_payload.get("thresholds", {}).get("overall_pass_rate_min_pct")
                    if isinstance(corpus_payload.get("thresholds"), dict)
                    else None
                )
                if isinstance(measured, (int, float)) and isinstance(required, (int, float)):
                    result["measured"] = float(measured)
                    result["required"] = float(required)
                    result["pass"] = float(measured) >= float(required)
                    result["detail"] = f"overall_pass_rate_pct={measured} required={required}"
                    return result
            except Exception:
                pass
        for check in script_payload.get("checks", []):
            if not isinstance(check, dict):
                continue
            if str(check.get("check", "")).strip() == "gate: overall threshold >=95 met":
                detail = str(check.get("detail", ""))
                current, threshold = _extract_current_threshold(detail)
                result["measured"] = current
                result["required"] = threshold
                result["pass"] = bool(check.get("pass", False))
                result["detail"] = detail
                return result
        return result

    computed = script_payload.get("computed", {}) if isinstance(script_payload.get("computed"), dict) else {}

    if entry.bead == "bd-3agp":
        measured = computed.get("overall_velocity_ratio")
        required = computed.get("required_velocity_ratio")
        if isinstance(measured, (int, float)) and isinstance(required, (int, float)):
            result["measured"] = float(measured)
            result["required"] = float(required)
            result["pass"] = float(measured) >= float(required)
            result["detail"] = f"ratio={measured} required={required}"
        return result

    if entry.bead == "bd-3cpa":
        measured = computed.get("compromise_reduction_ratio")
        required = computed.get("minimum_required_ratio")
        if isinstance(measured, (int, float)) and isinstance(required, (int, float)):
            result["measured"] = float(measured)
            result["required"] = float(required)
            result["pass"] = float(measured) >= float(required)
            result["detail"] = f"ratio={measured} required={required}"
        return result

    if entry.bead == "bd-34d5":
        total = script_payload.get("total", evidence_payload.get("total_checks"))
        passed = script_payload.get("passed", evidence_payload.get("passed"))
        if isinstance(total, int) and isinstance(passed, int):
            result["measured"] = f"{passed}/{total} checks"
            result["required"] = f"{total}/{total} checks"
            result["pass"] = bool(script_payload.get("all_passed", evidence_payload.get("all_passed", False)))
            result["detail"] = "all friction pathway checks must pass"
        return result

    if entry.bead == "bd-2l1k":
        measured = computed.get("coverage_ratio")
        required = computed.get("minimum_required_coverage_ratio")
        if isinstance(measured, (int, float)) and isinstance(required, (int, float)):
            result["measured"] = float(measured)
            result["required"] = float(required)
            result["pass"] = float(measured) >= float(required)
            result["detail"] = f"coverage_ratio={measured} required={required}"
        return result

    if entry.bead == "bd-whxp":
        measured = computed.get("independent_replications_passing")
        required = computed.get("required_minimum_replications")
        if isinstance(measured, int) and isinstance(required, int):
            result["measured"] = measured
            result["required"] = required
            result["pass"] = measured >= required
            result["detail"] = f"independent_passing={measured} required={required}"
        return result

    return result


def remediation_plan(bead: str) -> str:
    mapping = {
        "bd-28sz": "Raise compatibility corpus pass rate and fix failing API families until >=95% overall and >=80% family floors.",
        "bd-3agp": "Improve migration pipeline throughput and remove cohort bottlenecks to restore >=3x velocity.",
        "bd-3cpa": "Increase mitigation effectiveness against attack vectors to re-establish >=10x compromise reduction.",
        "bd-34d5": "Tighten install-to-safe-production pathway steps and fix failing archetype checks.",
        "bd-2l1k": "Close replay coverage gaps and restore 100% incident-type artifact coverage.",
        "bd-whxp": "Secure additional independent replications and ensure >=2 pass with conflict-free evaluators.",
    }
    return mapping.get(bead, "Repair failing criterion checks and regenerate evidence artifacts.")


def _quantitative_threshold(pass_flags: list[bool]) -> tuple[bool, int, int]:
    passed = sum(1 for value in pass_flags if value)
    total = len(pass_flags)
    return passed >= 4, passed, total


def write_section_summary(report: dict[str, Any]) -> None:
    lines: list[str] = [
        "# Section 13 Verification Summary",
        "",
        f"- Gate bead: `{BEAD_ID}`",
        f"- Verdict: `{report['verdict']}`",
        f"- Coverage: `{report['overall_coverage_pct']}%`",
        f"- Quantitative targets passing: `{report['quantitative_targets_passing']}/{report['quantitative_targets_total']}`",
        "",
        "## Per-Criterion Matrix",
        "",
        "| Bead | Criterion | Script | Unit Tests | Evidence | Overall |",
        "|------|-----------|--------|------------|----------|---------|",
    ]

    for item in report["per_bead_results"]:
        lines.append(
            "| {bead} | {criterion} | {script} | {tests} | {evidence} | {overall} |".format(
                bead=item["bead_id"],
                criterion=item["criterion"],
                script="PASS" if item["script_pass"] else "FAIL",
                tests="PASS" if item["unit_pass"] else "FAIL",
                evidence="PASS" if item["evidence_pass"] else "FAIL",
                overall="PASS" if item["overall_pass"] else "FAIL",
            )
        )

    lines.extend(
        [
            "",
            "## Quantitative Targets",
            "",
            "| Bead | Target | Measured | Required | Pass |",
            "|------|--------|----------|----------|------|",
        ]
    )
    for target in report["quantitative_targets"]:
        lines.append(
            "| {bead} | {target_desc} | {measured} | {required} | {status} |".format(
                bead=target["bead"],
                target_desc=target["target"],
                measured=target["measured"],
                required=target["required"],
                status="PASS" if target["pass"] else "FAIL",
            )
        )

    lines.extend(
        [
            "",
            "## Gate Checks",
            "",
            "| Gate | Status |",
            "|------|--------|",
        ]
    )
    for gate in report["gate_checks"]:
        lines.append(f"| {gate['id']} | {gate['status']} |")

    lines.extend(["", "## Gap Analysis"]) 
    if report["gaps"]:
        for idx, gap in enumerate(report["gaps"], start=1):
            lines.append(
                f"{idx}. `{gap['bead']}` - {gap['criterion']} | measured={gap['measured']} required={gap['required']} | remediation: {gap['remediation']}"
            )
    else:
        lines.append("No open gaps. All criteria and quantitative targets satisfied.")

    SUMMARY_MATRIX.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_MATRIX.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_report(execute: bool = True, write_outputs: bool = True) -> dict[str, Any]:
    events: list[dict[str, Any]] = [
        {
            "event_code": "GATE_13_EVALUATION_STARTED",
            "message": "Section 13 gate evaluation started.",
        }
    ]

    per_bead_results: list[dict[str, Any]] = []
    quantitative_targets: list[dict[str, Any]] = []

    for entry in SECTION_ENTRIES:
        script_result = run_script(entry, execute=execute)
        unit_result = run_unit_test(entry, execute=execute)
        evidence_result = load_evidence(entry)

        evidence_payload = evidence_result.get("payload", {})
        script_payload = script_result.get("payload", {})

        methodology_defined = (
            script_result.get("exists", False)
            and script_result.get("self_test_present", False)
            and evidence_result.get("exists", False)
            and evidence_result.get("has_checks", False)
        )

        quantitative = None
        quantitative_pass = True
        if entry.quantitative:
            quantitative = extract_quantitative_target(entry, script_payload, evidence_payload)
            quantitative_pass = bool(quantitative.get("pass", False))
            quantitative_targets.append(
                {
                    "bead": entry.bead,
                    "criterion": entry.criterion,
                    "target": entry.target,
                    "measured": quantitative.get("measured"),
                    "required": quantitative.get("required"),
                    "pass": quantitative_pass,
                    "detail": quantitative.get("detail"),
                }
            )
            events.append(
                {
                    "event_code": "GATE_13_TARGET_MEASURED",
                    "bead": entry.bead,
                    "target": entry.target,
                    "pass": quantitative_pass,
                }
            )

        overall = (
            script_result["status"] == "PASS"
            and unit_result["status"] == "PASS"
            and evidence_result["status"] == "PASS"
            and (methodology_defined if not entry.quantitative else True)
            and quantitative_pass
        )

        per_bead_results.append(
            {
                "bead_id": entry.bead,
                "criterion": entry.criterion,
                "quantitative": entry.quantitative,
                "target": entry.target,
                "script": entry.script,
                "test": entry.test,
                "script_pass": script_result["status"] == "PASS",
                "unit_pass": unit_result["status"] == "PASS",
                "evidence_pass": evidence_result["status"] == "PASS",
                "measurement_methodology_defined": methodology_defined,
                "quantitative_pass": quantitative_pass,
                "overall_pass": overall,
                "script_result": script_result,
                "unit_result": unit_result,
                "evidence_result": evidence_result,
            }
        )

        events.append(
            {
                "event_code": "GATE_13_BEAD_CHECKED",
                "bead": entry.bead,
                "overall_pass": overall,
            }
        )

    scripts_ok = all(item["script_pass"] for item in per_bead_results)
    tests_ok = all(item["unit_pass"] for item in per_bead_results)
    evidence_ok = all(item["evidence_pass"] for item in per_bead_results)
    all_beads_ok = all(item["overall_pass"] for item in per_bead_results)

    qualitative_entries = [item for item in per_bead_results if not item["quantitative"]]
    qualitative_methodology_ok = all(item["measurement_methodology_defined"] for item in qualitative_entries)

    quantitative_flags = [bool(item["pass"]) for item in quantitative_targets]
    quant_threshold_ok, quant_passed, quant_total = _quantitative_threshold(quantitative_flags)
    quantitative_measurements_ok = all(
        item["measured"] is not None and item["required"] is not None for item in quantitative_targets
    )

    gate_checks = [
        {"id": "GATE-13-SCRIPTS", "status": "PASS" if scripts_ok else "FAIL"},
        {"id": "GATE-13-TESTS", "status": "PASS" if tests_ok else "FAIL"},
        {"id": "GATE-13-EVIDENCE", "status": "PASS" if evidence_ok else "FAIL"},
        {
            "id": "GATE-13-MEASUREMENT-METHODOLOGY",
            "status": "PASS" if qualitative_methodology_ok else "FAIL",
        },
        {
            "id": "GATE-13-QUANTITATIVE-MEASUREMENTS",
            "status": "PASS" if quantitative_measurements_ok else "FAIL",
        },
        {
            "id": "GATE-13-QUANTITATIVE-THRESHOLD",
            "status": "PASS" if quant_threshold_ok else "FAIL",
        },
        {"id": "GATE-13-ALL-BEADS", "status": "PASS" if all_beads_ok else "FAIL"},
    ]

    gate_pass = all(item["status"] == "PASS" for item in gate_checks)
    verdict = "PASS" if gate_pass else "FAIL"

    gaps: list[dict[str, Any]] = []
    for item in quantitative_targets:
        if not item["pass"]:
            gaps.append(
                {
                    "bead": item["bead"],
                    "criterion": item["criterion"],
                    "measured": item["measured"],
                    "required": item["required"],
                    "remediation": remediation_plan(item["bead"]),
                }
            )

    for item in qualitative_entries:
        if not item["measurement_methodology_defined"]:
            gaps.append(
                {
                    "bead": item["bead_id"],
                    "criterion": item["criterion"],
                    "measured": "methodology missing",
                    "required": "measurement mechanism defined",
                    "remediation": "Add explicit measurement methodology and regenerate evidence artifacts.",
                }
            )

    events.append(
        {
            "event_code": "GATE_13_VERDICT_EMITTED",
            "verdict": verdict,
            "gate_pass": gate_pass,
            "quantitative_targets_passing": quant_passed,
            "quantitative_targets_total": quant_total,
        }
    )

    content_hash = hashlib.sha256(
        _canonical_json(
            {
                "per_bead_results": per_bead_results,
                "quantitative_targets": quantitative_targets,
                "gate_checks": gate_checks,
                "events": events,
            }
        ).encode("utf-8")
    ).hexdigest()

    report: dict[str, Any] = {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gate_pass": gate_pass,
        "verdict": verdict,
        "section_beads_expected": len(SECTION_ENTRIES),
        "section_beads_verified": len(per_bead_results),
        "overall_coverage_pct": round((len(per_bead_results) / len(SECTION_ENTRIES)) * 100.0, 2),
        "quantitative_targets_passing": quant_passed,
        "quantitative_targets_total": quant_total,
        "quantitative_targets": quantitative_targets,
        "per_bead_results": per_bead_results,
        "gate_checks": gate_checks,
        "gaps": gaps,
        "events": events,
        "content_hash": content_hash,
    }

    if write_outputs:
        write_section_summary(report)

    return report


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []

    ok_threshold, ok_passed, ok_total = _quantitative_threshold([True, True, True, True, False, False])
    checks.append(
        {
            "check": "mock_threshold_four_of_six_passes",
            "pass": ok_threshold and ok_passed == 4 and ok_total == 6,
        }
    )

    bad_threshold, bad_passed, bad_total = _quantitative_threshold([True, True, True, False, False, False])
    checks.append(
        {
            "check": "mock_threshold_three_of_six_fails",
            "pass": (not bad_threshold) and bad_passed == 3 and bad_total == 6,
        }
    )

    digest_a = hashlib.sha256(_canonical_json({"a": 1, "b": 2}).encode("utf-8")).hexdigest()
    digest_b = hashlib.sha256(_canonical_json({"b": 2, "a": 1}).encode("utf-8")).hexdigest()
    checks.append(
        {
            "check": "canonical_hash_deterministic",
            "pass": digest_a == digest_b,
        }
    )

    return all(item["pass"] for item in checks), checks


def main() -> int:
    logger = configure_test_logging("check_section_13_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--self-test", action="store_true", help="Run gate self-test")
    parser.add_argument("--no-exec", action="store_true", help="Skip executing scripts/unit tests")
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        payload = {
            "bead_id": BEAD_ID,
            "section": SECTION,
            "check": "self_test",
            "verdict": "PASS" if ok else "FAIL",
            "checks": checks,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for item in checks:
                print(f"[{ 'PASS' if item['pass'] else 'FAIL' }] {item['check']}")
            print(f"self_test verdict: {payload['verdict']}")
        return 0 if ok else 1

    report = build_report(execute=not args.no_exec, write_outputs=True)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"Section {SECTION} gate verdict: {report['verdict']} "
            f"({report['section_beads_verified']}/{report['section_beads_expected']} beads, "
            f"quantitative {report['quantitative_targets_passing']}/{report['quantitative_targets_total']})"
        )
        for gate in report["gate_checks"]:
            print(f"- {gate['id']}: {gate['status']}")
        if report["gaps"]:
            print("Open gaps:")
            for gap in report["gaps"]:
                print(f"  - {gap['bead']}: {gap['remediation']}")
    return 0 if report["gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
