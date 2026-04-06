#!/usr/bin/env python3
"""Section 11 comprehensive verification gate (bd-c781)."""

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



@dataclass(frozen=True)
class SectionEntry:
    bead: str
    name: str
    script: str
    test: str
    uses_changed_files: bool = False


SECTION_ENTRIES: list[SectionEntry] = [
    SectionEntry(
        bead="bd-3se1",
        name="Contract field: change summary",
        script="scripts/check_change_summary_contract.py",
        test="tests/test_check_change_summary_contract.py",
        uses_changed_files=True,
    ),
    SectionEntry(
        bead="bd-36wa",
        name="Contract field: compatibility and threat evidence",
        script="scripts/check_compatibility_threat_evidence.py",
        test="tests/test_check_compatibility_threat_evidence.py",
        uses_changed_files=True,
    ),
    SectionEntry(
        bead="bd-1jmq",
        name="Contract field: EV score and tier",
        script="scripts/check_ev_score.py",
        test="tests/test_check_ev_score.py",
    ),
    SectionEntry(
        bead="bd-2fpj",
        name="Contract field: expected-loss model",
        script="scripts/check_expected_loss.py",
        test="tests/test_check_expected_loss.py",
    ),
    SectionEntry(
        bead="bd-3v8f",
        name="Contract field: fallback trigger",
        script="scripts/check_fallback_trigger.py",
        test="tests/test_check_fallback_trigger.py",
    ),
    SectionEntry(
        bead="bd-2ymp",
        name="Contract field: rollout wedge",
        script="scripts/check_rollout_wedge.py",
        test="tests/test_check_rollout_wedge.py",
    ),
    SectionEntry(
        bead="bd-nglx",
        name="Contract field: rollback command",
        script="scripts/check_rollback_command.py",
        test="tests/test_check_rollback_command.py",
        uses_changed_files=True,
    ),
    SectionEntry(
        bead="bd-3l8d",
        name="Contract field: benchmark and correctness artifacts",
        script="scripts/check_benchmark_correctness_artifacts.py",
        test="tests/test_check_benchmark_correctness_artifacts.py",
        uses_changed_files=True,
    ),
    SectionEntry(
        bead="bd-2ut3",
        name="No-contract-no-merge gate",
        script="scripts/check_no_contract_no_merge.py",
        test="tests/test_check_no_contract_no_merge.py",
        uses_changed_files=True,
    ),
]

REQUIRED_CONTRACT_FIELDS = [
    "intent",
    "scope",
    "surface_area_delta",
    "affected_contracts",
    "operational_impact",
    "risk_delta",
    "compatibility",
    "dependency_changes",
    "compatibility_and_threat_evidence",
    "ev_score_and_tier",
    "expected_loss_model",
    "fallback_trigger",
    "rollout_wedge",
    "rollback_command",
    "benchmark_and_correctness_artifacts",
]

EVENT_CODES = {
    "GATE_11_EVALUATION_STARTED",
    "GATE_11_BEAD_CHECKED",
    "GATE_11_CONTRACT_COVERAGE",
    "GATE_11_VERDICT_EMITTED",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _parse_passed_failed(stdout: str) -> tuple[int, int]:
    passed = 0
    failed = 0
    passed_match = re.search(r"(\d+)\s+passed", stdout)
    failed_match = re.search(r"(\d+)\s+failed", stdout)
    if passed_match:
        passed = int(passed_match.group(1))
    if failed_match:
        failed = int(failed_match.group(1))
    return passed, failed


def _is_script_payload_pass(payload: dict[str, Any]) -> bool:
    if "ok" in payload:
        return bool(payload.get("ok"))
    if "verdict" in payload:
        return str(payload.get("verdict")) == "PASS"
    if "gate_pass" in payload:
        return bool(payload.get("gate_pass"))
    if "status" in payload:
        status = str(payload.get("status", "")).strip().lower()
        if status in {"pass", "passed", "ok", "success"}:
            return True
        if status in {"fail", "failed", "error"}:
            return False
    if "all_passed" in payload:
        return bool(payload.get("all_passed"))
    if "passed" in payload and "total" in payload:
        try:
            passed = int(payload.get("passed", -1))
            total = int(payload.get("total", -1))
        except (TypeError, ValueError):
            return False
        return total >= 0 and passed == total
    return False


def _ensure_changed_files_fixture() -> Path:
    fixture = ROOT / "artifacts" / "section_11" / "bd-c781" / "changed_files_for_validation.txt"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(
        "crates/franken-node/src/connector/lease_service.rs\n"
        "docs/change_summaries/example_change_summary.json\n",
        encoding="utf-8",
    )
    return fixture


def run_script(entry: SectionEntry, changed_files_fixture: Path, timeout: int = 120) -> dict[str, Any]:
    script_path = ROOT / entry.script
    if not script_path.exists():
        return {
            "status": "FAIL",
            "script": entry.script,
            "exit_code": None,
            "error": "script missing",
            "payload": None,
        }

    cmd = [sys.executable, str(script_path), "--json"]
    if entry.uses_changed_files:
        cmd.extend(["--changed-files", str(changed_files_fixture)])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=ROOT,
    )

    status = "PASS" if proc.returncode == 0 else "FAIL"
    payload: dict[str, Any] | None = None
    stdout = proc.stdout.strip()
    if stdout:
        try:
            payload = json.loads(stdout)
            if not _is_script_payload_pass(payload):
                status = "FAIL"
        except json.JSONDecodeError:
            status = "FAIL"

    return {
        "status": status,
        "script": entry.script,
        "exit_code": proc.returncode,
        "payload": payload,
        "stderr": proc.stderr.strip()[:400] if proc.stderr else "",
    }


def run_verification_scripts(changed_files_fixture: Path) -> dict[str, Any]:
    details: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    overall = "PASS"

    for entry in SECTION_ENTRIES:
        script_result = run_script(entry, changed_files_fixture)
        detail = {
            "bead": entry.bead,
            "name": entry.name,
            "script": entry.script,
            **script_result,
        }
        if detail["status"] != "PASS":
            overall = "FAIL"
        details.append(detail)
        events.append(
            {
                "event_code": "GATE_11_BEAD_CHECKED",
                "severity": "info" if detail["status"] == "PASS" else "error",
                "bead": entry.bead,
                "script": entry.script,
                "status": detail["status"],
            }
        )

    return {
        "id": "GATE11-SCRIPTS",
        "status": overall,
        "details": {
            "total": len(details),
            "passing": sum(1 for item in details if item["status"] == "PASS"),
            "results": details,
            "events": events,
        },
    }


def run_unit_tests() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    overall = "PASS"
    total_passed = 0
    total_failed = 0

    for entry in SECTION_ENTRIES:
        test_path = ROOT / entry.test
        result = {
            "bead": entry.bead,
            "test": entry.test,
            "status": "PASS",
            "passed": 0,
            "failed": 0,
            "exit_code": None,
        }
        if not test_path.exists():
            result["status"] = "FAIL"
            result["error"] = "test file missing"
            overall = "FAIL"
            results.append(result)
            continue

        proc = subprocess.run(
            [sys.executable, "-m", "unittest", entry.test],
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=ROOT,
        )

        combined_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        passed, failed = _parse_passed_failed(combined_output)
        result["passed"] = passed
        result["failed"] = failed
        result["exit_code"] = proc.returncode
        if proc.returncode != 0:
            result["status"] = "FAIL"
            result["stderr"] = combined_output.strip()[:400]
            overall = "FAIL"

        total_passed += passed
        total_failed += failed
        results.append(result)

    coverage_pct = round(
        100.0 * sum(1 for item in results if item["status"] == "PASS") / len(SECTION_ENTRIES),
        2,
    )

    return {
        "id": "GATE11-TESTS",
        "status": overall,
        "details": {
            "results": results,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "companion_test_coverage_pct": coverage_pct,
            "threshold_pct": 100.0,
            "meets_threshold": coverage_pct >= 100.0,
        },
    }


def check_evidence_artifacts() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    overall = "PASS"

    for entry in SECTION_ENTRIES:
        artifact_rel = f"artifacts/section_11/{entry.bead}/verification_evidence.json"
        artifact_path = ROOT / artifact_rel
        item = {
            "bead": entry.bead,
            "path": artifact_rel,
            "status": "PASS",
            "verdict": "PASS",
        }

        if not artifact_path.exists():
            item["status"] = "FAIL"
            item["verdict"] = "MISSING"
            overall = "FAIL"
        else:
            try:
                json.loads(artifact_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                item["status"] = "FAIL"
                item["verdict"] = "INVALID_JSON"
                overall = "FAIL"

        results.append(item)

    return {
        "id": "GATE11-EVIDENCE",
        "status": overall,
        "details": {
            "results": results,
            "missing_or_invalid": [item["bead"] for item in results if item["status"] != "PASS"],
        },
    }


def check_contract_coverage() -> dict[str, Any]:
    template_path = ROOT / "docs" / "templates" / "change_summary_template.md"
    example_path = ROOT / "docs" / "change_summaries" / "example_change_summary.json"

    errors: list[str] = []

    if not template_path.exists():
        errors.append("missing docs/templates/change_summary_template.md")
        template_text = ""
    else:
        template_text = template_path.read_text(encoding="utf-8")

    if not example_path.exists():
        errors.append("missing docs/change_summaries/example_change_summary.json")
        example_payload = {}
    else:
        try:
            example_payload = json.loads(example_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            errors.append("invalid JSON in docs/change_summaries/example_change_summary.json")
            example_payload = {}

    for field in REQUIRED_CONTRACT_FIELDS:
        if template_text and field not in template_text:
            errors.append(f"template missing field `{field}`")

    change_summary = example_payload.get("change_summary") if isinstance(example_payload, dict) else None
    if not isinstance(change_summary, dict):
        errors.append("example missing change_summary object")
    else:
        for field in REQUIRED_CONTRACT_FIELDS:
            if field not in change_summary:
                errors.append(f"example missing change_summary.{field}")

    status = "PASS" if not errors else "FAIL"
    return {
        "id": "GATE11-CONTRACT-COVERAGE",
        "status": status,
        "details": {
            "required_fields": REQUIRED_CONTRACT_FIELDS,
            "missing_or_invalid": errors,
        },
    }


def build_report() -> dict[str, Any]:
    changed_files_fixture = _ensure_changed_files_fixture()
    timestamp = datetime.now(timezone.utc).isoformat()

    events: list[dict[str, Any]] = [
        {
            "event_code": "GATE_11_EVALUATION_STARTED",
            "severity": "info",
            "timestamp": timestamp,
        }
    ]

    script_check = run_verification_scripts(changed_files_fixture)
    test_check = run_unit_tests()
    evidence_check = check_evidence_artifacts()
    coverage_check = check_contract_coverage()

    checks = [script_check, test_check, evidence_check, coverage_check]
    gate_pass = all(check["status"] == "PASS" for check in checks)

    script_by_bead = {item["bead"]: item for item in script_check["details"]["results"]}
    test_by_bead = {item["bead"]: item for item in test_check["details"]["results"]}
    evidence_by_bead = {item["bead"]: item for item in evidence_check["details"]["results"]}

    per_bead_results: list[dict[str, Any]] = []
    for entry in SECTION_ENTRIES:
        script_pass = script_by_bead[entry.bead]["status"] == "PASS"
        unit_pass = test_by_bead[entry.bead]["status"] == "PASS"
        evidence_pass = evidence_by_bead[entry.bead]["status"] == "PASS"
        overall_pass = script_pass and unit_pass and evidence_pass
        per_bead_results.append(
            {
                "bead_id": entry.bead,
                "script_pass": script_pass,
                "unit_pass": unit_pass,
                "evidence_pass": evidence_pass,
                "overall_pass": overall_pass,
            }
        )

    events.extend(script_check["details"]["events"])
    events.append(
        {
            "event_code": "GATE_11_CONTRACT_COVERAGE",
            "severity": "info" if coverage_check["status"] == "PASS" else "error",
            "status": coverage_check["status"],
            "missing_or_invalid_count": len(coverage_check["details"]["missing_or_invalid"]),
        }
    )
    events.append(
        {
            "event_code": "GATE_11_VERDICT_EMITTED",
            "severity": "info" if gate_pass else "error",
            "verdict": "PASS" if gate_pass else "FAIL",
        }
    )

    report = {
        "gate": "section_11_comprehensive_gate",
        "bead_id": "bd-c781",
        "section": "11",
        "gate_pass": gate_pass,
        "verdict": "PASS" if gate_pass else "FAIL",
        "timestamp": timestamp,
        "beads_tested": [entry.bead for entry in SECTION_ENTRIES],
        "required_event_codes": sorted(EVENT_CODES),
        "events": events,
        "per_bead_results": per_bead_results,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for check in checks if check["status"] == "PASS"),
            "failing_checks": sum(1 for check in checks if check["status"] == "FAIL"),
            "scripts_passing": script_check["details"]["passing"],
            "scripts_total": script_check["details"]["total"],
            "test_coverage_pct": test_check["details"]["companion_test_coverage_pct"],
        },
    }

    stable = dict(report)
    stable.pop("timestamp", None)
    report["content_hash"] = hashlib.sha256(
        _canonical_json(stable).encode("utf-8")
    ).hexdigest()
    return report


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []

    sample = {"a": 1, "b": [2, 3]}
    hash_one = hashlib.sha256(_canonical_json(sample).encode("utf-8")).hexdigest()
    hash_two = hashlib.sha256(_canonical_json(sample).encode("utf-8")).hexdigest()
    checks.append({"check": "canonical hash deterministic", "pass": hash_one == hash_two, "detail": hash_one})

    checks.append(
        {
            "check": "section entry count",
            "pass": len(SECTION_ENTRIES) == 9,
            "detail": f"count={len(SECTION_ENTRIES)}",
        }
    )

    checks.append(
        {
            "check": "required event codes",
            "pass": EVENT_CODES == {
                "GATE_11_EVALUATION_STARTED",
                "GATE_11_BEAD_CHECKED",
                "GATE_11_CONTRACT_COVERAGE",
                "GATE_11_VERDICT_EMITTED",
            },
            "detail": ",".join(sorted(EVENT_CODES)),
        }
    )

    checks.append(
        {
            "check": "required field coverage list",
            "pass": len(REQUIRED_CONTRACT_FIELDS) == 15,
            "detail": f"count={len(REQUIRED_CONTRACT_FIELDS)}",
        }
    )

    return all(item["pass"] for item in checks), checks


def main() -> None:
    logger = configure_test_logging("check_section_11_gate")
    parser = argparse.ArgumentParser(description="Section 11 comprehensive gate")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run deterministic self-test")
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        payload = {"ok": ok, "checks": checks}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"self_test: {sum(1 for item in checks if item['pass'])}/{len(checks)} checks pass")
            for item in checks:
                status = "PASS" if item["pass"] else "FAIL"
                print(f"[{status}] {item['check']}: {item['detail']}")
        sys.exit(0 if ok else 1)

    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=== Section 11 Comprehensive Gate ===")
        print(f"Verdict: {report['verdict']}")
        print(f"Content hash: {report['content_hash']}")
        for check in report["checks"]:
            status = "PASS" if check["status"] == "PASS" else "FAIL"
            print(f"[{status}] {check['id']}")

    sys.exit(0 if report["gate_pass"] else 1)


if __name__ == "__main__":
    main()
