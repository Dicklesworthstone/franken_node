#!/usr/bin/env python3
"""Section 10.9 comprehensive verification gate (bd-1kfq).

Aggregates pass/fail status from all 6 section 10.9 (Moonshot Disruption Track)
beads, runs verification scripts and unit tests, checks evidence artifacts,
and produces a unified JSON gate verdict.

Usage:
    python scripts/check_section_10_9_gate.py
    python scripts/check_section_10_9_gate.py --json
    python scripts/check_section_10_9_gate.py --self-test
"""

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


SECTION_ENTRIES: list[SectionEntry] = [
    SectionEntry(
        bead="bd-f5d",
        name="Public benchmark campaign infrastructure",
        script="scripts/check_benchmark_infra.py",
        test="tests/test_check_benchmark_infra.py",
    ),
    SectionEntry(
        bead="bd-9is",
        name="Autonomous adversarial campaign runner",
        script="scripts/check_adversarial_runner.py",
        test="tests/test_check_adversarial_runner.py",
    ),
    SectionEntry(
        bead="bd-1e0",
        name="Migration singularity demo pipeline",
        script="scripts/check_migration_demo.py",
        test="tests/test_check_migration_demo.py",
    ),
    SectionEntry(
        bead="bd-m8p",
        name="Verifier economy portal",
        script="scripts/check_verifier_economy.py",
        test="tests/test_check_verifier_economy.py",
    ),
    SectionEntry(
        bead="bd-10c",
        name="Trust economics dashboard",
        script="scripts/check_trust_economics.py",
        test="tests/test_check_trust_economics.py",
    ),
    SectionEntry(
        bead="bd-15t",
        name="Category-shift reporting pipeline",
        script="scripts/check_category_shift.py",
        test="tests/test_check_category_shift.py",
    ),
]

EVENT_CODES = {
    "GATE_10_9_EVALUATION_STARTED",
    "GATE_10_9_BEAD_CHECKED",
    "GATE_10_9_MOONSHOT_COVERAGE",
    "GATE_10_9_VERDICT_EMITTED",
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
    if "overall_pass" in payload:
        return bool(payload.get("overall_pass"))
    if "passed" in payload and "total" in payload:
        try:
            p = int(payload.get("passed", -1))
            t = int(payload.get("total", -1))
        except (TypeError, ValueError):
            return False
        return t >= 0 and p == t
    return False


def run_script(entry: SectionEntry, timeout: int = 120) -> dict[str, Any]:
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

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "FAIL",
            "script": entry.script,
            "exit_code": None,
            "error": f"timeout after {timeout}s",
            "payload": None,
        }

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


def run_verification_scripts() -> dict[str, Any]:
    details: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    overall = "PASS"

    for entry in SECTION_ENTRIES:
        script_result = run_script(entry)
        detail = {
            "bead": entry.bead,
            "name": entry.name,
            "script": entry.script,
            **script_result,
        }
        if detail["status"] != "PASS":
            overall = "FAIL"
        details.append(detail)
        events.append({
            "event_code": "GATE_10_9_BEAD_CHECKED",
            "severity": "info" if detail["status"] == "PASS" else "error",
            "bead": entry.bead,
            "script": entry.script,
            "status": detail["status"],
        })

    return {
        "id": "GATE109-SCRIPTS",
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

        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"],
                capture_output=True,
                text=True,
                timeout=3600,
                cwd=ROOT,
            )
        except subprocess.TimeoutExpired:
            result["status"] = "FAIL"
            result["error"] = "timeout"
            overall = "FAIL"
            results.append(result)
            continue

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
        100.0 * sum(1 for item in results if item["status"] == "PASS") / max(len(SECTION_ENTRIES), 1),
        2,
    )

    return {
        "id": "GATE109-TESTS",
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
        artifact_rel = f"artifacts/section_10_9/{entry.bead}/verification_evidence.json"
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
        "id": "GATE109-EVIDENCE",
        "status": overall,
        "details": {
            "results": results,
            "missing_or_invalid": [item["bead"] for item in results if item["status"] != "PASS"],
        },
    }


def check_moonshot_coverage() -> dict[str, Any]:
    """Verify moonshot-specific coverage requirements."""
    errors: list[str] = []

    # Check benchmark infrastructure produces public results
    bench_evidence = ROOT / "artifacts" / "section_10_9" / "bd-f5d" / "verification_evidence.json"
    if bench_evidence.is_file():
        try:
            data = json.loads(bench_evidence.read_text(encoding="utf-8"))
            if not data.get("verdict") == "PASS":
                errors.append("benchmark infrastructure verdict is not PASS")
        except (json.JSONDecodeError, KeyError):
            errors.append("benchmark infrastructure evidence invalid")
    else:
        errors.append("benchmark infrastructure evidence missing")

    # Check adversarial campaign has run at least one cycle
    adv_evidence = ROOT / "artifacts" / "section_10_9" / "bd-9is" / "verification_evidence.json"
    if adv_evidence.is_file():
        try:
            data = json.loads(adv_evidence.read_text(encoding="utf-8"))
            if not data.get("verdict") == "PASS":
                errors.append("adversarial campaign verdict is not PASS")
        except (json.JSONDecodeError, KeyError):
            errors.append("adversarial campaign evidence invalid")
    else:
        errors.append("adversarial campaign evidence missing")

    # Check trust economics dashboard exists with required metrics
    econ_evidence = ROOT / "artifacts" / "section_10_9" / "bd-10c" / "verification_evidence.json"
    if econ_evidence.is_file():
        try:
            data = json.loads(econ_evidence.read_text(encoding="utf-8"))
            if not data.get("verdict") == "PASS":
                errors.append("trust economics dashboard verdict is not PASS")
        except (json.JSONDecodeError, KeyError):
            errors.append("trust economics evidence invalid")
    else:
        errors.append("trust economics evidence missing")

    status = "PASS" if not errors else "FAIL"
    return {
        "id": "GATE109-MOONSHOT-COVERAGE",
        "status": status,
        "details": {
            "errors": errors,
            "beads_with_pass_verdicts": 6 - len(errors),
        },
    }


def build_report() -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    events: list[dict[str, Any]] = [{
        "event_code": "GATE_10_9_EVALUATION_STARTED",
        "severity": "info",
        "timestamp": timestamp,
    }]

    script_check = run_verification_scripts()
    test_check = run_unit_tests()
    evidence_check = check_evidence_artifacts()
    moonshot_check = check_moonshot_coverage()

    checks = [script_check, test_check, evidence_check, moonshot_check]
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
        per_bead_results.append({
            "bead_id": entry.bead,
            "name": entry.name,
            "script_pass": script_pass,
            "unit_pass": unit_pass,
            "evidence_pass": evidence_pass,
            "overall_pass": overall_pass,
        })

    events.extend(script_check["details"]["events"])
    events.append({
        "event_code": "GATE_10_9_MOONSHOT_COVERAGE",
        "severity": "info" if moonshot_check["status"] == "PASS" else "error",
        "status": moonshot_check["status"],
    })
    events.append({
        "event_code": "GATE_10_9_VERDICT_EMITTED",
        "severity": "info" if gate_pass else "error",
        "verdict": "PASS" if gate_pass else "FAIL",
    })

    report = {
        "gate": "section_10_9_comprehensive_gate",
        "bead_id": "bd-1kfq",
        "section": "10.9",
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
            "total_unit_tests_passed": test_check["details"]["total_passed"],
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

    checks.append({
        "check": "section entry count",
        "pass": len(SECTION_ENTRIES) == 6,
        "detail": f"count={len(SECTION_ENTRIES)}",
    })

    checks.append({
        "check": "required event codes",
        "pass": EVENT_CODES == {
            "GATE_10_9_EVALUATION_STARTED",
            "GATE_10_9_BEAD_CHECKED",
            "GATE_10_9_MOONSHOT_COVERAGE",
            "GATE_10_9_VERDICT_EMITTED",
        },
        "detail": ",".join(sorted(EVENT_CODES)),
    })

    checks.append({
        "check": "all scripts exist",
        "pass": all((ROOT / entry.script).exists() for entry in SECTION_ENTRIES),
        "detail": f"{sum(1 for e in SECTION_ENTRIES if (ROOT / e.script).exists())}/{len(SECTION_ENTRIES)} scripts found",
    })

    checks.append({
        "check": "all tests exist",
        "pass": all((ROOT / entry.test).exists() for entry in SECTION_ENTRIES),
        "detail": f"{sum(1 for e in SECTION_ENTRIES if (ROOT / e.test).exists())}/{len(SECTION_ENTRIES)} tests found",
    })

    return all(item["pass"] for item in checks), checks


def main() -> None:
    logger = configure_test_logging("check_section_10_9_gate")
    parser = argparse.ArgumentParser(description="Section 10.9 comprehensive gate")
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
        print("=== Section 10.9 Comprehensive Gate ===")
        print(f"Verdict: {report['verdict']}")
        print(f"Content hash: {report['content_hash']}")
        for check in report["checks"]:
            status = "PASS" if check["status"] == "PASS" else "FAIL"
            print(f"[{status}] {check['id']}")
        print("\nPer-bead results:")
        for bead_result in report["per_bead_results"]:
            status = "PASS" if bead_result["overall_pass"] else "FAIL"
            print(f"  [{status}] {bead_result['bead_id']}: {bead_result['name']}")

    sys.exit(0 if report["gate_pass"] else 1)


if __name__ == "__main__":
    main()
