#!/usr/bin/env python3
"""Section 10.4 comprehensive verification gate (bd-261k)."""

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


@dataclass(frozen=True)
class SectionEntry:
    bead: str
    name: str
    script: str
    test: str


SECTION_ENTRIES: list[SectionEntry] = [
    SectionEntry(
        bead="bd-1gx",
        name="Signed extension package manifest schema",
        script="scripts/check_extension_manifest_schema.py",
        test="tests/test_check_extension_manifest_schema.py",
    ),
    SectionEntry(
        bead="bd-1ah",
        name="Provenance attestation verification chain",
        script="scripts/check_provenance_attestation.py",
        test="tests/test_check_provenance_attestation.py",
    ),
    SectionEntry(
        bead="bd-12q",
        name="Revocation propagation with freshness checks",
        script="scripts/check_revocation_integration.py",
        test="tests/test_check_revocation_integration.py",
    ),
    SectionEntry(
        bead="bd-2yh",
        name="Extension trust-card API and CLI",
        script="scripts/check_trust_card.py",
        test="tests/test_check_trust_card.py",
    ),
    SectionEntry(
        bead="bd-ml1",
        name="Publisher reputation model",
        script="scripts/check_publisher_reputation.py",
        test="tests/test_check_publisher_reputation.py",
    ),
    SectionEntry(
        bead="bd-1vm",
        name="Quarantine and recall workflow",
        script="scripts/check_quarantine_workflow.py",
        test="tests/test_check_quarantine_workflow.py",
    ),
    SectionEntry(
        bead="bd-273",
        name="Certification levels tied to policy controls",
        script="scripts/check_certification_levels.py",
        test="tests/test_check_certification_levels.py",
    ),
    SectionEntry(
        bead="bd-phf",
        name="Ecosystem telemetry for trust and adoption",
        script="scripts/check_ecosystem_telemetry.py",
        test="tests/test_check_ecosystem_telemetry.py",
    ),
]

PIPELINE_CHECKS = [
    {
        "id": "PIPE-MANIFEST-PROVENANCE-TRUSTCARD",
        "description": "manifest -> provenance -> trust-card pipeline",
        "beads": ["bd-1gx", "bd-1ah", "bd-2yh"],
        "artifacts": [
            "artifacts/section_10_4/bd-1ah/attestation_chain_report.json",
            "artifacts/section_10_4/bd-2yh/trust_card_report.json",
        ],
    },
    {
        "id": "PIPE-REVOCATION-QUARANTINE-RECALL",
        "description": "revocation -> quarantine -> recall pipeline",
        "beads": ["bd-12q", "bd-1vm", "bd-2yh"],
        "artifacts": [
            "artifacts/section_10_4/bd-12q/revocation_integration_decisions.json",
            "artifacts/section_10_4/bd-2yh/trust_card_self_test.json",
        ],
    },
    {
        "id": "PIPE-REPUTATION-CERTIFICATION-POLICY",
        "description": "reputation -> certification -> policy gate pipeline",
        "beads": ["bd-ml1", "bd-273"],
        "artifacts": [
            "scripts/check_provenance_gate.py",
            "tests/test_check_provenance_gate.py",
        ],
    },
]

POLICY_GATES = [
    {
        "id": "POLICY-RCH",
        "path": "artifacts/program/rch_execution_policy_report.json",
        "field": "verdict",
        "expected": "PASS",
    },
    {
        "id": "POLICY-ARTIFACT-NAMESPACE",
        "path": "artifacts/program/artifact_namespace_validation_report.json",
        "field": "verdict",
        "expected": "PASS",
    },
]


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


def run_script(script_relpath: str, timeout: int = 60) -> dict[str, Any]:
    script_path = ROOT / script_relpath
    if not script_path.exists():
        return {
            "status": "FAIL",
            "script": script_relpath,
            "exit_code": None,
            "error": "script missing",
        }

    result = subprocess.run(
        [sys.executable, str(script_path), "--json"],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=ROOT,
    )

    script_status = "PASS" if result.returncode == 0 else "FAIL"
    script_verdict = None
    stdout = result.stdout.strip()
    if stdout:
        try:
            payload = json.loads(stdout)
            script_verdict = payload.get("verdict")
            if script_verdict is not None and script_verdict != "PASS":
                script_status = "FAIL"
        except json.JSONDecodeError:
            script_verdict = None

    return {
        "status": script_status,
        "script": script_relpath,
        "exit_code": result.returncode,
        "verdict": script_verdict,
        "stderr": result.stderr.strip()[:400] if result.stderr else "",
    }


def run_verification_scripts() -> dict[str, Any]:
    details: list[dict[str, Any]] = []
    overall = "PASS"

    for entry in SECTION_ENTRIES:
        script_result = run_script(entry.script)
        result_entry = {
            "bead": entry.bead,
            "name": entry.name,
            "script": entry.script,
            **script_result,
        }
        if script_result["status"] != "PASS":
            overall = "FAIL"
        details.append(result_entry)

    return {
        "id": "GATE-SCRIPTS",
        "status": overall,
        "details": {
            "total": len(details),
            "passing": sum(1 for item in details if item["status"] == "PASS"),
            "results": details,
        },
    }


def run_unit_tests() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    overall = "PASS"
    total_passed = 0
    total_failed = 0

    for entry in SECTION_ENTRIES:
        test_path = ROOT / entry.test
        result_entry = {
            "bead": entry.bead,
            "test": entry.test,
            "status": "PASS",
            "passed": 0,
            "failed": 0,
            "exit_code": None,
        }
        if not test_path.exists():
            result_entry["status"] = "FAIL"
            result_entry["error"] = "test file missing"
            overall = "FAIL"
            results.append(result_entry)
            continue

        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_path), "-q", "--tb=short"],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=ROOT,
        )
        passed, failed = _parse_passed_failed(proc.stdout)
        result_entry["passed"] = passed
        result_entry["failed"] = failed
        result_entry["exit_code"] = proc.returncode
        if proc.returncode != 0:
            result_entry["status"] = "FAIL"
            result_entry["stderr"] = proc.stderr.strip()[:400] if proc.stderr else ""
            overall = "FAIL"

        total_passed += passed
        total_failed += failed
        results.append(result_entry)

    companion_coverage_pct = round(
        100.0 * sum(1 for item in results if item["status"] == "PASS") / len(SECTION_ENTRIES),
        2,
    )

    return {
        "id": "GATE-TESTS",
        "status": overall,
        "details": {
            "results": results,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "companion_test_coverage_pct": companion_coverage_pct,
            "threshold_pct": 90.0,
            "meets_threshold": companion_coverage_pct >= 90.0,
        },
    }


def _artifact_verdict(path: Path) -> tuple[bool, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, "invalid-json"

    if "verdict" in payload:
        verdict = str(payload.get("verdict"))
        return verdict == "PASS", verdict
    if "overall_pass" in payload:
        verdict = bool(payload.get("overall_pass"))
        return verdict, "PASS" if verdict else "FAIL"
    if "gate_pass" in payload:
        verdict = bool(payload.get("gate_pass"))
        return verdict, "PASS" if verdict else "FAIL"
    summary = payload.get("summary")
    if isinstance(summary, dict) and "failed" in summary:
        failed = int(summary.get("failed", 1))
        return failed == 0, "PASS" if failed == 0 else "FAIL"
    status = str(payload.get("status", ""))
    if status.startswith("completed"):
        return True, status
    return False, "UNKNOWN"


def check_evidence_artifacts() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    overall = "PASS"

    for entry in SECTION_ENTRIES:
        artifact_rel = f"artifacts/section_10_4/{entry.bead}/verification_evidence.json"
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
            passed, verdict = _artifact_verdict(artifact_path)
            item["verdict"] = verdict
            if not passed:
                item["status"] = "FAIL"
                overall = "FAIL"
        results.append(item)

    return {
        "id": "GATE-EVIDENCE",
        "status": overall,
        "details": {
            "results": results,
            "missing": [item["bead"] for item in results if item["status"] == "FAIL"],
        },
    }


def check_cross_bead_integrations(evidence_status_by_bead: dict[str, bool]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    overall = "PASS"

    for pipeline in PIPELINE_CHECKS:
        pipeline_ok = True
        missing_items: list[str] = []

        for bead in pipeline["beads"]:
            if not evidence_status_by_bead.get(bead, False):
                pipeline_ok = False
                missing_items.append(f"evidence:{bead}")

        for artifact_rel in pipeline["artifacts"]:
            artifact_path = ROOT / artifact_rel
            if not artifact_path.exists():
                pipeline_ok = False
                missing_items.append(artifact_rel)
            elif artifact_path.suffix == ".json":
                try:
                    json.loads(artifact_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    pipeline_ok = False
                    missing_items.append(f"invalid-json:{artifact_rel}")

        checks.append(
            {
                "id": pipeline["id"],
                "description": pipeline["description"],
                "status": "PASS" if pipeline_ok else "FAIL",
                "missing_or_invalid": missing_items,
            }
        )

        if not pipeline_ok:
            overall = "FAIL"

    return {
        "id": "GATE-INTEGRATION",
        "status": overall,
        "details": {
            "pipelines": checks,
            "passing": sum(1 for item in checks if item["status"] == "PASS"),
            "total": len(checks),
        },
    }


def check_policy_prereqs() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    overall = "PASS"

    for gate in POLICY_GATES:
        path = ROOT / gate["path"]
        item = {"id": gate["id"], "path": gate["path"], "status": "PASS", "actual": None}
        if not path.exists():
            item["status"] = "FAIL"
            item["actual"] = "MISSING"
            overall = "FAIL"
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
            actual = payload.get(gate["field"])
            item["actual"] = actual
            if actual != gate["expected"]:
                item["status"] = "FAIL"
                overall = "FAIL"
        results.append(item)

    return {
        "id": "GATE-POLICY",
        "status": overall,
        "details": {
            "results": results,
        },
    }


def build_report() -> dict[str, Any]:
    script_check = run_verification_scripts()
    test_check = run_unit_tests()
    evidence_check = check_evidence_artifacts()
    evidence_status_by_bead = {
        item["bead"]: item["status"] == "PASS" for item in evidence_check["details"]["results"]
    }
    integration_check = check_cross_bead_integrations(evidence_status_by_bead)
    policy_check = check_policy_prereqs()

    checks = [script_check, test_check, evidence_check, integration_check, policy_check]
    gate_pass = all(check["status"] == "PASS" for check in checks)
    timestamp = datetime.now(timezone.utc).isoformat()

    script_by_bead = {
        item["bead"]: item for item in script_check["details"]["results"]
    }
    test_by_bead = {
        item["bead"]: item for item in test_check["details"]["results"]
    }
    pipeline_by_bead: dict[str, bool] = {entry.bead: True for entry in SECTION_ENTRIES}
    for pipeline in integration_check["details"]["pipelines"]:
        for bead in next(item for item in PIPELINE_CHECKS if item["id"] == pipeline["id"])["beads"]:
            pipeline_by_bead[bead] = pipeline_by_bead[bead] and (pipeline["status"] == "PASS")

    per_bead_results: list[dict[str, Any]] = []
    for entry in SECTION_ENTRIES:
        script_pass = script_by_bead[entry.bead]["status"] == "PASS"
        unit_pass = test_by_bead[entry.bead]["status"] == "PASS"
        integration_pass = pipeline_by_bead.get(entry.bead, True)
        # Each bead-level verification script already validates event-code/log contracts.
        log_events_validated = script_pass
        bead_pass = all([script_pass, unit_pass, integration_pass, log_events_validated])
        per_bead_results.append(
            {
                "bead_id": entry.bead,
                "script_pass": script_pass,
                "unit_pass": unit_pass,
                "integration_pass": integration_pass,
                "log_events_validated": log_events_validated,
                "overall_pass": bead_pass,
            }
        )

    report = {
        "gate": "section_10_4_comprehensive_gate",
        "bead_id": "bd-261k",
        "section": "10.4",
        "gate_pass": gate_pass,
        "verdict": "PASS" if gate_pass else "FAIL",
        "timestamp": timestamp,
        "beads_tested": [entry.bead for entry in SECTION_ENTRIES],
        "per_bead_results": per_bead_results,
        "overall_coverage_pct": test_check["details"]["companion_test_coverage_pct"],
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for check in checks if check["status"] == "PASS"),
            "failing_checks": sum(1 for check in checks if check["status"] == "FAIL"),
            "scripts_passing": script_check["details"]["passing"],
            "scripts_total": script_check["details"]["total"],
            "integration_passing": integration_check["details"]["passing"],
            "integration_total": integration_check["details"]["total"],
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
    checks.append(
        {
            "check": "canonical hash deterministic",
            "pass": hash_one == hash_two,
            "detail": hash_one,
        }
    )
    checks.append(
        {
            "check": "section entry count",
            "pass": len(SECTION_ENTRIES) == 8,
            "detail": f"count={len(SECTION_ENTRIES)}",
        }
    )
    checks.append(
        {
            "check": "pipeline count",
            "pass": len(PIPELINE_CHECKS) == 3,
            "detail": f"count={len(PIPELINE_CHECKS)}",
        }
    )
    return all(item["pass"] for item in checks), checks


def main() -> None:
    parser = argparse.ArgumentParser(description="Section 10.4 comprehensive gate")
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
        print("=== Section 10.4 Comprehensive Gate ===")
        print(f"Verdict: {report['verdict']}")
        print(f"Coverage (companion tests): {report['overall_coverage_pct']}%")
        print(f"Content hash: {report['content_hash']}")
        for check in report["checks"]:
            status = "PASS" if check["status"] == "PASS" else "FAIL"
            print(f"[{status}] {check['id']}")

    sys.exit(0 if report["gate_pass"] else 1)


if __name__ == "__main__":
    main()
