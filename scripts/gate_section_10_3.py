#!/usr/bin/env python3
"""
Section 10.3 Verification Gate.

Usage:
    python3 scripts/gate_section_10_3.py [--json]
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SECTION_SCRIPTS = [
    {"bead": "bd-2a0", "name": "Project Scanner", "script": "scripts/check_project_scanner.py"},
    {"bead": "bd-33x", "name": "Risk Scorer", "script": "scripts/check_risk_scorer.py"},
    {"bead": "bd-2ew", "name": "Rewrite Engine", "script": "scripts/check_rewrite_engine.py"},
    {"bead": "bd-2st", "name": "Migration Validation", "script": "scripts/check_migration_validation.py"},
    {"bead": "bd-3dn", "name": "Rollout Planner", "script": "scripts/check_rollout_planner.py"},
    {"bead": "bd-12f", "name": "Confidence Report", "script": "scripts/check_confidence_report.py"},
    {"bead": "bd-hg1", "name": "Migrate Report", "script": "scripts/check_migrate_report.py"},
    {"bead": "bd-3f9", "name": "Failure Replay", "script": "scripts/check_failure_replay.py"},
]

SECTION_TESTS = [
    "tests/test_check_project_scanner.py",
    "tests/test_check_risk_scorer.py",
    "tests/test_check_rewrite_engine.py",
    "tests/test_check_migration_validation.py",
    "tests/test_check_rollout_planner.py",
    "tests/test_check_confidence_report.py",
    "tests/test_check_migrate_report.py",
    "tests/test_check_failure_replay.py",
]

EVIDENCE_DIRS = ["bd-2a0", "bd-33x", "bd-2ew", "bd-2st", "bd-3dn", "bd-12f", "bd-hg1", "bd-3f9"]


def run_script(script_path: str) -> dict:
    full_path = ROOT / script_path
    if not full_path.exists():
        return {"status": "FAIL", "error": f"Not found: {script_path}"}
    try:
        result = subprocess.run(
            [sys.executable, str(full_path), "--json"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        try:
            data = json.loads(result.stdout)
            return {"status": data.get("verdict", "UNKNOWN")}
        except json.JSONDecodeError:
            return {"status": "PASS" if result.returncode == 0 else "FAIL"}
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def run_tests() -> dict:
    test_files = [str(ROOT / t) for t in SECTION_TESTS if (ROOT / t).exists()]
    if not test_files:
        return {"status": "FAIL", "error": "No test files"}
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest"] + test_files + ["-v", "--tb=short"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        return {"status": "PASS" if result.returncode == 0 else "FAIL", "summary": lines[-1] if lines else ""}
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def check_evidence() -> dict:
    check = {"status": "PASS", "details": {}}
    for bead in EVIDENCE_DIRS:
        ev = (ROOT / "artifacts" / "section_10_3" / bead / "verification_evidence.json").exists()
        check["details"][bead] = ev
        if not ev:
            check["status"] = "FAIL"
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    script_results = []
    for entry in SECTION_SCRIPTS:
        r = run_script(entry["script"])
        script_results.append({"bead": entry["bead"], "name": entry["name"], "status": r["status"]})

    test_result = run_tests()
    evidence_result = check_evidence()

    script_pass = all(r["status"] == "PASS" for r in script_results)
    verdict = "PASS" if all([script_pass, test_result["status"] == "PASS", evidence_result["status"] == "PASS"]) else "FAIL"

    report = {
        "gate": "section_10_3_verification", "section": "10.3", "verdict": verdict, "timestamp": timestamp,
        "verification_scripts": {"total": len(script_results), "passing": sum(1 for r in script_results if r["status"] == "PASS"), "results": script_results},
        "unit_tests": test_result, "evidence_artifacts": evidence_result,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Section 10.3 Verification Gate ===")
        for r in script_results:
            print(f"  [{'OK' if r['status'] == 'PASS' else 'FAIL'}] {r['bead']}: {r['name']}")
        print(f"\n{test_result.get('summary', '')}")
        print(f"\nScripts: {sum(1 for r in script_results if r['status'] == 'PASS')}/{len(script_results)} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
