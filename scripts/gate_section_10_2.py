#!/usr/bin/env python3
"""
Section 10.2 Verification Gate.

Runs all section 10.2 verification scripts and produces a comprehensive
gate verdict for CI/release gating.

Usage:
    python3 scripts/gate_section_10_2.py [--json]

Exit codes:
    0 = PASS (all sub-gates pass)
    1 = FAIL (any sub-gate fails)
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SECTION_SCRIPTS = [
    {"bead": "bd-2wz", "name": "Compatibility Bands", "script": "scripts/check_compat_bands.py"},
    {"bead": "bd-2qf", "name": "Compatibility Registry", "script": "scripts/check_compat_registry.py"},
    {"bead": "bd-38l", "name": "Divergence Ledger", "script": "scripts/check_divergence_ledger.py"},
    {"bead": "bd-2kf", "name": "Compatibility Mode Policy", "script": "scripts/check_compat_modes.py"},
    {"bead": "bd-1z3", "name": "Fixture Runner", "script": "scripts/fixture_runner.py"},
    {"bead": "bd-2vi", "name": "L1 Lockstep Runner", "script": "scripts/check_lockstep_runner.py"},
    {"bead": "bd-32v", "name": "Minimized Fixture Generation", "script": "scripts/check_minimized_fixtures.py"},
    {"bead": "bd-1ck", "name": "L2 Engine-Boundary Oracle", "script": "scripts/check_l2_oracle.py"},
    {"bead": "bd-240", "name": "Compatibility Dashboard", "script": "scripts/check_compat_dashboard.py"},
    {"bead": "bd-2hs", "name": "Four-Doc Spec Pack", "script": "scripts/check_spec_pack.py"},
    {"bead": "bd-80g", "name": "Fixture Corpus", "script": "scripts/check_fixture_corpus.py"},
    {"bead": "bd-7mt", "name": "Compat CI Gate", "script": "scripts/check_compat_ci_gate.py"},
]

SECTION_TESTS = [
    "tests/test_check_compat_bands.py",
    "tests/test_check_compat_registry.py",
    "tests/test_check_divergence_ledger.py",
    "tests/test_check_compat_modes.py",
    "tests/test_fixture_runner.py",
    "tests/test_check_lockstep_runner.py",
    "tests/test_check_minimized_fixtures.py",
    "tests/test_check_l2_oracle.py",
    "tests/test_check_compat_dashboard.py",
    "tests/test_check_spec_pack.py",
    "tests/test_check_fixture_corpus.py",
    "tests/test_check_compat_ci_gate.py",
]

EVIDENCE_DIRS = [
    "bd-2wz", "bd-2qf", "bd-38l", "bd-2kf", "bd-1z3", "bd-2vi",
    "bd-32v", "bd-1ck", "bd-240", "bd-2hs", "bd-80g", "bd-7mt",
]

GOVERNANCE_DOCS = [
    "docs/COMPATIBILITY_BANDS.md",
    "docs/COMPATIBILITY_MODE_POLICY.md",
    "docs/COMPATIBILITY_REGISTRY.json",
    "docs/DIVERGENCE_LEDGER.json",
    "docs/L1_LOCKSTEP_RUNNER.md",
    "docs/L2_ENGINE_BOUNDARY_ORACLE.md",
    "docs/MINIMIZED_FIXTURE_SPEC.md",
    "docs/COMPAT_DASHBOARD_SPEC.md",
]


def run_script(script_path: str) -> dict:
    """Run a verification script and capture result."""
    full_path = ROOT / script_path
    if not full_path.exists():
        return {"status": "FAIL", "error": f"Script not found: {script_path}"}
    try:
        result = subprocess.run(
            [sys.executable, str(full_path), "--json"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        try:
            data = json.loads(result.stdout)
            return {"status": data.get("verdict", "UNKNOWN"), "output": data}
        except json.JSONDecodeError:
            return {"status": "PASS" if result.returncode == 0 else "FAIL", "raw": result.stdout[:500]}
    except subprocess.TimeoutExpired:
        return {"status": "FAIL", "error": "Timeout"}
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def run_tests() -> dict:
    """Run all section 10.2 unit tests."""
    test_files = [str(ROOT / t) for t in SECTION_TESTS if (ROOT / t).exists()]
    if not test_files:
        return {"status": "FAIL", "error": "No test files found"}
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest"] + test_files + ["-v", "--tb=short"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        summary = lines[-1] if lines else ""
        return {
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "summary": summary,
            "test_count": len(test_files),
        }
    except Exception as e:
        return {"status": "FAIL", "error": str(e)}


def check_evidence() -> dict:
    """Verify evidence artifacts exist for all beads."""
    check = {"status": "PASS", "details": {}}
    for bead in EVIDENCE_DIRS:
        edir = ROOT / "artifacts" / "section_10_2" / bead
        ev_file = edir / "verification_evidence.json"
        exists = ev_file.exists()
        check["details"][bead] = exists
        if not exists:
            check["status"] = "FAIL"
    return check


def check_governance_docs() -> dict:
    """Verify governance documents exist."""
    check = {"status": "PASS", "details": {}}
    for doc in GOVERNANCE_DOCS:
        exists = (ROOT / doc).exists()
        check["details"][doc] = exists
        if not exists:
            check["status"] = "FAIL"
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    # Run verification scripts
    script_results = []
    for entry in SECTION_SCRIPTS:
        result = run_script(entry["script"])
        script_results.append({
            "bead": entry["bead"],
            "name": entry["name"],
            "script": entry["script"],
            "status": result["status"],
        })

    # Run tests
    test_result = run_tests()

    # Check evidence
    evidence_result = check_evidence()

    # Check governance docs
    governance_result = check_governance_docs()

    # Compute verdict
    script_pass = all(r["status"] == "PASS" for r in script_results)
    tests_pass = test_result["status"] == "PASS"
    evidence_pass = evidence_result["status"] == "PASS"
    governance_pass = governance_result["status"] == "PASS"
    verdict = "PASS" if all([script_pass, tests_pass, evidence_pass, governance_pass]) else "FAIL"

    report = {
        "gate": "section_10_2_verification",
        "section": "10.2",
        "verdict": verdict,
        "timestamp": timestamp,
        "verification_scripts": {
            "total": len(script_results),
            "passing": sum(1 for r in script_results if r["status"] == "PASS"),
            "results": script_results,
        },
        "unit_tests": test_result,
        "evidence_artifacts": evidence_result,
        "governance_docs": governance_result,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Section 10.2 Verification Gate ===")
        print(f"Timestamp: {timestamp}\n")
        print("--- Verification Scripts ---")
        for r in script_results:
            print(f"  [{'OK' if r['status'] == 'PASS' else 'FAIL'}] {r['bead']}: {r['name']}")
        print("\n--- Unit Tests ---")
        print(f"  {test_result.get('summary', 'N/A')}")
        print("\n--- Evidence Artifacts ---")
        for bead, exists in evidence_result["details"].items():
            print(f"  [{'OK' if exists else 'FAIL'}] {bead}")
        print("\n--- Governance Docs ---")
        for doc, exists in governance_result["details"].items():
            print(f"  [{'OK' if exists else 'FAIL'}] {doc}")
        scripts_pass_count = sum(1 for r in script_results if r["status"] == "PASS")
        print(f"\nScripts: {scripts_pass_count}/{len(script_results)} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
