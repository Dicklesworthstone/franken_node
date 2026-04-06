#!/usr/bin/env python3
"""
Section 10.1 Verification Gate.

Runs all section 10.1 verification scripts and produces a comprehensive
gate verdict for CI/release gating.

Usage:
    python3 scripts/gate_section_10_1.py [--json]

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

# All section 10.1 verification scripts in dependency order
SECTION_SCRIPTS = [
    {
        "bead": "bd-vjq",
        "name": "Product Charter Verification",
        "script": "scripts/verify_product_charter.py",
    },
    {
        "bead": "bd-1j2",
        "name": "Split Contract CI Enforcement",
        "script": "scripts/check_split_contract.py",
    },
    {
        "bead": "bd-2zz",
        "name": "Dependency Direction Guard",
        "script": "scripts/guard_dependency_direction.py",
    },
    {
        "bead": "bd-4yv",
        "name": "Reproducibility Pack Validation",
        "script": "scripts/validate_repro_pack.py",
    },
    {
        "bead": "bd-1mj",
        "name": "Claim-Language Policy",
        "script": "scripts/check_claim_language.py",
    },
    {
        "bead": "bd-20l",
        "name": "ADR Hybrid Baseline Strategy",
        "script": "scripts/verify_adr_hybrid_baseline.py",
    },
    {
        "bead": "bd-1pc",
        "name": "Implementation Governance Policy",
        "script": "scripts/check_impl_governance.py",
    },
]

# All section 10.1 unit test files
SECTION_TESTS = [
    "tests/test_check_split_contract.py",
    "tests/test_guard_dependency_direction.py",
    "tests/test_validate_repro_pack.py",
    "tests/test_check_claim_language.py",
    "tests/test_verify_adr_hybrid_baseline.py",
    "tests/test_check_impl_governance.py",
]

# Required evidence artifacts
SECTION_ARTIFACTS = [
    "artifacts/section_10_1/bd-2nd/verification_evidence.json",
    "artifacts/section_10_1/bd-vjq/verification_evidence.json",
    "artifacts/section_10_1/bd-1j2/verification_evidence.json",
    "artifacts/section_10_1/bd-2zz/verification_evidence.json",
    "artifacts/section_10_1/bd-4yv/verification_evidence.json",
    "artifacts/section_10_1/bd-1mj/verification_evidence.json",
    "artifacts/section_10_1/bd-20l/verification_evidence.json",
    "artifacts/section_10_1/bd-1pc/verification_evidence.json",
]


def run_verification_scripts() -> dict:
    """GATE-SCRIPTS: Run all section verification scripts."""
    check = {"id": "GATE-SCRIPTS", "status": "PASS", "details": {"scripts": []}}

    for entry in SECTION_SCRIPTS:
        script_path = ROOT / entry["script"]
        result_entry = {
            "bead": entry["bead"],
            "name": entry["name"],
            "script": entry["script"],
            "status": "PASS",
        }

        if not script_path.exists():
            result_entry["status"] = "FAIL"
            result_entry["error"] = "Script not found"
            check["status"] = "FAIL"
        else:
            try:
                result = subprocess.run(
                    [sys.executable, str(script_path), "--json"],
                    capture_output=True, text=True, timeout=3600, cwd=ROOT,
                )
                result_entry["exit_code"] = result.returncode
                if result.returncode != 0:
                    result_entry["status"] = "FAIL"
                    check["status"] = "FAIL"
                    # Try to parse the JSON output for details
                    try:
                        data = json.loads(result.stdout)
                        failing = [c for c in data.get("checks", []) if c["status"] == "FAIL"]
                        result_entry["failing_checks"] = [c["id"] for c in failing]
                    except (json.JSONDecodeError, KeyError):
                        result_entry["stderr"] = result.stderr[:200] if result.stderr else ""
            except subprocess.TimeoutExpired:
                result_entry["status"] = "FAIL"
                result_entry["error"] = "Timeout (30s)"
                check["status"] = "FAIL"

        check["details"]["scripts"].append(result_entry)

    return check


def run_unit_tests() -> dict:
    """GATE-TESTS: Run all section unit tests."""
    check = {"id": "GATE-TESTS", "status": "PASS", "details": {"test_files": []}}

    total_passed = 0
    total_failed = 0

    for test_file in SECTION_TESTS:
        test_path = ROOT / test_file
        result_entry = {"file": test_file, "status": "PASS"}

        if not test_path.exists():
            result_entry["status"] = "FAIL"
            result_entry["error"] = "Test file not found"
            check["status"] = "FAIL"
        else:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"],
                    capture_output=True, text=True, timeout=3600, cwd=ROOT,
                )
                result_entry["exit_code"] = result.returncode
                # Parse test counts from pytest output
                for line in result.stdout.splitlines():
                    if "passed" in line:
                        import re
                        m = re.search(r'(\d+)\s+passed', line)
                        if m:
                            count = int(m.group(1))
                            result_entry["passed"] = count
                            total_passed += count
                        m = re.search(r'(\d+)\s+failed', line)
                        if m:
                            count = int(m.group(1))
                            result_entry["failed"] = count
                            total_failed += count
                if result.returncode != 0:
                    result_entry["status"] = "FAIL"
                    check["status"] = "FAIL"
            except subprocess.TimeoutExpired:
                result_entry["status"] = "FAIL"
                result_entry["error"] = "Timeout (60s)"
                check["status"] = "FAIL"

        check["details"]["test_files"].append(result_entry)

    check["details"]["total_passed"] = total_passed
    check["details"]["total_failed"] = total_failed
    return check


def check_evidence_artifacts() -> dict:
    """GATE-ARTIFACTS: Check all section evidence artifacts exist and have PASS verdicts."""
    check = {"id": "GATE-ARTIFACTS", "status": "PASS", "details": {"artifacts": []}}

    for artifact_path in SECTION_ARTIFACTS:
        full_path = ROOT / artifact_path
        entry = {"path": artifact_path, "status": "PASS"}

        if not full_path.exists():
            entry["status"] = "FAIL"
            entry["error"] = "Not found"
            check["status"] = "FAIL"
        else:
            try:
                data = json.loads(full_path.read_text())
                verdict = data.get("verdict", "MISSING")
                entry["verdict"] = verdict
                if verdict != "PASS":
                    entry["status"] = "FAIL"
                    check["status"] = "FAIL"
            except json.JSONDecodeError:
                entry["status"] = "FAIL"
                entry["error"] = "Invalid JSON"
                check["status"] = "FAIL"

        check["details"]["artifacts"].append(entry)

    return check


def check_governance_docs() -> dict:
    """GATE-GOVERNANCE: Check all governance documents exist."""
    check = {"id": "GATE-GOVERNANCE", "status": "PASS", "details": {"documents": []}}

    required_docs = [
        ("docs/PRODUCT_CHARTER.md", "Product Charter"),
        ("docs/CLAIMS_REGISTRY.md", "Claims Registry"),
        ("docs/IMPLEMENTATION_GOVERNANCE.md", "Implementation Governance"),
        ("docs/adr/ADR-001-hybrid-baseline-strategy.md", "ADR-001 Hybrid Baseline"),
        ("docs/ENGINE_SPLIT_CONTRACT.md", "Engine Split Contract"),
    ]

    for path, name in required_docs:
        full_path = ROOT / path
        entry = {"name": name, "path": path, "exists": full_path.exists()}
        if not full_path.exists():
            check["status"] = "FAIL"
        check["details"]["documents"].append(entry)

    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        run_verification_scripts(),
        run_unit_tests(),
        check_evidence_artifacts(),
        check_governance_docs(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "section_10_1_comprehensive_gate",
        "section": "10.1",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Section 10.1 Comprehensive Verification Gate ===")
        print(f"Timestamp: {timestamp}")
        print()

        # Scripts
        scripts_check = checks[0]
        icon = "OK" if scripts_check["status"] == "PASS" else "FAIL"
        print(f"  [{icon}] {scripts_check['id']}: Verification Scripts")
        for s in scripts_check["details"]["scripts"]:
            si = "OK" if s["status"] == "PASS" else "FAIL"
            print(f"       [{si}] {s['bead']}: {s['name']}")

        # Tests
        tests_check = checks[1]
        icon = "OK" if tests_check["status"] == "PASS" else "FAIL"
        tp = tests_check["details"]["total_passed"]
        tf = tests_check["details"]["total_failed"]
        print(f"  [{icon}] {tests_check['id']}: Unit Tests ({tp} passed, {tf} failed)")

        # Artifacts
        artifacts_check = checks[2]
        icon = "OK" if artifacts_check["status"] == "PASS" else "FAIL"
        acount = len(artifacts_check["details"]["artifacts"])
        print(f"  [{icon}] {artifacts_check['id']}: Evidence Artifacts ({acount} checked)")

        # Governance
        gov_check = checks[3]
        icon = "OK" if gov_check["status"] == "PASS" else "FAIL"
        dcount = sum(1 for d in gov_check["details"]["documents"] if d["exists"])
        dtotal = len(gov_check["details"]["documents"])
        print(f"  [{icon}] {gov_check['id']}: Governance Documents ({dcount}/{dtotal})")

        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
