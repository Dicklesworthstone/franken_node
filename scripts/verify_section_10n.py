#!/usr/bin/env python3
"""
Section 10.N Verification Gate.

Runs all 10.N deliverables (ownership registry, duplicate-impl gate,
oracle close condition, cross-track linter) and produces a section-level
gate verdict.

Usage:
    python3 scripts/verify_section_10n.py [--json]

Exit codes:
    0 = PASS (all checks pass)
    1 = FAIL (one or more checks failed)
    2 = ERROR (script failure)
"""

import json
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path


# 10.N deliverables to verify
CHECKS = [
    {
        "id": "10N-REG",
        "name": "Capability Ownership Registry",
        "bead": "bd-zxk8",
        "type": "artifact_exists",
        "paths": [
            ROOT / "docs" / "capability_ownership_registry.json",
            ROOT / "docs" / "CAPABILITY_OWNERSHIP_REGISTRY.md",
        ],
        "validation": "registry_schema",
    },
    {
        "id": "10N-DUP",
        "name": "Duplicate-Implementation CI Gate",
        "bead": "bd-2yhs",
        "type": "script_run",
        "command": ["python3", str(ROOT / "scripts" / "check_ownership_violations.py"), "--json"],
    },
    {
        "id": "10N-ORACLE",
        "name": "Dual-Oracle Close Condition Gate",
        "bead": "bd-1oyt",
        "type": "artifact_exists",
        "paths": [
            ROOT / "scripts" / "check_oracle_close_condition.py",
            ROOT / "docs" / "DUAL_ORACLE_CLOSE_CONDITION.md",
        ],
        "validation": "script_parseable",
    },
    {
        "id": "10N-XREF",
        "name": "Cross-Track Canonical-Reference Linter",
        "bead": "bd-1v2c",
        "type": "script_run",
        "command": ["python3", str(ROOT / "scripts" / "lint_cross_track_references.py"), "--json"],
        "allow_findings": True,  # Findings are informational, not blocking
    },
]

# Unit test suites for 10.N
UNIT_TESTS = [
    {
        "id": "10N-UT-XREF",
        "name": "Cross-track linter unit tests",
        "command": ["python3", str(ROOT / "tests" / "test_lint_cross_track_references.py")],
    },
]


def check_artifact_exists(check: dict) -> dict:
    """Verify artifacts exist on disk."""
    result = {"check_id": check["id"], "status": "PASS", "details": {}}
    missing = []
    for p in check["paths"]:
        if not p.exists():
            missing.append(str(p.relative_to(ROOT)))
    if missing:
        result["status"] = "FAIL"
        result["details"]["missing"] = missing
    else:
        result["details"]["present"] = [str(p.relative_to(ROOT)) for p in check["paths"]]

    # Additional validation
    if check.get("validation") == "registry_schema":
        try:
            with open(check["paths"][0]) as f:
                data = json.load(f)
            caps = data.get("capabilities", [])
            ids = [c["id"] for c in caps]
            if len(ids) != len(set(ids)):
                result["status"] = "FAIL"
                result["details"]["error"] = "Duplicate capability IDs"
            else:
                result["details"]["capabilities"] = len(caps)
        except Exception as e:
            result["status"] = "FAIL"
            result["details"]["error"] = str(e)

    return result


def check_script_run(check: dict) -> dict:
    """Run a script and check its output."""
    result = {"check_id": check["id"], "status": "PASS", "details": {}}
    try:
        proc = subprocess.run(
            check["command"],
            capture_output=True, text=True, timeout=3600,
        )
        result["details"]["exit_code"] = proc.returncode

        # Parse JSON output if available
        try:
            output = json.loads(proc.stdout)
            result["details"]["verdict"] = output.get("verdict", "UNKNOWN")
            if "findings_count" in output:
                result["details"]["findings"] = output["findings_count"]
        except (json.JSONDecodeError, ValueError):
            result["details"]["stdout_lines"] = proc.stdout.count("\n")

        # Non-zero exit is FAIL unless findings are informational
        if proc.returncode != 0:
            if check.get("allow_findings"):
                result["status"] = "INFO"
                result["details"]["note"] = "Findings detected (informational)"
            else:
                result["status"] = "FAIL"
                result["details"]["stderr"] = proc.stderr[:200] if proc.stderr else None

    except subprocess.TimeoutExpired:
        result["status"] = "FAIL"
        result["details"]["error"] = "Timeout"
    except Exception as e:
        result["status"] = "FAIL"
        result["details"]["error"] = str(e)

    return result


def run_unit_tests(tests: list[dict]) -> list[dict]:
    """Run unit test suites."""
    results = []
    for test in tests:
        result = {"test_id": test["id"], "name": test["name"], "status": "PASS"}
        try:
            proc = subprocess.run(
                test["command"],
                capture_output=True, text=True, timeout=3600,
            )
            result["exit_code"] = proc.returncode
            if proc.returncode != 0:
                result["status"] = "FAIL"
                result["output"] = proc.stdout[-300:] if proc.stdout else ""
        except Exception as e:
            result["status"] = "FAIL"
            result["error"] = str(e)
        results.append(result)
    return results


def main():
    logger = configure_test_logging("verify_section_10n")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    # Run all checks
    check_results = []
    for check in CHECKS:
        if check["type"] == "artifact_exists":
            check_results.append(check_artifact_exists(check))
        elif check["type"] == "script_run":
            check_results.append(check_script_run(check))

    # Run unit tests
    unit_results = run_unit_tests(UNIT_TESTS)

    # Compute verdict
    failing = [c for c in check_results if c["status"] == "FAIL"]
    failing_tests = [t for t in unit_results if t["status"] == "FAIL"]

    verdict = "PASS" if not failing and not failing_tests else "FAIL"

    report = {
        "gate": "section_10n_verification",
        "section": "10.N",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": check_results,
        "unit_tests": unit_results,
        "summary": {
            "total_checks": len(check_results),
            "passing_checks": sum(1 for c in check_results if c["status"] in ("PASS", "INFO")),
            "failing_checks": len(failing),
            "total_unit_tests": len(unit_results),
            "passing_unit_tests": sum(1 for t in unit_results if t["status"] == "PASS"),
            "failing_unit_tests": len(failing_tests),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Section 10.N Verification Gate ===")
        print(f"Timestamp: {timestamp}")
        print()
        print("Checks:")
        for c in check_results:
            name = next(ch["name"] for ch in CHECKS if ch["id"] == c["check_id"])
            icon = "OK" if c["status"] in ("PASS", "INFO") else "FAIL"
            print(f"  [{icon}] {c['check_id']}: {name} ({c['status']})")
        print()
        print("Unit Tests:")
        for t in unit_results:
            icon = "OK" if t["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {t['test_id']}: {t['name']}")
        print()
        s = report["summary"]
        print(f"Checks: {s['passing_checks']}/{s['total_checks']} pass")
        print(f"Unit tests: {s['passing_unit_tests']}/{s['total_unit_tests']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
