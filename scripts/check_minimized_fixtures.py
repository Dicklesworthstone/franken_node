#!/usr/bin/env python3
"""
Minimized Divergence Fixture Verifier.

Validates that the minimized fixture spec exists, the directory is set up,
and the design covers all required strategies.

Usage:
    python3 scripts/check_minimized_fixtures.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone

SPEC_PATH = ROOT / "docs" / "MINIMIZED_FIXTURE_SPEC.md"
FIXTURES_DIR = ROOT / "docs" / "fixtures" / "minimized"
FIXTURE_SCHEMA = ROOT / "schemas" / "compatibility_fixture.schema.json"

EVIDENCE_PATHS = {
    "fixture_spec": "docs/MINIMIZED_FIXTURE_SPEC.md",
    "minimized_fixture_dir": "docs/fixtures/minimized/",
    "contract": "docs/specs/section_10_2/bd-32v_contract.md",
    "verifier": "scripts/check_minimized_fixtures.py",
    "regression_tests": "tests/test_check_minimized_fixtures.py",
    "machine_evidence": "artifacts/section_10_2/bd-32v/verification_evidence.json",
    "human_summary": "artifacts/section_10_2/bd-32v/verification_summary.md",
}

VERIFICATION_COMMANDS = [
    {
        "command": "python3 scripts/check_minimized_fixtures.py --json",
        "covers": [
            "minimized fixture spec",
            "minimized fixture directory",
            "required minimization strategies",
            "fixture format fields",
            "L1 and divergence-ledger integration",
        ],
    },
    {
        "command": "python3 -m pytest tests/test_check_minimized_fixtures.py",
        "covers": [
            "verifier checks",
            "storage section contract",
            "fixture generation evidence path citations",
        ],
    },
]

REQUIRED_STRATEGIES = ["input reduction", "scope isolation", "output extraction"]


def check_spec_exists() -> dict:
    """MIN-SPEC: Check spec document exists."""
    check = {"id": "MIN-SPEC", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "MINIMIZED_FIXTURE_SPEC.md not found"
    else:
        check["details"]["path"] = str(SPEC_PATH.relative_to(ROOT))
    return check


def check_dir_exists() -> dict:
    """MIN-DIR: Check minimized fixtures directory exists."""
    check = {"id": "MIN-DIR", "status": "PASS", "details": {}}
    if not FIXTURES_DIR.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/fixtures/minimized/ not found"
    else:
        check["details"]["path"] = str(FIXTURES_DIR.relative_to(ROOT))
    return check


def check_strategies() -> dict:
    """MIN-STRATEGIES: Check all minimization strategies are documented."""
    check = {"id": "MIN-STRATEGIES", "status": "PASS", "details": {"strategies": {}}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text(encoding="utf-8").lower()
    for strategy in REQUIRED_STRATEGIES:
        found = strategy in text
        check["details"]["strategies"][strategy] = found
        if not found:
            check["status"] = "FAIL"

    return check


def check_fixture_format() -> dict:
    """MIN-FORMAT: Check generated fixture format is documented."""
    check = {"id": "MIN-FORMAT", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text(encoding="utf-8")
    has_schema_ref = "compatibility_fixture" in text or "fixture schema" in text.lower()
    has_extra_fields = "minimized_from" in text and "divergence_id" in text
    check["details"]["schema_referenced"] = has_schema_ref
    check["details"]["extra_fields_documented"] = has_extra_fields

    if not (has_schema_ref and has_extra_fields):
        check["status"] = "FAIL"
        check["details"]["error"] = "Generated fixture format incomplete"
    return check


def check_integration() -> dict:
    """MIN-INTEGRATION: Check integration with L1 runner and divergence ledger."""
    check = {"id": "MIN-INTEGRATION", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text(encoding="utf-8")
    has_l1 = "L1" in text or "lockstep" in text.lower()
    has_ledger = "divergence" in text.lower() and "ledger" in text.lower()
    check["details"]["l1_integration"] = has_l1
    check["details"]["ledger_integration"] = has_ledger

    if not (has_l1 and has_ledger):
        check["status"] = "FAIL"
    return check


def build_report(timestamp: str) -> dict:
    checks = [
        check_spec_exists(),
        check_dir_exists(),
        check_strategies(),
        check_fixture_format(),
        check_integration(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    return {
        "gate": "minimized_fixtures_verification",
        "section": "10.2",
        "verdict": verdict,
        "timestamp": timestamp,
        "evidence_paths": EVIDENCE_PATHS,
        "verification_commands": VERIFICATION_COMMANDS,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }


def main():
    logger = configure_test_logging("check_minimized_fixtures")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()
    report = build_report(timestamp)
    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Minimized Fixture Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in report["checks"]:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {report['verdict']}")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
