#!/usr/bin/env python3
"""
L1 Lockstep Runner Design Verifier.

Validates that the lockstep runner design document and configuration
schema exist with all required phases and fields.

Usage:
    python3 scripts/check_lockstep_runner.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

DESIGN_PATH = ROOT / "docs" / "L1_LOCKSTEP_RUNNER.md"
CONFIG_SCHEMA_PATH = ROOT / "schemas" / "lockstep_runner_config.schema.json"
FIXTURE_SCHEMA_PATH = ROOT / "schemas" / "compatibility_fixture.schema.json"
CONTRACT_PATH = ROOT / "docs" / "specs" / "section_10_2" / "bd-2vi_contract.md"

PRIMARY_IMPLEMENTATION_PATHS = {
    "lockstep_harness": "crates/franken-node/src/runtime/lockstep_harness.rs",
    "verify_cli_dispatch": "crates/franken-node/src/main.rs",
    "verify_cli_args": "crates/franken-node/src/cli.rs",
}

EVIDENCE_PATHS = {
    "primary_lockstep_harness": PRIMARY_IMPLEMENTATION_PATHS["lockstep_harness"],
    "verify_cli_dispatch": PRIMARY_IMPLEMENTATION_PATHS["verify_cli_dispatch"],
    "verify_cli_args": PRIMARY_IMPLEMENTATION_PATHS["verify_cli_args"],
    "design": "docs/L1_LOCKSTEP_RUNNER.md",
    "runner_config_schema": "schemas/lockstep_runner_config.schema.json",
    "compatibility_fixture_schema": "schemas/compatibility_fixture.schema.json",
    "contract": "docs/specs/section_10_2/bd-2vi_contract.md",
    "verifier": "scripts/check_lockstep_runner.py",
    "regression_tests": "tests/test_check_lockstep_runner.py",
    "machine_evidence": "artifacts/section_10_2/bd-2vi/verification_evidence.json",
    "human_summary": "artifacts/section_10_2/bd-2vi/verification_summary.md",
}

VERIFICATION_COMMANDS = [
    {
        "command": "python3 scripts/check_lockstep_runner.py --json",
        "covers": [
            "L1 lockstep design document",
            "primary Rust implementation path citations",
            "verify lockstep CLI dispatch citations",
            "runner configuration schema",
            "phase coverage",
            "delta report format",
            "release gating rules",
        ],
    },
    {
        "command": "python3 -m pytest tests/test_check_lockstep_runner.py",
        "covers": [
            "lockstep runner verifier checks",
            "report evidence path citations",
            "checked-in machine evidence citations",
        ],
    },
]

REQUIRED_PHASES = [
    "fixture loading",
    "runtime execution",
    "result canonicalization",
    "delta detection",
    "report generation",
]


def check_design_exists() -> dict:
    """L1-DESIGN: Check design document exists."""
    check = {"id": "L1-DESIGN", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "L1_LOCKSTEP_RUNNER.md not found"
    else:
        check["details"]["path"] = str(DESIGN_PATH.relative_to(ROOT))
    return check


def check_config_schema() -> dict:
    """L1-CONFIG: Check config schema exists and is valid."""
    check = {"id": "L1-CONFIG", "status": "PASS", "details": {}}
    if not CONFIG_SCHEMA_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Config schema not found"
        return check

    try:
        data = json.loads(CONFIG_SCHEMA_PATH.read_text())
        required = data.get("required", [])
        check["details"]["required_fields"] = required
        if "runtimes" not in required:
            check["status"] = "FAIL"
            check["details"]["error"] = "Schema missing 'runtimes' in required"
    except json.JSONDecodeError:
        check["status"] = "FAIL"
        check["details"]["error"] = "Invalid JSON in schema"
    return check


def check_phases_documented() -> dict:
    """L1-PHASES: Check all 5 phases are documented."""
    check = {"id": "L1-PHASES", "status": "PASS", "details": {"phases": {}}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text().lower()
    for phase in REQUIRED_PHASES:
        found = phase in text
        check["details"]["phases"][phase] = found
        if not found:
            check["status"] = "FAIL"

    missing = [p for p, found in check["details"]["phases"].items() if not found]
    if missing:
        check["details"]["missing_phases"] = missing
    return check


def check_delta_format() -> dict:
    """L1-DELTA: Check delta report format is documented."""
    check = {"id": "L1-DELTA", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text()
    has_report = "delta report" in text.lower() or "report format" in text.lower()
    has_json = "schema_version" in text and "divergences" in text
    check["details"]["report_documented"] = has_report
    check["details"]["json_format"] = has_json

    if not (has_report and has_json):
        check["status"] = "FAIL"
        check["details"]["error"] = "Delta report format not fully documented"
    return check


def check_release_gating() -> dict:
    """L1-GATING: Check release gating rules are documented."""
    check = {"id": "L1-GATING", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text().lower()
    has_core_block = "core" in text and "block" in text
    has_mode_ref = "strict" in text or "balanced" in text
    check["details"]["core_blocks_release"] = has_core_block
    check["details"]["mode_integration"] = has_mode_ref

    if not has_core_block:
        check["status"] = "FAIL"
        check["details"]["error"] = "Core band release blocking not documented"
    return check


def check_primary_implementation_cited() -> dict:
    """L1-IMPL: Check primary Rust implementation paths are cited."""
    check = {
        "id": "L1-IMPL",
        "status": "PASS",
        "details": {
            "paths": PRIMARY_IMPLEMENTATION_PATHS,
            "existing_paths": {},
            "design_citations": {},
            "contract_citations": {},
        },
    }

    design_text = DESIGN_PATH.read_text(encoding="utf-8") if DESIGN_PATH.exists() else ""
    contract_text = CONTRACT_PATH.read_text(encoding="utf-8") if CONTRACT_PATH.exists() else ""

    missing_paths = []
    missing_design_citations = []
    missing_contract_citations = []

    for name, path in PRIMARY_IMPLEMENTATION_PATHS.items():
        exists = (ROOT / path).exists()
        design_cited = path in design_text
        contract_cited = path in contract_text
        check["details"]["existing_paths"][name] = exists
        check["details"]["design_citations"][name] = design_cited
        check["details"]["contract_citations"][name] = contract_cited

        if not exists:
            missing_paths.append(path)
        if not design_cited:
            missing_design_citations.append(path)
        if not contract_cited:
            missing_contract_citations.append(path)

    if missing_paths or missing_design_citations or missing_contract_citations:
        check["status"] = "FAIL"
        check["details"]["missing_paths"] = missing_paths
        check["details"]["missing_design_citations"] = missing_design_citations
        check["details"]["missing_contract_citations"] = missing_contract_citations

    return check


def build_report(timestamp: str) -> dict:
    checks = [
        check_design_exists(),
        check_primary_implementation_cited(),
        check_config_schema(),
        check_phases_documented(),
        check_delta_format(),
        check_release_gating(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "lockstep_runner_verification",
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
    return report


def main():
    configure_test_logging("check_lockstep_runner")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()
    report = build_report(timestamp)

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== L1 Lockstep Runner Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in report["checks"]:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "error" in details:
                    print(f"       Error: {details['error']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {report['verdict']}")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
