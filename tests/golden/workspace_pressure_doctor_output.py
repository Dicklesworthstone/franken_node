#!/usr/bin/env python3
"""Golden artifact test for workspace pressure doctor output (bd-p9mpd.5)."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "debug" / "franken-node"
GOLDEN_DIR = ROOT / "tests" / "golden"
WORKSPACE_PRESSURE_JSON = GOLDEN_DIR / "doctor_workspace_pressure.json"


def run_doctor_command() -> dict:
    """Run doctor command and return JSON output."""
    if not BIN.exists():
        print(f"Binary not found at {BIN}")
        return {}

    result = subprocess.run(
        [str(BIN), "doctor", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,  # Handle errors explicitly
        timeout=30,
    )

    if result.returncode != 0:
        print(f"Doctor command failed: {result.stderr}")
        return {}

    try:
        return json.loads(result.stdout)  # ubs:ignore - JSONDecodeError is handled below.
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Failed to parse JSON output: {e}")
        return {}


def test_workspace_pressure_checks():
    """Test that workspace pressure checks are included in doctor output."""
    report = run_doctor_command()

    if not report:
        print("No report data available")
        return False

    # Check that workspace pressure checks are present
    workspace_checks = [
        check for check in report.get("checks", [])
        if check.get("scope", "").startswith("workspace.")
    ]

    expected_scopes = [
        "workspace.pressure",
    ]
    forbidden_legacy_scopes = {
        "workspace.inventory",
        "workspace.build_pressure",
        "workspace.rch_availability",
        "workspace.coordination",
        "workspace.reservations",
    }

    found_scopes = {check.get("scope") for check in workspace_checks}

    for expected in expected_scopes:
        if expected not in found_scopes:
            print(f"Missing expected workspace check: {expected}")
            return False
    legacy_scopes = sorted(found_scopes.intersection(forbidden_legacy_scopes))
    if legacy_scopes:
        print(f"Default doctor still exposes legacy workspace checks: {legacy_scopes}")
        return False

    # Verify check structure
    for check in workspace_checks:
        required_fields = ["code", "event_code", "scope", "status", "message", "remediation"]
        for field in required_fields:
            if field not in check:
                print(f"Missing field {field} in check {check.get('scope')}")
                return False
        if check.get("scope") == "workspace.pressure":
            message = check.get("message", "")
            remediation = check.get("remediation", "")
            if "Workspace pressure" not in message:
                print("workspace.pressure check does not report real pressure summary")
                return False
            if "doctor workspace-pressure --json" not in remediation:
                print("workspace.pressure remediation does not point to real JSON report")
                return False

    print(f"✓ All {len(workspace_checks)} workspace pressure checks present and valid")
    return True


def generate_golden_artifact():
    """Generate golden artifact for workspace pressure output."""
    report = run_doctor_command()

    if not report:
        print("Cannot generate golden artifact - no report data")
        return False

    # Extract workspace-related checks for golden artifact
    workspace_data = {
        "schema_version": "bd-p9mpd.5/v1",
        "description": "Workspace pressure doctor output golden artifact",
        "workspace_checks": [
            check for check in report.get("checks", [])
            if check.get("scope", "").startswith("workspace.")
        ],
        "overall_status": report.get("overall_status"),
        "generated_at": report.get("generated_at_utc")
    }

    GOLDEN_DIR.mkdir(exist_ok=True)
    WORKSPACE_PRESSURE_JSON.write_text(
        json.dumps(workspace_data, indent=2, sort_keys=True)
    )

    print(f"✓ Generated golden artifact: {WORKSPACE_PRESSURE_JSON}")
    return True


def main():
    """Run tests and generate golden artifacts."""
    print("Testing workspace pressure doctor output...")

    if test_workspace_pressure_checks():
        print("✓ All tests passed")
        if generate_golden_artifact():
            print("✓ Golden artifact generated")
            return True

    return False


if __name__ == "__main__":
    exit(0 if main() else 1)
