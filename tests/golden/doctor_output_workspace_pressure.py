#!/usr/bin/env python3
"""Real-output golden verifier for workspace-pressure doctor output."""

import json
import os
import subprocess  # nosec B404 - this verifier intentionally runs franken-node.
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BIN = ROOT / "target" / "debug" / "franken-node"
GOLDEN_DIR = ROOT / "tests" / "golden"
DOCTOR_GOLDEN_JSON = GOLDEN_DIR / "doctor_output_workspace_pressure.json"
JSON_CAPTURE_ENV = "FRANKEN_NODE_DOCTOR_WORKSPACE_PRESSURE_JSON"
HUMAN_CAPTURE_ENV = "FRANKEN_NODE_DOCTOR_WORKSPACE_PRESSURE_HUMAN"
BIN_ENV = "FRANKEN_NODE_BIN"
COMMAND_TIMEOUT_SECONDS = 30


def parse_json_document(raw: str, label: str) -> dict:
    """Parse JSON with context for fail-closed diagnostics."""
    try:
        parsed = json.loads(raw)  # ubs:ignore - this helper catches JSONDecodeError and validates object shape.
    except json.JSONDecodeError as err:
        raise RuntimeError(f"{label} did not parse as JSON: {err}") from err
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return parsed


def load_contract() -> dict:
    """Load the checked-in real-output contract."""
    return parse_json_document(DOCTOR_GOLDEN_JSON.read_text(), str(DOCTOR_GOLDEN_JSON))


def resolve_binary() -> Path:
    """Resolve the franken-node binary path for live output validation."""
    configured = os.environ.get(BIN_ENV)
    binary = Path(configured) if configured else DEFAULT_BIN
    if not binary.exists() or not os.access(binary, os.X_OK):
        raise RuntimeError(
            f"franken-node binary unavailable at {binary}; build it first or set {BIN_ENV}"
        )
    return binary


def run_command(args: list[str]) -> str:
    """Run franken-node and return stdout, failing closed on any error."""
    try:
        result = subprocess.run(  # nosec B603 - binary path and args are controlled by this test.
            [str(resolve_binary()), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as err:
        raise RuntimeError(
            f"doctor command timed out after {COMMAND_TIMEOUT_SECONDS}s"
        ) from err
    if result.returncode != 0:
        raise RuntimeError(
            "doctor command failed "
            f"(exit={result.returncode}, stderr={result.stderr.strip()})"
        )
    if not result.stdout.strip():
        raise RuntimeError("doctor command produced empty stdout")
    return result.stdout


def read_capture_or_run(env_name: str, command: list[str]) -> str:
    """Read an explicit captured product output file, or run the live command."""
    capture_path = os.environ.get(env_name)
    if capture_path:
        path = Path(capture_path)
        if not path.exists():
            raise RuntimeError(f"{env_name} points to missing file: {path}")
        return path.read_text()
    return run_command(command)


def doctor_json_output(contract: dict) -> dict:
    """Load real workspace-pressure JSON output."""
    raw = read_capture_or_run(JSON_CAPTURE_ENV, contract["commands"]["json"])
    return parse_json_document(raw, "doctor JSON output")


def doctor_human_output(contract: dict) -> str:
    """Load real workspace-pressure human output."""
    return read_capture_or_run(HUMAN_CAPTURE_ENV, contract["commands"]["human"])


def require_fields(container: dict, fields: list[str], label: str) -> None:
    """Require all fields in a JSON object."""
    missing = [field for field in fields if field not in container]
    if missing:
        raise AssertionError(f"{label} missing fields: {', '.join(missing)}")


def validate_json_report(report: dict, contract: dict) -> None:
    """Validate real JSON output against the golden contract."""
    json_contract = contract["json_contract"]
    require_fields(report, json_contract["required_root_fields"], "root report")

    expected_schema = json_contract["expected_schema_version"]
    if report["schema_version"] != expected_schema:
        raise AssertionError(
            f"schema_version {report['schema_version']!r} != {expected_schema!r}"
        )

    if report["status"] not in json_contract["valid_status_values"]:
        raise AssertionError(f"invalid status value: {report['status']!r}")

    resources = report["resources"]
    require_fields(resources, json_contract["required_resource_fields"], "resources")
    require_fields(
        resources["rch_status"],
        json_contract["required_rch_status_fields"],
        "resources.rch_status",
    )

    policy_decisions = report["policy_decisions"]
    if len(policy_decisions) != json_contract["expected_policy_decision_count"]:
        raise AssertionError(
            "policy decision count "
            f"{len(policy_decisions)} != {json_contract['expected_policy_decision_count']}"
        )
    for work_class in json_contract["valid_work_classes"]:
        if work_class not in policy_decisions:
            raise AssertionError(f"missing policy decision for {work_class}")
        require_fields(
            policy_decisions[work_class],
            json_contract["required_policy_decision_fields"],
            f"policy_decisions.{work_class}",
        )

    for index, action in enumerate(report["recommended_actions"]):
        require_fields(
            action,
            json_contract["required_recommended_action_fields"],
            f"recommended_actions[{index}]",
        )
        if action["priority"] not in json_contract["valid_priority_values"]:
            raise AssertionError(f"invalid recommended action priority: {action}")


def validate_human_report(report: str, contract: dict) -> None:
    """Validate real human output against the golden contract."""
    for fragment in contract["human_contract"]["required_fragments"]:
        if fragment not in report:
            raise AssertionError(f"human report missing required fragment: {fragment}")


def main() -> bool:
    """Validate real workspace-pressure doctor output."""
    try:
        contract = load_contract()
        json_report = doctor_json_output(contract)
        human_report = doctor_human_output(contract)
        validate_json_report(json_report, contract)
        validate_human_report(human_report, contract)
    except (AssertionError, KeyError, RuntimeError, TypeError) as err:
        print(f"workspace-pressure doctor real-output golden contract failed: {err}")
        return False

    print("workspace-pressure doctor real-output golden contract passed")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
