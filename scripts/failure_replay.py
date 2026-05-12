#!/usr/bin/env python3
"""
Deterministic Migration Failure Replay Tooling.

Captures and replays migration failures for deterministic diagnosis.

Usage:
    python3 scripts/failure_replay.py --self-test [--json]
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent
REPLAY_DIR = ROOT / "artifacts" / "replays"


def capture_failure(failure_source: str, fixture_id: str, input_data: dict,
                    expected: dict, actual: dict, env: dict = None) -> dict:
    """Capture a failure as a deterministic replay artifact."""
    replay_id = f"REPLAY-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    return {
        "replay_id": replay_id,
        "failure_source": failure_source,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "context": {
            "fixture_id": fixture_id,
            "input": input_data,
            "expected_output": expected,
            "actual_output": actual,
            "environment": env or {},
        },
        "replay_command": f"franken-node --replay artifacts/replays/{replay_id}.json",
        "minimized": False,
        "diagnosis_hints": generate_hints(expected, actual),
    }


def generate_hints(expected: dict, actual: dict) -> list[str]:
    """Generate diagnostic hints from expected vs actual comparison."""
    hints = []
    if expected.get("return_value") != actual.get("return_value"):
        hints.append("Return value divergence — check data types and encoding")
    if expected.get("error") != actual.get("error"):
        hints.append("Error behavior divergence — check error code and message")
    if expected.get("side_effects") != actual.get("side_effects"):
        hints.append("Side effect divergence — check file/network/state operations")
    if not hints:
        hints.append("No specific divergence pattern detected — manual investigation needed")
    return hints


def save_replay(artifact: dict, replay_dir: Path = None) -> Path:
    """Save replay artifact to disk."""
    target_dir = replay_dir or REPLAY_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"{artifact['replay_id']}.json"
    path.write_text(json.dumps(artifact, indent=2))
    return path


def load_replay(path: Path) -> dict:
    """Load a replay artifact from disk."""
    return json.loads(path.read_text())


def validate_replay_artifact(artifact: dict) -> list[str]:
    """Validate a replay artifact has required fields."""
    errors = []
    required = ["replay_id", "failure_source", "captured_at", "context", "replay_command"]
    for field in required:
        if field not in artifact:
            errors.append(f"Missing required field: {field}")

    ctx = artifact.get("context", {})
    ctx_required = ["fixture_id", "input", "expected_output", "actual_output"]
    for field in ctx_required:
        if field not in ctx:
            errors.append(f"Missing context field: {field}")

    return errors


def self_test() -> dict:
    """Run self-test."""
    import tempfile
    checks = []

    # Test 1: Capture
    artifact = capture_failure(
        failure_source="validation_runner",
        fixture_id="fixture:fs:readFile:utf8-basic",
        input_data={"args": ["test.txt", {"encoding": "utf8"}]},
        expected={"return_value": "hello", "error": None},
        actual={"return_value": "HELLO", "error": None},
        env={"NODE_ENV": "test"},
    )
    checks.append({"id": "REPLAY-CAPTURE", "status": "PASS" if "replay_id" in artifact else "FAIL"})

    # Test 2: Validate
    errors = validate_replay_artifact(artifact)
    checks.append({"id": "REPLAY-VALID", "status": "PASS" if not errors else "FAIL",
                    "details": {"errors": errors}})

    # Test 3: Save and load
    with tempfile.TemporaryDirectory() as tmpdir:
        path = save_replay(artifact, Path(tmpdir))
        loaded = load_replay(path)
        checks.append({"id": "REPLAY-ROUNDTRIP", "status": "PASS" if loaded["replay_id"] == artifact["replay_id"] else "FAIL"})

    # Test 4: Hints generated
    checks.append({"id": "REPLAY-HINTS", "status": "PASS" if len(artifact.get("diagnosis_hints", [])) > 0 else "FAIL",
                    "details": {"hint_count": len(artifact.get("diagnosis_hints", []))}})

    # Test 5: Self-contained
    ctx = artifact.get("context", {})
    has_input = "input" in ctx
    has_expected = "expected_output" in ctx
    has_actual = "actual_output" in ctx
    checks.append({"id": "REPLAY-SELFCONTAINED", "status": "PASS" if all([has_input, has_expected, has_actual]) else "FAIL"})

    failing = [c for c in checks if c["status"] == "FAIL"]
    return {
        "gate": "failure_replay_verification",
        "section": "10.3",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }


def main():
    logger = configure_test_logging("failure_replay")
    logger.info("starting failure_replay tool")
    json_output = "--json" in sys.argv
    is_self_test = "--self-test" in sys.argv

    if is_self_test:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    print("Usage: python3 scripts/failure_replay.py --self-test [--json]", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
