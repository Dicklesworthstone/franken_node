import os
#!/usr/bin/env python3
"""
Health Gate and Rollout-State Persistence Verification (bd-1rk).

Validates that lifecycle-aware health gating and rollout-state persistence
are correctly implemented.

Usage:
    python3 scripts/check_health_gate.py [--json]
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


# --- Health gate specification ---

REQUIRED_CHECKS = ["liveness", "readiness", "config_valid"]
OPTIONAL_CHECKS = ["resource_ok"]
ALL_CHECKS = REQUIRED_CHECKS + OPTIONAL_CHECKS

ROLLOUT_PHASES = ["shadow", "canary", "ramp", "default"]

ERROR_CODES = ["HEALTH_GATE_FAILED", "PERSIST_STALE_VERSION", "PERSIST_IO_ERROR", "REPLAY_MISMATCH"]


def check_health_gate_spec() -> dict:
    """HEALTH-SPEC: Health gate spec has required and optional checks."""
    has_required = len(REQUIRED_CHECKS) == 3
    has_optional = len(OPTIONAL_CHECKS) >= 1
    return {
        "id": "HEALTH-SPEC",
        "status": "PASS" if has_required and has_optional else "FAIL",
        "details": {"required": REQUIRED_CHECKS, "optional": OPTIONAL_CHECKS},
    }


def check_health_gate_impl() -> dict:
    """HEALTH-IMPL: Health gate Rust implementation exists."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "health_gate.rs"
    if not path.exists():
        return {"id": "HEALTH-IMPL", "status": "FAIL", "details": {"error": "file not found"}}
    content = path.read_text()
    expected = ["HealthCheck", "HealthGateResult", "HealthGateError", "fn evaluate", "fn standard_checks"]
    missing = [e for e in expected if e not in content]
    return {
        "id": "HEALTH-IMPL",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_symbols": missing},
    }


def check_rollout_state_impl() -> dict:
    """ROLLOUT-IMPL: Rollout state persistence Rust implementation exists."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "rollout_state.rs"
    if not path.exists():
        return {"id": "ROLLOUT-IMPL", "status": "FAIL", "details": {"error": "file not found"}}
    content = path.read_text()
    expected = ["RolloutState", "RolloutPhase", "PersistError", "fn persist", "fn load", "fn verify_replay"]
    missing = [e for e in expected if e not in content]
    return {
        "id": "ROLLOUT-IMPL",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_symbols": missing},
    }


def check_rollout_phases() -> dict:
    """ROLLOUT-PHASES: All four rollout phases defined."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "rollout_state.rs"
    if not path.exists():
        return {"id": "ROLLOUT-PHASES", "status": "FAIL"}
    content = path.read_text()
    missing = [p for p in ["Shadow", "Canary", "Ramp", "Default"] if p not in content]
    return {
        "id": "ROLLOUT-PHASES",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_phases": missing},
    }


def check_error_codes() -> dict:
    """HEALTH-ERRORS: All error codes defined in implementation."""
    paths = [
        ROOT / "crates" / "franken-node" / "src" / "connector" / "health_gate.rs",
        ROOT / "crates" / "franken-node" / "src" / "connector" / "rollout_state.rs",
    ]
    all_content = ""
    for p in paths:
        if p.exists():
            all_content += p.read_text()
    missing = [c for c in ERROR_CODES if c not in all_content]
    return {
        "id": "HEALTH-ERRORS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_codes": missing},
    }


def check_rust_tests() -> dict:
    """HEALTH-TESTS: Rust unit tests pass."""
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        summary = [l for l in lines if "test result:" in l]
        return {
            "id": "HEALTH-TESTS",
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "details": {"summary": summary[-1] if summary else "", "returncode": result.returncode},
        }
    except Exception as e:
        return {"id": "HEALTH-TESTS", "status": "FAIL", "details": {"error": str(e)}}


def check_replay_log() -> dict:
    """HEALTH-REPLAY: Replay log artifact exists."""
    path = ROOT / "artifacts" / "section_10_13" / "bd-1rk" / "rollout_state_replay.log"
    if not path.exists():
        return {"id": "HEALTH-REPLAY", "status": "FAIL"}
    content = path.read_text()
    has_summary = "SUMMARY" in content
    has_pass = "PASS" in content
    return {
        "id": "HEALTH-REPLAY",
        "status": "PASS" if has_summary and has_pass else "FAIL",
    }


def check_spec_document() -> dict:
    """HEALTH-SPEC-DOC: Specification document exists."""
    path = ROOT / "docs" / "specs" / "section_10_13" / "bd-1rk_contract.md"
    if not path.exists():
        return {"id": "HEALTH-SPEC-DOC", "status": "FAIL"}
    content = path.read_text()
    required = ["Health Gate", "Rollout State", "Invariants", "Error Codes"]
    missing = [r for r in required if r not in content]
    return {
        "id": "HEALTH-SPEC-DOC",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_sections": missing},
    }


def check_integration_tests() -> dict:
    """HEALTH-INTEGRATION: Integration test file exists."""
    path = ROOT / "tests" / "integration" / "lifecycle_health_gate.rs"
    if not path.exists():
        return {"id": "HEALTH-INTEGRATION", "status": "FAIL"}
    content = path.read_text()
    expected_tests = [
        "activation_blocked_by_failing_health_gate",
        "activation_permitted_with_passing_gate",
        "stale_write_rejected",
        "replay_catches_state_mismatch",
    ]
    missing = [t for t in expected_tests if t not in content]
    return {
        "id": "HEALTH-INTEGRATION",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_tests": missing},
    }


def self_test() -> dict:
    """Run all checks."""
    checks = [
        check_health_gate_spec(),
        check_health_gate_impl(),
        check_rollout_state_impl(),
        check_rollout_phases(),
        check_error_codes(),
        check_rust_tests(),
        check_replay_log(),
        check_spec_document(),
        check_integration_tests(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "health_gate_verification",
        "section": "10.13",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main():
    logger = configure_test_logging("check_health_gate")
    json_output = "--json" in sys.argv
    result = self_test()

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
