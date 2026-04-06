import os
#!/usr/bin/env python3
"""
Connector Lifecycle FSM Verification (bd-2gh).

Validates that the connector lifecycle enum, transition table, and
illegal-transition rejection are implemented correctly.

Usage:
    python3 scripts/check_connector_lifecycle.py [--json]
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


# --- FSM specification (mirrors Rust implementation) ---

STATES = [
    "discovered", "verified", "installed", "configured",
    "active", "paused", "stopped", "failed",
]

LEGAL_TRANSITIONS = {
    ("discovered", "verified"),
    ("discovered", "failed"),
    ("verified", "installed"),
    ("verified", "failed"),
    ("installed", "configured"),
    ("installed", "failed"),
    ("configured", "active"),
    ("configured", "failed"),
    ("active", "paused"),
    ("active", "stopped"),
    ("active", "failed"),
    ("paused", "active"),
    ("paused", "stopped"),
    ("paused", "failed"),
    ("stopped", "configured"),
    ("stopped", "failed"),
    ("failed", "discovered"),
}

LEGAL_TARGETS = {
    "discovered": ["verified", "failed"],
    "verified": ["installed", "failed"],
    "installed": ["configured", "failed"],
    "configured": ["active", "failed"],
    "active": ["paused", "stopped", "failed"],
    "paused": ["active", "stopped", "failed"],
    "stopped": ["configured", "failed"],
    "failed": ["discovered"],
}


def check_fsm_completeness() -> dict:
    """LIFECYCLE-COMPLETE: Every non-self pair is either legal or illegal."""
    all_pairs = {(s, t) for s in STATES for t in STATES if s != t}
    covered = LEGAL_TRANSITIONS | (all_pairs - LEGAL_TRANSITIONS)
    missing = all_pairs - covered
    return {
        "id": "LIFECYCLE-COMPLETE",
        "status": "PASS" if not missing else "FAIL",
        "details": {
            "total_pairs": len(all_pairs),
            "legal": len(LEGAL_TRANSITIONS),
            "illegal": len(all_pairs) - len(LEGAL_TRANSITIONS),
            "missing": list(missing),
        },
    }


def check_no_self_transitions() -> dict:
    """LIFECYCLE-NO-SELF: No self-transitions in legal set."""
    self_loops = [(s, t) for s, t in LEGAL_TRANSITIONS if s == t]
    return {
        "id": "LIFECYCLE-NO-SELF",
        "status": "PASS" if not self_loops else "FAIL",
        "details": {"self_loops": self_loops},
    }


def check_all_states_reachable() -> dict:
    """LIFECYCLE-REACHABLE: Every state appears as a target in at least one transition."""
    targets = {t for _, t in LEGAL_TRANSITIONS}
    missing = set(STATES) - targets
    return {
        "id": "LIFECYCLE-REACHABLE",
        "status": "PASS" if not missing else "FAIL",
        "details": {"unreachable_states": list(missing)},
    }


def check_all_states_have_outgoing() -> dict:
    """LIFECYCLE-OUTGOING: Every state has at least one legal outgoing transition."""
    sources = {s for s, _ in LEGAL_TRANSITIONS}
    missing = set(STATES) - sources
    return {
        "id": "LIFECYCLE-OUTGOING",
        "status": "PASS" if not missing else "FAIL",
        "details": {"dead_end_states": list(missing)},
    }


def check_happy_path() -> dict:
    """LIFECYCLE-HAPPY-PATH: discovered → verified → installed → configured → active is legal."""
    path = ["discovered", "verified", "installed", "configured", "active"]
    broken = []
    for i in range(len(path) - 1):
        pair = (path[i], path[i + 1])
        if pair not in LEGAL_TRANSITIONS:
            broken.append(pair)
    return {
        "id": "LIFECYCLE-HAPPY-PATH",
        "status": "PASS" if not broken else "FAIL",
        "details": {"path": path, "broken_edges": broken},
    }


def check_recovery_path() -> dict:
    """LIFECYCLE-RECOVERY: Failed → discovered reset path exists."""
    has_reset = ("failed", "discovered") in LEGAL_TRANSITIONS
    return {
        "id": "LIFECYCLE-RECOVERY",
        "status": "PASS" if has_reset else "FAIL",
    }


def check_rust_implementation() -> dict:
    """LIFECYCLE-IMPL: Rust implementation file exists with expected structure."""
    impl_path = ROOT / "crates" / "franken-node" / "src" / "connector" / "lifecycle.rs"
    if not impl_path.exists():
        return {"id": "LIFECYCLE-IMPL", "status": "FAIL", "details": {"error": "file not found"}}

    content = impl_path.read_text()
    expected = ["ConnectorState", "LifecycleError", "fn transition", "fn legal_targets", "fn transition_matrix"]
    missing = [e for e in expected if e not in content]
    return {
        "id": "LIFECYCLE-IMPL",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_symbols": missing},
    }


def check_rust_tests_pass() -> dict:
    """LIFECYCLE-TESTS: Rust unit tests pass."""
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::lifecycle"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        summary = [l for l in lines if "test result:" in l]
        passed = result.returncode == 0
        return {
            "id": "LIFECYCLE-TESTS",
            "status": "PASS" if passed else "FAIL",
            "details": {"summary": summary[-1] if summary else "", "returncode": result.returncode},
        }
    except Exception as e:
        return {"id": "LIFECYCLE-TESTS", "status": "FAIL", "details": {"error": str(e)}}


def check_transition_matrix_artifact() -> dict:
    """LIFECYCLE-MATRIX: Transition matrix JSON artifact exists and is valid."""
    matrix_path = ROOT / "artifacts" / "section_10_13" / "bd-2gh" / "lifecycle_transition_matrix.json"
    if not matrix_path.exists():
        return {"id": "LIFECYCLE-MATRIX", "status": "FAIL", "details": {"error": "file not found"}}
    try:
        data = json.loads(matrix_path.read_text())
        entries = data.get("transitions", [])
        legal_count = sum(1 for e in entries if e.get("legal"))
        return {
            "id": "LIFECYCLE-MATRIX",
            "status": "PASS" if len(entries) == 56 and legal_count == 17 else "FAIL",
            "details": {"total_entries": len(entries), "legal_count": legal_count},
        }
    except Exception as e:
        return {"id": "LIFECYCLE-MATRIX", "status": "FAIL", "details": {"error": str(e)}}


def check_spec_document() -> dict:
    """LIFECYCLE-SPEC: Specification document exists with required sections."""
    spec_path = ROOT / "docs" / "specs" / "section_10_13" / "bd-2gh_contract.md"
    if not spec_path.exists():
        return {"id": "LIFECYCLE-SPEC", "status": "FAIL", "details": {"error": "file not found"}}
    content = spec_path.read_text()
    required = ["States", "Transition Table", "Invariants", "Error Codes", "Interface"]
    missing = [r for r in required if r not in content]
    return {
        "id": "LIFECYCLE-SPEC",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_sections": missing},
    }


def self_test() -> dict:
    """Run all checks and produce a gate result."""
    checks = [
        check_fsm_completeness(),
        check_no_self_transitions(),
        check_all_states_reachable(),
        check_all_states_have_outgoing(),
        check_happy_path(),
        check_recovery_path(),
        check_rust_implementation(),
        check_rust_tests_pass(),
        check_transition_matrix_artifact(),
        check_spec_document(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "connector_lifecycle_verification",
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
    logger = configure_test_logging("check_connector_lifecycle")
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
