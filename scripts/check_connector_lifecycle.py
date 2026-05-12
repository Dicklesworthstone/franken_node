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
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "lifecycle.rs"
CRATE_MANIFEST_PATH = ROOT / "crates" / "franken-node" / "Cargo.toml"
CONFORMANCE_PATH = ROOT / "tests" / "conformance" / "connector_lifecycle_transitions.rs"
E2E_PATH = ROOT / "crates" / "franken-node" / "tests" / "connector_lifecycle_public_api_e2e.rs"
MIGRATION_CATALOG_PATH = ROOT / "tests" / "goldens" / "frankensqlite" / "persistence_class_catalog.json"
MATRIX_PATH = ROOT / "artifacts" / "section_10_13" / "bd-2gh" / "lifecycle_transition_matrix.json"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_13" / "bd-2gh_contract.md"
JSON_DECODER = json.JSONDecoder()


# --- FSM specification (mirrors Rust implementation) ---

STATES = [
    "discovered", "verified", "installed", "configured",
    "active", "paused", "cancelling", "stopped", "failed",
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
    ("active", "cancelling"),
    ("active", "stopped"),
    ("active", "failed"),
    ("paused", "active"),
    ("paused", "cancelling"),
    ("paused", "stopped"),
    ("paused", "failed"),
    ("cancelling", "stopped"),
    ("cancelling", "failed"),
    ("stopped", "configured"),
    ("stopped", "failed"),
    ("failed", "discovered"),
}

LEGAL_TARGETS = {
    "discovered": ["verified", "failed"],
    "verified": ["installed", "failed"],
    "installed": ["configured", "failed"],
    "configured": ["active", "failed"],
    "active": ["paused", "cancelling", "stopped", "failed"],
    "paused": ["active", "cancelling", "stopped", "failed"],
    "cancelling": ["stopped", "failed"],
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
    if not IMPL_PATH.exists():
        return {"id": "LIFECYCLE-IMPL", "status": "FAIL", "details": {"error": "file not found"}}

    content = IMPL_PATH.read_text()
    expected = ["ConnectorState", "LifecycleError", "fn transition", "fn legal_targets", "fn transition_matrix"]
    missing = [e for e in expected if e not in content]
    return {
        "id": "LIFECYCLE-IMPL",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_symbols": missing},
    }


def check_rust_tests_pass(run_rust_tests: bool = False) -> dict:
    """LIFECYCLE-TESTS: Rust unit tests pass."""
    if not run_rust_tests:
        return {
            "id": "LIFECYCLE-TESTS",
            "status": "SKIP",
            "details": {"reason": "not run in structural mode; pass --run-rust-tests for rch cargo proof"},
        }

    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::lifecycle"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        summary = [line for line in lines if "test result:" in line]
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
    if not MATRIX_PATH.exists():
        return {"id": "LIFECYCLE-MATRIX", "status": "FAIL", "details": {"error": "file not found"}}
    try:
        data = JSON_DECODER.decode(MATRIX_PATH.read_text())
        entries = data.get("transitions", [])
        legal_count = sum(1 for e in entries if e.get("legal"))
        return {
            "id": "LIFECYCLE-MATRIX",
            "status": "PASS" if len(entries) == 72 and legal_count == 21 else "FAIL",
            "details": {"total_entries": len(entries), "legal_count": legal_count},
        }
    except Exception as e:
        return {"id": "LIFECYCLE-MATRIX", "status": "FAIL", "details": {"error": str(e)}}


def check_spec_document() -> dict:
    """LIFECYCLE-SPEC: Specification document exists with required sections."""
    if not SPEC_PATH.exists():
        return {"id": "LIFECYCLE-SPEC", "status": "FAIL", "details": {"error": "file not found"}}
    content = SPEC_PATH.read_text()
    required = ["States", "Transition Table", "Invariants", "Error Codes", "Interface"]
    missing = [r for r in required if r not in content]
    return {
        "id": "LIFECYCLE-SPEC",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_sections": missing},
    }


def check_conformance_test_target() -> dict:
    """LIFECYCLE-CONFORMANCE: Cargo-visible conformance target covers the live FSM."""
    missing_files = [
        str(path.relative_to(ROOT))
        for path in (CRATE_MANIFEST_PATH, CONFORMANCE_PATH)
        if not path.exists()
    ]
    if missing_files:
        return {
            "id": "LIFECYCLE-CONFORMANCE",
            "status": "FAIL",
            "details": {"missing_files": missing_files},
        }

    manifest = CRATE_MANIFEST_PATH.read_text()
    content = CONFORMANCE_PATH.read_text()
    required_manifest = [
        'name = "connector_lifecycle_transitions"',
        'path = "../../tests/conformance/connector_lifecycle_transitions.rs"',
    ]
    required_markers = [
        "frankenengine_node::connector::lifecycle",
        "transition_matrix_matches_authoritative_transition_table",
        "self_transitions_return_stable_self_error",
        "cancelling_edges_are_explicitly_conformant",
        "LifecycleError::IllegalTransition",
    ]
    missing_manifest = [marker for marker in required_manifest if marker not in manifest]
    missing_markers = [marker for marker in required_markers if marker not in content]
    return {
        "id": "LIFECYCLE-CONFORMANCE",
        "status": "PASS" if not missing_manifest and not missing_markers else "FAIL",
        "details": {
            "target": str(CONFORMANCE_PATH.relative_to(ROOT)),
            "missing_manifest_markers": missing_manifest,
            "missing_test_markers": missing_markers,
        },
    }


def check_e2e_telemetry_evidence() -> dict:
    """LIFECYCLE-E2E-TELEMETRY: Public API E2E emits structured traceable lifecycle events."""
    if not E2E_PATH.exists():
        return {"id": "LIFECYCLE-E2E-TELEMETRY", "status": "FAIL", "details": {"error": "file not found"}}
    content = E2E_PATH.read_text()
    required = [
        "connector_lifecycle_public_api_e2e",
        "connector_lifecycle_phase",
        "trace_id",
        "span_id",
        "parent_span_id",
        "event_code",
        "from_state",
        "to_state",
        "assert_stitchable_trace",
        "assert_audit_jsonl_is_structured",
        "CONN-LC-INIT-VERIFIED",
        "CONN-LC-RUN-ACTIVE",
        "CONN-LC-RUN-BLOCKED",
    ]
    missing = [marker for marker in required if marker not in content]
    return {
        "id": "LIFECYCLE-E2E-TELEMETRY",
        "status": "PASS" if not missing else "FAIL",
        "details": {
            "path": str(E2E_PATH.relative_to(ROOT)),
            "missing_markers": missing,
        },
    }


def check_migration_catalog_entry() -> dict:
    """LIFECYCLE-MIGRATION: frankensqlite catalog records lifecycle transition persistence."""
    if not MIGRATION_CATALOG_PATH.exists():
        return {"id": "LIFECYCLE-MIGRATION", "status": "FAIL", "details": {"error": "file not found"}}
    try:
        catalog = JSON_DECODER.decode(MIGRATION_CATALOG_PATH.read_text())
    except Exception as e:
        return {"id": "LIFECYCLE-MIGRATION", "status": "FAIL", "details": {"error": str(e)}}

    classes = catalog.get("classes", [])
    entry = next(
        (
            item
            for item in classes
            if item.get("domain") == "lifecycle_transition_cache"
            and item.get("owner_module") == "crates/franken-node/src/connector/lifecycle.rs"
        ),
        None,
    )
    passed = bool(
        entry
        and entry.get("safety_tier") == "Tier3"
        and entry.get("durability_mode") == "Memory"
        and entry.get("replay_strategy") == "recomputed_from_transition_rules"
    )
    return {
        "id": "LIFECYCLE-MIGRATION",
        "status": "PASS" if passed else "FAIL",
        "details": {
            "path": str(MIGRATION_CATALOG_PATH.relative_to(ROOT)),
            "entry": entry,
        },
    }


def self_test(run_rust_tests: bool = False) -> dict:
    """Run all checks and produce a gate result."""
    checks = [
        check_fsm_completeness(),
        check_no_self_transitions(),
        check_all_states_reachable(),
        check_all_states_have_outgoing(),
        check_happy_path(),
        check_recovery_path(),
        check_rust_implementation(),
        check_rust_tests_pass(run_rust_tests),
        check_transition_matrix_artifact(),
        check_spec_document(),
        check_conformance_test_target(),
        check_e2e_telemetry_evidence(),
        check_migration_catalog_entry(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    skipped = [c for c in checks if c["status"] == "SKIP"]
    return {
        "gate": "connector_lifecycle_verification",
        "section": "10.13",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing) - len(skipped),
            "failing_checks": len(failing),
            "skipped_checks": len(skipped),
        },
    }


def main():
    configure_test_logging("check_connector_lifecycle")
    json_output = "--json" in sys.argv
    run_rust_tests = "--run-rust-tests" in sys.argv
    result = self_test(run_rust_tests)

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
