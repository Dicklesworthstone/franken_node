import os
#!/usr/bin/env python3
"""
Connector State Root/Object Model Verification (bd-18o).

Usage:
    python3 scripts/check_state_model.py [--json]
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


STATE_MODEL_TYPES = ["stateless", "key_value", "document", "append_only"]
DIVERGENCE_TYPES = ["none", "stale", "split_brain", "hash_mismatch"]
ERROR_CODES = ["STATE_MODEL_MISSING", "ROOT_HASH_MISMATCH", "CACHE_STALE", "CACHE_SPLIT_BRAIN"]


def check_impl_exists() -> dict:
    """STATE-IMPL: State model Rust implementation exists."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "state_model.rs"
    if not path.exists():
        return {"id": "STATE-IMPL", "status": "FAIL"}
    content = path.read_text()
    expected = ["StateModelType", "StateRoot", "DivergenceType", "DivergenceCheck",
                "ReconcileAction", "fn detect_divergence", "fn reconcile_action"]
    missing = [e for e in expected if e not in content]
    return {"id": "STATE-IMPL", "status": "PASS" if not missing else "FAIL", "details": {"missing": missing}}


def check_model_types() -> dict:
    """STATE-TYPES: All 4 state model types in implementation."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "state_model.rs"
    if not path.exists():
        return {"id": "STATE-TYPES", "status": "FAIL"}
    content = path.read_text()
    missing = [t for t in ["Stateless", "KeyValue", "Document", "AppendOnly"] if t not in content]
    return {"id": "STATE-TYPES", "status": "PASS" if not missing else "FAIL", "details": {"missing": missing}}


def check_error_codes() -> dict:
    """STATE-ERRORS: All error codes defined."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "state_model.rs"
    if not path.exists():
        return {"id": "STATE-ERRORS", "status": "FAIL"}
    content = path.read_text()
    missing = [c for c in ERROR_CODES if c not in content]
    return {"id": "STATE-ERRORS", "status": "PASS" if not missing else "FAIL", "details": {"missing": missing}}


def check_rust_tests() -> dict:
    """STATE-TESTS: Rust unit tests pass."""
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::state_model"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        summary = [l for l in lines if "test result:" in l]
        return {"id": "STATE-TESTS", "status": "PASS" if result.returncode == 0 else "FAIL",
                "details": {"summary": summary[-1] if summary else ""}}
    except Exception as e:
        return {"id": "STATE-TESTS", "status": "FAIL", "details": {"error": str(e)}}


def check_samples() -> dict:
    """STATE-SAMPLES: Sample state models artifact exists."""
    path = ROOT / "artifacts" / "section_10_13" / "bd-18o" / "state_model_samples.json"
    if not path.exists():
        return {"id": "STATE-SAMPLES", "status": "FAIL"}
    data = json.loads(path.read_text())
    samples = data.get("samples", [])
    return {"id": "STATE-SAMPLES", "status": "PASS" if len(samples) == 4 else "FAIL",
            "details": {"count": len(samples)}}


def check_integration_tests() -> dict:
    """STATE-INTEGRATION: Integration test file exists."""
    path = ROOT / "tests" / "integration" / "connector_state_persistence.rs"
    if not path.exists():
        return {"id": "STATE-INTEGRATION", "status": "FAIL"}
    content = path.read_text()
    expected = ["state_model_type_required", "stale_cache_reconciled", "split_brain_flagged"]
    missing = [t for t in expected if t not in content]
    return {"id": "STATE-INTEGRATION", "status": "PASS" if not missing else "FAIL"}


def check_spec_document() -> dict:
    """STATE-SPEC: Specification document exists."""
    path = ROOT / "docs" / "specs" / "section_10_13" / "bd-18o_contract.md"
    if not path.exists():
        return {"id": "STATE-SPEC", "status": "FAIL"}
    content = path.read_text()
    required = ["State Model Types", "State Root", "Cache Divergence", "Invariants"]
    missing = [r for r in required if r not in content]
    return {"id": "STATE-SPEC", "status": "PASS" if not missing else "FAIL"}


def self_test() -> dict:
    checks = [
        check_impl_exists(),
        check_model_types(),
        check_error_codes(),
        check_rust_tests(),
        check_samples(),
        check_integration_tests(),
        check_spec_document(),
    ]
    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "state_model_verification", "section": "10.13",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }


def main():
    logger = configure_test_logging("check_state_model")
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
