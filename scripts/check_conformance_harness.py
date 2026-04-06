import os
#!/usr/bin/env python3
"""
Conformance Harness and Publication Gate Verification (bd-3en).

Validates the connector protocol conformance harness and publication
gate are correctly implemented.

Usage:
    python3 scripts/check_conformance_harness.py [--json]
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



def check_harness_impl() -> dict:
    """HARNESS-IMPL: Protocol harness Rust implementation exists."""
    path = ROOT / "crates" / "franken-node" / "src" / "conformance" / "protocol_harness.rs"
    if not path.exists():
        return {"id": "HARNESS-IMPL", "status": "FAIL", "details": {"error": "file not found"}}
    content = path.read_text()
    expected = [
        "PolicyOverride", "GateErrorCode", "PublicationGateResult",
        "HarnessReport", "fn check_publication", "fn run_harness",
    ]
    missing = [e for e in expected if e not in content]
    return {
        "id": "HARNESS-IMPL",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_symbols": missing},
    }


def check_gate_error_codes() -> dict:
    """HARNESS-ERRORS: All gate error codes defined."""
    path = ROOT / "crates" / "franken-node" / "src" / "conformance" / "protocol_harness.rs"
    if not path.exists():
        return {"id": "HARNESS-ERRORS", "status": "FAIL"}
    content = path.read_text()
    codes = ["PublicationBlocked", "OverrideExpired", "OverrideScopeMismatch"]
    missing = [c for c in codes if c not in content]
    return {
        "id": "HARNESS-ERRORS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_codes": missing},
    }


def check_override_support() -> dict:
    """HARNESS-OVERRIDE: Policy override artifact support exists."""
    path = ROOT / "crates" / "franken-node" / "src" / "conformance" / "protocol_harness.rs"
    if not path.exists():
        return {"id": "HARNESS-OVERRIDE", "status": "FAIL"}
    content = path.read_text()
    features = ["override_id", "expires_at", "scope", "authorized_by"]
    missing = [f for f in features if f not in content]
    return {
        "id": "HARNESS-OVERRIDE",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_features": missing},
    }


def check_rust_tests() -> dict:
    """HARNESS-TESTS: Rust unit tests pass."""
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "conformance::protocol_harness"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        summary = [l for l in lines if "test result:" in l]
        return {
            "id": "HARNESS-TESTS",
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "details": {"summary": summary[-1] if summary else ""},
        }
    except Exception as e:
        return {"id": "HARNESS-TESTS", "status": "FAIL", "details": {"error": str(e)}}


def check_ci_workflow() -> dict:
    """HARNESS-CI: CI workflow exists."""
    path = ROOT / ".github" / "workflows" / "connector-conformance.yml"
    if not path.exists():
        return {"id": "HARNESS-CI", "status": "FAIL", "details": {"error": "file not found"}}
    content = path.read_text()
    expected = ["conformance", "cargo test", "Conformance Gate"]
    missing = [e for e in expected if e not in content]
    return {
        "id": "HARNESS-CI",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_elements": missing},
    }


def check_conformance_test_file() -> dict:
    """HARNESS-CONFORMANCE: Conformance test file exists."""
    path = ROOT / "tests" / "conformance" / "connector_protocol_harness.rs"
    if not path.exists():
        return {"id": "HARNESS-CONFORMANCE", "status": "FAIL"}
    content = path.read_text()
    expected = ["fail_closed_default", "expired_override_rejected", "deterministic_outcome"]
    missing = [e for e in expected if e not in content]
    return {
        "id": "HARNESS-CONFORMANCE",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_tests": missing},
    }


def check_spec_document() -> dict:
    """HARNESS-SPEC: Specification document exists."""
    path = ROOT / "docs" / "specs" / "section_10_13" / "bd-3en_contract.md"
    if not path.exists():
        return {"id": "HARNESS-SPEC", "status": "FAIL"}
    content = path.read_text()
    required = ["Publication Gate", "Policy Override", "Invariants", "Error Codes"]
    missing = [r for r in required if r not in content]
    return {
        "id": "HARNESS-SPEC",
        "status": "PASS" if not missing else "FAIL",
    }


def check_publication_evidence() -> dict:
    """HARNESS-EVIDENCE: Publication gate evidence artifact exists."""
    path = ROOT / "artifacts" / "section_10_13" / "bd-3en" / "publication_gate_evidence.json"
    if not path.exists():
        return {"id": "HARNESS-EVIDENCE", "status": "FAIL", "details": {"error": "file not found"}}
    try:
        data = json.loads(path.read_text())
        has_gate = "gate_logic" in data
        has_override = "override_support" in data
        return {
            "id": "HARNESS-EVIDENCE",
            "status": "PASS" if has_gate and has_override else "FAIL",
        }
    except Exception as e:
        return {"id": "HARNESS-EVIDENCE", "status": "FAIL", "details": {"error": str(e)}}


def self_test() -> dict:
    """Run all checks."""
    checks = [
        check_harness_impl(),
        check_gate_error_codes(),
        check_override_support(),
        check_rust_tests(),
        check_ci_workflow(),
        check_conformance_test_file(),
        check_spec_document(),
        check_publication_evidence(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "conformance_harness_verification",
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
    logger = configure_test_logging("check_conformance_harness")
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
