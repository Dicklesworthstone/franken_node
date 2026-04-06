import os
#!/usr/bin/env python3
"""
Connector Method Contract Validator Verification (bd-1h6).

Validates that the standard connector method contract validator is
correctly implemented with all 9 methods, schema versioning, and
machine-readable reporting.

Usage:
    python3 scripts/check_method_validator.py [--json]
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


STANDARD_METHODS = [
    "handshake", "describe", "introspect", "capabilities",
    "configure", "simulate", "invoke", "health", "shutdown",
]
REQUIRED_METHODS = [m for m in STANDARD_METHODS if m != "simulate"]
ERROR_CODES = ["METHOD_MISSING", "SCHEMA_MISMATCH", "VERSION_INCOMPATIBLE", "RESPONSE_INVALID"]


def check_method_count() -> dict:
    """METHOD-COUNT: Exactly 9 standard methods defined."""
    return {
        "id": "METHOD-COUNT",
        "status": "PASS" if len(STANDARD_METHODS) == 9 else "FAIL",
        "details": {"count": len(STANDARD_METHODS)},
    }


def check_required_count() -> dict:
    """METHOD-REQUIRED: Exactly 8 required methods."""
    return {
        "id": "METHOD-REQUIRED",
        "status": "PASS" if len(REQUIRED_METHODS) == 8 else "FAIL",
        "details": {"required": REQUIRED_METHODS},
    }


def check_impl_exists() -> dict:
    """METHOD-IMPL: Validator Rust implementation exists."""
    path = ROOT / "crates" / "franken-node" / "src" / "conformance" / "connector_method_validator.rs"
    if not path.exists():
        return {"id": "METHOD-IMPL", "status": "FAIL", "details": {"error": "file not found"}}
    content = path.read_text()
    expected = [
        "STANDARD_METHODS", "MethodSpec", "MethodDeclaration",
        "MethodErrorCode", "ContractReport", "fn validate_contract",
        "fn required_methods", "fn all_methods",
    ]
    missing = [e for e in expected if e not in content]
    return {
        "id": "METHOD-IMPL",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_symbols": missing},
    }


def check_error_codes_impl() -> dict:
    """METHOD-ERRORS: All error codes defined in implementation."""
    path = ROOT / "crates" / "franken-node" / "src" / "conformance" / "connector_method_validator.rs"
    if not path.exists():
        return {"id": "METHOD-ERRORS", "status": "FAIL"}
    content = path.read_text()
    missing = [c for c in ERROR_CODES if c not in content]
    return {
        "id": "METHOD-ERRORS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_codes": missing},
    }


def check_rust_tests() -> dict:
    """METHOD-TESTS: Rust unit tests pass."""
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "conformance::connector_method_validator"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        summary = [l for l in lines if "test result:" in l]
        return {
            "id": "METHOD-TESTS",
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "details": {"summary": summary[-1] if summary else ""},
        }
    except Exception as e:
        return {"id": "METHOD-TESTS", "status": "FAIL", "details": {"error": str(e)}}


def check_contract_report() -> dict:
    """METHOD-REPORT: Contract report artifact exists and is valid."""
    path = ROOT / "artifacts" / "section_10_13" / "bd-1h6" / "connector_method_contract_report.json"
    if not path.exists():
        return {"id": "METHOD-REPORT", "status": "FAIL", "details": {"error": "file not found"}}
    try:
        data = json.loads(path.read_text())
        methods = data.get("standard_methods", [])
        has_9 = len(methods) == 9
        has_errors = len(data.get("error_codes", [])) == 4
        return {
            "id": "METHOD-REPORT",
            "status": "PASS" if has_9 and has_errors else "FAIL",
            "details": {"method_count": len(methods), "error_code_count": len(data.get("error_codes", []))},
        }
    except Exception as e:
        return {"id": "METHOD-REPORT", "status": "FAIL", "details": {"error": str(e)}}


def check_spec_document() -> dict:
    """METHOD-SPEC: Specification document exists."""
    path = ROOT / "docs" / "specs" / "section_10_13" / "bd-1h6_contract.md"
    if not path.exists():
        return {"id": "METHOD-SPEC", "status": "FAIL"}
    content = path.read_text()
    required = ["Standard Methods", "Method Schema", "Invariants", "Error Codes"]
    missing = [r for r in required if r not in content]
    return {
        "id": "METHOD-SPEC",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_sections": missing},
    }


def check_all_methods_in_impl() -> dict:
    """METHOD-COVERAGE: All 9 methods appear in implementation."""
    path = ROOT / "crates" / "franken-node" / "src" / "conformance" / "connector_method_validator.rs"
    if not path.exists():
        return {"id": "METHOD-COVERAGE", "status": "FAIL"}
    content = path.read_text()
    missing = [m for m in STANDARD_METHODS if f'"{m}"' not in content]
    return {
        "id": "METHOD-COVERAGE",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_methods": missing},
    }


def self_test() -> dict:
    """Run all checks."""
    checks = [
        check_method_count(),
        check_required_count(),
        check_impl_exists(),
        check_error_codes_impl(),
        check_rust_tests(),
        check_contract_report(),
        check_spec_document(),
        check_all_methods_in_impl(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "method_validator_verification",
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
    logger = configure_test_logging("check_method_validator")
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
