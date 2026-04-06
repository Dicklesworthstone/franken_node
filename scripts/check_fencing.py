import os
#!/usr/bin/env python3
"""
Singleton-Writer Fencing Verification (bd-1cm).

Usage:
    python3 scripts/check_fencing.py [--json]
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


ERROR_CODES = ["WRITE_UNFENCED", "WRITE_STALE_FENCE", "LEASE_EXPIRED", "LEASE_OBJECT_MISMATCH"]


def check_impl() -> dict:
    """FENCE-IMPL: Fencing Rust implementation exists."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "fencing.rs"
    if not path.exists():
        return {"id": "FENCE-IMPL", "status": "FAIL"}
    content = path.read_text()
    expected = ["Lease", "FencedWrite", "FencingError", "FenceState", "fn validate_write", "fn acquire_lease"]
    missing = [e for e in expected if e not in content]
    return {"id": "FENCE-IMPL", "status": "PASS" if not missing else "FAIL", "details": {"missing": missing}}


def check_error_codes() -> dict:
    """FENCE-ERRORS: All error codes defined."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "fencing.rs"
    if not path.exists():
        return {"id": "FENCE-ERRORS", "status": "FAIL"}
    content = path.read_text()
    missing = [c for c in ERROR_CODES if c not in content]
    return {"id": "FENCE-ERRORS", "status": "PASS" if not missing else "FAIL", "details": {"missing": missing}}


def check_rust_tests() -> dict:
    """FENCE-TESTS: Rust unit tests pass."""
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::fencing"],
            capture_output=True, text=True, timeout=3600, cwd=str(ROOT),
        )
        lines = result.stdout.strip().split("\n")
        summary = [l for l in lines if "test result:" in l]
        return {"id": "FENCE-TESTS", "status": "PASS" if result.returncode == 0 else "FAIL",
                "details": {"summary": summary[-1] if summary else ""}}
    except Exception as e:
        return {"id": "FENCE-TESTS", "status": "FAIL", "details": {"error": str(e)}}


def check_conformance() -> dict:
    """FENCE-CONFORMANCE: Conformance test file exists."""
    path = ROOT / "tests" / "conformance" / "singleton_writer_fencing.rs"
    if not path.exists():
        return {"id": "FENCE-CONFORMANCE", "status": "FAIL"}
    content = path.read_text()
    expected = ["fence_seq_monotonic", "unfenced_write_rejected", "stale_fenced_write_rejected"]
    missing = [t for t in expected if t not in content]
    return {"id": "FENCE-CONFORMANCE", "status": "PASS" if not missing else "FAIL"}


def check_receipts() -> dict:
    """FENCE-RECEIPTS: Rejection receipts artifact exists."""
    path = ROOT / "artifacts" / "section_10_13" / "bd-1cm" / "fencing_rejection_receipts.json"
    if not path.exists():
        return {"id": "FENCE-RECEIPTS", "status": "FAIL"}
    data = json.loads(path.read_text())
    receipts = data.get("receipts", [])
    return {"id": "FENCE-RECEIPTS", "status": "PASS" if len(receipts) >= 4 else "FAIL",
            "details": {"count": len(receipts)}}


def check_spec() -> dict:
    """FENCE-SPEC: Specification document exists."""
    path = ROOT / "docs" / "specs" / "section_10_13" / "bd-1cm_contract.md"
    if not path.exists():
        return {"id": "FENCE-SPEC", "status": "FAIL"}
    content = path.read_text()
    required = ["Fencing Rules", "Invariants", "Error Codes", "lease_seq"]
    missing = [r for r in required if r not in content]
    return {"id": "FENCE-SPEC", "status": "PASS" if not missing else "FAIL"}


def self_test() -> dict:
    checks = [check_impl(), check_error_codes(), check_rust_tests(),
              check_conformance(), check_receipts(), check_spec()]
    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "fencing_verification", "section": "10.13",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }


def main():
    logger = configure_test_logging("check_fencing")
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
