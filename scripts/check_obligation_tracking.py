#!/usr/bin/env python3
"""Verification script for bd-1n5p: Obligation-Tracked Two-Phase Channels.

Validates spec, Rust implementation, event codes, invariants, core types,
error codes, flow tracking, leak oracle, and test coverage.

Usage:
    python scripts/check_obligation_tracking.py           # human-readable
    python scripts/check_obligation_tracking.py --json     # JSON output
    python scripts/check_obligation_tracking.py --self-test  # self-test mode
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


BEAD_ID = "bd-1n5p"
SECTION = "10.15"
TITLE = "Obligation-Tracked Two-Phase Channels"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_15" / "bd-1n5p_contract.md"
TWO_PHASE_SPEC_PATH = ROOT / "docs" / "specs" / "two_phase_effects.md"
RUST_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "obligation_tracker.rs"
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
TEST_PATH = ROOT / "tests" / "test_check_obligation_tracking.py"
ORACLE_REPORT_PATH = ROOT / "artifacts" / "10.15" / "obligation_leak_oracle_report.json"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_15" / "bd-1n5p" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_15" / "bd-1n5p" / "verification_summary.md"

EVENT_CODES = [
    "OBL-001", "OBL-002", "OBL-003", "OBL-004", "OBL-005", "OBL-006",
]

INVARIANTS = [
    "INV-OBL-TWO-PHASE",
    "INV-OBL-NO-LEAK",
    "INV-OBL-BUDGET-BOUND",
    "INV-OBL-DROP-SAFE",
    "INV-OBL-ATOMIC-COMMIT",
    "INV-OBL-ROLLBACK-SAFE",
    "INV-OBL-AUDIT-COMPLETE",
    "INV-OBL-SCAN-PERIODIC",
]

ERROR_CODES = [
    "ERR_OBL_ALREADY_COMMITTED",
    "ERR_OBL_ALREADY_ROLLED_BACK",
    "ERR_OBL_NOT_FOUND",
    "ERR_OBL_LEAK_TIMEOUT",
    "ERR_OBL_DUPLICATE_RESERVE",
]

CORE_TYPES = [
    "ObligationTracker",
    "ObligationId",
    "ObligationFlow",
    "ObligationState",
    "Obligation",
    "ObligationAuditRecord",
    "LeakScanResult",
    "LeakOracleReport",
    "FlowObligationCounts",
    "ObligationGuard",
]

TRACKED_FLOWS = [
    "publish", "revoke", "quarantine", "migration", "fencing",
]

REQUIRED_METHODS = [
    "reserve",
    "commit",
    "rollback",
    "run_leak_scan",
    "get_obligation",
    "count_in_state",
    "total_obligations",
    "export_audit_log_jsonl",
    "generate_leak_oracle_report",
    "export_leak_oracle_report_json",
]

MIN_TEST_COUNT = 15


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def _file_text(path: Path) -> str | None:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


def run_all() -> dict:
    checks: list[dict] = []

    # --- SOURCE_EXISTS ---
    rust_text = _file_text(RUST_PATH)
    checks.append(_check(
        "SOURCE_EXISTS",
        rust_text is not None,
        f"{RUST_PATH.relative_to(ROOT)} exists" if rust_text else "obligation_tracker.rs missing",
    ))

    # --- EVENT_CODES ---
    if rust_text:
        for code in EVENT_CODES:
            found = f'"{code}"' in rust_text
            checks.append(_check(
                f"EVENT_CODE:{code}",
                found,
                f"{code} found in Rust" if found else f"{code} missing from Rust",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"EVENT_CODE:{code}", False, "obligation_tracker.rs missing"))

    # --- INVARIANTS ---
    if rust_text:
        for inv in INVARIANTS:
            found = inv in rust_text or inv.replace("-", "_") in rust_text
            checks.append(_check(
                f"INVARIANT:{inv}",
                found,
                f"{inv} found in Rust" if found else f"{inv} missing from Rust",
            ))
    else:
        for inv in INVARIANTS:
            checks.append(_check(f"INVARIANT:{inv}", False, "obligation_tracker.rs missing"))

    # --- ERROR_CODES ---
    if rust_text:
        for code in ERROR_CODES:
            found = f'"{code}"' in rust_text or f"{code}" in rust_text
            checks.append(_check(
                f"ERROR_CODE:{code}",
                found,
                f"{code} found in Rust" if found else f"{code} missing from Rust",
            ))
    else:
        for code in ERROR_CODES:
            checks.append(_check(f"ERROR_CODE:{code}", False, "obligation_tracker.rs missing"))

    # --- CORE_TYPES ---
    if rust_text:
        for typ in CORE_TYPES:
            found = (f"pub struct {typ}" in rust_text
                     or f"pub enum {typ}" in rust_text
                     or f"pub type {typ}" in rust_text)
            checks.append(_check(
                f"CORE_TYPE:{typ}",
                found,
                f"{typ} defined" if found else f"{typ} not defined",
            ))
    else:
        for typ in CORE_TYPES:
            checks.append(_check(f"CORE_TYPE:{typ}", False, "obligation_tracker.rs missing"))

    # --- TRACKED_FLOWS ---
    if rust_text:
        for flow in TRACKED_FLOWS:
            # Check flow is represented as a variant (capitalized) in ObligationFlow enum
            variant = flow.capitalize()
            found = variant in rust_text
            checks.append(_check(
                f"TRACKED_FLOW:{flow}",
                found,
                f"{flow} flow tracked" if found else f"{flow} flow missing",
            ))
    else:
        for flow in TRACKED_FLOWS:
            checks.append(_check(f"TRACKED_FLOW:{flow}", False, "obligation_tracker.rs missing"))

    # --- REQUIRED_METHODS ---
    if rust_text:
        for method in REQUIRED_METHODS:
            found = f"fn {method}" in rust_text
            checks.append(_check(
                f"METHOD:{method}",
                found,
                f"{method} implemented" if found else f"{method} not found",
            ))
    else:
        for method in REQUIRED_METHODS:
            checks.append(_check(f"METHOD:{method}", False, "obligation_tracker.rs missing"))

    # --- SCHEMA_VERSION ---
    if rust_text:
        found = '"obl-v1.0"' in rust_text
        checks.append(_check(
            "SCHEMA_VERSION",
            found,
            "obl-v1.0 declared" if found else "schema version missing",
        ))
    else:
        checks.append(_check("SCHEMA_VERSION", False, "obligation_tracker.rs missing"))

    # --- SERDE_DERIVES ---
    if rust_text:
        found = "Serialize" in rust_text and "Deserialize" in rust_text
        checks.append(_check(
            "SERDE_DERIVES",
            found,
            "Serialize/Deserialize present" if found else "serde derives missing",
        ))
    else:
        checks.append(_check("SERDE_DERIVES", False, "obligation_tracker.rs missing"))

    # --- TEST_COVERAGE ---
    if rust_text:
        test_count = len(re.findall(r"#\[test\]", rust_text))
        checks.append(_check(
            "TEST_COVERAGE",
            test_count >= MIN_TEST_COUNT,
            f"{test_count} tests (>= {MIN_TEST_COUNT} required)",
        ))
    else:
        checks.append(_check("TEST_COVERAGE", False, "obligation_tracker.rs missing"))

    # --- MODULE_REGISTERED ---
    mod_text = _file_text(MOD_PATH)
    registered = mod_text is not None and "pub mod obligation_tracker;" in mod_text
    checks.append(_check(
        "MODULE_REGISTERED",
        registered,
        "obligation_tracker registered in connector/mod.rs" if registered else "not registered",
    ))

    # --- SPEC_EXISTS ---
    spec_text = _file_text(SPEC_PATH)
    checks.append(_check(
        "SPEC_EXISTS",
        spec_text is not None,
        f"{SPEC_PATH.relative_to(ROOT)} exists" if spec_text else "spec contract missing",
    ))

    # --- TWO_PHASE_SPEC_EXISTS ---
    two_phase_text = _file_text(TWO_PHASE_SPEC_PATH)
    checks.append(_check(
        "TWO_PHASE_SPEC_EXISTS",
        two_phase_text is not None,
        f"{TWO_PHASE_SPEC_PATH.relative_to(ROOT)} exists" if two_phase_text
        else "two_phase_effects.md missing",
    ))

    # Verify spec references key elements
    if spec_text:
        for code in EVENT_CODES:
            found = code in spec_text
            checks.append(_check(
                f"SPEC_EVENT:{code}",
                found,
                f"{code} in spec" if found else f"{code} missing from spec",
            ))
        for inv in INVARIANTS:
            found = inv in spec_text
            checks.append(_check(
                f"SPEC_INVARIANT:{inv}",
                found,
                f"{inv} in spec" if found else f"{inv} missing from spec",
            ))
        for code in ERROR_CODES:
            found = code in spec_text
            checks.append(_check(
                f"SPEC_ERROR:{code}",
                found,
                f"{code} in spec" if found else f"{code} missing from spec",
            ))
        for typ in CORE_TYPES:
            found = typ in spec_text
            checks.append(_check(
                f"SPEC_TYPE:{typ}",
                found,
                f"{typ} in spec" if found else f"{typ} missing from spec",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"SPEC_EVENT:{code}", False, "spec missing"))
        for inv in INVARIANTS:
            checks.append(_check(f"SPEC_INVARIANT:{inv}", False, "spec missing"))
        for code in ERROR_CODES:
            checks.append(_check(f"SPEC_ERROR:{code}", False, "spec missing"))
        for typ in CORE_TYPES:
            checks.append(_check(f"SPEC_TYPE:{typ}", False, "spec missing"))

    # --- ORACLE_REPORT ---
    oracle_text = _file_text(ORACLE_REPORT_PATH)
    checks.append(_check(
        "ORACLE_REPORT_EXISTS",
        oracle_text is not None,
        "obligation_leak_oracle_report.json exists" if oracle_text
        else "oracle report missing",
    ))

    if oracle_text:
        try:
            report = json.loads(oracle_text)
            checks.append(_check(
                "ORACLE_REPORT_VALID_JSON",
                True,
                "oracle report is valid JSON",
            ))
            has_verdict = "verdict" in report
            checks.append(_check(
                "ORACLE_REPORT_VERDICT",
                has_verdict and report["verdict"] == "PASS",
                f"verdict={report.get('verdict', 'MISSING')}"
                if has_verdict else "verdict field missing",
            ))
        except json.JSONDecodeError:
            checks.append(_check("ORACLE_REPORT_VALID_JSON", False, "invalid JSON"))
            checks.append(_check("ORACLE_REPORT_VERDICT", False, "cannot parse"))
    else:
        checks.append(_check("ORACLE_REPORT_VALID_JSON", False, "oracle report missing"))
        checks.append(_check("ORACLE_REPORT_VERDICT", False, "oracle report missing"))

    # --- TEST_FILE ---
    test_text = _file_text(TEST_PATH)
    checks.append(_check(
        "TEST_FILE_EXISTS",
        test_text is not None,
        f"{TEST_PATH.relative_to(ROOT)} exists" if test_text else "test file missing",
    ))

    # --- EVIDENCE ---
    evidence_text = _file_text(EVIDENCE_PATH)
    checks.append(_check(
        "EVIDENCE_EXISTS",
        evidence_text is not None,
        "evidence JSON exists" if evidence_text else "evidence missing",
    ))

    # --- SUMMARY ---
    summary_text = _file_text(SUMMARY_PATH)
    checks.append(_check(
        "SUMMARY_EXISTS",
        summary_text is not None,
        "verification summary exists" if summary_text else "summary missing",
    ))

    # --- Compile result ---
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    total = len(checks)
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": total,
        "verdict": verdict,
        "all_passed": failed == 0,
        "status": "pass" if failed == 0 else "fail",
    }


def self_test() -> bool:
    """Verify the checker itself is well-formed."""
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == BEAD_ID
    assert result["section"] == SECTION
    assert isinstance(result["checks"], list)
    assert isinstance(result["total"], int)
    assert result["total"] > 0
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
        assert isinstance(check["passed"], bool)
    return True


def main() -> None:
    logger = configure_test_logging("check_obligation_tracking")
    if "--self-test" in sys.argv:
        ok = self_test()
        print("self_test passed" if ok else "self_test FAILED")
        sys.exit(0 if ok else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== {TITLE} ({BEAD_ID}) ===")
        print(f"Section: {SECTION}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"  [{status}] {check['name']}: {check['detail']}")
        print()
        print(f"Verdict: {result['verdict']} ({result['passed']}/{result['total']})")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
