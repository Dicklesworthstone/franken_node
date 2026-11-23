#!/usr/bin/env python3
"""bd-2tdi: Region-owned execution tree verification gate (Section 10.15).

Validates that the region ownership module, spec doc, integration tests,
and quiescence trace exist and are well-formed.

Usage:
    python3 scripts/check_region_ownership.py
    python3 scripts/check_region_ownership.py --json
    python3 scripts/check_region_ownership.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path

BEAD = "bd-2tdi"
SECTION = "10.15"


REGION_MODULE = ROOT / "crates" / "franken-node" / "src" / "connector" / "region_ownership.rs"
SPEC_DOC = ROOT / "docs" / "specs" / "region_tree_topology.md"
INTEGRATION_TEST = ROOT / "tests" / "integration" / "region_owned_lifecycle.rs"
QUIESCENCE_TRACE = ROOT / "artifacts" / "10.15" / "region_quiescence_trace.jsonl"

REQUIRED_EVENT_CODES = {"RGN-001", "RGN-002", "RGN-003", "RGN-004", "RGN-005"}

REQUIRED_REGION_KINDS = {"connector_lifecycle", "health_gate", "rollout", "fencing"}

REQUIRED_TYPES = [
    "RegionId",
    "RegionKind",
    "Region",
    "TaskState",
    "RegionTask",
    "CloseResult",
    "RegionEvent",
]


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {
        "check": name,
        "passed": passed,
        "detail": detail or ("ok" if passed else "failed"),
    }


def check_file_exists(path: Path, label: str) -> dict:
    exists = path.is_file()
    return _check(
        f"file: {label}",
        exists,
        f"exists: {path.relative_to(ROOT)}" if exists else f"MISSING: {path}",
    )


def check_module_types() -> list[dict]:
    checks = []
    if not REGION_MODULE.exists():
        return [_check("module types", False, "module file missing")]

    content = REGION_MODULE.read_text(encoding="utf-8")
    for type_name in REQUIRED_TYPES:
        found = f"pub struct {type_name}" in content or f"pub enum {type_name}" in content
        checks.append(_check(
            f"type: {type_name}",
            found,
            "defined" if found else f"{type_name} not found in module",
        ))
    return checks


def check_event_codes_in_module() -> list[dict]:
    checks = []
    if not REGION_MODULE.exists():
        return [_check("event codes in module", False, "module file missing")]

    content = REGION_MODULE.read_text(encoding="utf-8")
    for code in sorted(REQUIRED_EVENT_CODES):
        found = f'"{code}"' in content
        checks.append(_check(
            f"event code: {code}",
            found,
            "present" if found else f"{code} not found in module",
        ))
    return checks


def check_region_kinds_in_module() -> list[dict]:
    checks = []
    if not REGION_MODULE.exists():
        return [_check("region kinds", False, "module file missing")]

    content = REGION_MODULE.read_text(encoding="utf-8")
    for kind in sorted(REQUIRED_REGION_KINDS):
        # Check for enum variant (capitalized) or string literal
        variant = kind.replace("_", " ").title().replace(" ", "")
        found = variant in content
        checks.append(_check(
            f"region kind: {kind}",
            found,
            "defined" if found else f"{kind} ({variant}) not found",
        ))
    return checks


def check_quiescence_trace() -> list[dict]:
    checks = []
    if not QUIESCENCE_TRACE.exists():
        return [_check("quiescence trace", False, "trace file missing")]

    lines = QUIESCENCE_TRACE.read_text(encoding="utf-8").strip().splitlines()
    checks.append(_check(
        "trace: non-empty",
        len(lines) > 0,
        f"{len(lines)} entries",
    ))

    valid_json = True
    for i, line in enumerate(lines):
        try:
            json.loads(line)
        except json.JSONDecodeError:
            valid_json = False
            checks.append(_check(
                f"trace: line {i+1} valid JSON",
                False,
                f"invalid JSON at line {i+1}",
            ))
            break

    if valid_json:
        checks.append(_check("trace: all entries valid JSON", True, f"{len(lines)} entries"))

    # Check for open and close/drain events
    has_open = any("open" in line for line in lines)
    has_close = any("close" in line or "drain" in line for line in lines)
    checks.append(_check("trace: has open events", has_open, "open events present"))
    checks.append(_check("trace: has close events", has_close, "close events present"))

    return checks


def check_spec_doc_sections() -> list[dict]:
    checks = []
    if not SPEC_DOC.exists():
        return [_check("spec doc sections", False, "spec doc missing")]

    content = SPEC_DOC.read_text(encoding="utf-8")
    required_sections = [
        "Region Hierarchy",
        "Ownership Rules",
        "Quiescence Guarantees",
        "Event Codes",
    ]
    for section in required_sections:
        found = section in content
        checks.append(_check(
            f"spec section: {section}",
            found,
            "present" if found else f"section '{section}' not found",
        ))
    return checks


def run_checks() -> dict:
    checks: list[dict] = []

    # File existence
    checks.append(check_file_exists(REGION_MODULE, "region_ownership.rs"))
    checks.append(check_file_exists(SPEC_DOC, "region_tree_topology.md"))
    checks.append(check_file_exists(INTEGRATION_TEST, "region_owned_lifecycle.rs"))
    checks.append(check_file_exists(QUIESCENCE_TRACE, "region_quiescence_trace.jsonl"))

    # Module structure
    checks.extend(check_module_types())
    checks.extend(check_event_codes_in_module())
    checks.extend(check_region_kinds_in_module())

    # Spec doc
    checks.extend(check_spec_doc_sections())

    # Trace validation
    checks.extend(check_quiescence_trace())

    passing = sum(1 for c in checks if c["passed"])
    failing = len(checks) - passing

    return {
        "bead_id": BEAD,
        "section": SECTION,
        "gate_script": "check_region_ownership.py",
        "verdict": "PASS" if failing == 0 else "FAIL",
        "checks_passed": passing,
        "checks_total": len(checks),
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test() -> bool:
    # Verify constants
    assert len(REQUIRED_EVENT_CODES) == 5, f"expected 5 event codes, got {len(REQUIRED_EVENT_CODES)}"
    assert len(REQUIRED_REGION_KINDS) == 4, f"expected 4 region kinds, got {len(REQUIRED_REGION_KINDS)}"
    assert len(REQUIRED_TYPES) == 7, f"expected 7 types, got {len(REQUIRED_TYPES)}"

    # Verify _check helper
    sample = _check("test", True, "ok")
    assert sample["passed"] is True
    assert sample["detail"] == "ok"

    sample_fail = _check("test", False)
    assert sample_fail["passed"] is False
    assert sample_fail["detail"] == "failed"

    # Verify event code format
    for code in REQUIRED_EVENT_CODES:
        assert code.startswith("RGN-"), f"unexpected prefix: {code}"

    return True


def main() -> int:
    logger = configure_test_logging("check_region_ownership")
    parser = argparse.ArgumentParser(
        description="bd-2tdi: Region-owned execution tree verification gate",
    )
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test")
    args = parser.parse_args()

    if args.self_test:
        try:
            self_test()
            print("self_test passed")
            return 0
        except AssertionError as exc:
            print(f"self_test FAILED: {exc}")
            return 1

    result = run_checks()

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["verdict"] == "PASS" else 1

    for c in result["checks"]:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"  [{status}] {c['check']}: {c['detail']}")

    print(f"\n{BEAD} verification: {result['verdict']} ({result['checks_passed']}/{result['checks_total']})")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
