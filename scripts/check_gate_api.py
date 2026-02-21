#!/usr/bin/env python3
"""Verification script for bd-137: Policy-Visible Compatibility Gate APIs.

Checks API surfaces, modes, event codes, invariants, policy-as-data contracts,
non-interference, monotonicity, and performance requirements.

Usage:
    python scripts/check_gate_api.py [--json] [--self-test]
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_5" / "bd-137_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "compatibility_gate_api.md"

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str = "") -> bool:
    RESULTS.append({"name": name, "pass": passed, "detail": detail})
    return passed


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def check_files_exist() -> int:
    ok = 0
    if _check("file_exists:spec", SPEC_PATH.is_file(), f"spec at {_safe_rel(SPEC_PATH)}"):
        ok += 1
    if _check("file_exists:policy", POLICY_PATH.is_file(), f"policy at {_safe_rel(POLICY_PATH)}"):
        ok += 1
    return ok


def check_api_surfaces() -> int:
    if not SPEC_PATH.is_file():
        _check("api_surfaces:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    surfaces = ["gate-check", "mode?scope", "mode/transition", "receipts?scope", "shims?scope"]
    ok = 0
    for s in surfaces:
        if _check(f"api:{s[:20]}", s in text, f"API surface: {s}"):
            ok += 1
    return ok


def check_compatibility_modes() -> int:
    if not SPEC_PATH.is_file():
        _check("modes:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    modes = ["strict", "balanced", "legacy_risky"]
    ok = 0
    for m in modes:
        if _check(f"mode:{m}", m in text, f"mode: {m}"):
            ok += 1
    return ok


def check_event_codes() -> int:
    if not SPEC_PATH.is_file():
        _check("event_codes:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    codes = ["PCG-001", "PCG-002", "PCG-003", "PCG-004"]
    ok = 0
    for c in codes:
        if _check(f"event_code:{c}", c in text, c):
            ok += 1
    return ok


def check_invariants() -> int:
    if not SPEC_PATH.is_file():
        _check("invariants:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    invs = ["INV-PCG-VISIBLE", "INV-PCG-AUDITABLE", "INV-PCG-RECEIPT", "INV-PCG-TRANSITION"]
    ok = 0
    for inv in invs:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_policy_contracts() -> int:
    if not SPEC_PATH.is_file():
        _check("policy_contracts:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    kws = ["policy-as-data", "predicate", "signature", "attenuation"]
    ok = 0
    for kw in kws:
        if _check(f"policy:{kw}", kw in text, f"policy contract: {kw}"):
            ok += 1
    return ok


def check_properties() -> int:
    if not SPEC_PATH.is_file():
        _check("properties:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    props = ["non-interference", "monotonicity"]
    ok = 0
    for p in props:
        if _check(f"property:{p}", p in text, f"property: {p}"):
            ok += 1
    return ok


def check_performance() -> int:
    if not SPEC_PATH.is_file():
        _check("perf:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    kws = ["1ms", "p99", "cached"]
    ok = 0
    for kw in kws:
        if _check(f"perf:{kw}", kw in text, f"performance: {kw}"):
            ok += 1
    return ok


def check_acceptance_criteria() -> int:
    if not SPEC_PATH.is_file():
        _check("acceptance:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    kws = ["acceptance criteria", "typed metadata", "signed receipts", "machine-readable rationale"]
    ok = 0
    for kw in kws:
        if _check(f"acceptance:{kw[:20]}", kw in text, f"acceptance: {kw}"):
            ok += 1
    return ok


def check_policy_doc() -> int:
    if not POLICY_PATH.is_file():
        _check("policy_doc:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    kws = ["gate", "compatibility", "receipt", "transition", "shim"]
    ok = 0
    for kw in kws:
        if _check(f"policy_doc:{kw}", kw in text, f"policy doc: {kw}"):
            ok += 1
    return ok


def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_api_surfaces()
    check_compatibility_modes()
    check_event_codes()
    check_invariants()
    check_policy_contracts()
    check_properties()
    check_performance()
    check_acceptance_criteria()
    check_policy_doc()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-137",
        "title": "Policy-Visible Compatibility Gate APIs",
        "section": "10.5",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    assert callable(check_files_exist)
    assert callable(check_api_surfaces)
    assert callable(check_event_codes)
    assert callable(check_invariants)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    assert result["bead_id"] == "bd-137"
    print("self_test: OK")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-137 Compatibility Gate APIs: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
