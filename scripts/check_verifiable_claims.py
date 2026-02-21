#!/usr/bin/env python3
"""Verification script for bd-2a4l: Externally Verifiable Trust/Security Claims.

Checks that the spec and policy documents define all required verifiability
dimensions, evidence bundle format, reproduction protocol, adversarial
resilience, CI integration, event codes, and invariants.

Usage:
    python scripts/check_verifiable_claims.py [--json] [--self-test]
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_13" / "bd-2a4l_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "externally_verifiable_claims.md"

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


def check_verifiability_dimensions() -> int:
    if not SPEC_PATH.is_file():
        _check("dimensions:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    dims = ["VD-01", "VD-02", "VD-03", "VD-04", "VD-05"]
    ok = 0
    for d in dims:
        if _check(f"dimension:{d}", d in text, f"{d} in spec"):
            ok += 1
    return ok


def check_quantitative_targets() -> int:
    if not SPEC_PATH.is_file():
        _check("targets:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    targets = ["100%", "95%", "30 days", "sha-256"]
    ok = 0
    for t in targets:
        if _check(f"target:{t}", t in text, f"target {t} in spec"):
            ok += 1
    return ok


def check_event_codes() -> int:
    if not SPEC_PATH.is_file():
        _check("event_codes:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    codes = ["EVC-001", "EVC-002", "EVC-003", "EVC-004"]
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
    invs = ["INV-EVC-COVERAGE", "INV-EVC-REPRODUCE", "INV-EVC-DETERMINISM", "INV-EVC-INTEGRITY"]
    ok = 0
    for inv in invs:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_evidence_bundle_format() -> int:
    if not POLICY_PATH.is_file():
        _check("bundle_format:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["claim.json", "procedure.md", "manifest.json", "sha-256"]
    ok = 0
    for kw in keywords:
        if _check(f"bundle:{kw}", kw in text, f"bundle format: {kw}"):
            ok += 1
    return ok


def check_reproduction_protocol() -> int:
    if not POLICY_PATH.is_file():
        _check("reproduction:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["reproduction", "external", "determinism", "timestamp", "non-determinism"]
    ok = 0
    for kw in keywords:
        if _check(f"reproduction:{kw}", kw in text, f"reproduction: {kw}"):
            ok += 1
    return ok


def check_adversarial_resilience() -> int:
    if not POLICY_PATH.is_file():
        _check("adversarial:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["corrupted", "truncated", "tampered", "replayed"]
    ok = 0
    for kw in keywords:
        if _check(f"adversarial:{kw}", kw in text, f"adversarial: {kw}"):
            ok += 1
    return ok


def check_ci_integration() -> int:
    if not POLICY_PATH.is_file():
        _check("ci:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["release gate", "freshness", "nightly"]
    ok = 0
    for kw in keywords:
        if _check(f"ci:{kw}", kw in text, f"CI: {kw}"):
            ok += 1
    return ok


def check_claim_categories() -> int:
    if not POLICY_PATH.is_file():
        _check("categories:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    cats = ["compatibility", "security", "trust", "performance", "migration"]
    ok = 0
    for cat in cats:
        if _check(f"category:{cat}", cat in text, f"category: {cat}"):
            ok += 1
    return ok


def check_spec_acceptance_criteria() -> int:
    if not SPEC_PATH.is_file():
        _check("acceptance:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    keywords = ["claim registry", "content-addressed", "external-reproduction", "adversarial"]
    ok = 0
    for kw in keywords:
        if _check(f"acceptance:{kw}", kw in text, f"acceptance: {kw}"):
            ok += 1
    return ok


def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_verifiability_dimensions()
    check_quantitative_targets()
    check_event_codes()
    check_invariants()
    check_evidence_bundle_format()
    check_reproduction_protocol()
    check_adversarial_resilience()
    check_ci_integration()
    check_claim_categories()
    check_spec_acceptance_criteria()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-2a4l",
        "title": "Externally Verifiable Trust/Security Claims",
        "section": "13",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    assert callable(check_files_exist)
    assert callable(check_verifiability_dimensions)
    assert callable(check_event_codes)
    assert callable(check_invariants)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    assert result["bead_id"] == "bd-2a4l"
    assert isinstance(result["checks"], list)
    print("self_test: OK")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-2a4l Externally Verifiable Claims: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
