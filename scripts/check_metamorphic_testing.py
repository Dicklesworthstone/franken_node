#!/usr/bin/env python3
"""Verification script for bd-1u4: Metamorphic tests for compatibility invariants.

Checks that the spec and policy documents define all required metamorphic
relations, event codes, invariants, test generation strategy, equivalence
oracle design, corpus requirements, violation reporting, and CI integration.

Usage:
    python scripts/check_metamorphic_testing.py          # human-readable
    python scripts/check_metamorphic_testing.py --json    # machine-readable
    python scripts/check_metamorphic_testing.py --self-test
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_7" / "bd-1u4_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "metamorphic_testing.md"

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str = "") -> bool:
    RESULTS.append({"name": name, "pass": passed, "detail": detail})
    return passed


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# ── Check group 1: File existence ──────────────────────────────────────

def check_files_exist() -> int:
    ok = 0
    if _check("file_exists:spec", SPEC_PATH.is_file(),
              f"spec at {_safe_rel(SPEC_PATH)}"):
        ok += 1
    if _check("file_exists:policy", POLICY_PATH.is_file(),
              f"policy at {_safe_rel(POLICY_PATH)}"):
        ok += 1
    return ok


# ── Check group 2: Metamorphic relations in spec ──────────────────────

def check_metamorphic_relations() -> int:
    if not SPEC_PATH.is_file():
        _check("relations:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    relations = ["MR-EQUIV", "MR-MONO", "MR-IDEM", "MR-COMM"]
    ok = 0
    for r in relations:
        if _check(f"relation:{r}", r in text, f"{r} in spec"):
            ok += 1
    return ok


# ── Check group 3: Event codes in spec ────────────────────────────────

def check_event_codes() -> int:
    if not SPEC_PATH.is_file():
        _check("event_codes:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    codes = ["MMT-001", "MMT-002", "MMT-003", "MMT-004"]
    ok = 0
    for c in codes:
        if _check(f"event_code:{c}", c in text, c):
            ok += 1
    return ok


# ── Check group 4: Invariants in spec ─────────────────────────────────

def check_invariants() -> int:
    if not SPEC_PATH.is_file():
        _check("invariants:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    invs = [
        "INV-MMT-RELATIONS",
        "INV-MMT-CORPUS",
        "INV-MMT-PLUGGABLE",
        "INV-MMT-REPORT",
    ]
    ok = 0
    for inv in invs:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


# ── Check group 5: Error codes in spec ────────────────────────────────

def check_error_codes() -> int:
    if not SPEC_PATH.is_file():
        _check("error_codes:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    codes = [
        "ERR_MMT_CORPUS_EMPTY",
        "ERR_MMT_RELATION_INVALID",
        "ERR_MMT_TRANSFORM_FAILED",
        "ERR_MMT_EXECUTION_TIMEOUT",
    ]
    ok = 0
    for c in codes:
        if _check(f"error_code:{c}", c in text, c):
            ok += 1
    return ok


# ── Check group 6: Equivalence oracle design in policy ────────────────

def check_oracle_design() -> int:
    if not POLICY_PATH.is_file():
        _check("oracle:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["oracle-free", "normalization", "canonicalize", "divergence"]
    ok = 0
    for kw in keywords:
        if _check(f"oracle:{kw}", kw in text, f"oracle design: {kw}"):
            ok += 1
    return ok


# ── Check group 7: Test generation strategy in policy ─────────────────

def check_generation_strategy() -> int:
    if not POLICY_PATH.is_file():
        _check("generation:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["base input", "transformation", "corpus", "extensibility"]
    ok = 0
    for kw in keywords:
        if _check(f"generation:{kw}", kw in text, f"generation: {kw}"):
            ok += 1
    return ok


# ── Check group 8: Violation reporting in policy ──────────────────────

def check_violation_reporting() -> int:
    if not POLICY_PATH.is_file():
        _check("violation:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    fields = [
        "base_input",
        "transformation",
        "expected_relation",
        "original_output",
        "followup_output",
        "divergence_point",
        "severity",
    ]
    ok = 0
    for f in fields:
        if _check(f"violation_field:{f}", f in text,
                  f"violation report field: {f}"):
            ok += 1
    return ok


# ── Check group 9: CI integration in policy ───────────────────────────

def check_ci_integration() -> int:
    if not POLICY_PATH.is_file():
        _check("ci:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["gate", "95%", "blocking", "structured logging"]
    ok = 0
    for kw in keywords:
        if _check(f"ci:{kw}", kw in text, f"CI: {kw}"):
            ok += 1
    return ok


# ── Check group 10: Corpus requirements in policy ─────────────────────

def check_corpus_requirements() -> int:
    if not POLICY_PATH.is_file():
        _check("corpus:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["api_usage", "migration", "policy", "edge_case", "100 inputs"]
    ok = 0
    for kw in keywords:
        if _check(f"corpus:{kw}", kw in text, f"corpus: {kw}"):
            ok += 1
    return ok


# ── Check group 11: Comparison modes in policy ────────────────────────

def check_comparison_modes() -> int:
    if not POLICY_PATH.is_file():
        _check("comparison:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    modes = ["strict", "structural", "subset", "set_equal"]
    ok = 0
    for m in modes:
        if _check(f"comparison_mode:{m}", m in text,
                  f"comparison mode: {m}"):
            ok += 1
    return ok


# ── Check group 12: Acceptance criteria in spec ───────────────────────

def check_acceptance_criteria() -> int:
    if not SPEC_PATH.is_file():
        _check("acceptance:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    keywords = [
        "pluggable",
        "100 inputs",
        "violation report",
        "ci gate",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"acceptance:{kw}", kw in text, f"acceptance: {kw}"):
            ok += 1
    return ok


# ── Check group 13: Relation descriptions in spec ─────────────────────

def check_relation_descriptions() -> int:
    if not SPEC_PATH.is_file():
        _check("relation_desc:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text().lower()
    descriptions = [
        "equivalence relation",
        "monotonicity relation",
        "idempotency relation",
        "commutativity relation",
    ]
    ok = 0
    for d in descriptions:
        if _check(f"relation_desc:{d}", d in text, f"relation: {d}"):
            ok += 1
    return ok


# ── Check group 14: Severity classification in policy ─────────────────

def check_severity_classification() -> int:
    if not POLICY_PATH.is_file():
        _check("severity:present", False, "policy missing")
        return 0
    text = POLICY_PATH.read_text().lower()
    keywords = ["blocking", "degraded", "triage"]
    ok = 0
    for kw in keywords:
        if _check(f"severity:{kw}", kw in text, f"severity: {kw}"):
            ok += 1
    return ok


# ── Check group 15: Pluggable interface in spec ───────────────────────

def check_pluggable_interface() -> int:
    if not SPEC_PATH.is_file():
        _check("pluggable:present", False, "spec missing")
        return 0
    text = SPEC_PATH.read_text()
    keywords = [
        "MetamorphicRelation",
        "transform",
        "validate",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"pluggable:{kw}", kw in text,
                  f"pluggable interface: {kw}"):
            ok += 1
    return ok


# ── Runners ───────────────────────────────────────────────────────────

def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_metamorphic_relations()
    check_event_codes()
    check_invariants()
    check_error_codes()
    check_oracle_design()
    check_generation_strategy()
    check_violation_reporting()
    check_ci_integration()
    check_corpus_requirements()
    check_comparison_modes()
    check_acceptance_criteria()
    check_relation_descriptions()
    check_severity_classification()
    check_pluggable_interface()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-1u4",
        "title": "Metamorphic tests for compatibility invariants",
        "section": "10.7",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    assert callable(check_files_exist)
    assert callable(check_metamorphic_relations)
    assert callable(check_event_codes)
    assert callable(check_invariants)
    assert callable(check_error_codes)
    assert callable(check_oracle_design)
    assert callable(check_generation_strategy)
    assert callable(check_violation_reporting)
    assert callable(check_ci_integration)
    assert callable(check_corpus_requirements)
    assert callable(check_comparison_modes)
    assert callable(check_acceptance_criteria)
    assert callable(check_relation_descriptions)
    assert callable(check_severity_classification)
    assert callable(check_pluggable_interface)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    assert result["bead_id"] == "bd-1u4"
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
        print(f"bd-1u4 Metamorphic Testing: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
