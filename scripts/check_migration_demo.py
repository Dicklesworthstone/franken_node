#!/usr/bin/env python3
"""Verification script for bd-1e0: Migration Singularity Demo Pipeline.

Checks that the spec, policy, and fixture documents define all required
pipeline stages, event codes, invariants, flagship repository criteria,
confidence grading, rollback policy, evidence integrity, and reproducibility.

Usage:
    python scripts/check_migration_demo.py [--json] [--self-test]
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_9" / "bd-1e0_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "migration_singularity_demo.md"
FIXTURES_DIR = ROOT / "fixtures" / "migration-demos"

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str = "") -> bool:
    RESULTS.append({"name": name, "pass": passed, "detail": detail})
    return passed


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_files_exist() -> int:
    ok = 0
    if _check("file_exists:spec", SPEC_PATH.is_file(),
              f"spec at {_safe_rel(SPEC_PATH)}"):
        ok += 1
    if _check("file_exists:policy", POLICY_PATH.is_file(),
              f"policy at {_safe_rel(POLICY_PATH)}"):
        ok += 1
    if _check("file_exists:fixtures_dir", FIXTURES_DIR.is_dir(),
              f"fixtures at {_safe_rel(FIXTURES_DIR)}"):
        ok += 1
    return ok


def check_flagship_configs() -> int:
    """Check that at least three flagship repo configs exist and are valid."""
    ok = 0
    if not FIXTURES_DIR.is_dir():
        _check("flagship:directory", False, "fixtures dir missing")
        return 0

    configs = sorted(FIXTURES_DIR.glob("*.json"))
    if not _check("flagship:min_three_configs", len(configs) >= 3,
                   f"{len(configs)} config(s) found"):
        return 0
    ok += 1

    required_keys = [
        "name", "category", "repository_url", "pinned_version",
        "pipeline_timeout_seconds", "rollback_test_pass_threshold_percent",
    ]
    categories_seen = set()

    for cfg_path in configs:
        label = cfg_path.stem
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            _check(f"flagship:{label}:valid_json", False, str(exc))
            continue

        all_keys = all(k in data for k in required_keys)
        if _check(f"flagship:{label}:required_keys", all_keys,
                   f"keys present in {_safe_rel(cfg_path)}"):
            ok += 1

        cat = data.get("category", "")
        if cat:
            categories_seen.add(cat)

    distinct = len(categories_seen) >= 3
    if _check("flagship:distinct_categories", distinct,
              f"{len(categories_seen)} categories: {sorted(categories_seen)}"):
        ok += 1

    return ok


def check_pipeline_stages() -> int:
    """Verify all six pipeline stages are documented in the spec."""
    if not SPEC_PATH.is_file():
        _check("stages:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8")
    stages = ["Discovery", "Analysis", "Migration Plan Generation",
              "Execution", "Validation", "Rollback"]
    ok = 0
    for stage in stages:
        if _check(f"stage:{stage}", stage in text, f"stage '{stage}' in spec"):
            ok += 1
    return ok


def check_stage_outputs() -> int:
    """Verify that structured output artifacts are defined for each stage."""
    if not SPEC_PATH.is_file():
        _check("outputs:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8")
    outputs = [
        "discovery_manifest.json",
        "analysis_report.json",
        "migration_plan.json",
        "execution_log.json",
        "validation_report.json",
        "rollback_report.json",
    ]
    ok = 0
    for out in outputs:
        if _check(f"output:{out}", out in text, f"output '{out}' in spec"):
            ok += 1
    return ok


def check_event_codes() -> int:
    """Verify all four event codes are defined in the spec."""
    if not SPEC_PATH.is_file():
        _check("event_codes:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8")
    codes = ["MSD-001", "MSD-002", "MSD-003", "MSD-004"]
    ok = 0
    for code in codes:
        if _check(f"event_code:{code}", code in text, code):
            ok += 1
    return ok


def check_invariants() -> int:
    """Verify all four invariants are defined in the spec."""
    if not SPEC_PATH.is_file():
        _check("invariants:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8")
    invs = [
        "INV-MSD-PIPELINE",
        "INV-MSD-VALIDATION",
        "INV-MSD-ROLLBACK",
        "INV-MSD-ARTIFACTS",
    ]
    ok = 0
    for inv in invs:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_error_codes() -> int:
    """Verify error codes are defined in the spec."""
    if not SPEC_PATH.is_file():
        _check("error_codes:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8")
    codes = [
        "ERR-MSD-CLONE-FAIL",
        "ERR-MSD-ANALYSIS-TIMEOUT",
        "ERR-MSD-TRANSFORM-CONFLICT",
        "ERR-MSD-VALIDATION-TIMEOUT",
        "ERR-MSD-ROLLBACK-INCOMPLETE",
    ]
    ok = 0
    for code in codes:
        if _check(f"error_code:{code}", code in text, code):
            ok += 1
    return ok


def check_confidence_grades() -> int:
    """Verify confidence grading is defined in spec and policy."""
    ok = 0
    for label, path in [("spec", SPEC_PATH), ("policy", POLICY_PATH)]:
        if not path.is_file():
            _check(f"confidence:{label}:present", False, f"{label} missing")
            continue
        text = path.read_text(encoding="utf-8").lower()
        for grade in ["high", "medium", "low"]:
            if _check(f"confidence:{label}:{grade}", grade in text,
                       f"grade '{grade}' in {label}"):
                ok += 1
    return ok


def check_rollback_policy() -> int:
    """Verify rollback policy details in the policy doc."""
    if not POLICY_PATH.is_file():
        _check("rollback:present", False, "policy missing")
        return 0

    text = POLICY_PATH.read_text(encoding="utf-8").lower()
    keywords = [
        "automatic rollback",
        "test pass rate",
        "rollback completeness",
        "partial rollback",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"rollback:{kw}", kw in text, f"rollback: {kw}"):
            ok += 1
    return ok


def check_reproducibility() -> int:
    """Verify reproducibility requirements are defined."""
    ok = 0
    for label, path in [("spec", SPEC_PATH), ("policy", POLICY_PATH)]:
        if not path.is_file():
            _check(f"reproducibility:{label}:present", False,
                   f"{label} missing")
            continue
        text = path.read_text(encoding="utf-8").lower()
        keywords = ["hermetic", "pinned", "reproducib"]
        for kw in keywords:
            if _check(f"reproducibility:{label}:{kw}", kw in text,
                       f"'{kw}' in {label}"):
                ok += 1
    return ok


def check_evidence_integrity() -> int:
    """Verify evidence integrity (SHA-256, manifest) requirements."""
    ok = 0
    for label, path in [("spec", SPEC_PATH), ("policy", POLICY_PATH)]:
        if not path.is_file():
            _check(f"integrity:{label}:present", False, f"{label} missing")
            continue
        text = path.read_text(encoding="utf-8").lower()
        keywords = ["sha-256", "integrity", "manifest"]
        for kw in keywords:
            if _check(f"integrity:{label}:{kw}", kw in text,
                       f"'{kw}' in {label}"):
                ok += 1
    return ok


def check_before_after_evidence() -> int:
    """Verify before/after comparison dimensions are specified."""
    if not SPEC_PATH.is_file():
        _check("before_after:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8").lower()
    dims = ["test pass rate", "startup time", "request throughput",
            "memory usage", "security posture"]
    ok = 0
    for dim in dims:
        if _check(f"before_after:{dim}", dim in text,
                   f"dimension '{dim}' in spec"):
            ok += 1
    return ok


def check_timeline() -> int:
    """Verify migration timeline targets are specified."""
    if not SPEC_PATH.is_file():
        _check("timeline:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8").lower()
    keywords = ["< 10 min", "< 30s", "< 120s", "< 300s"]
    ok = 0
    for kw in keywords:
        if _check(f"timeline:{kw}", kw in text, f"timeline target '{kw}'"):
            ok += 1
    return ok


def check_acceptance_criteria() -> int:
    """Verify acceptance criteria section exists with key items."""
    if not SPEC_PATH.is_file():
        _check("acceptance:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8").lower()
    keywords = [
        "single command",
        "structured output",
        "confidence grades",
        "reproducible",
        "publication",
        "gracefully",
        "under 10 minutes",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"acceptance:{kw}", kw in text,
                   f"acceptance: '{kw}'"):
            ok += 1
    return ok


def check_policy_event_logging() -> int:
    """Verify event logging policy section in policy doc."""
    if not POLICY_PATH.is_file():
        _check("logging:present", False, "policy missing")
        return 0

    text = POLICY_PATH.read_text(encoding="utf-8")
    codes = ["MSD-001", "MSD-002", "MSD-003", "MSD-004"]
    ok = 0
    for code in codes:
        if _check(f"logging:{code}", code in text,
                   f"event code {code} in policy"):
            ok += 1
    return ok


def check_policy_invariants() -> int:
    """Verify invariants are referenced in the policy doc."""
    if not POLICY_PATH.is_file():
        _check("policy_inv:present", False, "policy missing")
        return 0

    text = POLICY_PATH.read_text(encoding="utf-8")
    invs = [
        "INV-MSD-PIPELINE",
        "INV-MSD-VALIDATION",
        "INV-MSD-ROLLBACK",
        "INV-MSD-ARTIFACTS",
    ]
    ok = 0
    for inv in invs:
        if _check(f"policy_inv:{inv}", inv in text,
                   f"invariant {inv} in policy"):
            ok += 1
    return ok


def check_flagship_criteria() -> int:
    """Verify flagship repository qualification criteria in spec."""
    if not SPEC_PATH.is_file():
        _check("criteria:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8").lower()
    criteria = [
        "10,000",
        "500,000",
        "test coverage",
        "active maintenance",
    ]
    ok = 0
    for c in criteria:
        if _check(f"criteria:{c}", c in text, f"criterion '{c}' in spec"):
            ok += 1
    return ok


def check_compatibility_report() -> int:
    """Verify compatibility/migration report requirements in spec."""
    if not SPEC_PATH.is_file():
        _check("report:present", False, "spec missing")
        return 0

    text = SPEC_PATH.read_text(encoding="utf-8").lower()
    keywords = [
        "executive summary",
        "detailed findings",
        "before/after",
        "confidence assessment",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"report:{kw}", kw in text, f"report: '{kw}'"):
            ok += 1
    return ok


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_flagship_configs()
    check_pipeline_stages()
    check_stage_outputs()
    check_event_codes()
    check_invariants()
    check_error_codes()
    check_confidence_grades()
    check_rollback_policy()
    check_reproducibility()
    check_evidence_integrity()
    check_before_after_evidence()
    check_timeline()
    check_acceptance_criteria()
    check_policy_event_logging()
    check_policy_invariants()
    check_flagship_criteria()
    check_compatibility_report()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-1e0",
        "title": "Migration Singularity Demo Pipeline",
        "section": "10.9",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test():
    assert callable(check_files_exist)
    assert callable(check_pipeline_stages)
    assert callable(check_event_codes)
    assert callable(check_invariants)
    assert callable(check_flagship_configs)
    assert callable(check_rollback_policy)
    assert callable(check_reproducibility)
    assert callable(check_evidence_integrity)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    assert result["bead_id"] == "bd-1e0"
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
        print(f"bd-1e0 Migration Singularity Demo: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
