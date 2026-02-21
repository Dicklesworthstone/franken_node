#!/usr/bin/env python3
"""Verification script for bd-1ul: fuzz/adversarial tests for migration and shim logic.

Usage:
    python3 scripts/check_fuzz_testing.py              # human-readable
    python3 scripts/check_fuzz_testing.py --json        # machine-readable JSON
    python3 scripts/check_fuzz_testing.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

# ── Paths ────────────────────────────────────────────────────────────

SPEC = ROOT / "docs" / "specs" / "section_10_7" / "bd-1ul_contract.md"
POLICY = ROOT / "docs" / "policy" / "fuzz_adversarial_testing.md"
BUDGET_CONFIG = ROOT / "fuzz" / "config" / "fuzz_budget.toml"
CORPUS_MIGRATION = ROOT / "fuzz" / "corpus" / "migration"
CORPUS_SHIM = ROOT / "fuzz" / "corpus" / "shim"
REGRESSION_MIGRATION = ROOT / "fuzz" / "regression" / "migration"
REGRESSION_SHIM = ROOT / "fuzz" / "regression" / "shim"
COVERAGE_MIGRATION = ROOT / "fuzz" / "coverage" / "latest_migration.json"
COVERAGE_SHIM = ROOT / "fuzz" / "coverage" / "latest_shim.json"
EVIDENCE = ROOT / "artifacts" / "section_10_7" / "bd-1ul" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_7" / "bd-1ul" / "verification_summary.md"
TARGETS_DIR = ROOT / "fuzz" / "targets"

MIGRATION_TARGETS = [
    "migration_directory_scan.rs",
    "migration_package_parse.rs",
    "migration_dependency_resolve.rs",
]

SHIM_TARGETS = [
    "shim_api_translation.rs",
    "shim_type_coercion.rs",
]

EVENT_CODES = ["FZT-001", "FZT-002", "FZT-003", "FZT-004"]

INVARIANTS = [
    "INV-FZT-CORPUS",
    "INV-FZT-REGRESS",
    "INV-FZT-BUDGET",
    "INV-FZT-COVERAGE",
    "INV-FZT-TRIAGE",
]

SPEC_REQUIRED_CONTENT = (
    EVENT_CODES
    + INVARIANTS
    + [
        "fuzz_migration_directory_scan",
        "fuzz_migration_package_parse",
        "fuzz_migration_dependency_resolve",
        "fuzz_shim_api_translation",
        "fuzz_shim_type_coercion",
    ]
)

POLICY_REQUIRED_CONTENT = [
    "Corpus Management",
    "Regression Seed",
    "CI Gate",
    "Coverage Tracking",
    "Structured Logging",
]

RESULTS: list[dict[str, Any]] = []


# ── Helpers ──────────────────────────────────────────────────────────

def _safe_rel(path: Path) -> str:
    """Return a relative path string, guarding against non-ROOT paths."""
    s_path = str(path)
    s_root = str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file_exists: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _dir_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_dir()
    rel = _safe_rel(path)
    return _check(
        f"dir_exists: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _contains(path: Path, pattern: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: {pattern}", False, "file missing")
    content = path.read_text(encoding="utf-8")
    found = pattern in content
    return _check(
        f"{label}: {pattern}",
        found,
        "found" if found else "not found",
    )


def _count_files(directory: Path) -> int:
    """Count regular files in a directory (non-recursive)."""
    if not directory.is_dir():
        return 0
    return sum(1 for f in directory.iterdir() if f.is_file())


# ── Check functions ──────────────────────────────────────────────────

def check_spec_exists() -> None:
    _file_exists(SPEC, "spec contract")


def check_policy_exists() -> None:
    _file_exists(POLICY, "fuzz policy document")


def check_budget_config() -> None:
    _file_exists(BUDGET_CONFIG, "fuzz budget config")
    if BUDGET_CONFIG.is_file():
        text = BUDGET_CONFIG.read_text(encoding="utf-8")
        _check("budget_config: migration section", "[migration]" in text)
        _check("budget_config: shim section", "[shim]" in text)
        _check(
            "budget_config: min_seconds_per_target",
            "min_seconds_per_target" in text,
        )


def check_corpus_migration() -> None:
    _dir_exists(CORPUS_MIGRATION, "migration corpus directory")
    count = _count_files(CORPUS_MIGRATION)
    _check(
        "corpus_migration: seed count >= 50",
        count >= 50,
        f"{count} seeds (minimum 50)",
    )


def check_corpus_shim() -> None:
    _dir_exists(CORPUS_SHIM, "shim corpus directory")
    count = _count_files(CORPUS_SHIM)
    _check(
        "corpus_shim: seed count >= 50",
        count >= 50,
        f"{count} seeds (minimum 50)",
    )


def check_regression_migration() -> None:
    _dir_exists(REGRESSION_MIGRATION, "migration regression directory")
    count = _count_files(REGRESSION_MIGRATION)
    _check(
        "regression_migration: seed count >= 1",
        count >= 1,
        f"{count} regression seeds",
    )


def check_regression_shim() -> None:
    _dir_exists(REGRESSION_SHIM, "shim regression directory")
    count = _count_files(REGRESSION_SHIM)
    _check(
        "regression_shim: seed count >= 1",
        count >= 1,
        f"{count} regression seeds",
    )


def check_fuzz_targets() -> None:
    _dir_exists(TARGETS_DIR, "fuzz targets directory")
    for target in MIGRATION_TARGETS:
        path = TARGETS_DIR / target
        _file_exists(path, f"target: {target}")
    for target in SHIM_TARGETS:
        path = TARGETS_DIR / target
        _file_exists(path, f"target: {target}")


def check_target_test_coverage() -> None:
    """Verify each target file contains at least one #[test]."""
    all_targets = MIGRATION_TARGETS + SHIM_TARGETS
    for target in all_targets:
        path = TARGETS_DIR / target
        if not path.is_file():
            _check(f"target_tests: {target}", False, "target file missing")
            continue
        text = path.read_text(encoding="utf-8")
        import re
        test_count = len(re.findall(r"#\[test\]", text))
        _check(
            f"target_tests: {target}",
            test_count >= 2,
            f"{test_count} tests (minimum 2)",
        )


def check_coverage_reports() -> None:
    _file_exists(COVERAGE_MIGRATION, "migration coverage report")
    _file_exists(COVERAGE_SHIM, "shim coverage report")
    for label, path in [
        ("migration", COVERAGE_MIGRATION),
        ("shim", COVERAGE_SHIM),
    ]:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            _check(f"coverage_{label}: valid JSON", False, "parse error")
            continue
        _check(
            f"coverage_{label}: has event_code FZT-004",
            data.get("event_code") == "FZT-004",
            f"event_code={data.get('event_code')}",
        )
        pct = data.get("coverage_pct", 0)
        _check(
            f"coverage_{label}: coverage > 0%",
            pct > 0,
            f"coverage_pct={pct}",
        )
        _check(
            f"coverage_{label}: crashes_found field",
            "crashes_found" in data,
            "field present" if "crashes_found" in data else "field missing",
        )


def check_spec_content() -> None:
    if not SPEC.is_file():
        for item in SPEC_REQUIRED_CONTENT:
            _check(f"spec_content: {item}", False, "spec file missing")
        return
    text = SPEC.read_text(encoding="utf-8")
    for item in SPEC_REQUIRED_CONTENT:
        _check(
            f"spec_content: {item}",
            item in text,
            "found" if item in text else "not found in spec",
        )


def check_policy_content() -> None:
    if not POLICY.is_file():
        for item in POLICY_REQUIRED_CONTENT:
            _check(f"policy_content: {item}", False, "policy file missing")
        return
    text = POLICY.read_text(encoding="utf-8")
    for item in POLICY_REQUIRED_CONTENT:
        _check(
            f"policy_content: {item}",
            item in text,
            "found" if item in text else "not found in policy",
        )


def check_evidence_exists() -> None:
    _file_exists(EVIDENCE, "verification evidence")


def check_summary_exists() -> None:
    _file_exists(SUMMARY, "verification summary")


# ── Runner ───────────────────────────────────────────────────────────

def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_spec_exists()
    check_policy_exists()
    check_budget_config()
    check_corpus_migration()
    check_corpus_shim()
    check_regression_migration()
    check_regression_shim()
    check_fuzz_targets()
    check_target_test_coverage()
    check_coverage_reports()
    check_spec_content()
    check_policy_content()
    check_evidence_exists()
    check_summary_exists()

    passing = sum(1 for r in RESULTS if r["pass"])
    failing = sum(1 for r in RESULTS if not r["pass"])

    return {
        "bead_id": "bd-1ul",
        "title": "Fuzz and adversarial tests for migration and shim logic",
        "section": "10.7",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": list(RESULTS),
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    report = run_all()
    return report["overall_pass"], report["checks"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-1ul fuzz/adversarial testing implementation"
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        if args.json:
            print(json.dumps({"ok": ok, "checks": checks}, indent=2))
        else:
            passing = sum(1 for c in checks if c["pass"])
            print(f"self_test: {passing}/{len(checks)} checks pass")
            if not ok:
                for c in checks:
                    if not c["pass"]:
                        print(f"  FAIL: {c['check']} :: {c['detail']}")
        sys.exit(0 if ok else 1)

    report = run_all()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(
            f"\n{report['summary']['passing']}/{report['summary']['total']} checks pass "
            f"(verdict={report['verdict']})"
        )

    sys.exit(0 if report["overall_pass"] else 1)


if __name__ == "__main__":
    main()
