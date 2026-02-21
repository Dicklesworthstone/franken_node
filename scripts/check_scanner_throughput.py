#!/usr/bin/env python3
"""Verification script for bd-2q5: Optimize migration scanner throughput for large monorepos.

Usage:
    python scripts/check_scanner_throughput.py          # human-readable
    python scripts/check_scanner_throughput.py --json    # machine-readable
    python scripts/check_scanner_throughput.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_10_6" / "bd-2q5_contract.md"
POLICY = ROOT / "docs" / "policy" / "scanner_throughput_optimization.md"

RESULTS: list[dict[str, Any]] = []

EVENT_CODES = ["OMS-001", "OMS-002", "OMS-003", "OMS-004"]

INVARIANTS = ["INV-OMS-HASH", "INV-OMS-BATCH", "INV-OMS-TTL", "INV-OMS-SCALE"]

SPEC_KEYWORDS = [
    "incremental",
    "parallel",
    "deterministic",
    "cache",
    "TTL",
    "hash",
]

OPTIMIZATION_STRATEGIES = [
    "Incremental scanning",
    "Parallel file processing",
    "Cache reuse",
]

BENCHMARK_TARGETS = [
    "wall-clock",
    "files/second",
    "cache hit ratio",
    "peak memory",
]


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    """Record a single check result."""
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    """Return a relative path string if path is under ROOT, else absolute."""
    try:
        if str(path).startswith(str(ROOT)):
            return str(path.relative_to(ROOT))
    except ValueError:
        pass
    return str(path)


def check_spec_exists() -> dict[str, Any]:
    """Check that the spec contract file exists."""
    exists = SPEC.is_file()
    rel = _safe_rel(SPEC)
    return _check(
        "spec_exists",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def check_policy_exists() -> dict[str, Any]:
    """Check that the policy document exists."""
    exists = POLICY.is_file()
    rel = _safe_rel(POLICY)
    return _check(
        "policy_exists",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def check_spec_keyword(keyword: str) -> dict[str, Any]:
    """Check that a keyword appears in the spec document."""
    if not SPEC.is_file():
        return _check(f"spec_keyword: {keyword}", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    found = keyword.lower() in content.lower()
    return _check(
        f"spec_keyword: {keyword}",
        found,
        "found" if found else "not found in spec",
    )


def check_event_code(code: str) -> dict[str, Any]:
    """Check that an event code appears in the spec."""
    if not SPEC.is_file():
        return _check(f"event_code: {code}", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    found = code in content
    return _check(
        f"event_code: {code}",
        found,
        "found" if found else "not found in spec",
    )


def check_invariant(inv: str) -> dict[str, Any]:
    """Check that an invariant appears in the spec."""
    if not SPEC.is_file():
        return _check(f"invariant: {inv}", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    found = inv in content
    return _check(
        f"invariant: {inv}",
        found,
        "found" if found else "not found in spec",
    )


def check_policy_strategy(strategy: str) -> dict[str, Any]:
    """Check that an optimization strategy is documented in the policy."""
    if not POLICY.is_file():
        return _check(f"policy_strategy: {strategy}", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    found = strategy.lower() in content.lower()
    return _check(
        f"policy_strategy: {strategy}",
        found,
        "found" if found else "not found in policy",
    )


def check_policy_benchmark_target(target: str) -> dict[str, Any]:
    """Check that a benchmark target metric is documented in the policy."""
    if not POLICY.is_file():
        return _check(f"benchmark_target: {target}", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    found = target.lower() in content.lower()
    return _check(
        f"benchmark_target: {target}",
        found,
        "found" if found else "not found in policy",
    )


def check_spec_quantitative_targets() -> dict[str, Any]:
    """Check that the spec contains quantitative performance targets."""
    if not SPEC.is_file():
        return _check("quantitative_targets", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    has_10_percent = "10%" in content
    has_3x = "3.0x" in content
    has_7_days = "7 days" in content
    all_present = has_10_percent and has_3x and has_7_days
    detail_parts = []
    if has_10_percent:
        detail_parts.append("10% threshold")
    if has_3x:
        detail_parts.append("3.0x speedup")
    if has_7_days:
        detail_parts.append("7-day TTL")
    return _check(
        "quantitative_targets",
        all_present,
        ", ".join(detail_parts) if detail_parts else "no targets found",
    )


def check_spec_cache_path() -> dict[str, Any]:
    """Check that the spec references the scan cache path."""
    if not SPEC.is_file():
        return _check("cache_path", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    found = "scan_cache.json" in content
    return _check(
        "cache_path",
        found,
        "scan_cache.json referenced" if found else "scan_cache.json not found",
    )


def check_spec_clear_cache_flag() -> dict[str, Any]:
    """Check that the spec documents the --clear-cache flag."""
    if not SPEC.is_file():
        return _check("clear_cache_flag", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    found = "--clear-cache" in content
    return _check(
        "clear_cache_flag",
        found,
        "found" if found else "--clear-cache not documented",
    )


def check_policy_cache_versioning() -> dict[str, Any]:
    """Check that the policy documents cache format versioning."""
    if not POLICY.is_file():
        return _check("cache_versioning", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    found = "version" in content.lower() and "1.0" in content
    return _check(
        "cache_versioning",
        found,
        "found" if found else "cache versioning not documented",
    )


def check_policy_workers_flag() -> dict[str, Any]:
    """Check that the policy documents the --workers flag."""
    if not POLICY.is_file():
        return _check("workers_flag", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    found = "--workers" in content
    return _check(
        "workers_flag",
        found,
        "found" if found else "--workers not documented",
    )


def check_policy_synthetic_fixture() -> dict[str, Any]:
    """Check that the policy documents the synthetic monorepo fixture."""
    if not POLICY.is_file():
        return _check("synthetic_fixture", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    found = "10,000" in content or "10000" in content or "10k" in content.lower()
    return _check(
        "synthetic_fixture",
        found,
        "found" if found else "synthetic fixture (10k+ files) not documented",
    )


def run_all() -> dict[str, Any]:
    """Run all checks and return the full report."""
    global RESULTS
    RESULTS = []

    # File existence
    check_spec_exists()
    check_policy_exists()

    # Spec keywords
    for kw in SPEC_KEYWORDS:
        check_spec_keyword(kw)

    # Event codes
    for code in EVENT_CODES:
        check_event_code(code)

    # Invariants
    for inv in INVARIANTS:
        check_invariant(inv)

    # Policy optimization strategies
    for strategy in OPTIMIZATION_STRATEGIES:
        check_policy_strategy(strategy)

    # Benchmark targets
    for target in BENCHMARK_TARGETS:
        check_policy_benchmark_target(target)

    # Quantitative targets
    check_spec_quantitative_targets()

    # Cache path
    check_spec_cache_path()

    # --clear-cache flag
    check_spec_clear_cache_flag()

    # Cache versioning
    check_policy_cache_versioning()

    # --workers flag
    check_policy_workers_flag()

    # Synthetic fixture
    check_policy_synthetic_fixture()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-2q5",
        "title": "Optimize migration scanner throughput for large monorepos",
        "section": "10.6",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "overall_pass": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    """Run all checks and return (ok, checks)."""
    report = run_all()
    ok = report["overall_pass"]
    return ok, report["checks"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-2q5: scanner throughput optimization"
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
            f"\n{report['passed']}/{report['total']} checks pass "
            f"(verdict={report['verdict']})"
        )

    sys.exit(0 if report["overall_pass"] else 1)


if __name__ == "__main__":
    main()
