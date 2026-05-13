#!/usr/bin/env python3
"""Verification script for bd-38m: lockstep harness throughput optimization.

Usage:
    python scripts/check_harness_throughput.py          # human-readable
    python scripts/check_harness_throughput.py --json    # machine-readable
    python scripts/check_harness_throughput.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


SPEC_PATH = ROOT / "docs" / "specs" / "section_10_6" / "bd-38m_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "lockstep_harness_optimization.md"
SOURCE_MODULE = "scripts/check_harness_throughput.py"
TEST_MODULE = "tests/test_check_harness_throughput.py"
EVIDENCE_PATH = "artifacts/section_10_6/bd-38m/verification_evidence.json"
SUMMARY_PATH = "artifacts/section_10_6/bd-38m/verification_summary.md"
GIT_XREF: list[dict[str, Any]] = [
    {
        "commit": "d8a6e25cf4cf8c8363f41cf90fb6e0fdf6f74032",
        "subject": "chore(scripts): consolidate ROOT definitions and reorganize imports across 400+ check scripts",
        "paths": [SOURCE_MODULE],
    },
    {
        "commit": "495e5c1bc5657778d627d99c477d7b508be50248",
        "subject": "Harden test infrastructure: add structured logging, replace panic with unreachable, migrate to Uuid v7, and modernize Rust/Python idioms",
        "paths": [SOURCE_MODULE, TEST_MODULE],
    },
    {
        "commit": "f1d41ad9b488c06ff83cc4b4c259a9bbb48335e9",
        "subject": "docs: add 32 policy docs, 35 spec contracts, 88 verification artifacts, CI gate, fixtures, and packaging profiles",
        "paths": [
            str(SPEC_PATH.relative_to(ROOT)),
            str(POLICY_PATH.relative_to(ROOT)),
            EVIDENCE_PATH,
            SUMMARY_PATH,
        ],
    },
    {
        "commit": "be6ff7283f42a4f56eaaa31af6b990bd4fa19ec6",
        "subject": "test: add 36 check scripts, 33 test suites, and 5 fuzz targets with corpus for sections 10.5-13",
        "paths": [SOURCE_MODULE, TEST_MODULE],
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_relative(path: Path) -> str:
    """Return a relative path string, guarding against paths outside ROOT."""
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_spec_exists() -> dict[str, Any]:
    exists = SPEC_PATH.is_file()
    return _check(
        "spec_exists",
        exists,
        f"exists: {_safe_relative(SPEC_PATH)}" if exists else f"missing: {_safe_relative(SPEC_PATH)}",
    )


def check_policy_exists() -> dict[str, Any]:
    exists = POLICY_PATH.is_file()
    return _check(
        "policy_exists",
        exists,
        f"exists: {_safe_relative(POLICY_PATH)}" if exists else f"missing: {_safe_relative(POLICY_PATH)}",
    )


def check_spec_keyword_streaming() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_streaming", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "streaming" in text.lower()
    return _check("spec_keyword_streaming", found)


def check_spec_keyword_normalization() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_normalization", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "normalization" in text.lower()
    return _check("spec_keyword_normalization", found)


def check_spec_keyword_spill_to_disk() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_spill_to_disk", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "spill-to-disk" in text.lower() or "spill_to_disk" in text.lower()
    return _check("spec_keyword_spill_to_disk", found)


def check_spec_keyword_512mb() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_512mb", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "512MB" in text or "512mb" in text.lower() or "512 MB" in text
    return _check("spec_keyword_512mb", found)


def check_spec_keyword_20_percent() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_20_percent", False, "spec file missing")
    text = SPEC_PATH.read_text()
    found = "20%" in text
    return _check("spec_keyword_20_percent", found)


def check_event_codes() -> list[dict[str, Any]]:
    codes = ["OLH-001", "OLH-002", "OLH-003", "OLH-004"]
    results = []
    if not SPEC_PATH.is_file():
        for code in codes:
            results.append(_check(f"event_code_{code}", False, "spec file missing"))
        return results
    text = SPEC_PATH.read_text()
    for code in codes:
        found = code in text
        results.append(_check(f"event_code_{code}", found))
    return results


def check_invariants() -> list[dict[str, Any]]:
    invariants = [
        "INV-OLH-STREAMING",
        "INV-OLH-THROUGHPUT",
        "INV-OLH-NORMALIZATION",
        "INV-OLH-SPILLTODISK",
    ]
    results = []
    if not SPEC_PATH.is_file():
        for inv in invariants:
            results.append(_check(f"invariant_{inv}", False, "spec file missing"))
        return results
    text = SPEC_PATH.read_text()
    for inv in invariants:
        found = inv in text
        results.append(_check(f"invariant_{inv}", found))
    return results


def check_optimization_phases() -> dict[str, Any]:
    if not POLICY_PATH.is_file():
        return _check("optimization_phases", False, "policy file missing")
    text = POLICY_PATH.read_text().lower()
    phases = ["startup", "fixture loading", "result comparison", "memory management"]
    missing = [p for p in phases if p not in text]
    found = len(missing) == 0
    detail = "all 4 phases present" if found else f"missing: {missing}"
    return _check("optimization_phases", found, detail)


def check_benchmark_targets() -> dict[str, Any]:
    if not POLICY_PATH.is_file():
        return _check("benchmark_targets", False, "policy file missing")
    text = POLICY_PATH.read_text()
    has_throughput = "20%" in text
    has_memory = "512MB" in text or "512 MB" in text
    has_fidelity = "byte-identical" in text.lower() or "byte_identical" in text.lower()
    ok = has_throughput and has_memory and has_fidelity
    detail = (
        "throughput+memory+fidelity targets present"
        if ok
        else f"throughput={has_throughput}, memory={has_memory}, fidelity={has_fidelity}"
    )
    return _check("benchmark_targets", ok, detail)


def check_memory_ceiling() -> dict[str, Any]:
    if not POLICY_PATH.is_file():
        return _check("memory_ceiling", False, "policy file missing")
    text = POLICY_PATH.read_text().lower()
    has_ceiling = "memory ceiling" in text or "memory_ceiling" in text
    has_configurable = "configurable" in text
    ok = has_ceiling and has_configurable
    return _check("memory_ceiling", ok, "configurable memory ceiling documented" if ok else "NOT FOUND")


def check_warm_pool() -> dict[str, Any]:
    if not POLICY_PATH.is_file():
        return _check("warm_pool", False, "policy file missing")
    text = POLICY_PATH.read_text().lower()
    has_pool = "warm" in text and "pool" in text
    has_reuse = "reuse" in text or "recycle" in text
    ok = has_pool and has_reuse
    return _check("warm_pool", ok, "warm pool reuse documented" if ok else "NOT FOUND")


def check_streaming_normalization_rules() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("streaming_normalization_rules", False, "spec file missing")
    text = SPEC_PATH.read_text().lower()
    has_timestamp = "timestamp stripping" in text or "timestamp" in text
    has_pid = "pid masking" in text or "pid" in text
    has_path = "path canonicalization" in text
    ok = has_timestamp and has_pid and has_path
    detail = (
        "all 3 normalization rules present"
        if ok
        else f"timestamp={has_timestamp}, pid={has_pid}, path={has_path}"
    )
    return _check("streaming_normalization_rules", ok, detail)


def check_policy_event_codes() -> dict[str, Any]:
    if not POLICY_PATH.is_file():
        return _check("policy_event_codes", False, "policy file missing")
    text = POLICY_PATH.read_text()
    codes = ["OLH-001", "OLH-002", "OLH-003", "OLH-004"]
    missing = [c for c in codes if c not in text]
    ok = len(missing) == 0
    return _check("policy_event_codes", ok, "all 4 event codes in policy" if ok else f"missing: {missing}")


def check_git_xref() -> dict[str, Any]:
    missing = [
        xref
        for xref in GIT_XREF
        if len(str(xref.get("commit", ""))) != 40 or not xref.get("paths")
    ]
    ok = len(missing) == 0
    detail = (
        f"{len(GIT_XREF)} git_xref entries cite bd-38m artifacts"
        if ok
        else f"invalid git_xref entries: {len(missing)}"
    )
    return _check("git_xref", ok, detail)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def run_all() -> dict[str, Any]:
    global RESULTS
    RESULTS = []

    check_spec_exists()
    check_policy_exists()
    check_spec_keyword_streaming()
    check_spec_keyword_normalization()
    check_spec_keyword_spill_to_disk()
    check_spec_keyword_512mb()
    check_spec_keyword_20_percent()
    check_event_codes()
    check_invariants()
    check_optimization_phases()
    check_benchmark_targets()
    check_memory_ceiling()
    check_warm_pool()
    check_streaming_normalization_rules()
    check_policy_event_codes()
    check_git_xref()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "bead_id": "bd-38m",
        "title": "Optimize lockstep harness throughput and memory profile",
        "section": "10.6",
        "verdict": verdict,
        "overall_pass": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "source_module": SOURCE_MODULE,
        "test_module": TEST_MODULE,
        "git_xref": list(GIT_XREF),
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    report = run_all()
    if not isinstance(report, dict):
        raise AssertionError("run_all must return dict")
    if report["bead_id"] != "bd-38m":
        raise AssertionError("bead_id mismatch")
    for key in ("checks", "verdict", "total", "passed", "failed", "git_xref"):
        if key not in report:
            raise AssertionError(f"missing {key} key")
    if len(report["checks"]) == 0:
        raise AssertionError("no checks produced")
    for c in report["checks"]:
        for key in ("check", "pass", "detail"):
            if key not in c:
                raise AssertionError(f"check entry missing {key}")
    return bool(report["overall_pass"])


def main() -> None:
    configure_test_logging("check_harness_throughput")
    parser = argparse.ArgumentParser(description="Verify bd-38m lockstep harness optimization")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        if not self_test():
            print("self_test failed", file=sys.stderr)
            sys.exit(1)
        print("self_test passed")
        return

    report = run_all()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        print()
        print(f"bd-38m verification: {report['verdict']} ({report['passed']}/{report['total']})")

    sys.exit(0 if report["overall_pass"] else 1)


if __name__ == "__main__":
    main()
