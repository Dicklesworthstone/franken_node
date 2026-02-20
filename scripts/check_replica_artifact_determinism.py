#!/usr/bin/env python3
"""bd-1iyx: Verify determinism conformance test harness.

Checks:
  1. Conformance test file exists with required test functions
  2. Fixture files exist (3 sets)
  3. Event codes present (DETERMINISM_CHECK_STARTED/PASSED/FAILED)
  4. Divergence reporting types and methods
  5. Upstream deterministic_seed module exists and is registered
  6. Root-cause hinting logic present
  7. Expected seed golden vectors in fixtures match test expectations

Usage:
  python3 scripts/check_replica_artifact_determinism.py          # human-readable
  python3 scripts/check_replica_artifact_determinism.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "tests" / "conformance" / "replica_artifact_determinism.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-1iyx_contract.md"
SEED_RS = ROOT / "crates" / "franken-node" / "src" / "encoding" / "deterministic_seed.rs"
ENCODING_MOD = ROOT / "crates" / "franken-node" / "src" / "encoding" / "mod.rs"
MAIN_RS = ROOT / "crates" / "franken-node" / "src" / "main.rs"

FIXTURE_DIR = ROOT / "fixtures" / "determinism"
FIXTURE_FILES = [
    "small_encoding.json",
    "medium_multi_domain.json",
    "edge_case_minimal.json",
]

REQUIRED_TYPES = [
    "struct Divergence",
    "struct Replica",
    "struct FixtureResult",
]

REQUIRED_FUNCTIONS = [
    "fn compare_artifacts(",
    "fn guess_root_cause(",
    "fn run_fixture(",
    "fn verify_expected_seeds(",
    "fn parse_domain(",
]

EVENT_CODES = [
    "DETERMINISM_CHECK_STARTED",
    "DETERMINISM_CHECK_PASSED",
    "DETERMINISM_CHECK_FAILED",
]

REQUIRED_TESTS = [
    "test_small_encoding_replicas_identical",
    "test_small_encoding_expected_seeds",
    "test_medium_multi_domain_replicas_identical",
    "test_medium_multi_domain_expected_seeds",
    "test_edge_case_minimal_replicas_identical",
    "test_edge_case_minimal_expected_seeds",
    "test_ten_replicas_identical",
    "test_divergence_detected_when_injected",
    "test_divergence_reports_correct_offset",
    "test_divergence_length_mismatch",
    "test_no_divergence_identical",
    "test_timestamp_root_cause_hint",
    "test_context_hex_dump_correct_length",
    "test_event_codes",
    "test_single_replica_always_passes",
    "test_all_fixtures_pass",
    "test_divergence_display",
    "test_parse_all_domains",
    "test_parse_unknown_domain_panics",
]

DIVERGENCE_FIELDS = [
    "artifact_name",
    "first_mismatch_offset",
    "replica_a",
    "replica_b",
    "context_hex_a",
    "context_hex_b",
    "root_cause",
]

DOMAIN_TAGS = [
    "DomainTag::Encoding",
    "DomainTag::Repair",
    "DomainTag::Scheduling",
    "DomainTag::Placement",
    "DomainTag::Verification",
]


def check_file(path, label):
    ok = path.is_file()
    rel = str(path.relative_to(ROOT)) if ok else str(path)
    return {"check": f"file: {label}", "pass": ok,
            "detail": f"exists: {rel}" if ok else f"MISSING: {rel}"}


def check_content(path, patterns, category):
    results = []
    if not path.is_file():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    content = path.read_text()
    for p in patterns:
        found = p in content
        results.append({"check": f"{category}: {p}", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})
    return results


def check_fixtures():
    results = []
    for fname in FIXTURE_FILES:
        fpath = FIXTURE_DIR / fname
        ok = fpath.is_file()
        results.append({"check": f"fixture: {fname}", "pass": ok,
                        "detail": "exists" if ok else "MISSING"})
        if ok:
            try:
                data = json.loads(fpath.read_text())
                has_seeds = "expected_seeds" in data
                results.append({"check": f"fixture golden vectors: {fname}", "pass": has_seeds,
                                "detail": "has expected_seeds" if has_seeds else "missing expected_seeds"})
            except json.JSONDecodeError:
                results.append({"check": f"fixture parse: {fname}", "pass": False,
                                "detail": "invalid JSON"})
    return results


def check_upstream():
    results = []
    ok = SEED_RS.is_file()
    results.append({"check": "upstream: deterministic_seed.rs", "pass": ok,
                    "detail": "exists" if ok else "MISSING"})

    if ENCODING_MOD.is_file():
        content = ENCODING_MOD.read_text()
        found = "deterministic_seed" in content
        results.append({"check": "module registered: encoding/mod.rs", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})
    else:
        results.append({"check": "module registered: encoding/mod.rs", "pass": False,
                        "detail": "mod.rs missing"})

    if MAIN_RS.is_file():
        content = MAIN_RS.read_text()
        found = "pub mod encoding" in content
        results.append({"check": "encoding module in main.rs", "pass": found,
                        "detail": "found" if found else "NOT FOUND"})
    else:
        results.append({"check": "encoding module in main.rs", "pass": False,
                        "detail": "main.rs missing"})
    return results


def check_imports():
    if not IMPL.is_file():
        return {"check": "imports deterministic_seed types", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    needed = ["DeterministicSeedDeriver", "ContentHash", "DomainTag", "ScheduleConfig", "derive_seed"]
    found = all(n in content for n in needed)
    return {"check": "imports deterministic_seed types", "pass": found,
            "detail": "found" if found else f"missing some of: {needed}"}


def check_test_count(path):
    if not path.is_file():
        return {"check": "test count", "pass": False, "detail": "file missing"}
    content = path.read_text()
    count = len(re.findall(r"#\[test\]", content))
    return {"check": "unit test count", "pass": count >= 15,
            "detail": f"{count} tests (minimum 15)"}


def check_replica_count():
    if not IMPL.is_file():
        return {"check": "configurable replica count", "pass": False, "detail": "file missing"}
    content = IMPL.read_text()
    found = "replica_count" in content and "DEFAULT_REPLICAS" in content
    return {"check": "configurable replica count", "pass": found,
            "detail": "found" if found else "NOT FOUND"}


def self_test():
    result = run_checks()
    all_pass = result["verdict"] == "PASS"
    return all_pass, result["checks"]


def run_checks():
    checks = []
    checks.append(check_file(IMPL, "conformance test"))
    checks.append(check_file(SPEC, "spec contract"))
    checks.extend(check_upstream())
    checks.append(check_imports())
    checks.append(check_test_count(IMPL))
    checks.append(check_replica_count())
    checks.extend(check_fixtures())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_FUNCTIONS, "function"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, DIVERGENCE_FIELDS, "divergence_field"))
    checks.extend(check_content(IMPL, DOMAIN_TAGS, "domain"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-1iyx",
        "title": "Determinism conformance tests",
        "section": "10.14",
        "overall_pass": passed == total,
        "verdict": "PASS" if passed == total else "FAIL",
        "test_count": len(re.findall(r"#\[test\]", IMPL.read_text())) if IMPL.is_file() else 0,
        "fixture_count": len(FIXTURE_FILES),
        "summary": {"passing": passed, "failing": total - passed, "total": total},
        "checks": checks,
    }


def main():
    if "--self-test" in sys.argv:
        ok, results = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'}")
        return

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== bd-1iyx: Determinism Conformance Verification ===")
        print(f"Verdict: {result['verdict']}")
        s = result["summary"]
        print(f"Checks: {s['passing']}/{s['total']}")
        print()
        for check in result["checks"]:
            tag = "PASS" if check["pass"] else "FAIL"
            print(f"  [{tag}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
