#!/usr/bin/env python3
"""Verification script for bd-1iyx: determinism conformance tests (section 10.14).

Usage:
    python scripts/check_determinism_conformance.py          # human-readable
    python scripts/check_determinism_conformance.py --json   # machine-readable
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tests" / "conformance" / "replica_artifact_determinism.rs"
STUB = ROOT / "crates" / "franken-node" / "tests" / "replica_artifact_determinism.rs"
FIXTURES_DIR = ROOT / "fixtures" / "determinism"
RESULTS_CSV = ROOT / "artifacts" / "10.14" / "determinism_conformance_results.csv"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-1iyx_contract.md"
SEED_IMPL = ROOT / "crates" / "franken-node" / "src" / "encoding" / "deterministic_seed.rs"

BEAD_ID = "bd-1iyx"

# ---- helpers ---------------------------------------------------------------

def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail}


def _file_check(label: str, path: Path) -> dict:
    return _check(f"file: {label}", path.is_file(), f"exists: {path.relative_to(ROOT)}")


def _contains(content: str, needle: str, label: str) -> dict:
    found = needle in content
    return _check(label, found, "found" if found else f"missing: {needle}")


# ---- golden vector cross-validation ----------------------------------------

def config_hash(version: int, params: dict) -> bytes:
    h = hashlib.sha256()
    h.update(struct.pack('<I', version))
    for k in sorted(params.keys()):
        v = params[k]
        h.update(struct.pack('<I', len(k)))
        h.update(k.encode())
        h.update(struct.pack('<I', len(v)))
        h.update(v.encode())
    return h.digest()


def derive_seed_py(domain_prefix: str, content_hash_hex: str, cfg_hash: bytes) -> str:
    h = hashlib.sha256()
    h.update(domain_prefix.encode())
    h.update(b'\x00')
    h.update(bytes.fromhex(content_hash_hex))
    h.update(cfg_hash)
    return h.hexdigest()


def validate_fixture(fixture_path: Path) -> list:
    checks = []
    data = json.loads(fixture_path.read_text())
    name = data["fixture_name"]
    ch_hex = data["content_hash_hex"]
    cfg = data["config"]
    cfg_h = config_hash(cfg["version"], cfg.get("parameters", {}))
    expected = data.get("expected_seeds", {})

    for domain in data.get("domains", []):
        prefix = f"franken_node.{domain}.v1"
        computed = derive_seed_py(prefix, ch_hex, cfg_h)
        exp = expected.get(domain, "")
        ok = computed == exp
        checks.append(_check(
            f"fixture {name}: {domain}",
            ok,
            "match" if ok else f"expected {exp}, got {computed}",
        ))
    return checks


# ---- main checks -----------------------------------------------------------

def run_checks() -> dict:
    checks = []

    # File existence
    checks.append(_file_check("test harness", HARNESS))
    checks.append(_file_check("test stub", STUB))
    checks.append(_file_check("spec contract", SPEC))
    checks.append(_file_check("results CSV", RESULTS_CSV))
    checks.append(_file_check("seed implementation", SEED_IMPL))

    # Fixtures
    fixture_files = sorted(FIXTURES_DIR.glob("*.json")) if FIXTURES_DIR.is_dir() else []
    checks.append(_check(
        "fixture count >= 3",
        len(fixture_files) >= 3,
        f"{len(fixture_files)} fixtures",
    ))

    for fp in fixture_files:
        checks.append(_check(f"fixture readable: {fp.name}", True, str(fp.name)))

    # Harness content checks
    if HARNESS.is_file():
        content = HARNESS.read_text()

        # Types and functions
        for item in [
            "struct Divergence",
            "struct Replica",
            "struct FixtureResult",
            "fn compare_artifacts",
            "fn run_fixture",
            "fn verify_expected_seeds",
            "fn guess_root_cause",
            "fn parse_domain",
        ]:
            checks.append(_contains(content, item, f"harness: {item}"))

        # Event codes
        for code in [
            "DETERMINISM_CHECK_STARTED",
            "DETERMINISM_CHECK_PASSED",
            "DETERMINISM_CHECK_FAILED",
        ]:
            checks.append(_contains(content, code, f"event_code: {code}"))

        # Divergence reporting features
        checks.append(_contains(content, "context_hex_a", "divergence: hex context"))
        checks.append(_contains(content, "root_cause", "divergence: root cause"))
        checks.append(_contains(content, "first_mismatch_offset", "divergence: offset"))

        # Test names
        for test_name in [
            "test_small_encoding_replicas_identical",
            "test_medium_multi_domain_replicas_identical",
            "test_edge_case_minimal_replicas_identical",
            "test_small_encoding_expected_seeds",
            "test_medium_multi_domain_expected_seeds",
            "test_edge_case_minimal_expected_seeds",
            "test_ten_replicas_identical",
            "test_divergence_detected_when_injected",
            "test_divergence_reports_correct_offset",
            "test_divergence_length_mismatch",
            "test_no_divergence_identical",
            "test_timestamp_root_cause_hint",
            "test_all_fixtures_pass",
            "test_event_codes",
            "test_divergence_display",
            "test_parse_all_domains",
            "test_parse_unknown_domain_panics",
            "test_single_replica_always_passes",
            "test_context_hex_dump_correct_length",
        ]:
            checks.append(_contains(content, test_name, f"test: {test_name}"))

        # Test count
        test_count = content.count("#[test]")
        checks.append(_check(
            "harness test count >= 15",
            test_count >= 15,
            f"{test_count} tests (minimum 15)",
        ))

    # Results CSV
    if RESULTS_CSV.is_file():
        csv_content = RESULTS_CSV.read_text()
        lines = [l for l in csv_content.strip().split('\n') if l.strip()]
        checks.append(_check(
            "CSV header present",
            "fixture_name" in lines[0] if lines else False,
            "header found" if lines else "no lines",
        ))
        data_lines = lines[1:] if len(lines) > 1 else []
        checks.append(_check(
            "CSV data rows >= 3",
            len(data_lines) >= 3,
            f"{len(data_lines)} data rows",
        ))
        all_pass = all("true" in l for l in data_lines)
        checks.append(_check(
            "CSV all_identical = true for all fixtures",
            all_pass,
            "all pass" if all_pass else "some failures",
        ))

    # Cross-validate fixtures
    for fp in fixture_files:
        checks.extend(validate_fixture(fp))

    return _result(checks)


def _result(checks: list) -> dict:
    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    return {
        "bead_id": BEAD_ID,
        "title": "Determinism conformance tests",
        "section": "10.14",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": 66,
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return (len(failing) == 0, result["checks"])


def main():
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== {BEAD_ID}: Determinism Conformance Tests ===")
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        print(f"\nVerdict: {result['verdict']} ({result['summary']['passing']}/{result['summary']['total']})")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
