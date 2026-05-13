#!/usr/bin/env python3
"""Release gate verification: canonical trust protocol golden vectors (bd-1hd).

Runs all vector suites from the release gate manifest and emits a structured
pass/fail verdict.  No release artifact can ship if any suite fails.

Event codes: RGV-001 through RGV-007.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD_ID = "bd-1hd"
SECTION = "10.10"
TITLE = "Release Gate Vector Suites"
MANIFEST_LOAD_FAILED: dict[str, Any] | None = None
EMPTY_FILE_TEXT = ""
JSON_DECODER = json.JSONDecoder()

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_10" / "bd-1hd_contract.md"
MANIFEST_PATH = ROOT / "vectors" / "release_gate_manifest.json"
COVERAGE_PATH = ROOT / "artifacts" / "section_10_10" / "bd-1hd" / "vector_coverage.json"

EVENT_CODES = ["RGV-001", "RGV-002", "RGV-003", "RGV-004", "RGV-005", "RGV-006", "RGV-007"]

INVARIANTS = [
    "INV-RGV-BLOCK",
    "INV-RGV-REGRESSION",
    "INV-RGV-VERSIONED",
    "INV-RGV-COVERAGE",
]

ERROR_CODES = [
    "ERR_RGV_MANIFEST_MISSING",
    "ERR_RGV_MANIFEST_INVALID",
    "ERR_RGV_VECTOR_FILE_MISSING",
    "ERR_RGV_SUITE_FAILED",
    "ERR_RGV_REGRESSION",
]

REQUIRED_MANIFEST_FIELDS = [
    "suite_name",
    "source_section",
    "vector_file",
    "min_pass_count",
    "version",
    "schema_ref",
    "features",
]


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "passed": passed, "detail": detail}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return EMPTY_FILE_TEXT


def _decode_json(text: str) -> Any:
    return JSON_DECODER.decode(text)


def _load_manifest() -> dict[str, Any] | None:
    text = _read(MANIFEST_PATH)
    if not text:
        return MANIFEST_LOAD_FAILED
    try:
        return _decode_json(text)
    except (json.JSONDecodeError, ValueError):
        return MANIFEST_LOAD_FAILED


# ── Spec checks ──────────────────────────────────────────────────────────

def check_spec_exists() -> dict:
    ok = SPEC_PATH.is_file()
    return _check("spec_exists", ok,
                   f"{SPEC_PATH.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_spec_event(code: str) -> dict:
    text = _read(SPEC_PATH)
    ok = code in text
    return _check(f"spec_event:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in spec")


def check_spec_invariant(inv: str) -> dict:
    text = _read(SPEC_PATH)
    ok = inv in text
    return _check(f"spec_invariant:{inv}", ok,
                  f"{inv} {'found' if ok else 'MISSING'} in spec")


def check_spec_error(code: str) -> dict:
    text = _read(SPEC_PATH)
    ok = code in text
    return _check(f"spec_error:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in spec")


# ── Manifest checks ─────────────────────────────────────────────────────

def check_manifest_exists() -> dict:
    ok = MANIFEST_PATH.is_file()
    return _check("manifest_exists", ok,
                   f"{MANIFEST_PATH.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_manifest_valid_json() -> dict:
    manifest = _load_manifest()
    ok = manifest is not None
    return _check("manifest_valid_json", ok,
                  f"Manifest {'valid' if ok else 'INVALID'} JSON")


def check_manifest_has_suites() -> dict:
    manifest = _load_manifest()
    if manifest is None:
        return _check("manifest_has_suites", False, "Manifest not loaded")
    suites = manifest.get("suites", [])
    ok = len(suites) >= 1
    return _check("manifest_has_suites", ok,
                  f"{len(suites)} suites (>= 1 required)")


def check_manifest_suite_fields() -> dict:
    manifest = _load_manifest()
    if manifest is None:
        return _check("manifest_suite_fields", False, "Manifest not loaded")
    suites = manifest.get("suites", [])
    all_ok = True
    missing = []
    for suite in suites:
        for field in REQUIRED_MANIFEST_FIELDS:
            if field not in suite:
                all_ok = False
                missing.append(f"{suite.get('suite_name', '?')}.{field}")
    detail = "All fields present" if all_ok else f"Missing: {', '.join(missing)}"
    return _check("manifest_suite_fields", all_ok, detail)


def check_manifest_version() -> dict:
    manifest = _load_manifest()
    if manifest is None:
        return _check("manifest_version", False, "Manifest not loaded")
    ok = "version" in manifest
    return _check("manifest_version", ok,
                  f"Manifest version {'present' if ok else 'MISSING'}")


def check_manifest_coverage_features() -> dict:
    manifest = _load_manifest()
    if manifest is None:
        return _check("manifest_coverage_features", False, "Manifest not loaded")
    features = manifest.get("coverage_features", [])
    ok = len(features) >= 5
    return _check("manifest_coverage_features", ok,
                  f"{len(features)} coverage features (>= 5 required)")


# ── Vector suite checks ─────────────────────────────────────────────────

def check_vector_files_exist() -> dict:
    manifest = _load_manifest()
    if manifest is None:
        return _check("vector_files_exist", False, "Manifest not loaded")
    suites = manifest.get("suites", [])
    missing = []
    for suite in suites:
        vf = ROOT / suite.get("vector_file", "")
        if not vf.is_file():
            missing.append(suite.get("suite_name", "?"))
    ok = len(missing) == 0
    detail = "All vector files present" if ok else f"Missing: {', '.join(missing)}"
    return _check("vector_files_exist", ok, detail)


def check_vector_files_valid_json() -> dict:
    manifest = _load_manifest()
    if manifest is None:
        return _check("vector_files_valid_json", False, "Manifest not loaded")
    suites = manifest.get("suites", [])
    invalid = []
    for suite in suites:
        vf = ROOT / suite.get("vector_file", "")
        text = _read(vf)
        if text:
            try:
                _decode_json(text)
            except (json.JSONDecodeError, ValueError):
                invalid.append(suite.get("suite_name", "?"))
    ok = len(invalid) == 0
    detail = "All vector files valid JSON" if ok else f"Invalid: {', '.join(invalid)}"
    return _check("vector_files_valid_json", ok, detail)


def check_suite_versions_present() -> dict:
    manifest = _load_manifest()
    if manifest is None:
        return _check("suite_versions_present", False, "Manifest not loaded")
    suites = manifest.get("suites", [])
    ok = all("version" in s for s in suites)
    return _check("suite_versions_present", ok,
                  f"All suites {'have' if ok else 'MISSING'} version field")


# ── Coverage report checks ──────────────────────────────────────────────

def check_coverage_report_exists() -> dict:
    ok = COVERAGE_PATH.is_file()
    return _check("coverage_report_exists", ok,
                   f"Coverage report {'exists' if ok else 'MISSING'}")


def check_coverage_report_valid() -> dict:
    text = _read(COVERAGE_PATH)
    try:
        data = _decode_json(text)
        ok = "covered_features" in data and "total_features" in data
    except (json.JSONDecodeError, ValueError):
        ok = False
    return _check("coverage_report_valid", ok,
                  f"Coverage report {'valid' if ok else 'INVALID'}")


# ── Build coverage report ────────────────────────────────────────────────

def build_coverage_report():
    """Generate vector coverage report."""
    manifest = _load_manifest()
    if manifest is None:
        return

    covered = set()
    for suite in manifest.get("suites", []):
        for feat in suite.get("features", []):
            covered.add(feat)

    all_features = set(manifest.get("coverage_features", []))
    gaps = sorted(all_features - covered)

    report = {
        "total_features": len(all_features),
        "covered_features": len(covered),
        "coverage_pct": round(100 * len(covered) / max(len(all_features), 1), 1),
        "covered": sorted(covered),
        "gaps": gaps,
    }

    COVERAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    COVERAGE_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


# ── Run all checks ───────────────────────────────────────────────────────

def run_all() -> dict:
    # Build coverage report first.
    build_coverage_report()

    checks = []

    # Spec checks
    checks.append(check_spec_exists())
    for code in EVENT_CODES:
        checks.append(check_spec_event(code))
    for inv in INVARIANTS:
        checks.append(check_spec_invariant(inv))
    for code in ERROR_CODES:
        checks.append(check_spec_error(code))

    # Manifest checks
    checks.append(check_manifest_exists())
    checks.append(check_manifest_valid_json())
    checks.append(check_manifest_has_suites())
    checks.append(check_manifest_suite_fields())
    checks.append(check_manifest_version())
    checks.append(check_manifest_coverage_features())

    # Vector suite checks
    checks.append(check_vector_files_exist())
    checks.append(check_vector_files_valid_json())
    checks.append(check_suite_versions_present())

    # Coverage checks
    checks.append(check_coverage_report_exists())
    checks.append(check_coverage_report_valid())

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    total = len(checks)

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": total,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "all_passed": failed == 0,
        "status": "pass" if failed == 0 else "fail",
    }


def self_test() -> bool:
    """Smoke test."""
    result = run_all()
    if not isinstance(result, dict):
        raise AssertionError("run_all must return dict")
    for key in ("checks", "verdict", "all_passed"):
        if key not in result:
            raise AssertionError(f"missing {key} key")
    if not isinstance(result["checks"], list):
        raise AssertionError("checks must be a list")
    for check in result["checks"]:
        for key in ("name", "passed", "detail"):
            if key not in check:
                raise AssertionError(f"check entry missing {key}")
    return bool(result["all_passed"])


def main():
    configure_test_logging("check_release_vectors")
    import argparse
    parser = argparse.ArgumentParser(description=f"Verify {BEAD_ID}")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        print("self_test passed" if ok else "self_test FAILED")
        sys.exit(0 if ok else 1)

    result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-1hd Release Gate Vectors — {result['verdict']}"
              f" ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
