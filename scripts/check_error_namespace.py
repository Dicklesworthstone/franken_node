#!/usr/bin/env python3
"""Verification script for bd-13q stable error namespace adoption."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any

SPEC = ROOT / "docs" / "specs" / "section_10_10" / "bd-13q_contract.md"
IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "error_surface.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
SCRIPT_COMPAT = ROOT / "scripts" / "check_error_compat.py"
SCRIPT_COVERAGE = ROOT / "scripts" / "check_error_coverage.py"
UNIT_TESTS = ROOT / "tests" / "test_check_error_namespace.py"
AUDIT = ROOT / "artifacts" / "section_10_10" / "bd-13q" / "error_audit.json"

EVENT_CODES = ["ENS-001", "ENS-002", "ENS-003", "ENS-004"]
INVARIANTS = [
    "INV-ENS-REGISTRY-SOURCE",
    "INV-ENS-APPEND-ONLY",
    "INV-ENS-CATEGORY-STABLE",
    "INV-ENS-TELEMETRY-DIMENSION",
    "INV-ENS-RECOVERY-HINT",
]
REQUIRED_PREFIXES = ["FN-CTRL-", "FN-MIG-", "FN-AUTH-", "FN-POL-", "FN-ZON-", "FN-TOK-"]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"check": name, "pass": bool(passed), "detail": detail})


def _read(path: Path) -> str:
    return path.read_text() if path.is_file() else ""


def _run_json_cmd(cmd: list[str]) -> tuple[bool, dict[str, Any], str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=3600)
    except (subprocess.SubprocessError, OSError) as exc:
        return False, {}, str(exc)
    stdout = proc.stdout.strip()
    if not stdout:
        return False, {}, "empty stdout"
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return False, {}, f"invalid json: {exc}"
    ok = proc.returncode == 0 and data.get("verdict") == "PASS"
    return ok, data, proc.stderr.strip()


def check_spec_exists() -> None:
    _check("spec_exists", SPEC.is_file(), f"{SPEC.relative_to(ROOT)}")


def check_spec_invariants() -> None:
    text = _read(SPEC)
    for inv in INVARIANTS:
        _check(f"spec_invariant_{inv}", inv in text, "found" if inv in text else "NOT FOUND")


def check_spec_event_codes() -> None:
    text = _read(SPEC)
    for code in EVENT_CODES:
        _check(f"spec_event_code_{code}", code in text, "found" if code in text else "NOT FOUND")


def check_impl_exists() -> None:
    _check("impl_exists", IMPL.is_file(), f"{IMPL.relative_to(ROOT)}")


def check_impl_prefixes() -> None:
    text = _read(IMPL)
    for prefix in REQUIRED_PREFIXES:
        _check(
            f"impl_prefix_{prefix}",
            prefix in text,
            "found" if prefix in text else "NOT FOUND",
        )


def check_impl_required_symbols() -> None:
    text = _read(IMPL)
    required = [
        "struct ProductError",
        "enum ProductSurface",
        "struct ErrorCompatibilityPolicy",
        "struct CompatibilityReport",
        "fn telemetry_error_dimensions(",
        "macro_rules! product_error",
        "error.code",
    ]
    for symbol in required:
        _check(
            f"impl_symbol_{symbol}",
            symbol in text,
            "found" if symbol in text else "NOT FOUND",
        )


def check_mod_rs_registration() -> None:
    text = _read(MOD_RS)
    _check(
        "mod_rs_registers_error_surface",
        "pub mod error_surface;" in text,
        "registered" if "pub mod error_surface;" in text else "NOT FOUND",
    )


def check_scripts_exist() -> None:
    _check("script_check_error_compat", SCRIPT_COMPAT.is_file(), f"{SCRIPT_COMPAT.relative_to(ROOT)}")
    _check(
        "script_check_error_coverage",
        SCRIPT_COVERAGE.is_file(),
        f"{SCRIPT_COVERAGE.relative_to(ROOT)}",
    )


def check_unit_tests_exist() -> None:
    _check("unit_tests_exist", UNIT_TESTS.is_file(), f"{UNIT_TESTS.relative_to(ROOT)}")


def check_audit_exists() -> None:
    _check("error_audit_exists", AUDIT.is_file(), f"{AUDIT.relative_to(ROOT)}")


def check_audit_unmapped_zero() -> None:
    if not AUDIT.is_file():
        _check("error_audit_unmapped_zero", False, "audit file missing")
        return
    try:
        data = json.loads(AUDIT.read_text())
        summary = data.get("summary", {})
        unmapped = int(summary.get("unmapped_error_count", 1))
        _check(
            "error_audit_unmapped_zero",
            unmapped == 0,
            "0 unmapped errors" if unmapped == 0 else f"{unmapped} unmapped errors",
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _check("error_audit_unmapped_zero", False, f"audit parse error: {exc}")


def check_compat_script() -> None:
    ok, data, err = _run_json_cmd(["python3", str(SCRIPT_COMPAT), "--json"])
    detail = f"verdict={data.get('verdict')}" if data else err
    _check("compatibility_policy", ok, detail)


def check_coverage_script() -> None:
    ok, data, err = _run_json_cmd(["python3", str(SCRIPT_COVERAGE), "--json"])
    detail = f"verdict={data.get('verdict')}" if data else err
    _check("coverage_policy", ok, detail)


ALL_CHECKS = [
    check_spec_exists,
    check_spec_invariants,
    check_spec_event_codes,
    check_impl_exists,
    check_impl_prefixes,
    check_impl_required_symbols,
    check_mod_rs_registration,
    check_scripts_exist,
    check_unit_tests_exist,
    check_audit_exists,
    check_audit_unmapped_zero,
    check_compat_script,
    check_coverage_script,
]


def run_all() -> dict[str, Any]:
    global RESULTS
    RESULTS = []
    for fn in ALL_CHECKS:
        fn()
    total = len(RESULTS)
    passed = sum(1 for item in RESULTS if item["pass"])
    failed = total - passed
    return {
        "bead_id": "bd-13q",
        "title": "stable product error namespace adoption",
        "section": "10.10",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    compat_ok, _, _ = _run_json_cmd(["python3", str(SCRIPT_COMPAT), "--self-test", "--json"])
    coverage_ok, _, _ = _run_json_cmd(
        ["python3", str(SCRIPT_COVERAGE), "--self-test", "--json"]
    )
    return compat_ok and coverage_ok


def main() -> int:
    logger = configure_test_logging("check_error_namespace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-test")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        report = {"bead_id": "bd-13q", "check": "self_test", "verdict": "PASS" if ok else "FAIL"}
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"self_test verdict: {report['verdict']}")
        return 0 if ok else 1

    report = run_all()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for item in report["checks"]:
            status = "PASS" if item["pass"] else "FAIL"
            print(f"[{status}] {item['check']}: {item['detail']}")
        print(f"\nverdict: {report['verdict']} ({report['passed']}/{report['total']})")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
