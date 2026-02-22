#!/usr/bin/env python3
"""Verification script for bd-3ptu: VEF adversarial suite contract.

Usage:
    python3 scripts/check_vef_adversarial_suite.py
    python3 scripts/check_vef_adversarial_suite.py --json
    python3 scripts/check_vef_adversarial_suite.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SUITE_PRIMARY = ROOT / "tests" / "security" / "vef_adversarial_suite.rs"
SUITE_HARNESS = ROOT / "tests" / "vef_adversarial_suite.rs"
DOC = ROOT / "docs" / "security" / "vef_adversarial_testing.md"
REPORT = ROOT / "artifacts" / "10.18" / "vef_adversarial_results.json"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-3ptu" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-3ptu" / "verification_summary.md"
UNIT_TEST = ROOT / "tests" / "test_check_vef_adversarial_suite.py"

REQUIRED_ATTACK_CLASSES = [
    "receipt tampering",
    "proof replay",
    "stale-policy",
    "commitment mismatch",
]

REQUIRED_EVENT_CODES = [
    "VEF-ADVERSARIAL-001",
    "VEF-ADVERSARIAL-002",
]

REQUIRED_ERROR_CODES = [
    "VEF-ADVERSARIAL-ERR-TAMPER",
    "VEF-ADVERSARIAL-ERR-REPLAY",
    "VEF-ADVERSARIAL-ERR-STALE-POLICY",
    "VEF-ADVERSARIAL-ERR-COMMITMENT",
]

REQUIRED_SUITE_SYMBOLS = [
    "tamper",
    "replay",
    "stale",
    "commitment",
]

RESULTS: list[dict[str, Any]] = []


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _safe_rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if str(path).startswith(str(ROOT)) else str(path)


def _check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("ok" if passed else "NOT FOUND"),
        }
    )


def _load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _contains_all(text: str, tokens: list[str]) -> bool:
    return all(token in text for token in tokens)


def _suite_path() -> Path:
    if SUITE_PRIMARY.is_file():
        return SUITE_PRIMARY
    if SUITE_HARNESS.is_file():
        return SUITE_HARNESS
    return SUITE_PRIMARY


def check_file_presence() -> None:
    suite_exists = SUITE_PRIMARY.is_file() or SUITE_HARNESS.is_file()
    suite_detail = (
        _safe_rel(SUITE_PRIMARY)
        if SUITE_PRIMARY.is_file()
        else (
            _safe_rel(SUITE_HARNESS)
            if SUITE_HARNESS.is_file()
            else f"{_safe_rel(SUITE_PRIMARY)} or {_safe_rel(SUITE_HARNESS)}"
        )
    )
    _check("suite_exists", suite_exists, suite_detail)

    files = [
        ("doc_exists", DOC),
        ("report_exists", REPORT),
        ("evidence_exists", EVIDENCE),
        ("summary_exists", SUMMARY),
        ("unit_test_exists", UNIT_TEST),
    ]
    for name, path in files:
        _check(name, path.is_file(), _safe_rel(path))


def check_suite_content() -> None:
    src = _read(_suite_path())
    if not src:
        _check("suite_readable", False, "missing suite source")
        return

    _check("suite_readable", True, _safe_rel(_suite_path()))

    for symbol in REQUIRED_SUITE_SYMBOLS:
        _check(f"suite_symbol_{symbol}", symbol in src.lower(), symbol)

    has_expect_err = "expect_err" in src
    has_matches_err = "matches!(" in src and "Err(" in src
    _check(
        "suite_symbol_error_assertion",
        has_expect_err or has_matches_err,
        "expect_err or matches!(..., Err(...))",
    )

    for attack_class in REQUIRED_ATTACK_CLASSES:
        _check(
            f"suite_attack_class_{attack_class}",
            attack_class in src.lower(),
            attack_class,
        )

    for code in REQUIRED_EVENT_CODES:
        _check(f"suite_event_code_{code}", code in src, code)

    for code in REQUIRED_ERROR_CODES:
        _check(f"suite_error_code_{code}", code in src, code)

    test_count = src.count("#[test]")
    _check("suite_minimum_test_count", test_count >= 12, f"{test_count} tests")

    deterministic_loop = bool(re.search(r"\b100\b", src))
    _check("suite_has_determinism_loop_hint", deterministic_loop, "contains 100x loop marker")

    has_false_positive_guard = "false positive" in src.lower() or "legitimate" in src.lower()
    _check(
        "suite_mentions_false_positive_guard",
        has_false_positive_guard,
        "false positive or legitimate marker",
    )


def check_doc_content() -> None:
    text = _read(DOC)
    if not text:
        _check("doc_readable", False, _safe_rel(DOC))
        return

    lower = text.lower()
    _check("doc_readable", True, _safe_rel(DOC))
    _check("doc_mentions_bd", "bd-3ptu" in lower, "bd-3ptu")
    _check("doc_mentions_fail_closed", "fail-closed" in lower, "fail-closed")
    _check("doc_mentions_deterministic", "deterministic" in lower, "deterministic")
    _check("doc_mentions_remediation", "remediation" in lower, "remediation")

    attack_class_checks = {
        "receipt tampering": _contains_all(lower, ["receipt", "tamper"]),
        "proof replay": _contains_all(lower, ["proof", "replay"]),
        "stale-policy": _contains_all(lower, ["stale", "policy"]),
        "commitment mismatch": _contains_all(lower, ["commitment", "mismatch"])
        or _contains_all(lower, ["commitment", "substitute"]),
    }
    for attack_class, present in attack_class_checks.items():
        _check(f"doc_attack_class_{attack_class}", present, attack_class)

    for code in REQUIRED_EVENT_CODES:
        _check(f"doc_event_code_{code}", code in text, code)
    for code in REQUIRED_ERROR_CODES:
        _check(f"doc_error_code_{code}", code in text, code)


def check_report_and_evidence() -> None:
    report = _load_json(REPORT)
    if report is None:
        _check("report_parseable_json", False, "invalid or missing JSON")
    else:
        _check("report_parseable_json", True, "valid JSON")
        _check("report_bead_id", report.get("bead_id") == "bd-3ptu", str(report.get("bead_id")))
        _check("report_section", report.get("section") == "10.18", str(report.get("section")))

        classes = report.get("attack_classes", [])
        _check(
            "report_attack_classes_coverage",
            isinstance(classes, list)
            and {str(x).lower() for x in classes} >= set(REQUIRED_ATTACK_CLASSES),
            str(classes),
        )

        counts = report.get("detection_counts", {})
        _check("report_detection_counts_block", isinstance(counts, dict), "detection_counts")

    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check("evidence_bead_id", evidence.get("bead_id") == "bd-3ptu", str(evidence.get("bead_id")))
        _check(
            "evidence_verdict_domain",
            evidence.get("verdict") in ("PASS", "FAIL", "PENDING"),
            str(evidence.get("verdict")),
        )
        _check("evidence_has_checks", isinstance(evidence.get("checks"), list), "checks list")

    summary = _read(SUMMARY)
    _check("summary_mentions_bd", "bd-3ptu" in summary.lower(), "bd-3ptu")
    _check("summary_mentions_verdict", any(x in summary for x in ("PASS", "FAIL", "PENDING")), "verdict marker")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_suite_content()
    check_doc_content()
    check_report_and_evidence()

    total = len(RESULTS)
    passed = sum(1 for entry in RESULTS if entry["pass"])
    failed = total - passed
    check_state = {entry["check"]: bool(entry["pass"]) for entry in RESULTS}
    detection_counts = {
        "tamper": int(check_state.get("suite_error_code_VEF-ADVERSARIAL-ERR-TAMPER", False)),
        "replay": int(check_state.get("suite_error_code_VEF-ADVERSARIAL-ERR-REPLAY", False)),
        "stale_policy": int(check_state.get("suite_error_code_VEF-ADVERSARIAL-ERR-STALE-POLICY", False)),
        "commitment_mismatch": int(
            check_state.get("suite_error_code_VEF-ADVERSARIAL-ERR-COMMITMENT", False)
        ),
    }

    return {
        "bead_id": "bd-3ptu",
        "title": "VEF adversarial suite contract verification",
        "section": "10.18",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "attack_classes": REQUIRED_ATTACK_CLASSES,
        "detection_counts": detection_counts,
        "checks": RESULTS,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("attack_class_count", len(REQUIRED_ATTACK_CLASSES) == 4, str(len(REQUIRED_ATTACK_CLASSES)))
    push("event_code_count", len(REQUIRED_EVENT_CODES) == 2, str(len(REQUIRED_EVENT_CODES)))
    push("error_code_count", len(REQUIRED_ERROR_CODES) == 4, str(len(REQUIRED_ERROR_CODES)))
    push("symbol_count", len(REQUIRED_SUITE_SYMBOLS) >= 5, str(len(REQUIRED_SUITE_SYMBOLS)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_consistent", report.get("total") == len(report.get("checks", [])), "total vs checks")

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed

    return {
        "bead_id": "bd-3ptu",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify bd-3ptu artifacts")
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    parser.add_argument("--self-test", action="store_true", help="run checker self-test")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['bead_id']}] {result['verdict']} ({result['passed']}/{result['total']})")
        for check in result["checks"]:
            mark = "PASS" if check["pass"] else "FAIL"
            print(f"- {mark} {check['check']}: {check['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
