#!/usr/bin/env python3
"""Report fixture verifier for bd-15t category-shift evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_category_shift  # noqa: E402
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


def run_all() -> dict:
    checks = check_category_shift.report_fixture_checks()
    total = len(checks)
    passed = sum(1 for check in checks if check["pass"])
    failed = total - passed
    return {
        "bead_id": "bd-15t",
        "title": "Category-shift report fixture verification",
        "section": "10.9",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "fixtures": [
            "fixtures/category-shift/manifest.json",
            "fixtures/category-shift/category_shift_report.json",
            "fixtures/category-shift/category_shift_report.md",
        ],
        "checks": checks,
    }


def main() -> None:
    configure_test_logging("check_category_shift_reports")
    parser = argparse.ArgumentParser(
        description="Verify bd-15t category-shift report fixtures"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    report = run_all()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for check in report["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
        print(
            f"\n{report['passed']}/{report['total']} checks pass "
            f"(verdict={report['verdict']})"
        )

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
