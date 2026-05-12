"""Unit tests for scripts/check_category_shift_reports.py."""
# ruff: noqa: E402

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_category_shift_reports as mod


class TestCategoryShiftReportsChecker(unittest.TestCase):
    def test_run_all_passes(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_names_bd_15t(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-15t")
        self.assertEqual(result["section"], "10.9")

    def test_expected_fixture_paths_listed(self):
        result = mod.run_all()
        fixtures = set(result["fixtures"])
        self.assertIn("fixtures/category-shift/manifest.json", fixtures)
        self.assertIn("fixtures/category-shift/category_shift_report.json", fixtures)
        self.assertIn("fixtures/category-shift/category_shift_report.md", fixtures)

    def test_checker_focuses_on_fixture_gap(self):
        result = mod.run_all()
        check_names = {check["check"] for check in result["checks"]}
        self.assertIn("fixture: category-shift directory", check_names)
        self.assertIn("fixture manifest: expected checker", check_names)
        self.assertIn("fixture report: deterministic claim ids", check_names)

    def _failing(self, result):
        failures = [check for check in result["checks"] if not check["pass"]]
        return "\n".join(
            f"  FAIL: {check['check']}: {check['detail']}" for check in failures
        )


if __name__ == "__main__":
    unittest.main()
