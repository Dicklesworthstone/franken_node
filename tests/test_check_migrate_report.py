#!/usr/bin/env python3
"""Unit tests for migrate_report.py."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import migrate_report


class TestGenerateFullReport(unittest.TestCase):
    def test_report_has_all_sections(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "app.js").write_text("const p = process.env.HOME;\n")
            report = migrate_report.generate_full_report(project)
        for section in ["executive_summary", "scan", "risk_assessment",
                        "rewrite_suggestions", "rollout_plan", "confidence"]:
            self.assertIn(section, report)

    def test_executive_summary_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "index.js").write_text("require('fs');\n")
            report = migrate_report.generate_full_report(project)
        e = report["executive_summary"]
        self.assertIn("go_decision", e)
        self.assertIn("confidence_score", e)
        self.assertIn("risk_score", e)
        self.assertIn(e["go_decision"], ["GO", "NO-GO"])

    def test_empty_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = migrate_report.generate_full_report(Path(tmpdir))
        self.assertEqual(report["executive_summary"]["apis_detected"], 0)

    def test_report_version_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = migrate_report.generate_full_report(Path(tmpdir))
        self.assertEqual(report["report_version"], "1.0")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = migrate_report.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
