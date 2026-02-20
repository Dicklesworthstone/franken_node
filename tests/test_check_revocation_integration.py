#!/usr/bin/env python3
"""Unit tests for scripts/check_revocation_integration.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_revocation_integration as checker


class TestRevocationIntegrationVerifier(unittest.TestCase):
    def test_spec_contract_check_passes(self) -> None:
        result = checker.check_spec_contract()
        self.assertEqual(result["id"], "REV-SPEC")
        self.assertEqual(result["status"], "PASS")

    def test_rust_implementation_check_passes(self) -> None:
        result = checker.check_rust_implementation()
        self.assertEqual(result["id"], "REV-RUST")
        self.assertEqual(result["status"], "PASS")

    def test_module_export_check_passes(self) -> None:
        result = checker.check_module_export()
        self.assertEqual(result["id"], "REV-MOD")
        self.assertEqual(result["status"], "PASS")

    def test_integration_surface_check_passes(self) -> None:
        result = checker.check_integration_surface()
        self.assertEqual(result["id"], "REV-INTEG")
        self.assertEqual(result["status"], "PASS")

    def test_fixture_check_passes(self) -> None:
        result = checker.check_fixture_cases()
        self.assertEqual(result["id"], "REV-FIXTURE")
        self.assertEqual(result["status"], "PASS")

    def test_decision_artifact_check_passes(self) -> None:
        result = checker.check_decision_artifact()
        self.assertEqual(result["id"], "REV-ARTIFACT")
        self.assertEqual(result["status"], "PASS")

    def test_missing_spec_is_detected(self) -> None:
        with patch.object(checker, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = checker.check_spec_contract()
            self.assertEqual(result["status"], "FAIL")

    def test_missing_fixture_is_detected(self) -> None:
        with patch.object(checker, "FIXTURE_PATH", Path("/nonexistent/fixture.json")):
            result = checker.check_fixture_cases()
            self.assertEqual(result["status"], "FAIL")

    def test_collect_checks_count(self) -> None:
        checks = checker.collect_checks()
        self.assertEqual(len(checks), 6)

    def test_summary_markdown_has_table(self) -> None:
        report = {
            "verdict": "PASS",
            "checks": [
                {"id": "REV-SPEC", "description": "Spec", "status": "PASS"},
                {"id": "REV-RUST", "description": "Rust", "status": "PASS"},
            ],
            "summary": {"total_checks": 2, "passing_checks": 2, "failing_checks": 0},
        }
        markdown = checker._make_summary_md(report)
        self.assertIn("| Check | Description | Status |", markdown)
        self.assertIn("## Verdict: PASS", markdown)


if __name__ == "__main__":
    unittest.main()
