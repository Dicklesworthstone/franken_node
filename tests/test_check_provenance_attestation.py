#!/usr/bin/env python3
"""Unit tests for scripts/check_provenance_attestation.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_provenance_attestation as checker


class TestProvenanceAttestationVerifier(unittest.TestCase):
    def test_required_schema_fields_are_stable(self) -> None:
        self.assertIn("source_repository_url", checker.REQUIRED_SCHEMA_FIELDS)
        self.assertIn("build_system_identifier", checker.REQUIRED_SCHEMA_FIELDS)
        self.assertIn("builder_version", checker.REQUIRED_SCHEMA_FIELDS)
        self.assertIn("reproducibility_hash", checker.REQUIRED_SCHEMA_FIELDS)
        self.assertIn("vcs_commit_sha", checker.REQUIRED_SCHEMA_FIELDS)

    def test_spec_contract_check_passes(self) -> None:
        result = checker.check_spec_contract()
        self.assertEqual(result["id"], "PAT-SPEC")
        self.assertEqual(result["status"], "PASS")

    def test_schema_fields_check_passes(self) -> None:
        result = checker.check_schema_fields()
        self.assertEqual(result["id"], "PAT-SCHEMA")
        self.assertEqual(result["status"], "PASS")

    def test_schema_envelope_formats_check_passes(self) -> None:
        result = checker.check_schema_envelope_formats()
        self.assertEqual(result["id"], "PAT-ENVELOPE")
        self.assertEqual(result["status"], "PASS")

    def test_rust_implementation_check_passes(self) -> None:
        result = checker.check_rust_implementation()
        self.assertEqual(result["id"], "PAT-RUST")
        self.assertEqual(result["status"], "PASS")

    def test_integration_surface_check_passes(self) -> None:
        result = checker.check_integration_surface()
        self.assertEqual(result["id"], "PAT-INTEG")
        self.assertEqual(result["status"], "PASS")

    def test_fixture_cases_check_passes(self) -> None:
        result = checker.check_fixture_cases()
        self.assertEqual(result["id"], "PAT-FIXTURE")
        self.assertEqual(result["status"], "PASS")

    def test_chain_report_check_passes(self) -> None:
        result = checker.check_chain_report_artifact()
        self.assertEqual(result["id"], "PAT-ARTIFACT")
        self.assertEqual(result["status"], "PASS")

    def test_missing_schema_is_detected(self) -> None:
        with patch.object(checker, "SCHEMA_PATH", Path("/nonexistent/schema.json")):
            result = checker.check_schema_fields()
            self.assertEqual(result["status"], "FAIL")

    def test_summary_markdown_has_table(self) -> None:
        report = {
            "verdict": "PASS",
            "checks": [
                {"id": "PAT-SPEC", "description": "Spec check", "status": "PASS"},
                {"id": "PAT-SCHEMA", "description": "Schema check", "status": "PASS"},
            ],
            "summary": {"total_checks": 2, "passing_checks": 2, "failing_checks": 0},
        }
        markdown = checker._make_summary_md(report)
        self.assertIn("| Check | Description | Status |", markdown)
        self.assertIn("## Verdict: PASS", markdown)

    def test_collect_checks_count(self) -> None:
        checks = checker.collect_checks()
        self.assertEqual(len(checks), 7)


if __name__ == "__main__":
    unittest.main()
