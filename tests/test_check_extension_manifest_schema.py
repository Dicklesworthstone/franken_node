#!/usr/bin/env python3
"""Unit tests for scripts/check_extension_manifest_schema.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_extension_manifest_schema as checker


class TestManifestSchemaVerifier(unittest.TestCase):
    def test_required_capabilities_are_stable(self) -> None:
        self.assertEqual(
            checker.REQUIRED_CAPABILITIES,
            ["fs_read", "fs_write", "network_egress", "process_spawn", "env_read"],
        )

    def test_spec_contract_check_passes(self) -> None:
        result = checker.check_spec_contract()
        self.assertEqual(result["id"], "EMS-SPEC")
        self.assertEqual(result["status"], "PASS")

    def test_schema_shape_check_passes(self) -> None:
        result = checker.check_schema_shape()
        self.assertEqual(result["id"], "EMS-SCHEMA")
        self.assertEqual(result["status"], "PASS")

    def test_capability_enum_check_passes(self) -> None:
        result = checker.check_capability_enum()
        self.assertEqual(result["id"], "EMS-CAPS")
        self.assertEqual(result["status"], "PASS")

    def test_rust_integration_check_passes(self) -> None:
        result = checker.check_rust_integration()
        self.assertEqual(result["id"], "EMS-RUST")
        self.assertEqual(result["status"], "PASS")

    def test_log_codes_check_passes(self) -> None:
        result = checker.check_log_codes()
        self.assertEqual(result["id"], "EMS-LOGS")
        self.assertEqual(result["status"], "PASS")

    def test_integration_surface_check_passes(self) -> None:
        result = checker.check_integration_surface()
        self.assertEqual(result["id"], "EMS-INTEG")
        self.assertEqual(result["status"], "PASS")

    def test_missing_schema_is_detected(self) -> None:
        with patch.object(checker, "SCHEMA_PATH", Path("/nonexistent/schema.json")):
            result = checker.check_schema_shape()
            self.assertEqual(result["status"], "FAIL")

    def test_summary_markdown_has_table(self) -> None:
        report = {
            "verdict": "PASS",
            "checks": [
                {"id": "EMS-SPEC", "description": "Spec check", "status": "PASS"},
                {"id": "EMS-SCHEMA", "description": "Schema check", "status": "PASS"},
            ],
            "summary": {"total_checks": 2, "passing_checks": 2, "failing_checks": 0},
        }
        markdown = checker._make_summary_md(report)
        self.assertIn("| Check | Description | Status |", markdown)
        self.assertIn("## Verdict: PASS", markdown)

    def test_collect_checks_count(self) -> None:
        checks = checker.collect_checks()
        self.assertEqual(len(checks), 6)


if __name__ == "__main__":
    unittest.main()
