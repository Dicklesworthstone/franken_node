#!/usr/bin/env python3
"""Unit tests for scripts/check_extension_manifest_schema.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_extension_manifest_schema as checker  # noqa: E402


def write_comment_only_fixture(root: Path) -> dict[str, Path]:
    impl_path = root / "crates/franken-node/src/supply_chain/manifest.rs"
    test_path = root / "tests/integration/extension_manifest_admission.rs"
    impl_path.parent.mkdir(parents=True)
    test_path.parent.mkdir(parents=True)

    impl_markers = [
        "pub struct SignedExtensionManifest",
        "pub fn validate_signed_manifest",
        "validate_manifest_with_config",
        "to_engine_manifest",
        "ManifestSchemaError",
        *checker.REQUIRED_LOG_CODES,
    ]
    test_markers = [
        "inv_ems_engine_compatibility_gate",
        "inv_ems_signature_gate_fail_closed",
        "inv_ems_threshold_policy_required",
        "inv_ems_attestation_chain_required",
    ]
    impl_path.write_text(
        "// " + "\n// ".join(impl_markers[:4]) + "\n/*\n" + "\n".join(impl_markers[4:]) + "\n*/\n",
        encoding="utf-8",
    )
    test_path.write_text("// " + "\n// ".join(test_markers) + "\n", encoding="utf-8")
    return {"impl": impl_path, "test": test_path}


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

    def test_malformed_schema_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            schema = Path(tmpdir) / "schema.json"
            schema.write_text("{bad-json", encoding="utf-8")
            with patch.object(checker, "SCHEMA_PATH", schema):
                shape = checker.check_schema_shape()
                caps = checker.check_capability_enum()

        self.assertEqual(shape["status"], "FAIL")
        self.assertEqual(caps["status"], "FAIL")

    def test_non_object_schema_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            schema = Path(tmpdir) / "schema.json"
            schema.write_text("[]", encoding="utf-8")
            with patch.object(checker, "SCHEMA_PATH", schema):
                shape = checker.check_schema_shape()
                caps = checker.check_capability_enum()

        self.assertEqual(shape["status"], "FAIL")
        self.assertEqual(caps["status"], "FAIL")

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

    def test_comment_only_rust_markers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ems-comment-only-") as tmpdir:
            paths = write_comment_only_fixture(Path(tmpdir))
            with (
                patch.object(checker, "RUST_IMPL_PATH", paths["impl"]),
                patch.object(checker, "INTEGRATION_TEST_PATH", paths["test"]),
            ):
                rust_result = checker.check_rust_integration()
                logs_result = checker.check_log_codes()
                integ_result = checker.check_integration_surface()

        self.assertEqual(rust_result["status"], "FAIL")
        self.assertEqual(logs_result["status"], "FAIL")
        self.assertEqual(integ_result["status"], "FAIL")

    def test_strip_rust_comments_preserves_manifest_code_strings(self) -> None:
        source = (
            'const LOG: &str = "MANIFEST_CREATED // literal"; // "MANIFEST_SIGNED"\n'
            'const RAW: &str = r#"pub struct SignedExtensionManifest /* literal */"#;\n'
            "pub/* hidden */ fn validate_signed_manifest() {}\n"
        )

        stripped = checker._strip_rust_comments(source)

        self.assertIn('"MANIFEST_CREATED // literal"', stripped)
        self.assertIn('r#"pub struct SignedExtensionManifest /* literal */"#', stripped)
        self.assertIn("pub  fn validate_signed_manifest() {}", stripped)
        self.assertNotIn('"MANIFEST_SIGNED"', stripped)


if __name__ == "__main__":
    unittest.main()
