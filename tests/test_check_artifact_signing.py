"""Unit tests for scripts/check_artifact_signing.py (bd-2pw)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_artifact_signing",
    ROOT / "scripts" / "check_artifact_signing.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFilePaths(TestCase):
    """Verify all expected files are present on disk."""

    def test_spec_exists(self) -> None:
        self.assertTrue(mod.SPEC_PATH.is_file(), f"missing: {mod.SPEC_PATH}")

    def test_policy_exists(self) -> None:
        self.assertTrue(mod.POLICY_PATH.is_file(), f"missing: {mod.POLICY_PATH}")

    def test_rust_impl_exists(self) -> None:
        self.assertTrue(mod.RUST_IMPL_PATH.is_file(), f"missing: {mod.RUST_IMPL_PATH}")

    def test_mod_rs_exists(self) -> None:
        self.assertTrue(mod.MOD_PATH.is_file(), f"missing: {mod.MOD_PATH}")

    def test_cli_exists(self) -> None:
        self.assertTrue(mod.CLI_PATH.is_file(), f"missing: {mod.CLI_PATH}")

    def test_main_exists(self) -> None:
        self.assertTrue(mod.MAIN_PATH.is_file(), f"missing: {mod.MAIN_PATH}")


class TestSafeRel(TestCase):
    """Verify _safe_rel path helper."""

    def test_relative_to_root(self) -> None:
        result = mod._safe_rel(mod.SPEC_PATH)
        self.assertNotIn(str(ROOT), result)
        self.assertIn("bd-2pw_contract.md", result)

    def test_unrelated_path_fallback(self) -> None:
        result = mod._safe_rel(Path("/tmp/not_in_root/file.txt"))
        self.assertIn("/tmp/not_in_root/file.txt", result)


class TestCheckFileExists(TestCase):
    """Verify file existence check helper."""

    def test_existing_file(self) -> None:
        result = mod.check_file_exists(mod.RUST_IMPL_PATH)
        self.assertTrue(result["exists"])
        self.assertGreater(result["size_bytes"], 0)

    def test_missing_file(self) -> None:
        result = mod.check_file_exists(ROOT / "does_not_exist.rs")
        self.assertFalse(result["exists"])
        self.assertEqual(result["size_bytes"], 0)


class TestCheckContent(TestCase):
    """Verify content matching helper."""

    def test_all_found(self) -> None:
        result = mod.check_content("rust", mod.RUST_IMPL_PATH, ["pub struct KeyRing"])
        self.assertTrue(result["pass"])
        self.assertEqual(len(result["missing"]), 0)

    def test_missing_pattern(self) -> None:
        result = mod.check_content("rust", mod.RUST_IMPL_PATH, ["THIS_PATTERN_DOES_NOT_EXIST_XYZ"])
        self.assertFalse(result["pass"])
        self.assertIn("THIS_PATTERN_DOES_NOT_EXIST_XYZ", result["missing"])

    def test_file_not_found(self) -> None:
        result = mod.check_content("rust", ROOT / "nope.rs", ["anything"])
        self.assertFalse(result["pass"])


class TestSpecInvariants(TestCase):
    """Verify spec contains all invariants."""

    def test_all_invariants_present(self) -> None:
        result = mod.check_content("spec", mod.SPEC_PATH, mod.REQUIRED_INVARIANTS)
        self.assertTrue(result["pass"], f"missing invariants: {result.get('missing', [])}")

    def test_all_event_codes_present(self) -> None:
        result = mod.check_content("spec", mod.SPEC_PATH, mod.REQUIRED_EVENT_CODES)
        self.assertTrue(result["pass"], f"missing event codes: {result.get('missing', [])}")


class TestRustSymbols(TestCase):
    """Verify Rust impl contains required symbols."""

    def test_all_symbols(self) -> None:
        result = mod.check_content("rust", mod.RUST_IMPL_PATH, mod.REQUIRED_RUST_SYMBOLS)
        self.assertTrue(result["pass"], f"missing symbols: {result.get('missing', [])}")

    def test_all_error_variants(self) -> None:
        result = mod.check_content("rust", mod.RUST_IMPL_PATH, mod.REQUIRED_ERROR_VARIANTS)
        self.assertTrue(result["pass"], f"missing error variants: {result.get('missing', [])}")

    def test_all_rust_tests(self) -> None:
        result = mod.check_content("rust", mod.RUST_IMPL_PATH, mod.REQUIRED_TESTS)
        self.assertTrue(result["pass"], f"missing rust tests: {result.get('missing', [])}")


class TestModRegistration(TestCase):
    """Verify module is registered in mod.rs."""

    def test_registered(self) -> None:
        result = mod.check_mod_registration()
        self.assertTrue(result["pass"])
        self.assertTrue(result["registered"])


class TestTestCount(TestCase):
    """Verify sufficient Rust test count."""

    def test_at_least_20_tests(self) -> None:
        result = mod.check_test_count()
        self.assertTrue(result["pass"], f"only {result['count']} tests found, need >= 20")
        self.assertGreaterEqual(result["count"], 20)


class TestSigningScheme(TestCase):
    """Verify Ed25519 + SHA-256 usage."""

    def test_scheme_check(self) -> None:
        result = mod.check_signing_scheme()
        self.assertTrue(result["pass"])
        self.assertTrue(result["ed25519"])
        self.assertTrue(result["sha256"])


class TestThresholdLogic(TestCase):
    """Verify threshold signing implementation."""

    def test_threshold_check(self) -> None:
        result = mod.check_threshold_logic()
        self.assertTrue(result["pass"])
        self.assertTrue(result["partial_signatures"])
        self.assertTrue(result["collect_function"])
        self.assertTrue(result["deduplication"])
        self.assertTrue(result["threshold_error"])


class TestKeyRotationLogic(TestCase):
    """Verify key rotation implementation."""

    def test_rotation_check(self) -> None:
        result = mod.check_key_rotation_logic()
        self.assertTrue(result["pass"])
        self.assertTrue(result["transition_record"])
        self.assertTrue(result["create_fn"])
        self.assertTrue(result["verify_fn"])
        self.assertTrue(result["endorsement_flow"])


class TestManifestFormat(TestCase):
    """Verify manifest format implementation."""

    def test_format_check(self) -> None:
        result = mod.check_manifest_format()
        self.assertTrue(result["pass"])
        self.assertTrue(result["canonical_serialization"])
        self.assertTrue(result["ordered_entries"])
        self.assertTrue(result["format_fields"])


class TestCLIPatterns(TestCase):
    """Verify CLI wiring."""

    def test_cli_patterns(self) -> None:
        result = mod.check_content("cli", mod.CLI_PATH, mod.REQUIRED_CLI_PATTERNS)
        self.assertTrue(result["pass"], f"missing CLI patterns: {result.get('missing', [])}")

    def test_main_patterns(self) -> None:
        result = mod.check_content("main", mod.MAIN_PATH, mod.REQUIRED_MAIN_PATTERNS)
        self.assertTrue(result["pass"], f"missing main patterns: {result.get('missing', [])}")


class TestRunAllChecks(TestCase):
    """Integration tests for run_all_checks."""

    def test_report_structure(self) -> None:
        report = mod.run_all_checks()
        self.assertEqual(report["bead_id"], "bd-2pw")
        self.assertEqual(report["section"], "10.6")
        self.assertIn("checks", report)
        self.assertIn("summary", report)
        self.assertIn("overall_pass", report)

    def test_overall_pass(self) -> None:
        report = mod.run_all_checks()
        self.assertTrue(report["overall_pass"], f"failed checks: {report['summary']}")

    def test_all_checks_present(self) -> None:
        report = mod.run_all_checks()
        expected_keys = [
            "files", "spec_invariants", "spec_event_codes", "rust_symbols",
            "error_variants", "rust_event_codes", "rust_tests", "cli_patterns",
            "main_patterns", "mod_registration", "test_count", "signing_scheme",
            "threshold_logic", "key_rotation_logic", "manifest_format",
        ]
        for key in expected_keys:
            self.assertIn(key, report["checks"], f"missing check category: {key}")


class TestSelfTest(TestCase):
    """Verify self_test function."""

    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertTrue(result)


class TestMissingFile(TestCase):
    """Verify graceful handling of missing files."""

    def test_missing_impl(self) -> None:
        with patch.object(mod, "RUST_IMPL_PATH", ROOT / "does" / "not" / "exist.rs"):
            report = mod.run_all_checks()
        self.assertFalse(report["overall_pass"])

    def test_missing_spec(self) -> None:
        with patch.object(mod, "SPEC_PATH", ROOT / "does" / "not" / "exist.md"):
            report = mod.run_all_checks()
        self.assertFalse(report["overall_pass"])


if __name__ == "__main__":
    main()
