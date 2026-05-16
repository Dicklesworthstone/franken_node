"""Unit tests for scripts/check_vef_evidence_capsule.py (bd-3pds)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_evidence_capsule.py"

spec = importlib.util.spec_from_file_location("check_vef_evidence_capsule", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Unable to import VEF evidence capsule checker from {SCRIPT}")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-3pds")
        self.assertEqual(result["section"], "10.18")
        self.assertIn(result["verdict"], ("PASS", "FAIL"))
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertEqual(result["total"], len(result["checks"]))

    def test_check_entries_shape(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)
            self.assertIsInstance(check["check"], str)
            self.assertIsInstance(check["pass"], bool)
            self.assertIsInstance(check["detail"], str)

    def test_has_timestamp(self) -> None:
        result = mod.run_all()
        self.assertIn("timestamp", result)

    def test_total_checks_count(self) -> None:
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 50)


class TestVerdict(unittest.TestCase):
    def test_all_impl_checks_pass(self) -> None:
        result = mod.run_all()
        impl_checks = [c for c in result["checks"] if c["check"].startswith("impl_")]
        for c in impl_checks:
            self.assertTrue(c["pass"], f"FAIL: {c['check']}: {c['detail']}")


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_self_test_shape(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["mode"], "self-test")
        self.assertGreaterEqual(result["total"], 8)
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    @staticmethod
    def _failures(result: dict) -> str:
        return "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in result["checks"] if not c["pass"])


class TestCli(unittest.TestCase):
    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_self_test_json_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-3pds")
        self.assertEqual(parsed["mode"], "self-test")

    def test_json_output_parseable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-3pds")
        self.assertIn("checks", parsed)


class TestConstants(unittest.TestCase):
    def test_bead_id(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-3pds")

    def test_section(self) -> None:
        self.assertEqual(mod.SECTION, "10.18")

    def test_symbol_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_SYMBOLS), 18)

    def test_event_code_count(self) -> None:
        self.assertEqual(len(mod.EVENT_CODES), 5)

    def test_error_code_count(self) -> None:
        self.assertEqual(len(mod.ERROR_CODES), 6)

    def test_error_variant_count(self) -> None:
        self.assertEqual(len(mod.ERROR_VARIANTS), 6)

    def test_invariant_count(self) -> None:
        self.assertEqual(len(mod.INVARIANTS), 4)


class TestRustCommentStripping(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self) -> None:
        source = "\n".join(
            [
                'pub const URL: &str = "https://example.test//kept"; // pub struct CommentOnly',
                'pub const BLOCKY: &str = "not /* a comment */"; /* pub fn fake() {} */',
                'pub const RAW: &str = r#"raw // kept /* kept */"#;',
                "/* outer /* nested */ still comment */ pub struct RealMarker;",
            ]
        )

        stripped = mod._strip_rust_comments(source)

        self.assertIn('"https://example.test//kept"', stripped)
        self.assertIn('"not /* a comment */"', stripped)
        self.assertIn('r#"raw // kept /* kept */"#', stripped)
        self.assertIn("pub struct RealMarker;", stripped)
        self.assertNotIn("CommentOnly", stripped)
        self.assertNotIn("fake()", stripped)
        self.assertNotIn("nested", stripped)


class TestCommentOnlyRegressions(unittest.TestCase):
    def test_comment_only_impl_markers_fail_closed(self) -> None:
        original_impl = mod.IMPL_FILE
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                fake_impl = Path(tmpdir) / "evidence_capsule.rs"
                fake_impl.write_text(
                    "\n".join(
                        [
                            "// pub struct VefEvidence {}",
                            "// pub struct EvidenceCapsule {}",
                            "// pub struct CapsuleVerificationResult {}",
                            "// pub struct ExternalVerifierEndpoint {}",
                            "// pub struct ExportManifest {}",
                            "// pub struct VerifierRegistry {}",
                            "// pub enum CapsuleError { EmptyEvidence, AlreadySealed }",
                            '// pub const EVIDENCE_CAPSULE_CREATED: &str = "EVIDENCE_CAPSULE_CREATED";',
                            '// pub const ERR_CAPSULE_EMPTY_EVIDENCE: &str = "ERR_CAPSULE_EMPTY_EVIDENCE";',
                            '// pub const INV_EVIDENCE_CAPSULE_COMPLETE: &str = "INV-EVIDENCE-CAPSULE-COMPLETE";',
                            "// pub fn new() {}",
                            "// pub fn seal() {}",
                            "// #[test]",
                            "// fn comment_only_test() {}",
                        ]
                    ),
                    encoding="utf-8",
                )
                mod.IMPL_FILE = fake_impl
                mod.RESULTS.clear()

                mod.check_impl_symbols()
                mod.check_event_codes()
                mod.check_error_codes()
                mod.check_error_variants()
                mod.check_invariants()
                mod.check_unit_tests()
        finally:
            mod.IMPL_FILE = original_impl

        by_name = {entry["check"]: entry for entry in mod.RESULTS}
        self.assertFalse(by_name["impl_symbol_VefEvidence"]["pass"])
        self.assertFalse(by_name["impl_symbol_new"]["pass"])
        self.assertFalse(by_name["event_EVIDENCE_CAPSULE_CREATED"]["pass"])
        self.assertFalse(by_name["error_code_ERR_CAPSULE_EMPTY_EVIDENCE"]["pass"])
        self.assertFalse(by_name["error_variant_EmptyEvidence"]["pass"])
        self.assertFalse(by_name["invariant_INV-EVIDENCE-CAPSULE-COMPLETE"]["pass"])
        self.assertFalse(by_name["impl_minimum_unit_tests"]["pass"])

    def test_comment_only_mod_wiring_fails_closed(self) -> None:
        original_mod = mod.MOD_FILE
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                fake_mod = Path(tmpdir) / "mod.rs"
                fake_mod.write_text("// pub mod evidence_capsule;\n", encoding="utf-8")
                mod.MOD_FILE = fake_mod
                mod.RESULTS.clear()

                mod.check_mod_wiring()
        finally:
            mod.MOD_FILE = original_mod

        by_name = {entry["check"]: entry for entry in mod.RESULTS}
        self.assertFalse(by_name["mod_wires_evidence_capsule"]["pass"])


if __name__ == "__main__":
    unittest.main()
