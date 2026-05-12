#!/usr/bin/env python3
"""Unit tests for check_compat_ci_gate.py."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_compat_ci_gate as gate


class TestGateSpecExists(unittest.TestCase):
    def test_spec_exists(self):
        result = gate.check_gate_spec_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["details"]["spec_exists"])
        self.assertTrue(result["details"]["governance_exists"])


class TestGovernanceReferences(unittest.TestCase):
    def test_governance_mentions_required_concepts(self):
        result = gate.check_governance_references()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["details"]["governance_mentions_spec_refs"])
        self.assertTrue(result["details"]["governance_mentions_fixtures"])


class TestFixtureCorpusExists(unittest.TestCase):
    def test_corpus_has_fixtures(self):
        result = gate.check_fixture_corpus_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertGreaterEqual(result["details"]["fixture_count"], 5)


class TestRegistryHasEntries(unittest.TestCase):
    def test_registry_populated(self):
        result = gate.check_registry_has_entries()
        self.assertEqual(result["status"], "PASS")
        self.assertGreaterEqual(result["details"]["entry_count"], 1)

    def test_missing_registry_fails(self):
        with patch.object(gate, "REGISTRY_PATH", Path("/nonexistent.json")):
            result = gate.check_registry_has_entries()
            self.assertEqual(result["status"], "FAIL")


class TestImplementationCompliance(unittest.TestCase):
    def assert_single_violation(self, body, **expected_flags):
        with tempfile.TemporaryDirectory() as tmpdir:
            compat_dir = Path(tmpdir)
            rs_file = compat_dir / "test_shim.rs"
            rs_file.write_text(body, encoding="utf-8")
            with patch.object(gate, "COMPAT_SRC_DIRS", [compat_dir]):
                result = gate.check_implementation_compliance()
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(len(result["details"]["violations"]), 1)
        violation = result["details"]["violations"][0]
        for key, value in expected_flags.items():
            self.assertEqual(violation[key], value)

    def test_no_compat_files_passes(self):
        result = gate.check_implementation_compliance()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["details"]["compat_files_found"], 0)

    def test_noncompliant_file_fails(self):
        self.assert_single_violation(
            "fn stub() { /* no refs */ }",
            missing_spec_ref=True,
            missing_fixture_ref=True,
            missing_band_decl=True,
        )

    def test_compliant_file_passes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            compat_dir = Path(tmpdir)
            rs_file = compat_dir / "fs_shim.rs"
            rs_file.write_text(
                "// Spec: Section 10.2\n"
                "// fixture:fs:readFile:utf8-basic\n"
                "// Band: core\n"
                "fn read_file() {}\n",
                encoding="utf-8",
            )
            with patch.object(gate, "COMPAT_SRC_DIRS", [compat_dir]):
                result = gate.check_implementation_compliance()
                self.assertEqual(result["status"], "PASS")

    def test_missing_spec_reference_fails(self):
        self.assert_single_violation(
            "// fixture:fs:readFile:utf8-basic\n"
            "// Band: core\n"
            "fn read_file() {}\n",
            missing_spec_ref=True,
            missing_fixture_ref=False,
            missing_band_decl=False,
        )

    def test_missing_fixture_reference_fails(self):
        self.assert_single_violation(
            "// Spec: Section 10.2\n"
            "// Band: core\n"
            "fn read_file() {}\n",
            missing_spec_ref=False,
            missing_fixture_ref=True,
            missing_band_decl=False,
        )

    def test_missing_band_declaration_fails(self):
        self.assert_single_violation(
            "// Spec: Section 10.2\n"
            "// fixture:fs:readFile:utf8-basic\n"
            "fn read_file() {}\n",
            missing_spec_ref=False,
            missing_fixture_ref=False,
            missing_band_decl=True,
        )

    def test_unresolved_fixture_reference_fails(self):
        self.assert_single_violation(
            "// Spec: Section 10.2\n"
            "// fixture:fs:readFile:not-in-corpus\n"
            "// Band: core\n"
            "fn read_file() {}\n",
            missing_spec_ref=False,
            missing_fixture_ref=False,
            missing_band_decl=False,
            unresolved_fixtures=["fixture:fs:readFile:not-in-corpus"],
        )


class TestCollectFixtureIds(unittest.TestCase):
    def test_collects_ids(self):
        ids = gate.collect_fixture_ids()
        self.assertGreater(len(ids), 0)
        for fid in ids:
            self.assertTrue(fid.startswith("fixture:"))


class TestPatterns(unittest.TestCase):
    def test_spec_ref_pattern(self):
        self.assertTrue(gate.SPEC_REF_PATTERN.search("Spec: Section 10.2"))
        self.assertTrue(gate.SPEC_REF_PATTERN.search("ADR-001"))
        self.assertTrue(gate.SPEC_REF_PATTERN.search("docs/specs/foo"))
        self.assertIsNone(gate.SPEC_REF_PATTERN.search("nothing here"))

    def test_fixture_ref_pattern(self):
        self.assertTrue(gate.FIXTURE_REF_PATTERN.search("fixture:fs:readFile:utf8-basic"))
        self.assertIsNone(gate.FIXTURE_REF_PATTERN.search("not a fixture ref"))

    def test_band_pattern(self):
        self.assertTrue(gate.BAND_PATTERN.search("core"))
        self.assertTrue(gate.BAND_PATTERN.search("high-value"))
        self.assertIsNone(gate.BAND_PATTERN.search("invalid-band"))


if __name__ == "__main__":
    unittest.main()
