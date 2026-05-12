#!/usr/bin/env python3
"""Unit tests for migration_validation_runner.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import migration_validation_runner as runner


class TestDiscoverTests(unittest.TestCase):
    def test_finds_test_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "app.test.js").write_text("")
            (project / "lib.spec.ts").write_text("")
            (project / "util.js").write_text("")
            tests = runner.discover_tests(project)
        self.assertEqual(len(tests), 2)

    def test_ignores_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            nm = project / "node_modules" / "pkg"
            nm.mkdir(parents=True)
            (nm / "index.test.js").write_text("")
            (project / "app.test.js").write_text("")
            tests = runner.discover_tests(project)
        self.assertEqual(len(tests), 1)

    def test_empty_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tests = runner.discover_tests(Path(tmpdir))
        self.assertEqual(len(tests), 0)


class TestCanonicalizeOutput(unittest.TestCase):
    def test_replaces_timestamps(self):
        result = runner.canonicalize_output("at 2024-01-15T10:30:00")
        self.assertIn("<TIMESTAMP>", result)

    def test_replaces_pids(self):
        result = runner.canonicalize_output("pid=12345")
        self.assertIn("pid=<PID>", result)

    def test_replaces_abs_paths(self):
        result = runner.canonicalize_output("/home/user/project/file.js")
        self.assertIn("<ABS_PATH>", result)

    def test_preserves_normal_text(self):
        result = runner.canonicalize_output("hello world")
        self.assertEqual(result, "hello world")


class TestCompareOutputs(unittest.TestCase):
    def test_identical(self):
        cmp = runner.compare_outputs("a\nb\nc", "a\nb\nc")
        self.assertTrue(cmp["identical"])
        self.assertEqual(cmp["divergence_count"], 0)

    def test_divergent(self):
        cmp = runner.compare_outputs("a\nb", "a\nc")
        self.assertFalse(cmp["identical"])
        self.assertEqual(cmp["divergence_count"], 1)

    def test_different_lengths(self):
        cmp = runner.compare_outputs("a\nb\nc", "a\nb")
        self.assertFalse(cmp["identical"])

    def test_canonicalizes_before_compare(self):
        cmp = runner.compare_outputs(
            "at 2024-01-01T00:00:00 pid=1",
            "at 2025-12-31T23:59:59 pid=999",
        )
        self.assertTrue(cmp["identical"])


class TestClassifyDivergenceSeverity(unittest.TestCase):
    def test_core_is_critical(self):
        self.assertEqual(runner.classify_divergence_severity([{}], "core"), "critical")

    def test_high_value_is_high(self):
        self.assertEqual(runner.classify_divergence_severity([{}], "high-value"), "high")

    def test_edge_is_informational(self):
        self.assertEqual(runner.classify_divergence_severity([{}], "edge"), "informational")

    def test_no_divergences_is_none(self):
        self.assertEqual(runner.classify_divergence_severity([], "core"), "none")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = runner.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_cites_primary_implementations(self):
        result = runner.self_test()
        self.assertEqual(
            result["evidence_paths"]["migration_validation_runner"],
            "scripts/migration_validation_runner.py",
        )
        self.assertEqual(
            result["evidence_paths"]["lockstep_harness"],
            "crates/franken-node/src/runtime/lockstep_harness.rs",
        )
        self.assertIn("VALIDATE-IMPL", {check["id"] for check in result["checks"]})

    def test_checked_in_evidence_cites_primary_implementations(self):
        evidence_path = (
            Path(__file__).resolve().parent.parent
            / "artifacts"
            / "section_10_3"
            / "bd-2st"
            / "verification_evidence.json"
        )
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(
            evidence["evidence_paths"]["migration_validation_runner"],
            "scripts/migration_validation_runner.py",
        )
        self.assertEqual(
            evidence["evidence_paths"]["lockstep_harness"],
            "crates/franken-node/src/runtime/lockstep_harness.rs",
        )


if __name__ == "__main__":
    unittest.main()
