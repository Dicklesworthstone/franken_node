#!/usr/bin/env python3
"""Tests for bd-33u2: Verifier/benchmark releases gate."""
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_verifier_benchmark_releases.py")


def _load():
    spec = importlib.util.spec_from_file_location("chk", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load verifier benchmark release checker")
    spec.loader.exec_module(mod)
    return mod


def _run_json():
    proc = subprocess.run(
        [sys.executable, SCRIPT, "--json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise AssertionError(proc.stderr)
    return json.JSONDecoder().decode(proc.stdout)


mod = _load()


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


class TestJsonOutput(unittest.TestCase):
    def test_json_has_required_keys(self):
        d = _run_json()
        for k in ("bead_id", "section", "gate_script", "checks_passed", "checks_total", "verdict", "checks"):
            self.assertIn(k, d)

    def test_bead_id(self):
        d = _run_json()
        self.assertEqual(d["bead_id"], "bd-33u2")
        self.assertEqual(d["section"], "16")

    def test_verdict_field(self):
        self.assertIn(_run_json()["verdict"], ("PASS", "FAIL"))

    def test_checks_is_list(self):
        d = _run_json()
        self.assertIsInstance(d["checks"], list)
        self.assertGreaterEqual(len(d["checks"]), 16)

    def test_each_check_has_fields(self):
        for c in _run_json()["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)


class TestIndividualChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {x["check"]: x for x in mod._checks()}

    def test_source_exists(self):
        self.assertTrue(self.results["source_exists"]["passed"])

    def test_module_wiring(self):
        self.assertTrue(self.results["module_wiring"]["passed"])

    def test_release_types(self):
        self.assertTrue(self.results["release_types"]["passed"])

    def test_release_lifecycle(self):
        self.assertTrue(self.results["release_lifecycle"]["passed"])

    def test_struct_tool_release(self):
        self.assertTrue(self.results["struct_ToolRelease"]["passed"])

    def test_struct_release_artifact(self):
        self.assertTrue(self.results["struct_ReleaseArtifact"]["passed"])

    def test_struct_download_record(self):
        self.assertTrue(self.results["struct_DownloadRecord"]["passed"])

    def test_struct_adoption_metrics(self):
        self.assertTrue(self.results["struct_AdoptionMetrics"]["passed"])

    def test_struct_verifier_benchmark_releases(self):
        self.assertTrue(self.results["struct_VerifierBenchmarkReleases"]["passed"])

    def test_download_tracking(self):
        self.assertTrue(self.results["download_tracking"]["passed"])

    def test_quality_gating(self):
        self.assertTrue(self.results["quality_gating"]["passed"])

    def test_changelog_support(self):
        self.assertTrue(self.results["changelog_support"]["passed"])

    def test_content_hash(self):
        self.assertTrue(self.results["content_hash"]["passed"])

    def test_metrics_hashing(self):
        self.assertTrue(self.results["metrics_hashing"]["passed"])

    def test_event_codes(self):
        self.assertTrue(self.results["event_codes"]["passed"])

    def test_invariants(self):
        self.assertTrue(self.results["invariants"]["passed"])

    def test_audit_log(self):
        self.assertTrue(self.results["audit_log"]["passed"])

    def test_schema_version(self):
        self.assertTrue(self.results["schema_version"]["passed"])

    def test_spec_alignment(self):
        self.assertTrue(self.results["spec_alignment"]["passed"])

    def test_test_coverage(self):
        self.assertTrue(self.results["test_coverage"]["passed"])


class TestCommentOnlyRegressions(unittest.TestCase):
    def test_comment_only_impl_markers_fail_closed(self):
        comment_only_impl = """
// pub enum ReleaseType { VerifierTool, BenchmarkSuite, TestHarness, ComplianceChecker, DocumentationKit }
// pub enum ReleaseStatus { Draft, Published, Deprecated, Archived }
// pub struct ToolRelease;
// pub struct ReleaseArtifact;
// pub struct DownloadRecord;
// pub struct AdoptionMetrics;
// pub struct VerifierBenchmarkReleases;
// pub struct VbrAuditRecord;
// pub fn record_download() {}
// pub fn publish_release() {}
// pub fn update_changelog() {}
// pub fn generate_metrics() {}
// pub fn export_audit_log_jsonl() {}
// pub const VBR_RELEASE_CREATED: &str = "VBR-001";
// pub const VBR_ARTIFACT_ADDED: &str = "VBR-002";
// pub const VBR_DOWNLOAD_RECORDED: &str = "VBR-003";
// pub const VBR_STATUS_CHANGED: &str = "VBR-004";
// pub const VBR_METRICS_COMPUTED: &str = "VBR-005";
// pub const VBR_COMPAT_GENERATED: &str = "VBR-006";
// pub const VBR_CHANGELOG_UPDATED: &str = "VBR-007";
// pub const VBR_QUALITY_CHECKED: &str = "VBR-008";
// pub const VBR_VERSION_EMBEDDED: &str = "VBR-009";
// pub const VBR_CATALOG_GENERATED: &str = "VBR-010";
// pub const VBR_ERR_QUALITY_BELOW_THRESHOLD: &str = "VBR-ERR-001";
// pub const VBR_ERR_INVALID_RELEASE: &str = "VBR-ERR-002";
// pub const INV_VBR_TYPED: &str = "INV-VBR-TYPED";
// pub const INV_VBR_TRACKED: &str = "INV-VBR-TRACKED";
// pub const INV_VBR_DETERMINISTIC: &str = "INV-VBR-DETERMINISTIC";
// pub const INV_VBR_GATED: &str = "INV-VBR-GATED";
// pub const INV_VBR_VERSIONED: &str = "INV-VBR-VERSIONED";
// pub const INV_VBR_AUDITABLE: &str = "INV-VBR-AUDITABLE";
// pub const SCHEMA_VERSION: &str = "vbr-v1.0";
// #[test]
// #[test]
// #[test]
"""
        with patch.object(mod, "_impl_code", lambda: mod._strip_rust_comments(comment_only_impl)):
            results = {x["check"]: x for x in mod._checks()}
        for check in (
            "release_types",
            "release_lifecycle",
            "struct_ToolRelease",
            "download_tracking",
            "quality_gating",
            "event_codes",
            "invariants",
            "audit_log",
            "schema_version",
            "test_coverage",
        ):
            self.assertFalse(results[check]["passed"], check)

    def test_comment_only_module_wiring_fails_closed(self):
        with patch.object(mod, "_mod_code", lambda: mod._strip_rust_comments("// pub mod verifier_benchmark_releases;")):
            results = {x["check"]: x for x in mod._checks()}
        self.assertFalse(results["module_wiring"]["passed"])


class TestOverall(unittest.TestCase):
    def test_all_pass(self):
        failed = [x["check"] for x in mod._checks() if not x["passed"]]
        self.assertFalse(failed, f"Failed: {failed}")

    def test_minimum_check_count(self):
        self.assertGreaterEqual(len(mod._checks()), 16)
