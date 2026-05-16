"""Unit tests for check_bpet_economic.py verification script."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import check_bpet_economic as mod  # noqa: E402

SCRIPT = ROOT / "scripts" / "check_bpet_economic.py"


def run_script(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def run_json_script() -> dict:
    result = run_script("--json")
    try:
        return json.JSONDecoder().decode(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON output: {result.stdout}\n{result.stderr}") from exc


class TestRustCommentStripping(unittest.TestCase):
    def test_preserves_string_literals_while_stripping_comments(self):
        source = "\n".join(
            [
                'pub const URL: &str = "https://example.test//kept"; // pub struct PhenotypeTrajectory',
                'pub const BLOCKY: &str = "not /* a comment */"; /* fn compromise_propensity() {} */',
                'pub const RAW: &str = r#"raw // kept /* kept */"#;',
                "/* outer /* nested */ still comment */ pub struct RealMarker;",
            ]
        )

        stripped = mod._strip_rust_comments(source)

        self.assertIn('"https://example.test//kept"', stripped)
        self.assertIn('"not /* a comment */"', stripped)
        self.assertIn('r#"raw // kept /* kept */"#', stripped)
        self.assertIn("pub struct RealMarker;", stripped)
        self.assertNotIn("pub struct PhenotypeTrajectory", stripped)
        self.assertNotIn("fn compromise_propensity()", stripped)
        self.assertNotIn("nested", stripped)


class TestCommentOnlyRustRegression(unittest.TestCase):
    def test_comment_only_rust_markers_fail_closed(self):
        original_paths = (
            mod.BPET_SRC,
            mod.BPET_TRUST_SURFACE_SRC,
            mod.BPET_MOD,
            mod.SECURITY_MOD,
        )
        rust_markers = (
            [f"pub struct {name}" for name in mod.REQUIRED_STRUCTS]
            + [f"pub enum {name}" for name in mod.REQUIRED_STRUCTS]
            + mod.REQUIRED_EVENT_CODES
            + mod.REQUIRED_TEST_PATTERNS
            + [marker for markers in mod.REQUIRED_CAPABILITIES.values() for marker in markers]
            + mod.TRUST_SURFACE_REQUIRED_SYMBOLS
            + mod.TRUST_SURFACE_REQUIRED_TESTS
            + [
                "pub mod economic_integration",
                "pub mod trust_surface_integration",
                "pub mod bpet",
                "pub struct PhenotypeTrajectory",
                "pub struct PhenotypeObservation",
                "fn compromise_propensity",
                "trend_score",
                "maintainer_activity_score",
                "commit_velocity",
                "issue_response_time_hours",
                "contributor_diversity_index",
                "expected_loss_if_compromised",
                "fn compute(",
                "1.2",
                "StronglyRecommended",
                "NotRecommended",
                "ThresholdDirection",
                "fn default_motif_library",
                "Abandoned Critical",
                "Maintainer Turnover",
                "Slow Quality Decay",
                "Routine",
                "Elevated",
                "Urgent",
                "Critical",
                "monitoring_escalation",
                "fallback_strategy",
                "fn audit_log",
                "fn export_audit_log_jsonl",
                "trace_id",
                "event_code",
                "BPET trust-surface assessment",
                "active_quarantine: Some(assessment.active_quarantine_recommended)",
                "user_facing_risk_assessment: Some(RiskAssessment",
                "NonFinitePropensity",
                "InvalidMotifScore",
            ]
        )

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                fake_bpet = tmp / "economic_integration.rs"
                fake_trust = tmp / "trust_surface_integration.rs"
                fake_bpet_mod = tmp / "bpet_mod.rs"
                fake_security_mod = tmp / "security_mod.rs"
                comment_blob = (
                    "\n".join(f"// {marker}" for marker in rust_markers)
                    + "\n/*\n"
                    + "\n".join("#[test]" for _ in range(43))
                    + "\n*/\n"
                )
                fake_bpet.write_text(comment_blob, encoding="utf-8")
                fake_trust.write_text(comment_blob, encoding="utf-8")
                fake_bpet_mod.write_text("// pub mod economic_integration;\n", encoding="utf-8")
                fake_security_mod.write_text("// pub mod bpet;\n", encoding="utf-8")

                mod.BPET_SRC = fake_bpet
                mod.BPET_TRUST_SURFACE_SRC = fake_trust
                mod.BPET_MOD = fake_bpet_mod
                mod.SECURITY_MOD = fake_security_mod
                results = {check.name: check for check in mod.run_all_checks()}
        finally:
            (
                mod.BPET_SRC,
                mod.BPET_TRUST_SURFACE_SRC,
                mod.BPET_MOD,
                mod.SECURITY_MOD,
            ) = original_paths

        self.assertTrue(results["source_exists"].passed)
        for name, check in results.items():
            if name != "source_exists":
                self.assertFalse(check.passed, name)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        result = run_script("--self-test")
        self.assertEqual(result.returncode, 0, f"self_test failed: {result.stdout}\n{result.stderr}")


class TestJsonOutput(unittest.TestCase):
    def test_json_output_is_valid(self):
        data = run_json_script()
        self.assertEqual(data["gate"], "bpet_economic_integration")
        self.assertEqual(data["bead"], "bd-3cbi")
        self.assertEqual(data["section"], "10.21")
        self.assertIn("verdict", data)
        self.assertIn("checks", data)
        self.assertGreaterEqual(len(data["checks"]), 10)

    def test_all_checks_have_required_fields(self):
        data = run_json_script()
        for check in data["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("message", check)


class TestIndividualChecks(unittest.TestCase):
    def _check(self, name: str) -> dict:
        data = run_json_script()
        return next(c for c in data["checks"] if c["name"] == name)

    def test_source_exists(self):
        self.assertTrue(self._check("source_exists")["passed"])

    def test_module_wiring(self):
        self.assertTrue(self._check("module_wiring")["passed"])

    def test_structs(self):
        self.assertTrue(self._check("structs")["passed"])

    def test_event_codes(self):
        self.assertTrue(self._check("event_codes")["passed"])

    def test_propensity_scoring(self):
        self.assertTrue(self._check("propensity_scoring")["passed"])

    def test_economic_pricing(self):
        self.assertTrue(self._check("economic_pricing")["passed"])

    def test_intervention_roi(self):
        self.assertTrue(self._check("intervention_roi")["passed"])

    def test_motif_matching(self):
        self.assertTrue(self._check("motif_matching")["passed"])

    def test_playbook(self):
        self.assertTrue(self._check("playbook")["passed"])

    def test_test_coverage(self):
        self.assertTrue(self._check("test_coverage")["passed"])

    def test_audit_logging(self):
        self.assertTrue(self._check("audit_logging")["passed"])

    def test_trust_surface_integration(self):
        check = self._check("trust_surface_integration")
        self.assertTrue(check["passed"])
        self.assertEqual(
            check["details"]["path"],
            "crates/franken-node/src/security/bpet/trust_surface_integration.rs"
        )


class TestOverallVerdict(unittest.TestCase):
    def test_verdict_is_pass(self):
        data = run_json_script()
        self.assertEqual(
            data["verdict"],
            "PASS",
            f"Failed: {[c for c in data['checks'] if not c['passed']]}",
        )
        self.assertEqual(data["passed"], data["total"])


class TestHumanOutput(unittest.TestCase):
    def test_human_output_format(self):
        result = run_script()
        self.assertTrue("[PASS]" in result.stdout or "[FAIL]" in result.stdout)
        self.assertIn("checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
