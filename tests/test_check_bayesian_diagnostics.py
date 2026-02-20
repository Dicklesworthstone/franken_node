"""Tests for scripts/check_bayesian_diagnostics.py (bd-2igi).

Covers: file existence checks, type/method/event-code presence, invariant
markers, self_test(), --json CLI, and the full all-pass condition.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_bayesian_diagnostics",
    ROOT / "scripts" / "check_bayesian_diagnostics.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestFileExistence(TestCase):
    """Verify that check_file correctly detects present and absent files."""

    def test_impl_file_exists(self):
        result = mod.check_file(mod.IMPL, "implementation")
        self.assertTrue(result["pass"], "Implementation file must exist")

    def test_spec_file_exists(self):
        result = mod.check_file(mod.SPEC, "spec contract")
        self.assertTrue(result["pass"], "Spec contract must exist")

    def test_diagnostics_report_exists(self):
        result = mod.check_file(mod.DIAGNOSTICS_REPORT, "diagnostics report")
        self.assertTrue(result["pass"], "Diagnostics report JSON must exist")

    def test_missing_file_returns_fail(self):
        result = mod.check_file(ROOT / "does_not_exist.rs", "absent")
        self.assertFalse(result["pass"])
        self.assertIn("MISSING", result["detail"])

    def test_module_registered_in_mod_rs(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"], "bayesian_diagnostics must appear in mod.rs")


class TestTypePresence(TestCase):
    """Verify that all required types and structural elements are present."""

    def _impl_text(self):
        return mod.IMPL.read_text()

    def test_bayesian_diagnostics_struct(self):
        self.assertIn("pub struct BayesianDiagnostics", self._impl_text())

    def test_candidate_ref_struct(self):
        self.assertIn("pub struct CandidateRef", self._impl_text())

    def test_observation_struct(self):
        self.assertIn("pub struct Observation", self._impl_text())

    def test_ranked_candidate_struct(self):
        self.assertIn("pub struct RankedCandidate", self._impl_text())

    def test_diagnostic_confidence_enum(self):
        self.assertIn("pub enum DiagnosticConfidence", self._impl_text())

    def test_beta_state_struct(self):
        self.assertIn("struct BetaState", self._impl_text())

    def test_required_types_count(self):
        # 5 public types + BetaState (internal)
        self.assertEqual(len(mod.REQUIRED_TYPES), 6)

    def test_btreemap_for_determinism(self):
        result = mod.check_btreemap_usage()
        self.assertTrue(result["pass"], "BTreeMap must be used for deterministic ordering")

    def test_beta_distribution_conjugate(self):
        result = mod.check_beta_distribution()
        self.assertTrue(result["pass"], "Beta conjugate distribution (alpha/beta) must be present")

    def test_serialize_deserialize_derives(self):
        result = mod.check_serialization()
        self.assertTrue(result["pass"], "Serialize/Deserialize derives must be present")

    def test_test_count_at_least_25(self):
        result = mod.check_test_count()
        self.assertTrue(result["pass"], result["detail"])


class TestEventCodes(TestCase):
    """Verify all event codes and invariant markers are present in implementation."""

    def _impl_text(self):
        return mod.IMPL.read_text()

    def test_evd_bayes_001(self):
        self.assertIn("EVD-BAYES-001", self._impl_text())

    def test_evd_bayes_002(self):
        self.assertIn("EVD-BAYES-002", self._impl_text())

    def test_evd_bayes_003(self):
        self.assertIn("EVD-BAYES-003", self._impl_text())

    def test_evd_bayes_004(self):
        self.assertIn("EVD-BAYES-004", self._impl_text())

    def test_event_codes_list_length(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariant_advisory(self):
        self.assertIn("INV-BAYES-ADVISORY", self._impl_text())

    def test_invariant_reproducible(self):
        self.assertIn("INV-BAYES-REPRODUCIBLE", self._impl_text())

    def test_invariant_normalized(self):
        self.assertIn("INV-BAYES-NORMALIZED", self._impl_text())

    def test_invariant_transparent(self):
        self.assertIn("INV-BAYES-TRANSPARENT", self._impl_text())

    def test_invariants_list_length(self):
        # ADVISORY, REPRODUCIBLE, NORMALIZED, TRANSPARENT
        self.assertEqual(len(mod.INVARIANTS), 4)


class TestSelfTestAndCli(TestCase):
    """Verify self_test() and --json CLI output are well-formed and passing."""

    def test_self_test_returns_true(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok, "self_test() must return True when all checks pass")

    def test_self_test_returns_checks_list(self):
        ok, checks = mod.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)

    def test_cli_json_exit_zero(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_bayesian_diagnostics.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}")

    def test_cli_json_output_is_valid(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_bayesian_diagnostics.py"), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        self.assertEqual(data["bead_id"], "bd-2igi")
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_json_contains_summary(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_bayesian_diagnostics.py"), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        self.assertIn("summary", data)
        self.assertIn("passing", data["summary"])

    def test_bead_id_constant(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2igi")

    def test_section_constant(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.14")


class TestAllChecksPass(TestCase):
    """Verify the full check suite produces a clean PASS result."""

    @classmethod
    def setUpClass(cls):
        cls.result = mod.run_checks()

    def test_verdict_is_pass(self):
        self.assertEqual(self.result["verdict"], "PASS")

    def test_overall_pass_flag(self):
        self.assertTrue(self.result["overall_pass"])

    def test_no_failing_checks(self):
        failing = [c for c in self.result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0, f"Failing checks: {failing}")

    def test_total_checks_count(self):
        self.assertGreaterEqual(self.result["summary"]["total"], 58)

    def test_passing_equals_total(self):
        s = self.result["summary"]
        self.assertEqual(s["passing"], s["total"])

    def test_failing_is_zero(self):
        self.assertEqual(self.result["summary"]["failing"], 0)

    def test_test_count_at_least_25(self):
        self.assertGreaterEqual(self.result["test_count"], 25)

    def test_result_json_serializable(self):
        serialized = json.dumps(self.result)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["bead_id"], "bd-2igi")

    def test_required_tests_count(self):
        self.assertEqual(len(mod.REQUIRED_TESTS), 31)

    def test_methods_count(self):
        self.assertEqual(len(mod.REQUIRED_METHODS), 11)

    def test_check_content_helper_pass(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False)
        tmp.write("pub struct Foo;\n")
        tmp.close()
        try:
            results = mod.check_content(Path(tmp.name), ["pub struct Foo"], "type")
            self.assertTrue(results[0]["pass"])
        finally:
            os.unlink(tmp.name)

    def test_check_content_helper_fail(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False)
        tmp.write("pub struct Foo;\n")
        tmp.close()
        try:
            results = mod.check_content(Path(tmp.name), ["pub struct Bar"], "type")
            self.assertFalse(results[0]["pass"])
        finally:
            os.unlink(tmp.name)

    def test_check_content_missing_file(self):
        results = mod.check_content(Path("/nonexistent.rs"), ["x"], "type")
        self.assertFalse(results[0]["pass"])
        self.assertEqual(results[0]["detail"], "file missing")

    def test_checks_list_nonempty(self):
        self.assertGreater(len(self.result["checks"]), 0)

    def test_all_checks_have_pass_field(self):
        for c in self.result["checks"]:
            self.assertIn("pass", c, f"Check missing 'pass' field: {c}")


if __name__ == "__main__":
    main()
