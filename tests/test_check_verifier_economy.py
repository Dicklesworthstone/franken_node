"""Unit tests for scripts/check_verifier_economy.py (bd-m8p: verifier economy)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_verifier_economy",
    ROOT / "scripts" / "check_verifier_economy.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Test: run_all structure
# ---------------------------------------------------------------------------

class TestRunAllStructure(unittest.TestCase):
    def test_run_all_returns_dict(self):
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_run_all_has_required_keys(self):
        result = mod.run_all()
        for key in ["bead_id", "verdict", "total", "passed", "failed", "checks",
                     "section", "timestamp", "overall_pass"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_bead_id(self):
        self.assertEqual(mod.run_all()["bead_id"], "bd-m8p")

    def test_section(self):
        self.assertEqual(mod.run_all()["section"], "10.9")

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_total_equals_passed_plus_failed(self):
        result = mod.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_checks_is_list(self):
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)

    def test_check_entry_structure(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)

    def test_overall_pass_is_bool(self):
        result = mod.run_all()
        self.assertIsInstance(result["overall_pass"], bool)

    def test_timestamp_present(self):
        result = mod.run_all()
        self.assertIsInstance(result["timestamp"], str)
        self.assertGreater(len(result["timestamp"]), 10)


# ---------------------------------------------------------------------------
# Test: self_test
# ---------------------------------------------------------------------------

class TestSelfTest(unittest.TestCase):
    def test_self_test_returns_bool(self):
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


# ---------------------------------------------------------------------------
# Test: individual check functions
# ---------------------------------------------------------------------------

class TestIndividualChecks(unittest.TestCase):
    def _run_check(self, fn):
        mod.RESULTS.clear()
        fn()
        self.assertGreater(len(mod.RESULTS), 0)
        return mod.RESULTS[-1]

    def test_check_spec_exists(self):
        result = self._run_check(mod.check_spec_exists)
        self.assertTrue(result["pass"])

    def test_check_policy_exists(self):
        result = self._run_check(mod.check_policy_exists)
        self.assertTrue(result["pass"])

    def test_check_rust_impl_exists(self):
        result = self._run_check(mod.check_rust_impl_exists)
        self.assertTrue(result["pass"])

    def test_check_module_registered(self):
        result = self._run_check(mod.check_module_registered)
        self.assertTrue(result["pass"])

    def test_check_spec_event_codes(self):
        result = self._run_check(mod.check_spec_event_codes)
        self.assertTrue(result["pass"])

    def test_check_spec_invariants(self):
        result = self._run_check(mod.check_spec_invariants)
        self.assertTrue(result["pass"])

    def test_check_spec_error_codes(self):
        result = self._run_check(mod.check_spec_error_codes)
        self.assertTrue(result["pass"])

    def test_check_spec_attestation_format(self):
        result = self._run_check(mod.check_spec_attestation_format)
        self.assertTrue(result["pass"])

    def test_check_spec_anti_gaming(self):
        result = self._run_check(mod.check_spec_anti_gaming)
        self.assertTrue(result["pass"])

    def test_check_spec_replay_capsule(self):
        result = self._run_check(mod.check_spec_replay_capsule)
        self.assertTrue(result["pass"])

    def test_check_spec_reputation_scoring(self):
        result = self._run_check(mod.check_spec_reputation_scoring)
        self.assertTrue(result["pass"])

    def test_check_spec_dispute_resolution(self):
        result = self._run_check(mod.check_spec_dispute_resolution)
        self.assertTrue(result["pass"])

    def test_check_policy_publishing_flow(self):
        result = self._run_check(mod.check_policy_publishing_flow)
        self.assertTrue(result["pass"])

    def test_check_policy_event_codes(self):
        result = self._run_check(mod.check_policy_event_codes)
        self.assertTrue(result["pass"])

    def test_check_policy_invariants(self):
        result = self._run_check(mod.check_policy_invariants)
        self.assertTrue(result["pass"])

    def test_check_policy_reputation_tiers(self):
        result = self._run_check(mod.check_policy_reputation_tiers)
        self.assertTrue(result["pass"])

    def test_check_policy_governance(self):
        result = self._run_check(mod.check_policy_governance)
        self.assertTrue(result["pass"])

    def test_check_policy_dispute_resolution(self):
        result = self._run_check(mod.check_policy_dispute_resolution)
        self.assertTrue(result["pass"])

    def test_check_policy_anti_gaming(self):
        result = self._run_check(mod.check_policy_anti_gaming)
        self.assertTrue(result["pass"])

    def test_check_policy_appeal_process(self):
        result = self._run_check(mod.check_policy_appeal_process)
        self.assertTrue(result["pass"])

    def test_check_policy_upgrade_path(self):
        result = self._run_check(mod.check_policy_upgrade_path)
        self.assertTrue(result["pass"])

    def test_check_policy_downgrade_triggers(self):
        result = self._run_check(mod.check_policy_downgrade_triggers)
        self.assertTrue(result["pass"])

    def test_check_rust_test_count(self):
        mod.RESULTS.clear()
        result = mod.check_rust_test_count()
        self.assertTrue(result["pass"])


# ---------------------------------------------------------------------------
# Test: list checks (types, methods, event codes, tests)
# ---------------------------------------------------------------------------

class TestListChecks(unittest.TestCase):
    def test_rust_types_all_pass(self):
        mod.RESULTS.clear()
        results = mod.check_rust_types()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_rust_methods_all_pass(self):
        mod.RESULTS.clear()
        results = mod.check_rust_methods()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_rust_event_codes_all_pass(self):
        mod.RESULTS.clear()
        results = mod.check_rust_event_codes()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_rust_invariant_constants_all_pass(self):
        mod.RESULTS.clear()
        results = mod.check_rust_invariant_constants()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_rust_error_codes_all_pass(self):
        mod.RESULTS.clear()
        results = mod.check_rust_error_codes()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_rust_tests_all_pass(self):
        mod.RESULTS.clear()
        results = mod.check_rust_tests()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")


# ---------------------------------------------------------------------------
# Test: missing file detection
# ---------------------------------------------------------------------------

class TestMissingFileDetection(unittest.TestCase):
    def test_missing_spec_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "spec.md"
        with patch.object(mod, "SPEC", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("spec" in c["check"].lower() for c in failed))

    def test_missing_policy_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "policy.md"
        with patch.object(mod, "POLICY", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("policy" in c["check"].lower() for c in failed))

    def test_missing_rust_impl_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "mod.rs"
        with patch.object(mod, "RUST_IMPL", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("rust" in c["check"].lower() for c in failed))


# ---------------------------------------------------------------------------
# Test: safe_rel with mock paths
# ---------------------------------------------------------------------------

class TestSafeRel(unittest.TestCase):
    def test_safe_rel_with_root_path(self):
        p = mod.ROOT / "some" / "file.txt"
        result = mod._safe_rel(p)
        self.assertFalse(result.startswith("/"))

    def test_safe_rel_with_non_root_path(self):
        p = Path("/tmp/fakepath/file.txt")
        result = mod._safe_rel(p)
        self.assertEqual(result, "/tmp/fakepath/file.txt")


# ---------------------------------------------------------------------------
# Test: constants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 8)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.ERROR_CODES), 5)

    def test_reputation_tiers_count(self):
        self.assertEqual(len(mod.REPUTATION_TIERS), 4)

    def test_required_rust_types_nonempty(self):
        self.assertGreater(len(mod.REQUIRED_RUST_TYPES), 10)

    def test_required_rust_methods_nonempty(self):
        self.assertGreater(len(mod.REQUIRED_RUST_METHODS), 20)

    def test_required_rust_tests_nonempty(self):
        self.assertGreater(len(mod.REQUIRED_RUST_TESTS), 50)

    def test_all_checks_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 22)


# ---------------------------------------------------------------------------
# Test: JSON output
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-m8p")

    def test_json_flag_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_verifier_economy.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-m8p")
        self.assertEqual(data["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
