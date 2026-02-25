"""Unit tests for scripts/check_zk_attestation.py (bd-kcg9)."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_zk_attestation.py"

spec = importlib.util.spec_from_file_location("check_zk_attestation", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestVerdict(unittest.TestCase):
    def test_gate_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures[:10])


class TestResultShape(unittest.TestCase):
    def test_required_fields(self):
        result = mod.run_all()
        for key in [
            "schema_version",
            "bead_id",
            "section",
            "verdict",
            "checks",
            "event_codes",
            "error_codes",
            "invariants",
            "zk_contract",
        ]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-kcg9")
        self.assertEqual(result["section"], "10.17")

    def test_zk_contract_fields(self):
        result = mod.run_all()
        contract = result["zk_contract"]
        self.assertTrue(contract["selective_disclosure"])
        self.assertTrue(contract["proof_soundness"])
        self.assertTrue(contract["fail_closed"])
        self.assertTrue(contract["predicate_completeness"])


class TestChecks(unittest.TestCase):
    def test_minimum_check_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 40)

    def test_all_checks_have_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS")


class TestCli(unittest.TestCase):
    def test_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-kcg9")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_build_report_creates_file(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--build-report", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report_path = ROOT / "artifacts/10.17/zk_attestation_vectors.json"
        self.assertTrue(report_path.exists(), f"Report not created at {report_path}")


class TestSpecificChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {c["check"]: c for c in mod.run_all()["checks"]}

    def test_source_file_exists(self):
        self.assertTrue(self.results["Implementation file exists"]["passed"])

    def test_module_wired(self):
        self.assertTrue(self.results["Security module wired"]["passed"])

    def test_contract_exists(self):
        self.assertTrue(self.results["Contract file exists"]["passed"])

    def test_schema_version(self):
        self.assertTrue(self.results["Schema version value"]["passed"])

    def test_serde_derives(self):
        self.assertTrue(self.results["Serde derives"]["passed"])

    def test_btreemap_usage(self):
        self.assertTrue(self.results["Uses BTreeMap"]["passed"])

    def test_inline_test_count(self):
        self.assertTrue(self.results["Rust inline tests >= 20"]["passed"])

    def test_cfg_test_module(self):
        self.assertTrue(self.results["cfg(test) module"]["passed"])

    def test_invariants_module(self):
        self.assertTrue(self.results["Invariants module"]["passed"])

    def test_selective_disclosure(self):
        self.assertTrue(self.results["Selective disclosure"]["passed"])


class TestCodeCounts(unittest.TestCase):
    def test_event_codes_list(self):
        self.assertGreaterEqual(len(mod.REQUIRED_EVENT_CODES), 5)

    def test_fn_codes_list(self):
        self.assertEqual(len(mod.REQUIRED_FN_CODES), 12)

    def test_error_codes_list(self):
        self.assertGreaterEqual(len(mod.REQUIRED_ERROR_CODES), 6)

    def test_impl_error_codes_list(self):
        self.assertEqual(len(mod.REQUIRED_IMPL_ERROR_CODES), 10)

    def test_invariants_list(self):
        self.assertGreaterEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_impl_invariants_list(self):
        self.assertEqual(len(mod.REQUIRED_IMPL_INVARIANTS), 6)


class TestMissingSources(unittest.TestCase):
    def test_missing_source_detected(self):
        with mock.patch.object(mod, "IMPL_FILE", mod.ROOT / "nonexistent.rs"):
            checks = mod.run_all_checks()
            source_check = next(c for c in checks if c["check"] == "Implementation file exists")
            self.assertFalse(source_check["passed"])

    def test_missing_contract_detected(self):
        with mock.patch.object(mod, "CONTRACT_FILE", mod.ROOT / "nonexistent.md"):
            checks = mod.run_all_checks()
            spec_check = next(c for c in checks if c["check"] == "Contract file exists")
            self.assertFalse(spec_check["passed"])


if __name__ == "__main__":
    unittest.main()
