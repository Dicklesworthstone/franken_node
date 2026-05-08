"""Unit tests for scripts/check_cross_substrate_e2e.py (bd-8l9k)."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_cross_substrate_e2e.py"

# Load the module via importlib to match the bead spec
spec = importlib.util.spec_from_file_location("check_cross_substrate_e2e", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestVerdict(unittest.TestCase):
    """Test that the overall verdict is PASS."""

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestBeadId(unittest.TestCase):
    """Test that bead_id is correct."""

    def test_bead_id_correct(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-8l9k")


class TestNoFailures(unittest.TestCase):
    """Test that there are no failing checks."""

    def test_no_failures(self):
        result = mod.run_all()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestEvents(unittest.TestCase):
    """Test that events are present."""

    def test_events_present(self):
        result = mod.run_all()
        self.assertIn("events", result)
        self.assertIsInstance(result["events"], list)
        self.assertGreater(len(result["events"]), 0)


class TestAllChecksPass(unittest.TestCase):
    """Test that every individual check passes."""

    def test_all_checks_pass(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertTrue(c["passed"], f"Check failed: {c['check']}: {c['detail']}")


class TestMinimumCheckCount(unittest.TestCase):
    """Test that there is a minimum number of checks."""

    def test_minimum_checks(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 40)


class TestCheckStructure(unittest.TestCase):
    """Test that each check has the required structure."""

    def test_check_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)
            self.assertIsInstance(c["check"], str)
            self.assertIsInstance(c["passed"], bool)
            self.assertIsInstance(c["detail"], str)


class TestJsonCliOutput(unittest.TestCase):
    """Test that --json CLI output is valid JSON."""

    def test_json_output(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"--json output was not valid JSON: {exc}")
        self.assertEqual(parsed["bead_id"], "bd-8l9k")
        self.assertIn("verdict", parsed)
        self.assertIn("checks", parsed)


class TestSelfTestCliExit(unittest.TestCase):
    """Test that --self-test exits 0."""

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"self-test failed:\n{proc.stdout}\n{proc.stderr}")


class TestMissingEvidenceCausesFail(unittest.TestCase):
    """Test that missing evidence file would cause FAIL verdict."""

    def test_missing_evidence_fails(self):
        # Temporarily point to non-existent evidence
        original = mod.EVIDENCE_FILE
        mod.EVIDENCE_FILE = ROOT / "artifacts" / "section_10_16" / "bd-8l9k" / "nonexistent.json"
        try:
            result = mod.run_all()
            # At least the evidence check should fail
            evidence_checks = [c for c in result["checks"] if "evidence" in c["check"].lower() or "Evidence" in c["check"]]
            self.assertTrue(
                any(not c["passed"] for c in evidence_checks),
                "Missing evidence should cause at least one check failure",
            )
        finally:
            mod.EVIDENCE_FILE = original


class TestPersistenceContractChecks(unittest.TestCase):
    """Test that the cross-substrate gate rejects weak persistence evidence."""

    def test_mock_persistence_marker_fails(self):
        original = mod.IMPL_FILE
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "adjacent_substrate_flow.rs"
            src.write_text(
                "pub fn scenario_operator_status() {}\n"
                "// Mock Persistence\n"
                "struct MockPersistence;\n",
                encoding="utf-8",
            )
            mod.IMPL_FILE = src
            try:
                result = mod.run_all()
                persistence_checks = [
                    c for c in result["checks"]
                    if c["check"] == "Persistence harness is tempfile-backed"
                ]
                self.assertTrue(persistence_checks)
                self.assertFalse(persistence_checks[0]["passed"])
            finally:
                mod.IMPL_FILE = original

    def test_replay_report_without_frankensqlite_fails(self):
        original = mod.REPORT_FILE
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "adjacent_substrate_e2e_report.json"
            report.write_text(
                json.dumps({
                    "scenarios": [
                        {
                            "name": "replay_determinism",
                            "substrates": ["frankentui", "fastapi_rust"],
                        }
                    ],
                    "trace_coverage": {},
                    "replay_results": {
                        "persistence_backend": "tempfile-backed-frankensqlite-contract",
                        "persistence_state_match": True,
                        "persistence_state_hash_match": True,
                    },
                }),
                encoding="utf-8",
            )
            mod.REPORT_FILE = report
            try:
                result = mod.run_all()
                replay_checks = [
                    c for c in result["checks"]
                    if c["check"] == "Replay report covers frankensqlite persistence"
                ]
                self.assertTrue(replay_checks)
                self.assertFalse(replay_checks[0]["passed"])
            finally:
                mod.REPORT_FILE = original

    def test_replay_report_without_persistence_match_fails(self):
        original = mod.REPORT_FILE
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "adjacent_substrate_e2e_report.json"
            report.write_text(
                json.dumps({
                    "scenarios": [
                        {
                            "name": "replay_determinism",
                            "substrates": [
                                "frankentui",
                                "fastapi_rust",
                                "sqlmodel_rust",
                                "frankensqlite",
                            ],
                        }
                    ],
                    "trace_coverage": {},
                    "replay_results": {
                        "persistence_backend": "tempfile-backed-frankensqlite-contract",
                        "persistence_state_match": False,
                        "persistence_state_hash_match": True,
                    },
                }),
                encoding="utf-8",
            )
            mod.REPORT_FILE = report
            try:
                result = mod.run_all()
                match_checks = [
                    c for c in result["checks"]
                    if c["check"] == "Replay report records persistence state match"
                ]
                self.assertTrue(match_checks)
                self.assertFalse(match_checks[0]["passed"])
            finally:
                mod.REPORT_FILE = original


class TestResultFields(unittest.TestCase):
    """Test that run_all returns all required fields."""

    def test_required_fields(self):
        result = mod.run_all()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed",
                     "failed", "checks", "events", "summary", "timestamp"]:
            self.assertIn(key, result, f"Missing field: {key}")


class TestSelfTestFunction(unittest.TestCase):
    """Test self_test function directly."""

    def test_self_test_passes(self):
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS",
                         f"self_test failed: {[c for c in result['checks'] if not c['passed']]}")

    def test_self_test_has_required_keys(self):
        result = mod.self_test()
        for key in ["name", "bead", "section", "passed", "failed", "checks",
                     "verdict", "timestamp", "events", "summary"]:
            self.assertIn(key, result, f"self_test missing key: {key}")


if __name__ == "__main__":
    unittest.main()
