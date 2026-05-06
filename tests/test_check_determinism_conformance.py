"""Unit tests for check_determinism_conformance.py (bd-1iyx)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_determinism_conformance.py"
HARNESS = ROOT / "tests" / "conformance" / "replica_artifact_determinism.rs"
CRATE_TEST_BRIDGE = ROOT / "crates" / "franken-node" / "tests" / "replica_artifact_determinism.rs"
FIXTURES_DIR = ROOT / "fixtures" / "determinism"
RESULTS_CSV = ROOT / "artifacts" / "10.14" / "determinism_conformance_results.csv"

sys.path.insert(0, str(ROOT / "scripts"))
import check_determinism_conformance as cdc  # noqa: E402

JSON_DECODER = json.JSONDecoder()


def load_json_file(path: Path) -> object:
    return JSON_DECODER.decode(path.read_text())


def load_json_text(text: str) -> object:
    return JSON_DECODER.decode(text)


class TestFileExistence(unittest.TestCase):
    def test_harness_exists(self):
        self.assertTrue(HARNESS.is_file())

    def test_script_exists(self):
        self.assertTrue(SCRIPT.is_file())

    def test_crate_test_bridge_is_labeled_as_bridge(self):
        self.assertTrue(CRATE_TEST_BRIDGE.is_file())
        result = cdc.run_checks()
        check_names = [check["check"] for check in result["checks"]]
        self.assertIn("file: crate test bridge", check_names)
        stale_label = "file: test " + "stub"
        self.assertNotIn(stale_label, check_names)

    def test_results_csv_exists(self):
        self.assertTrue(RESULTS_CSV.is_file())


class TestFixtures(unittest.TestCase):
    def test_at_least_three_fixtures(self):
        fixtures = list(FIXTURES_DIR.glob("*.json"))
        self.assertGreaterEqual(len(fixtures), 3)

    def test_small_encoding_valid(self):
        fp = FIXTURES_DIR / "small_encoding.json"
        data = load_json_file(fp)
        self.assertIn("expected_seeds", data)
        self.assertIn("encoding", data["expected_seeds"])

    def test_medium_multi_domain_valid(self):
        fp = FIXTURES_DIR / "medium_multi_domain.json"
        data = load_json_file(fp)
        self.assertEqual(len(data["domains"]), 5)

    def test_edge_case_valid(self):
        fp = FIXTURES_DIR / "edge_case_minimal.json"
        data = load_json_file(fp)
        self.assertEqual(len(data["config"]["parameters"]), 0)


class TestResultsCSV(unittest.TestCase):
    def test_csv_has_header(self):
        content = RESULTS_CSV.read_text()
        self.assertIn("fixture_name", content)

    def test_csv_all_pass(self):
        lines = RESULTS_CSV.read_text().strip().split('\n')
        for line in lines[1:]:
            if line.strip():
                self.assertIn("true", line)


class TestHarnessContent(unittest.TestCase):
    def setUp(self):
        self.content = HARNESS.read_text()

    def test_event_codes(self):
        for code in ["DETERMINISM_CHECK_STARTED", "DETERMINISM_CHECK_PASSED", "DETERMINISM_CHECK_FAILED"]:
            self.assertIn(code, self.content)

    def test_divergence_reporting(self):
        self.assertIn("first_mismatch_offset", self.content)
        self.assertIn("context_hex", self.content)
        self.assertIn("root_cause", self.content)


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test(self):
        ok, results = cdc.self_test()
        self.assertTrue(ok)

    def test_cli_json(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = load_json_text(completed.stdout)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["bead_id"], "bd-1iyx")

    def test_cli_human(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-1iyx", completed.stdout)


class TestAllChecksPass(unittest.TestCase):
    def test_no_failures(self):
        result = cdc.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0,
                         f"Failing: {json.dumps(failing, indent=2)}")


if __name__ == "__main__":
    unittest.main()
