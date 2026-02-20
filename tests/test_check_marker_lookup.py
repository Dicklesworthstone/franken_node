"""Unit tests for check_marker_lookup.py (bd-129f)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_marker_lookup.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "marker_stream.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-129f_contract.md"

sys.path.insert(0, str(ROOT / "scripts"))
import check_marker_lookup as cml


class TestFileExistence(unittest.TestCase):
    def test_implementation_exists(self):
        self.assertTrue(IMPL.is_file(), f"Missing: {IMPL}")

    def test_spec_exists(self):
        self.assertTrue(SPEC.is_file(), f"Missing: {SPEC}")

    def test_check_script_exists(self):
        self.assertTrue(SCRIPT.is_file(), f"Missing: {SCRIPT}")


class TestMethodPresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_marker_by_sequence_present(self):
        self.assertIn("fn marker_by_sequence(", self.content)

    def test_sequence_by_timestamp_present(self):
        self.assertIn("fn sequence_by_timestamp(", self.content)

    def test_first_method_present(self):
        self.assertIn("fn first(", self.content)

    def test_marker_by_sequence_returns_option_ref(self):
        self.assertIn("-> Option<&Marker>", self.content)

    def test_sequence_by_timestamp_returns_option_u64(self):
        self.assertIn("-> Option<u64>", self.content)


class TestAlgorithmEvidence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_o1_vec_index(self):
        self.assertIn(".get(seq as usize)", self.content)

    def test_binary_search_loop(self):
        self.assertIn("while lo < hi", self.content)

    def test_midpoint_calculation(self):
        self.assertIn("lo + (hi - lo) / 2", self.content)


class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_empty_stream_check(self):
        self.assertIn("is_empty()", self.content)

    def test_before_first_timestamp(self):
        self.assertIn("ts < self.markers[0].timestamp", self.content)


class TestRequiredTests(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_marker_by_sequence_tests_exist(self):
        for test_name in [
            "marker_by_sequence_first",
            "marker_by_sequence_last",
            "marker_by_sequence_middle",
            "marker_by_sequence_out_of_range",
            "marker_by_sequence_empty_stream",
        ]:
            self.assertIn(test_name, self.content, f"Missing test: {test_name}")

    def test_sequence_by_timestamp_tests_exist(self):
        for test_name in [
            "sequence_by_timestamp_exact_match",
            "sequence_by_timestamp_between_markers",
            "sequence_by_timestamp_before_first",
            "sequence_by_timestamp_after_last",
            "sequence_by_timestamp_empty_stream",
            "sequence_by_timestamp_single_marker",
            "sequence_by_timestamp_duplicate_timestamps",
            "sequence_by_timestamp_large_stream",
        ]:
            self.assertIn(test_name, self.content, f"Missing test: {test_name}")

    def test_consistency_test_exists(self):
        self.assertIn("marker_by_sequence_matches_get", self.content)


class TestSpecContent(unittest.TestCase):
    def setUp(self):
        self.content = SPEC.read_text()

    def test_o1_mentioned(self):
        self.assertIn("O(1)", self.content)

    def test_ologn_mentioned(self):
        self.assertIn("O(log N)", self.content)

    def test_binary_search_mentioned(self):
        self.assertIn("binary search", self.content)

    def test_performance_target_seq(self):
        self.assertIn("< 1 microsecond", self.content)

    def test_performance_target_ts(self):
        self.assertIn("< 100 microseconds", self.content)


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test_passes(self):
        result = cml.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_cli_json_output(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(ROOT),
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["bead"], "bd-129f")

    def test_cli_human_readable(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(ROOT),
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-129f", completed.stdout)
        self.assertIn("PASS", completed.stdout)


class TestRunChecks(unittest.TestCase):
    def test_all_checks_pass(self):
        result = cml.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}"
        )

    def test_result_structure(self):
        result = cml.run_checks()
        self.assertIn("bead", result)
        self.assertIn("title", result)
        self.assertIn("section", result)
        self.assertIn("verdict", result)
        self.assertIn("summary", result)
        self.assertIn("checks", result)
        self.assertEqual(result["section"], "10.14")


if __name__ == "__main__":
    unittest.main()
