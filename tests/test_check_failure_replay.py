#!/usr/bin/env python3
"""Unit tests for failure_replay.py."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import failure_replay as replay


class TestCaptureFailure(unittest.TestCase):
    def test_has_replay_id(self):
        a = replay.capture_failure("test", "fixture:x:y:z", {}, {}, {})
        self.assertTrue(a["replay_id"].startswith("REPLAY-"))

    def test_has_context(self):
        a = replay.capture_failure("test", "fixture:x:y:z", {"a": 1}, {"b": 2}, {"c": 3})
        self.assertEqual(a["context"]["input"], {"a": 1})
        self.assertEqual(a["context"]["expected_output"], {"b": 2})
        self.assertEqual(a["context"]["actual_output"], {"c": 3})

    def test_includes_env(self):
        a = replay.capture_failure("test", "fx:x:y:z", {}, {}, {}, env={"KEY": "val"})
        self.assertEqual(a["context"]["environment"]["KEY"], "val")


class TestGenerateHints(unittest.TestCase):
    def test_return_value_hint(self):
        hints = replay.generate_hints({"return_value": "a"}, {"return_value": "b"})
        self.assertTrue(any("Return value" in h for h in hints))

    def test_error_hint(self):
        hints = replay.generate_hints({"error": None}, {"error": {"code": "ERR"}})
        self.assertTrue(any("Error" in h for h in hints))

    def test_no_divergence_hint(self):
        hints = replay.generate_hints({"return_value": "a"}, {"return_value": "a"})
        self.assertTrue(any("manual" in h.lower() for h in hints))


class TestSaveAndLoad(unittest.TestCase):
    def test_roundtrip(self):
        artifact = replay.capture_failure("test", "fx:x:y:z", {}, {}, {})
        with tempfile.TemporaryDirectory() as tmpdir:
            path = replay.save_replay(artifact, Path(tmpdir))
            loaded = replay.load_replay(path)
        self.assertEqual(loaded["replay_id"], artifact["replay_id"])


class TestValidateArtifact(unittest.TestCase):
    def test_valid_artifact_no_errors(self):
        a = replay.capture_failure("test", "fx:x:y:z", {}, {}, {})
        errors = replay.validate_replay_artifact(a)
        self.assertEqual(len(errors), 0)

    def test_missing_fields_errors(self):
        errors = replay.validate_replay_artifact({})
        self.assertGreater(len(errors), 0)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = replay.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
