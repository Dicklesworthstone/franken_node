"""Unit tests for check_control_channel.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestControlChannelVectors(unittest.TestCase):

    def test_vectors_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-v97o/control_channel_replay_vectors.json")
        self.assertTrue(os.path.isfile(path))

    def test_vectors_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-v97o/control_channel_replay_vectors.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("vectors", data)
        self.assertGreaterEqual(len(data["vectors"]), 3)


class TestControlChannelImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/control_channel.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_channel_config(self):
        self.assertIn("struct ChannelConfig", self.content)

    def test_has_channel_message(self):
        self.assertIn("struct ChannelMessage", self.content)

    def test_has_control_channel(self):
        self.assertIn("struct ControlChannel", self.content)

    def test_has_process_message(self):
        self.assertIn("fn process_message", self.content)

    def test_has_all_error_codes(self):
        for code in ["ACC_AUTH_FAILED", "ACC_SEQUENCE_REGRESS", "ACC_REPLAY_DETECTED",
                     "ACC_INVALID_CONFIG", "ACC_CHANNEL_CLOSED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestControlChannelSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-v97o_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-ACC-AUTHENTICATED", "INV-ACC-MONOTONIC",
                    "INV-ACC-REPLAY-WINDOW", "INV-ACC-AUDITABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestControlChannelIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/control_channel_replay.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_authenticated(self):
        self.assertIn("inv_acc_authenticated", self.content)

    def test_covers_monotonic(self):
        self.assertIn("inv_acc_monotonic", self.content)

    def test_covers_replay_window(self):
        self.assertIn("inv_acc_replay_window", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_acc_auditable", self.content)


if __name__ == "__main__":
    unittest.main()
