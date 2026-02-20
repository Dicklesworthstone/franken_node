"""Unit tests for check_artifact_persistence.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestArtifactFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-12h8/artifact_replay_fixtures.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixtures_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-12h8/artifact_replay_fixtures.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("fixtures", data)
        self.assertGreaterEqual(len(data["fixtures"]), 6)

    def test_all_six_types_present(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-12h8/artifact_replay_fixtures.json")
        with open(path) as f:
            data = json.load(f)
        types = {f["artifact_type"] for f in data["fixtures"]}
        for t in ["invoke", "response", "receipt", "approval", "revocation", "audit"]:
            self.assertIn(t, types, f"Missing artifact type {t}")


class TestArtifactPersistenceImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/artifact_persistence.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_artifact_type(self):
        self.assertIn("enum ArtifactType", self.content)

    def test_has_persisted_artifact(self):
        self.assertIn("struct PersistedArtifact", self.content)

    def test_has_replay_hook(self):
        self.assertIn("struct ReplayHook", self.content)

    def test_has_artifact_store(self):
        self.assertIn("struct ArtifactStore", self.content)

    def test_has_all_error_codes(self):
        for code in ["PRA_UNKNOWN_TYPE", "PRA_DUPLICATE", "PRA_SEQUENCE_GAP",
                     "PRA_REPLAY_MISMATCH", "PRA_INVALID_ARTIFACT"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestArtifactPersistenceSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-12h8_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-PRA-COMPLETE", "INV-PRA-DURABLE",
                    "INV-PRA-REPLAY", "INV-PRA-ORDERED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestArtifactIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/artifact_replay_hooks.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_complete(self):
        self.assertIn("inv_pra_complete", self.content)

    def test_covers_durable(self):
        self.assertIn("inv_pra_durable", self.content)

    def test_covers_replay(self):
        self.assertIn("inv_pra_replay", self.content)

    def test_covers_ordered(self):
        self.assertIn("inv_pra_ordered", self.content)


if __name__ == "__main__":
    unittest.main()
