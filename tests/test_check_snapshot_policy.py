"""Unit tests for check_snapshot_policy.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSnapshotFixtures(unittest.TestCase):
    """Test fixture files are valid and well-formed."""

    def _load_fixture(self, name):
        path = os.path.join(ROOT, "fixtures/snapshot_policy", name)
        self.assertTrue(os.path.isfile(path), f"Fixture {name} must exist")
        with open(path) as f:
            return json.load(f)

    def test_trigger_scenarios_exist(self):
        data = self._load_fixture("trigger_scenarios.json")
        self.assertIn("cases", data)
        self.assertGreater(len(data["cases"]), 0)

    def test_replay_bound_scenarios_exist(self):
        data = self._load_fixture("replay_bound_scenarios.json")
        self.assertIn("cases", data)
        self.assertGreater(len(data["cases"]), 0)

    def test_policy_audit_scenarios_exist(self):
        data = self._load_fixture("policy_audit_scenarios.json")
        self.assertIn("cases", data)
        self.assertGreater(len(data["cases"]), 0)

    def test_trigger_cases_have_expected_fields(self):
        data = self._load_fixture("trigger_scenarios.json")
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("policy", case)
            self.assertIn("expected_should_snapshot", case)

    def test_replay_cases_have_expected_fields(self):
        data = self._load_fixture("replay_bound_scenarios.json")
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("snapshot_version", case)
            self.assertIn("current_version", case)
            self.assertIn("max_replay_ops", case)
            self.assertIn("expected_within_bounds", case)

    def test_audit_cases_have_expected_fields(self):
        data = self._load_fixture("policy_audit_scenarios.json")
        for case in data["cases"]:
            self.assertIn("name", case)
            self.assertIn("old_policy", case)
            self.assertIn("new_policy", case)
            self.assertIn("valid", case)

    def test_trigger_has_false_and_true_cases(self):
        data = self._load_fixture("trigger_scenarios.json")
        results = [c["expected_should_snapshot"] for c in data["cases"]]
        self.assertIn(True, results)
        self.assertIn(False, results)

    def test_replay_has_bounded_and_exceeded(self):
        data = self._load_fixture("replay_bound_scenarios.json")
        results = [c["expected_within_bounds"] for c in data["cases"]]
        self.assertIn(True, results)
        self.assertIn(False, results)

    def test_audit_has_valid_and_invalid(self):
        data = self._load_fixture("policy_audit_scenarios.json")
        results = [c["valid"] for c in data["cases"]]
        self.assertIn(True, results)
        self.assertIn(False, results)


class TestSnapshotImplementation(unittest.TestCase):
    """Test that implementation file has expected structure."""

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/snapshot_policy.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_snapshot_policy(self):
        self.assertIn("struct SnapshotPolicy", self.content)

    def test_has_snapshot_tracker(self):
        self.assertIn("struct SnapshotTracker", self.content)

    def test_has_snapshot_record(self):
        self.assertIn("struct SnapshotRecord", self.content)

    def test_has_replay_target(self):
        self.assertIn("struct ReplayTarget", self.content)

    def test_has_policy_audit_record(self):
        self.assertIn("struct PolicyAuditRecord", self.content)

    def test_has_every_updates_trigger(self):
        self.assertIn("every_updates", self.content)

    def test_has_every_bytes_trigger(self):
        self.assertIn("every_bytes", self.content)

    def test_has_all_error_codes(self):
        for code in ["SNAPSHOT_HASH_MISMATCH", "SNAPSHOT_STALE",
                     "REPLAY_BOUND_EXCEEDED", "POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_should_snapshot(self):
        self.assertIn("fn should_snapshot", self.content)

    def test_has_take_snapshot(self):
        self.assertIn("fn take_snapshot", self.content)

    def test_has_check_replay_bound(self):
        self.assertIn("fn check_replay_bound", self.content)

    def test_tracks_replay_bytes_and_max_bytes(self):
        self.assertIn("pub max_replay_bytes: u64", self.content)
        self.assertIn("pub replay_bytes: u64", self.content)
        self.assertIn("self.replay_bytes < self.max_replay_bytes", self.content)

    def test_tracker_construction_validates_policy(self):
        self.assertIn("policy.validate()?;", self.content)

    def test_has_update_policy(self):
        self.assertIn("fn update_policy", self.content)

    def test_has_serde_derives(self):
        self.assertIn("Serialize", self.content)
        self.assertIn("Deserialize", self.content)


class TestSnapshotConformance(unittest.TestCase):
    """Test conformance test file structure."""

    def setUp(self):
        self.conf_path = os.path.join(ROOT, "tests/conformance/snapshot_policy_conformance.rs")
        self.assertTrue(os.path.isfile(self.conf_path))
        with open(self.conf_path) as f:
            self.content = f.read()

    def test_covers_triggers(self):
        self.assertIn("trigger", self.content.lower())

    def test_covers_replay_bounds(self):
        self.assertIn("replay", self.content.lower())

    def test_covers_byte_boundary_fail_closed(self):
        self.assertIn("replay_byte_boundary_fails_closed", self.content)

    def test_covers_hash_validation(self):
        self.assertIn("hash", self.content.lower())

    def test_covers_monotonicity(self):
        self.assertTrue(
            "monotonic" in self.content.lower() or "must_increase" in self.content.lower()
        )

    def test_covers_audit(self):
        self.assertIn("audit", self.content.lower())

    def test_covers_invalid_policy_construction(self):
        self.assertIn("tracker_construction_rejects_invalid_policy", self.content)


class TestSnapshotChecker(unittest.TestCase):
    """Test checker script structure stays aligned to the fail-closed surface."""

    def setUp(self):
        self.check_path = os.path.join(ROOT, "scripts/check_snapshot_policy.py")
        self.assertTrue(os.path.isfile(self.check_path))
        with open(self.check_path) as f:
            self.content = f.read()

    def test_checker_tracks_replay_byte_surface(self):
        self.assertIn("SNAP-REPLAY-BYTES", self.content)
        self.assertIn("self.replay_bytes < self.max_replay_bytes", self.content)

    def test_checker_tracks_fail_closed_surface(self):
        self.assertIn("SNAP-FAIL-CLOSED", self.content)
        self.assertIn("tracker_construction_rejects_invalid_policy", self.content)
        self.assertIn("replay_byte_boundary_fails_closed", self.content)

    def test_checker_no_longer_runs_local_cargo(self):
        self.assertNotIn("subprocess.run", self.content)
        self.assertNotIn('["~/.cargo/bin/cargo"', self.content)


class TestSnapshotSpec(unittest.TestCase):
    """Test spec contract file."""

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-24s_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_triggers(self):
        self.assertIn("every_updates", self.content)
        self.assertIn("every_bytes", self.content)

    def test_has_invariants(self):
        self.assertIn("INV-SNAP-BOUNDED", self.content)
        self.assertIn("INV-SNAP-HASH", self.content)
        self.assertIn("INV-SNAP-MONOTONIC", self.content)
        self.assertIn("INV-SNAP-AUDIT", self.content)

    def test_has_error_codes(self):
        for code in ["SNAPSHOT_HASH_MISMATCH", "SNAPSHOT_STALE",
                     "REPLAY_BOUND_EXCEEDED", "POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Spec missing error code {code}")


if __name__ == "__main__":
    unittest.main()
