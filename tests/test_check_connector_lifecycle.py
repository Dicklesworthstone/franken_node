#!/usr/bin/env python3
"""Unit tests for check_connector_lifecycle.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_connector_lifecycle as cl


class TestFSMSpec(unittest.TestCase):
    def test_nine_states(self):
        self.assertEqual(len(cl.STATES), 9)

    def test_twenty_one_legal_transitions(self):
        self.assertEqual(len(cl.LEGAL_TRANSITIONS), 21)

    def test_no_self_transitions_in_spec(self):
        for s, t in cl.LEGAL_TRANSITIONS:
            self.assertNotEqual(s, t)

    def test_all_states_in_legal_targets(self):
        for state in cl.STATES:
            self.assertIn(state, cl.LEGAL_TARGETS)

    def test_legal_targets_match_transitions(self):
        for state, targets in cl.LEGAL_TARGETS.items():
            for t in targets:
                self.assertIn((state, t), cl.LEGAL_TRANSITIONS)


class TestCheckFSMCompleteness(unittest.TestCase):
    def test_passes(self):
        result = cl.check_fsm_completeness()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["details"]["total_pairs"], 72)
        self.assertEqual(result["details"]["legal"], 21)
        self.assertEqual(result["details"]["illegal"], 51)


class TestCheckNoSelfTransitions(unittest.TestCase):
    def test_passes(self):
        result = cl.check_no_self_transitions()
        self.assertEqual(result["status"], "PASS")


class TestCheckReachable(unittest.TestCase):
    def test_passes(self):
        result = cl.check_all_states_reachable()
        self.assertEqual(result["status"], "PASS")


class TestCheckOutgoing(unittest.TestCase):
    def test_passes(self):
        result = cl.check_all_states_have_outgoing()
        self.assertEqual(result["status"], "PASS")


class TestCheckHappyPath(unittest.TestCase):
    def test_passes(self):
        result = cl.check_happy_path()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["details"]["path"]), 5)

    def test_happy_path_edges(self):
        path = ["discovered", "verified", "installed", "configured", "active"]
        for i in range(len(path) - 1):
            self.assertIn((path[i], path[i + 1]), cl.LEGAL_TRANSITIONS)


class TestCheckRecovery(unittest.TestCase):
    def test_passes(self):
        result = cl.check_recovery_path()
        self.assertEqual(result["status"], "PASS")


class TestCheckRustImpl(unittest.TestCase):
    def test_passes(self):
        result = cl.check_rust_implementation()
        self.assertEqual(result["status"], "PASS")


class TestRustProofMode(unittest.TestCase):
    def test_rust_tests_are_explicit_in_structural_mode(self):
        result = cl.check_rust_tests_pass()
        self.assertEqual(result["status"], "SKIP")
        self.assertIn("--run-rust-tests", result["details"]["reason"])


class TestCheckSpec(unittest.TestCase):
    def test_passes(self):
        result = cl.check_spec_document()
        self.assertEqual(result["status"], "PASS")


class TestCheckTransitionMatrix(unittest.TestCase):
    def test_passes(self):
        result = cl.check_transition_matrix_artifact()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["details"]["total_entries"], 72)
        self.assertEqual(result["details"]["legal_count"], 21)


class TestCompletionDebtChecks(unittest.TestCase):
    def test_conformance_target_is_cargo_visible(self):
        result = cl.check_conformance_test_target()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["details"]["missing_manifest_markers"], [])
        self.assertEqual(result["details"]["missing_test_markers"], [])

    def test_e2e_telemetry_evidence_is_structured(self):
        result = cl.check_e2e_telemetry_evidence()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["details"]["missing_markers"], [])

    def test_migration_catalog_records_lifecycle_transition_cache(self):
        result = cl.check_migration_catalog_entry()
        self.assertEqual(result["status"], "PASS")
        entry = result["details"]["entry"]
        self.assertEqual(entry["domain"], "lifecycle_transition_cache")
        self.assertEqual(entry["owner_module"], "crates/franken-node/src/connector/lifecycle.rs")
        self.assertEqual(entry["replay_strategy"], "recomputed_from_transition_rules")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = cl.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_has_all_checks(self):
        result = cl.self_test()
        self.assertGreaterEqual(result["summary"]["total_checks"], 13)


class TestIllegalTransitions(unittest.TestCase):
    def test_discovered_to_active_is_illegal(self):
        self.assertNotIn(("discovered", "active"), cl.LEGAL_TRANSITIONS)

    def test_active_to_discovered_is_illegal(self):
        self.assertNotIn(("active", "discovered"), cl.LEGAL_TRANSITIONS)

    def test_failed_only_goes_to_discovered(self):
        failed_targets = [t for s, t in cl.LEGAL_TRANSITIONS if s == "failed"]
        self.assertEqual(failed_targets, ["discovered"])

    def test_every_non_failed_state_can_fail(self):
        for state in cl.STATES:
            if state == "failed":
                continue
            self.assertIn((state, "failed"), cl.LEGAL_TRANSITIONS)

    def test_active_and_paused_can_enter_cancelling(self):
        self.assertIn(("active", "cancelling"), cl.LEGAL_TRANSITIONS)
        self.assertIn(("paused", "cancelling"), cl.LEGAL_TRANSITIONS)

    def test_cancelling_can_only_stop_or_fail(self):
        cancelling_targets = sorted(
            t for s, t in cl.LEGAL_TRANSITIONS if s == "cancelling"
        )
        self.assertEqual(cancelling_targets, ["failed", "stopped"])
        self.assertNotIn(("cancelling", "active"), cl.LEGAL_TRANSITIONS)


if __name__ == "__main__":
    unittest.main()
