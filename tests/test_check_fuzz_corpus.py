"""Unit tests for check_fuzz_corpus.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestFuzzSummary(unittest.TestCase):

    def test_summary_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-29ct/fuzz_campaign_summary.json")
        self.assertTrue(os.path.isfile(path))

    def test_summary_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-29ct/fuzz_campaign_summary.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("targets", data)
        self.assertGreaterEqual(len(data["targets"]), 4)

    def test_summary_has_verdict(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-29ct/fuzz_campaign_summary.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("gate_verdict", data)


class TestFuzzImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/fuzz_corpus.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_deterministic_fixture_adapter(self):
        self.assertIn("struct DeterministicFuzzTestAdapter", self.content)

    def test_has_deterministic_fixture_types(self):
        self.assertIn("struct DeterministicFuzzTarget", self.content)
        self.assertIn("struct DeterministicFuzzGateReport", self.content)
        self.assertIn("fn run_fixture_gate", self.content)
        self.assertIn("synthetic_test_fixture", self.content)

    def test_has_truthful_live_gate_types(self):
        self.assertIn("struct TruthfulFuzzGateReport", self.content)
        self.assertIn("struct FuzzTargetDescriptor", self.content)
        self.assertIn("fn run_truthful_fuzz_gate", self.content)

    def test_has_all_error_codes(self):
        for code in ["FCG_MISSING_TARGET", "FCG_INSUFFICIENT_CORPUS", "FCG_REGRESSION",
                     "FCG_UNTRIAGED_CRASH", "FCG_GATE_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestFuzzSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-29ct_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-FCG-TARGETS", "INV-FCG-CORPUS",
                    "INV-FCG-TRIAGE", "INV-FCG-GATE", "INV-FCG-FIXTURE-BOUNDARY"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestFuzzIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/fuzz_corpus_gates.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_targets(self):
        self.assertIn("inv_fcg_targets", self.content)

    def test_covers_corpus(self):
        self.assertIn("inv_fcg_corpus", self.content)

    def test_covers_triage(self):
        self.assertIn("inv_fcg_triage", self.content)

    def test_covers_gate(self):
        self.assertIn("inv_fcg_gate", self.content)

    def test_covers_fixture_boundary(self):
        self.assertIn("fixture_gate_reports_explicit_test_adapter_marker", self.content)

    def test_covers_truthful_live_gate(self):
        self.assertIn("truthful_gate_executes_checked_in_targets", self.content)
        self.assertIn(
            "truthful_gate_reports_explicit_coverage_and_relative_artifacts",
            self.content,
        )


if __name__ == "__main__":
    unittest.main()
