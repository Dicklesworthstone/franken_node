"""Unit tests for check_trace_context.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestTraceSample(unittest.TestCase):

    def test_sample_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1gnb/distributed_trace_sample.json")
        self.assertTrue(os.path.isfile(path))

    def test_sample_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1gnb/distributed_trace_sample.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("spans", data)
        self.assertGreaterEqual(len(data["spans"]), 3)

    def test_sample_has_conformance(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1gnb/distributed_trace_sample.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("conformance", data)
        self.assertIn("verdict", data["conformance"])


class TestTraceImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/trace_context.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_trace_context(self):
        self.assertIn("struct TraceContext", self.content)

    def test_has_trace_store(self):
        self.assertIn("struct TraceStore", self.content)

    def test_has_conformance_report(self):
        self.assertIn("struct ConformanceReport", self.content)

    def test_has_all_error_codes(self):
        for code in ["TRC_MISSING_TRACE_ID", "TRC_MISSING_SPAN_ID", "TRC_INVALID_FORMAT",
                     "TRC_PARENT_NOT_FOUND", "TRC_CONFORMANCE_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestTraceSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1gnb_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-TRC-REQUIRED", "INV-TRC-PROPAGATED",
                    "INV-TRC-STITCHABLE", "INV-TRC-CONFORMANCE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestTraceIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/trace_correlation_end_to_end.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_required(self):
        self.assertIn("inv_trc_required", self.content)

    def test_covers_propagated(self):
        self.assertIn("inv_trc_propagated", self.content)

    def test_covers_stitchable(self):
        self.assertIn("inv_trc_stitchable", self.content)

    def test_covers_conformance(self):
        self.assertIn("inv_trc_conformance", self.content)


if __name__ == "__main__":
    unittest.main()
