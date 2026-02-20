"""Unit tests for check_frame_parser.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestFrameDecodeResults(unittest.TestCase):

    def test_results_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3tzl/frame_decode_guardrail_results.json")
        self.assertTrue(os.path.isfile(path))

    def test_results_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3tzl/frame_decode_guardrail_results.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("test_frames", data)
        self.assertGreaterEqual(len(data["test_frames"]), 3)


class TestFrameParserImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/frame_parser.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_parser_config(self):
        self.assertIn("struct ParserConfig", self.content)

    def test_has_frame_input(self):
        self.assertIn("struct FrameInput", self.content)

    def test_has_decode_verdict(self):
        self.assertIn("struct DecodeVerdict", self.content)

    def test_has_check_frame(self):
        self.assertIn("fn check_frame", self.content)

    def test_has_all_error_codes(self):
        for code in ["BPG_SIZE_EXCEEDED", "BPG_DEPTH_EXCEEDED", "BPG_CPU_EXCEEDED",
                     "BPG_INVALID_CONFIG", "BPG_MALFORMED_FRAME"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestFrameParserSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3tzl_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-BPG-SIZE-BOUNDED", "INV-BPG-DEPTH-BOUNDED",
                    "INV-BPG-CPU-BOUNDED", "INV-BPG-AUDITABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestFrameParserIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/frame_decode_guardrails.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_size(self):
        self.assertIn("inv_bpg_size_bounded", self.content)

    def test_covers_depth(self):
        self.assertIn("inv_bpg_depth_bounded", self.content)

    def test_covers_cpu(self):
        self.assertIn("inv_bpg_cpu_bounded", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_bpg_auditable", self.content)


if __name__ == "__main__":
    unittest.main()
