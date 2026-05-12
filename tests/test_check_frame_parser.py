"""Unit tests for check_frame_parser.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_frame_parser.py"
RESULTS_PATH = ROOT / "artifacts/section_10_13/bd-3tzl/frame_decode_guardrail_results.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-3tzl/verification_evidence.json"
PLAN_SPEC_PATH = ROOT / "docs/specs/control_channel_parser_limits.md"
PLAN_PATH = ROOT / "docs/plans/PLAN_TO_CREATE_FRANKEN_NODE.md"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestFrameDecodeResults(unittest.TestCase):

    def test_results_exist(self):
        self.assertTrue(RESULTS_PATH.is_file())

    def test_results_valid_json(self):
        data = decode_json_object(RESULTS_PATH.read_text(encoding="utf-8"))
        self.assertIn("test_frames", data)
        self.assertGreaterEqual(len(data["test_frames"]), 3)


class TestFrameParserImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/frame_parser.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

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
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-3tzl_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-BPG-SIZE-BOUNDED", "INV-BPG-DEPTH-BOUNDED",
                    "INV-BPG-CPU-BOUNDED", "INV-BPG-AUDITABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_plan_level_spec_bridge_exists(self):
        self.assertTrue(PLAN_SPEC_PATH.is_file())
        bridge = PLAN_SPEC_PATH.read_text(encoding="utf-8")
        self.assertIn("docs/specs/section_10_13/bd-3tzl_contract.md", bridge)
        self.assertIn("tests/integration/frame_decode_guardrails.rs", bridge)
        self.assertNotIn("tests/security/parser_budget_guardrails.rs", bridge)

    def test_project_plan_paths_are_current(self):
        plan = PLAN_PATH.read_text(encoding="utf-8")
        self.assertIn("docs/specs/control_channel_parser_limits.md", plan)
        self.assertIn("docs/specs/section_10_13/bd-3tzl_contract.md", plan)
        self.assertIn("tests/integration/frame_decode_guardrails.rs", plan)
        self.assertIn("artifacts/section_10_13/bd-3tzl/frame_decode_guardrail_results.json", plan)
        self.assertNotIn("tests/security/parser_budget_guardrails.rs", plan)
        self.assertNotIn("artifacts/10.13/parser_guardrail_metrics.csv", plan)


class TestFrameParserIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/frame_decode_guardrails.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_size(self):
        self.assertIn("inv_bpg_size_bounded", self.content)

    def test_covers_depth(self):
        self.assertIn("inv_bpg_depth_bounded", self.content)

    def test_covers_cpu(self):
        self.assertIn("inv_bpg_cpu_bounded", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_bpg_auditable", self.content)


class TestFrameParserCheckerCli(unittest.TestCase):

    def test_json_mode_is_structural_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "frame_parser_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["BPG-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-3tzl:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
