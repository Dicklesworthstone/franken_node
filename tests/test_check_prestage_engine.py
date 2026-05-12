"""Unit tests for check_prestage_engine.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts import check_prestage_engine

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_prestage_engine.py"
REPORT_PATH = ROOT / "artifacts/section_10_13/bd-2t5u/prestaging_model_report.csv"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-2t5u/verification_evidence.json"
PLAN_SPEC_PATH = ROOT / "docs/specs/predictive_prestaging.md"
PLAN_PATH = ROOT / "docs/plans/PLAN_TO_CREATE_FRANKEN_NODE.md"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestPrestageReport(unittest.TestCase):

    def test_report_exists(self):
        self.assertTrue(REPORT_PATH.is_file())

    def test_report_has_header(self):
        header = REPORT_PATH.read_text(encoding="utf-8").splitlines()[0].strip()
        self.assertIn("scenario", header)
        self.assertIn("precision", header)

    def test_report_has_data(self):
        lines = [line for line in REPORT_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 4)


class TestPrestageImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/prestage_engine.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_prestage_config(self):
        self.assertIn("struct PrestageConfig", self.content)

    def test_has_artifact_candidate(self):
        self.assertIn("struct ArtifactCandidate", self.content)

    def test_has_prestage_decision(self):
        self.assertIn("struct PrestageDecision", self.content)

    def test_has_prestage_report(self):
        self.assertIn("struct PrestageReport", self.content)

    def test_has_quality_metrics(self):
        self.assertIn("struct QualityMetrics", self.content)

    def test_has_evaluate_candidates(self):
        self.assertIn("fn evaluate_candidates", self.content)

    def test_has_measure_quality(self):
        self.assertIn("fn measure_quality", self.content)

    def test_has_all_error_codes(self):
        for code in ["PSE_BUDGET_EXCEEDED", "PSE_INVALID_CONFIG",
                     "PSE_NO_CANDIDATES", "PSE_THRESHOLD_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestPrestageSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-2t5u_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-PSE-BUDGET", "INV-PSE-COVERAGE",
                    "INV-PSE-DETERMINISTIC", "INV-PSE-QUALITY"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["PSE_BUDGET_EXCEEDED", "PSE_INVALID_CONFIG",
                     "PSE_NO_CANDIDATES", "PSE_THRESHOLD_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_plan_level_spec_bridge_exists(self):
        self.assertTrue(PLAN_SPEC_PATH.is_file())
        bridge = PLAN_SPEC_PATH.read_text(encoding="utf-8")
        self.assertIn("docs/specs/section_10_13/bd-2t5u_contract.md", bridge)
        self.assertIn("tests/integration/prestaging_coverage_improvement.rs", bridge)
        self.assertNotIn("tests/perf/prestaging_coverage_improvement.rs", bridge)

    def test_project_plan_paths_are_current(self):
        plan = PLAN_PATH.read_text(encoding="utf-8")
        self.assertIn("docs/specs/predictive_prestaging.md", plan)
        self.assertIn("docs/specs/section_10_13/bd-2t5u_contract.md", plan)
        self.assertIn("tests/integration/prestaging_coverage_improvement.rs", plan)
        self.assertIn("artifacts/section_10_13/bd-2t5u/prestaging_model_report.csv", plan)
        self.assertNotIn("tests/perf/prestaging_coverage_improvement.rs", plan)
        self.assertNotIn("artifacts/10.13/prestaging_model_report.csv", plan)


class TestPrestageIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/prestaging_coverage_improvement.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_budget(self):
        self.assertIn("inv_pse_budget", self.content)

    def test_covers_coverage(self):
        self.assertIn("inv_pse_coverage", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_pse_deterministic", self.content)

    def test_covers_quality(self):
        self.assertIn("inv_pse_quality", self.content)


class TestPrestageCheckerCli(unittest.TestCase):

    def test_json_mode_requests_full_proof_by_default(self):
        args = check_prestage_engine.parse_args(["--json"])

        self.assertTrue(check_prestage_engine.should_run_rust_tests(args))

    def test_structural_json_mode_is_partial_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "prestage_engine_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        self.assertEqual(statuses["PSE-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("bd-2t5u:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
