"""Unit tests for check_prestage_engine.py verification logic."""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestPrestageReport(unittest.TestCase):

    def test_report_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2t5u/prestaging_model_report.csv")
        self.assertTrue(os.path.isfile(path))

    def test_report_has_header(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2t5u/prestaging_model_report.csv")
        with open(path) as f:
            header = f.readline().strip()
        self.assertIn("scenario", header)
        self.assertIn("precision", header)

    def test_report_has_data(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2t5u/prestaging_model_report.csv")
        with open(path) as f:
            lines = [l for l in f if l.strip()]
        self.assertGreaterEqual(len(lines), 4)


class TestPrestageImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/prestage_engine.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

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
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2t5u_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-PSE-BUDGET", "INV-PSE-COVERAGE",
                    "INV-PSE-DETERMINISTIC", "INV-PSE-QUALITY"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["PSE_BUDGET_EXCEEDED", "PSE_INVALID_CONFIG",
                     "PSE_NO_CANDIDATES", "PSE_THRESHOLD_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestPrestageIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/prestaging_coverage_improvement.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_budget(self):
        self.assertIn("inv_pse_budget", self.content)

    def test_covers_coverage(self):
        self.assertIn("inv_pse_coverage", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_pse_deterministic", self.content)

    def test_covers_quality(self):
        self.assertIn("inv_pse_quality", self.content)


if __name__ == "__main__":
    unittest.main()
