"""Unit tests for scripts/check_operator_runbooks.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_operator_runbooks as mod


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-nr4")
        self.assertEqual(mod.SECTION, "10.8")

    def test_runbook_count(self):
        self.assertEqual(len(mod.RUNBOOKS), 6)

    def test_required_coverage_tags(self):
        self.assertEqual(len(mod.REQUIRED_COVERAGE_TAGS), 5)


class TestHelpers(unittest.TestCase):
    def test_parse_date_valid(self):
        self.assertIsNotNone(mod.parse_date("2026-02-21"))

    def test_parse_date_invalid(self):
        self.assertIsNone(mod.parse_date("2026/02/21"))

    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 3)

    def test_manual_operator_reference_is_valid(self):
        self.assertTrue(mod.is_operator_reference("Manual: restart workers through supervisor"))

    def test_runtime_model_operator_reference_is_valid(self):
        self.assertTrue(
            mod.is_operator_reference(
                "Runtime safe-mode model: crates/franken-node/src/runtime/safe_mode.rs"
            )
        )

    def test_rb006_truth_rejects_unshipped_proof_surface(self):
        checks = mod.check_command_reference_truth(
            "RB-006",
            [
                "franken-node proofs queue status",
                "POST /api/v1/proofs/workers/restart",
            ],
        )
        self.assertTrue(any(not check["pass"] for check in checks))

    def test_rb006_truth_accepts_shipped_ops_references(self):
        checks = mod.check_command_reference_truth(
            "RB-006",
            [
                "franken-node ops validation-readiness --input <broker-snapshot.json> --receipt <receipt.json> --json",
                "franken-node ops resource-governor --requested-proof-class <proof-class> --source-only-allowed --json",
                "Manual: restart or scale proof workers through the deployment supervisor for the active environment",
                "Future dedicated proof queue/status and worker restart CLI/API surface: bd-rm6ex",
            ],
        )
        self.assertTrue(all(check["pass"] for check in checks))


class TestRepositoryChecks(unittest.TestCase):
    def test_schema_exists(self):
        result = mod.check_file(mod.SCHEMA_PATH, "schema")
        self.assertTrue(result["pass"])

    def test_index_exists(self):
        result = mod.check_file(mod.INDEX_PATH, "index")
        self.assertTrue(result["pass"])

    def test_drill_results_exist(self):
        result = mod.check_file(mod.DRILL_RESULTS, "drill")
        self.assertTrue(result["pass"])


class TestGateExecution(unittest.TestCase):
    def test_run_checks_passes(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertGreater(result["summary"]["passing"], 0)

    def test_json_serializable(self):
        result = mod.run_checks()
        blob = json.dumps(result, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-nr4")


if __name__ == "__main__":
    unittest.main()
