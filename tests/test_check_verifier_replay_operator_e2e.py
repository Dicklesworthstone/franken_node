"""Unit tests for scripts/check_verifier_replay_operator_e2e.py."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_verifier_replay_operator_e2e.py"

spec = importlib.util.spec_from_file_location("check_verifier_replay_operator_e2e", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestConstants(unittest.TestCase):
    def test_bead_constants(self):
        self.assertEqual(mod.BEAD, "bd-1z5a.3")
        self.assertEqual(mod.PARENT_BEAD, "bd-1z5a")

    def test_required_stage_ids(self):
        self.assertEqual(
            mod.REQUIRED_STAGE_IDS,
            [
                "capsule_verify_success",
                "capsule_verify_reject_tampered",
                "capsule_verify_fraud_proof",
                "capsule_verify_quarantine_replay",
                "verifier_score_update",
            ],
        )


class TestRunChecks(unittest.TestCase):
    def test_verdict_passes(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_result_shape(self):
        result = mod.run_checks()
        for key in ("bead_id", "parent_bead", "title", "verdict", "total", "passed", "failed", "checks"):
            self.assertIn(key, result)

    def test_checks_nonempty(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["total"], 10)
        self.assertIsInstance(result["checks"], list)

    def test_summary_and_bundle_artifacts_exist(self):
        result = mod.run_checks()
        checks = {check["id"]: check for check in result["checks"]}
        self.assertTrue(checks["OP-E2E-SUMMARY-FILE"]["pass"])
        self.assertTrue(checks["OP-E2E-BUNDLE-FILE"]["pass"])
        self.assertTrue(checks["OP-E2E-LOG-FILE"]["pass"])

    def test_stage_build_ids_are_present(self):
        result = mod.run_checks()
        checks = {check["id"]: check for check in result["checks"]}
        self.assertTrue(checks["OP-E2E-STAGE-BUILD-IDS"]["pass"], checks["OP-E2E-STAGE-BUILD-IDS"]["detail"])
        self.assertTrue(checks["OP-E2E-STAGE-PROVENANCE"]["pass"], checks["OP-E2E-STAGE-PROVENANCE"]["detail"])
        self.assertTrue(checks["OP-E2E-LOG-BUILD-IDS"]["pass"], checks["OP-E2E-LOG-BUILD-IDS"]["detail"])
        self.assertTrue(checks["OP-E2E-LOG-PROVENANCE"]["pass"], checks["OP-E2E-LOG-PROVENANCE"]["detail"])
        self.assertTrue(checks["OP-E2E-BUILD-IDS"]["pass"], checks["OP-E2E-BUILD-IDS"]["detail"])
        self.assertTrue(
            checks["OP-E2E-SUMMARY-PROVENANCE"]["pass"], checks["OP-E2E-SUMMARY-PROVENANCE"]["detail"]
        )
        self.assertTrue(
            checks["OP-E2E-SUMMARY-MD-BUILD-IDS"]["pass"], checks["OP-E2E-SUMMARY-MD-BUILD-IDS"]["detail"]
        )
        self.assertTrue(
            checks["OP-E2E-SUMMARY-MD-PROVENANCE"]["pass"], checks["OP-E2E-SUMMARY-MD-PROVENANCE"]["detail"]
        )

    def _failing(self, result):
        failures = [check for check in result["checks"] if not check["pass"]]
        return "\n".join(f"FAIL: {check['id']} :: {check['detail']}" for check in failures[:10])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        payload = mod.self_test()
        self.assertEqual(payload["verdict"], "PASS")


class TestCli(unittest.TestCase):
    def test_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["bead_id"], "bd-1z5a.3")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestSummaryMarkdownRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary = json.loads(mod.SUMMARY_JSON.read_text(encoding="utf-8"))
        cls.summary_md = mod.SUMMARY_MD.read_text(encoding="utf-8")

    def _checks(self, markdown_text):
        return {check["id"]: check for check in mod.evaluate_summary_markdown(self.summary, markdown_text)}

    def test_summary_markdown_matches_current_provenance(self):
        checks = self._checks(self.summary_md)
        self.assertTrue(
            checks["OP-E2E-SUMMARY-MD-BUILD-IDS"]["pass"], checks["OP-E2E-SUMMARY-MD-BUILD-IDS"]["detail"]
        )
        self.assertTrue(
            checks["OP-E2E-SUMMARY-MD-PROVENANCE"]["pass"], checks["OP-E2E-SUMMARY-MD-PROVENANCE"]["detail"]
        )

    def test_summary_markdown_fails_when_build_ids_drop(self):
        build_ids = self.summary["build_ids"]
        expected_line = f"- Build IDs: `{', '.join(str(build_id) for build_id in build_ids)}`"
        mutated_line = f"- Build IDs: `{', '.join(str(build_id) for build_id in build_ids[:-1])}`"
        mutated_markdown = self.summary_md.replace(expected_line, mutated_line, 1)
        checks = self._checks(mutated_markdown)
        self.assertFalse(checks["OP-E2E-SUMMARY-MD-BUILD-IDS"]["pass"])

    def test_summary_markdown_fails_when_stage_row_loses_worker(self):
        stage_id = mod.REQUIRED_STAGE_IDS[0]
        worker_id = self.summary["stage_provenance"][stage_id]["worker_id"]
        mutated_markdown = self.summary_md.replace(f"`{worker_id}`", "`worker-redacted`", 1)
        checks = self._checks(mutated_markdown)
        self.assertFalse(checks["OP-E2E-SUMMARY-MD-PROVENANCE"]["pass"])


if __name__ == "__main__":
    unittest.main()
