"""Unit tests for scripts/check_bd_1z5a_evidence_pack.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_bd_1z5a_evidence_pack.py"

spec = importlib.util.spec_from_file_location("check_bd_1z5a_evidence_pack", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture_root() -> tuple[Path, tempfile.TemporaryDirectory[str]]:
    tmpdir = tempfile.TemporaryDirectory()
    root = Path(tmpdir.name)
    mod._materialize_self_test_fixture(root)
    return root, tmpdir


class TestRunChecks(unittest.TestCase):
    def test_verdict_passes(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_result_shape(self):
        result = mod.run_checks()
        for key in (
            "schema_version",
            "bead_id",
            "parent_bead",
            "title",
            "verdict",
            "total",
            "passed",
            "failed",
            "checks",
            "coherence_contract",
        ):
            self.assertIn(key, result)

    def test_contract_flags(self):
        result = mod.run_checks()
        contract = result["coherence_contract"]
        self.assertTrue(contract["artifact_paths_resolve"])
        self.assertTrue(contract["fixture_index_resolves"])
        self.assertTrue(contract["fraud_witness_links_consistent"])
        self.assertTrue(contract["summary_markdown_matches_bundle"])
        self.assertTrue(contract["stale_gap_language_absent"])

    def _failing(self, result):
        failures = [check for check in result["checks"] if not check["passed"]]
        return "\n".join(f"FAIL: {check['check']} :: {check['detail']}" for check in failures[:10])


class TestMutations(unittest.TestCase):
    def test_missing_coherence_checker_fixture_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        fixture_index_path = root / "artifacts/replacement_gap/bd-1z5a/replay_fixture_index.json"
        payload = json.loads(fixture_index_path.read_text(encoding="utf-8"))
        payload["fixtures"] = [
            fixture
            for fixture in payload["fixtures"]
            if fixture.get("id") != "evidence_pack_coherence_checker"
        ]
        fixture_index_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["detail"] for check in result["checks"] if not check["passed"])
        self.assertIn("evidence_pack_coherence_checker", details)

    def test_missing_artifact_path_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        evidence_path = root / "artifacts/replacement_gap/bd-1z5a/verification_evidence.json"
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload["artifacts"]["operator_e2e_bundle"] = "artifacts/replacement_gap/bd-1z5a/missing.json"
        evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        failing = next(check for check in result["checks"] if not check["passed"])
        self.assertIn("artifact paths resolve", failing["check"])

    def test_fraud_proof_mismatch_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        fraud_path = root / "artifacts/replacement_gap/bd-1z5a/fraud_proof_bundle.json"
        payload = json.loads(fraud_path.read_text(encoding="utf-8"))
        payload["fraud_proof_id"] = "wrong-fraud-proof-id"
        fraud_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("fraud proof witness matches operator bundle and structured log", details)

    def test_stale_gap_phrase_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        summary_path = root / "artifacts/replacement_gap/bd-1z5a/verification_summary.md"
        summary_path.write_text(
            summary_path.read_text(encoding="utf-8") + "\nmissing operator shell coverage\n",
            encoding="utf-8",
        )

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("stale gap language", details)

    def test_operator_summary_markdown_drift_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        summary_md_path = root / "artifacts/replacement_gap/bd-1z5a/operator_e2e_summary.md"
        summary_md_path.write_text(
            summary_md_path.read_text(encoding="utf-8").replace("**PASS**", "**FAIL**"),
            encoding="utf-8",
        )

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("summary markdown matches canonical bundle rendering", details)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        payload = mod.self_test()
        self.assertEqual(payload["verdict"], "PASS", payload)


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
        self.assertEqual(payload["bead_id"], "bd-1z5a.9")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
