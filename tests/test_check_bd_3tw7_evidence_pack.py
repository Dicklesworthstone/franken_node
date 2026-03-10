"""Unit tests for scripts/check_bd_3tw7_evidence_pack.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_bd_3tw7_evidence_pack.py"

spec = importlib.util.spec_from_file_location("check_bd_3tw7_evidence_pack", SCRIPT_PATH)
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
        self.assertTrue(contract["witness_matrix_matches_evidence"])
        self.assertTrue(contract["source_paths_resolve"])
        self.assertTrue(contract["support_bead_contract_consistent"])
        self.assertTrue(contract["summary_markdown_matches_source"])
        self.assertTrue(contract["static_seed_notes_present"])

    def _failing(self, result):
        failures = [check for check in result["checks"] if not check["passed"]]
        return "\n".join(f"FAIL: {check['check']} :: {check['detail']}" for check in failures[:10])


class TestMutations(unittest.TestCase):
    def test_missing_support_bead_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        evidence_path = root / "artifacts/replacement_gap/bd-3tw7/verification_evidence.json"
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload["support_bead_ids"] = [bead for bead in payload["support_bead_ids"] if bead != "bd-3tw7.5"]
        evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("support bead ids", details)

    def test_witness_matrix_drift_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        witness_path = root / "artifacts/replacement_gap/bd-3tw7/witness_matrix.json"
        payload = json.loads(witness_path.read_text(encoding="utf-8"))
        payload[0]["reason_code"] = "TRUTHFULNESS_GATE_STATIC_DRIFT"
        witness_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("witness matrix file matches verification evidence payload", details)

    def test_summary_drift_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        summary_path = root / "artifacts/replacement_gap/bd-3tw7/verification_summary.md"
        summary_path.write_text(
            summary_path.read_text(encoding="utf-8").replace("`PASS`", "`FAIL`", 1),
            encoding="utf-8",
        )

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("verification summary markdown matches canonical evidence-pack rendering", details)

    def test_missing_artifact_path_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        evidence_path = root / "artifacts/replacement_gap/bd-3tw7/verification_evidence.json"
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload["artifacts"]["verification_summary"] = "artifacts/replacement_gap/bd-3tw7/missing_summary.md"
        evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("artifact paths resolve", details)

    def test_missing_note_phrase_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        evidence_path = root / "artifacts/replacement_gap/bd-3tw7/verification_evidence.json"
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload["notes"] = [
            note
            for note in payload["notes"]
            if "bd-3tw7.5 adds deterministic evidence-pack coherence coverage" not in note
        ]
        evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("verification evidence preserves required static-seed notes", details)


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
        self.assertEqual(payload["bead_id"], "bd-3tw7.5")

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
