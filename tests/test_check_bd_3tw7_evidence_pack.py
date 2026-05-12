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


def remove_issue_id(root: Path, bead_id: str) -> None:
    issues_path = root / ".beads/issues.jsonl"
    rows = [
        json.loads(line)
        for line in issues_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows = [row for row in rows if row.get("id") != bead_id]
    issues_path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


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
        self.assertTrue(contract["operator_e2e_contract_consistent"])
        self.assertTrue(contract["witness_matrix_matches_evidence"])
        self.assertTrue(contract["source_paths_resolve"])
        self.assertTrue(contract["support_bead_contract_consistent"])
        self.assertTrue(contract["bead_references_resolve"])
        self.assertTrue(contract["summary_markdown_matches_source"])
        self.assertTrue(contract["static_seed_notes_present"])
        self.assertTrue(contract["completion_debt_coverage_present"])
        self.assertTrue(contract["telemetry_contract_present"])

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

    def test_missing_operator_e2e_contract_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        evidence_path = root / "artifacts/replacement_gap/bd-3tw7/verification_evidence.json"
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload["artifacts"].pop("operator_e2e_suite", None)
        payload["operator_e2e"] = {}
        evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(
            check["check"] for check in result["checks"] if not check["passed"]
        )
        self.assertIn("operator E2E metadata matches primary truthfulness gate contract", details)

    def test_missing_support_bead_in_export_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        remove_issue_id(root, "bd-3tw7.1")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(
            check["check"] for check in result["checks"] if not check["passed"]
        )
        self.assertIn("referenced bead ids resolve in Beads export", details)

    def test_missing_parent_bead_in_export_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        remove_issue_id(root, "bd-3tw7")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        failing = next(check for check in result["checks"] if not check["passed"])
        self.assertEqual(
            failing["check"],
            "referenced bead ids resolve in Beads export",
        )
        self.assertIn("bd-3tw7", failing["detail"])

    def test_missing_checker_bead_in_export_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        remove_issue_id(root, "bd-3tw7.5")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        failing = next(check for check in result["checks"] if not check["passed"])
        self.assertEqual(
            failing["check"],
            "referenced bead ids resolve in Beads export",
        )
        self.assertIn("bd-3tw7.5", failing["detail"])

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

    def test_missing_completion_debt_coverage_item_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        evidence_path = root / "artifacts/replacement_gap/bd-3tw7/verification_evidence.json"
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload["coverage_obligations"] = [
            item
            for item in payload["coverage_obligations"]
            if item["spec_item"] != "telemetry.primary"
        ]
        evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("completion-debt coverage obligations cover e2e, migrations, and telemetry", details)

    def test_missing_witness_telemetry_field_fails(self):
        root, tmpdir = fixture_root()
        self.addCleanup(tmpdir.cleanup)
        evidence_path = root / "artifacts/replacement_gap/bd-3tw7/verification_evidence.json"
        witness_path = root / "artifacts/replacement_gap/bd-3tw7/witness_matrix.json"
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        witness_matrix = json.loads(witness_path.read_text(encoding="utf-8"))
        payload["witness_matrix"][0].pop("trace_id", None)
        witness_matrix[0].pop("trace_id", None)
        evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        witness_path.write_text(json.dumps(witness_matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = mod.run_checks(root)
        self.assertEqual(result["verdict"], "FAIL")
        details = "\n".join(check["check"] for check in result["checks"] if not check["passed"])
        self.assertIn("telemetry contract covers every witness result", details)


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
