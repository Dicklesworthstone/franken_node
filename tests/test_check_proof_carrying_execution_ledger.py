"""Unit tests for scripts/check_proof_carrying_execution_ledger.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_proof_carrying_execution_ledger",
    ROOT / "scripts" / "check_proof_carrying_execution_ledger.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestConstants(TestCase):
    def test_ids(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-2hqd.4")
        self.assertEqual(mod.SCHEMA_VERSION, "pcel-v1.0")

    def test_default_prefix(self) -> None:
        self.assertEqual(mod.DEFAULT_BEAD_PREFIX, "bd-2hqd")


class TestHelpers(TestCase):
    def test_canonical_json_deterministic(self) -> None:
        self.assertEqual(
            mod._canonical_json({"z": 1, "a": 2}),
            mod._canonical_json({"a": 2, "z": 1}),
        )

    def test_sha256_hex_deterministic(self) -> None:
        h1 = mod._sha256_hex(b"test")
        h2 = mod._sha256_hex(b"test")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_issue_dependencies_sorted(self) -> None:
        deps = mod._issue_dependencies(
            {
                "dependencies": [
                    {"depends_on_id": "bd-parent"},
                    {"depends_on_id": "bd-parent"},
                    {"id": "bd-alpha"},
                ]
            }
        )
        self.assertEqual(deps, ["bd-alpha", "bd-parent"])

    def test_merkle_root_deterministic(self) -> None:
        leaves = [mod._leaf_hash(mod._canonical_json({"bead_id": "a"})), mod._leaf_hash(mod._canonical_json({"bead_id": "b"}))]
        root1, depth1 = mod._merkle_root_hex(leaves)
        root2, depth2 = mod._merkle_root_hex(leaves)
        self.assertEqual(root1, root2)
        self.assertEqual(depth1, depth2)
        self.assertTrue(root1)

    def test_merkle_root_empty(self) -> None:
        root, depth = mod._merkle_root_hex([])
        self.assertEqual(root, "")
        self.assertEqual(depth, 0)

    def test_leaf_hash_matches_domain_separated_sha256(self) -> None:
        payload = mod._canonical_json({"bead_id": "a", "closed_at": "2026-02-22T00:00:00Z"})
        expected = mod._sha256_hex(mod.LEAF_DOMAIN + payload.encode("utf-8"))
        self.assertEqual(mod._leaf_hash(payload), expected)


class TestRunAll(TestCase):
    def test_default_scope_passes(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["scope"]["bead_prefix"], "bd-2hqd")
        self.assertGreaterEqual(report["scope"]["selected_closed_bead_count"], 4)

    def test_default_scope_contains_expected_beads(self) -> None:
        report = mod.run_all()
        bead_ids = {entry["bead_id"] for entry in report["beads"]}
        self.assertIn("bd-2hqd", bead_ids)
        self.assertIn("bd-2hqd.1", bead_ids)
        self.assertIn("bd-2hqd.2", bead_ids)
        self.assertIn("bd-2hqd.3", bead_ids)
        self.assertNotIn("bd-2hqd.4", bead_ids)

    def test_full_proof_count_matches_selected_for_default_scope(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["summary"]["full_proof_beads"], report["scope"]["selected_closed_bead_count"])

    def test_content_hash_is_sha256_hex(self) -> None:
        report = mod.run_all()
        self.assertEqual(len(report["content_hash"]), 64)
        int(report["content_hash"], 16)  # must parse as hex

    def test_custom_missing_issues_file_fails_scope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pcel-missing-issues-") as tmp:
            fake_issues = Path(tmp) / "missing.jsonl"
            report = mod.run_all(issues_path=fake_issues, artifacts_root=ROOT / "artifacts", bead_prefix="bd-does-not-exist")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["scope"]["selected_closed_bead_count"], 0)


class TestDependencyClosure(TestCase):
    def test_missing_dependency_detected(self) -> None:
        issue_index = {
            "bd-a": {"status": "closed"},
            "bd-b": {"status": "closed"},
        }
        entries = [
            {"bead_id": "bd-a", "dependencies": ["bd-b"], "evidence_sha256": "x", "summary_sha256": "y"},
        ]
        missing, out_scope, unresolved = mod._compute_dependency_closure(entries, issue_index, {"bd-a"})
        self.assertEqual(len(missing), 0)
        self.assertEqual(len(out_scope), 1)
        self.assertEqual(out_scope[0]["missing_dependency"], "bd-b")
        self.assertEqual(len(unresolved), 0)

    def test_unresolved_dependency_detected(self) -> None:
        issue_index = {
            "bd-a": {"status": "closed"},
        }
        entries = [
            {"bead_id": "bd-a", "dependencies": ["bd-missing"], "evidence_sha256": "x", "summary_sha256": "y"},
        ]
        missing, out_scope, unresolved = mod._compute_dependency_closure(entries, issue_index, {"bd-a"})
        self.assertEqual(len(missing), 0)
        self.assertEqual(len(out_scope), 0)
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]["missing_dependency"], "bd-missing")


class TestWriteReport(TestCase):
    def test_writes_json_and_markdown(self) -> None:
        report = mod.run_all()
        with tempfile.TemporaryDirectory(prefix="pcel-report-") as tmp:
            ledger = Path(tmp) / "ledger.json"
            summary = Path(tmp) / "ledger.md"
            mod.write_report(report, ledger_path=ledger, summary_path=summary)
            self.assertTrue(ledger.is_file())
            self.assertTrue(summary.is_file())
            parsed = json.loads(ledger.read_text(encoding="utf-8"))
            self.assertEqual(parsed["bead_id"], "bd-2hqd.4")
            self.assertIn("Proof-Carrying Execution Ledger", summary.read_text(encoding="utf-8"))


class TestSelfTest(TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertGreaterEqual(result["passed"], 5)


class TestCli(TestCase):
    def test_cli_self_test_json(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_proof_carrying_execution_ledger.py"), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS")

    def test_cli_default_json(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_proof_carrying_execution_ledger.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["bead_id"], "bd-2hqd.4")
        self.assertEqual(payload["verdict"], "PASS")


if __name__ == "__main__":
    main()
