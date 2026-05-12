#!/usr/bin/env python3
"""Unit tests for check_split_contract.py."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_split_contract.py"


class TestSplitContractChecks(unittest.TestCase):
    """Test split contract enforcement checks."""

    def run_script(self, *args, root: Path | None = None):
        env = os.environ.copy()
        if root is not None:
            env["FRANKEN_NODE_SPLIT_CONTRACT_ROOT"] = str(root)
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True, text=True, timeout=30, env=env,
        )

    def test_script_runs_successfully(self):
        """Script should run and produce JSON output."""
        result = self.run_script("--json")
        self.assertEqual(result.returncode, 0, f"Script failed: {result.stderr}")
        output = json.loads(result.stdout)
        self.assertEqual(output["schema_version"], "franken-node/split-contract-report/v1")
        self.assertIn("verdict", output)
        self.assertIn("checks", output)

    def test_verdict_is_pass(self):
        """Current repo should pass all split contract checks."""
        result = self.run_script("--json")
        output = json.loads(result.stdout)
        self.assertEqual(output["verdict"], "PASS")

    def test_all_checks_present(self):
        """All expected check IDs should be in output."""
        result = self.run_script("--json")
        output = json.loads(result.stdout)
        check_ids = {c["id"] for c in output["checks"]}
        expected = {"SPLIT-NO-LOCAL", "SPLIT-PATH-DEPS", "SPLIT-NO-INTERNALS", "SPLIT-GOVERNANCE"}
        self.assertEqual(check_ids, expected)

    def test_no_local_engine_crates_check(self):
        """SPLIT-NO-LOCAL check should pass (no local engine dirs)."""
        result = self.run_script("--json")
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "SPLIT-NO-LOCAL")
        self.assertEqual(check["status"], "PASS")
        self.assertIn("checked", check["details"])

    def test_path_deps_check(self):
        """SPLIT-PATH-DEPS check should find valid engine path deps."""
        result = self.run_script("--json")
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "SPLIT-PATH-DEPS")
        self.assertEqual(check["status"], "PASS")
        # Should have found at least one cargo file with engine deps
        self.assertTrue(len(check["details"]["cargo_files"]) > 0)

    def test_governance_docs_check(self):
        """SPLIT-GOVERNANCE check should pass (required docs exist)."""
        result = self.run_script("--json")
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "SPLIT-GOVERNANCE")
        self.assertEqual(check["status"], "PASS")

    def test_summary_counts(self):
        """Summary should have correct pass/total counts."""
        result = self.run_script("--json")
        output = json.loads(result.stdout)
        summary = output["summary"]
        self.assertEqual(summary["total_checks"], 4)
        self.assertEqual(summary["passing_checks"], 4)
        self.assertEqual(summary["failing_checks"], 0)

    def test_telemetry_events_cover_each_check_and_gate(self):
        """Telemetry output should expose stable check and gate event codes."""
        result = self.run_script("--json")
        output = json.loads(result.stdout)
        telemetry = output["telemetry"]
        self.assertEqual(telemetry["schema_version"], "franken-node/split-contract-telemetry/v1")
        self.assertEqual(telemetry["namespace"], "franken_node.section_10_1.split_contract")
        self.assertEqual(len(telemetry["events"]), 5)
        event_codes = {event["event_code"] for event in telemetry["events"]}
        self.assertIn("SPLIT_CONTRACT_CHECK_PASSED", event_codes)
        self.assertIn("SPLIT_CONTRACT_GATE_PASSED", event_codes)
        for event in telemetry["events"]:
            self.assertEqual(event["status"], "PASS")
            self.assertFalse(event["fail_closed"])

    def test_migration_policy_blocks_local_engine_reintroduction(self):
        """Migration policy should make boundary violations merge-blocking."""
        result = self.run_script("--json")
        output = json.loads(result.stdout)
        policy = output["migration_policy"]
        self.assertEqual(
            policy["schema_version"],
            "franken-node/split-contract-migration-policy/v1",
        )
        self.assertEqual(policy["violation_action"], "block_merge")
        self.assertTrue(policy["fail_closed"])
        self.assertIn("crates/franken-engine", policy["forbidden_local_engine_crate_paths"])
        self.assertIn("docs/ENGINE_SPLIT_CONTRACT.md", policy["required_governance_documents"])

    def test_e2e_temp_repo_local_engine_copy_fails_closed(self):
        """Temp-repo E2E should fail when a local engine crate is reintroduced."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "crates" / "franken-node").mkdir(parents=True)
            (root / "crates" / "franken-engine").mkdir(parents=True)
            (root / "docs" / "ENGINE_SPLIT_CONTRACT.md").write_text(
                "franken_engine MUST NOT be copied locally; use path dependencies.\n"
            )
            (root / "docs" / "PRODUCT_CHARTER.md").write_text("Product charter.\n")
            (root / "crates" / "franken-node" / "Cargo.toml").write_text(
                "[dependencies]\n"
                'frankenengine-engine = { path = "../../../franken_engine/crates/franken-engine" }\n'
            )

            result = self.run_script("--json", root=root)
            output = json.loads(result.stdout)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(output["verdict"], "FAIL")
        no_local = next(c for c in output["checks"] if c["id"] == "SPLIT-NO-LOCAL")
        self.assertEqual(no_local["status"], "FAIL")
        gate_event = output["telemetry"]["events"][-1]
        self.assertEqual(gate_event["event_code"], "SPLIT_CONTRACT_GATE_FAILED")
        self.assertTrue(gate_event["fail_closed"])

    def test_human_readable_output(self):
        """Script should produce human-readable output without --json."""
        result = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertIn("Split Contract", result.stdout)
        self.assertIn("Verdict: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
