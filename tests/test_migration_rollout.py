"""Integration and contract test for migration rollout state machine (bd-tenx3.3).

Verifies that `franken-node migrate rollout`:
- Enforces fail-closed validation when required arguments are missing
- Advances state through shadow -> canary -> ramp -> default
- Records durable transition receipts and state under .franken-node/state/rollout/
- Supports rollback action with proper status and history
- Rejects invalid stage skips unless forced
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def resolve_binary() -> Path:
    for var in ("FRANKEN_NODE_BIN", "CARGO_BIN_EXE_franken-node"):
        if os.environ.get(var):
            return Path(os.environ[var])
    target_roots = [ROOT / "target"]
    if os.environ.get("CARGO_TARGET_DIR"):
        target_roots.insert(0, Path(os.environ["CARGO_TARGET_DIR"]))
    for root in target_roots:
        for profile in ("debug", "release"):
            candidate = root / profile / "franken-node"
            if candidate.is_file():
                return candidate
    return ROOT / "target" / "debug" / "franken-node"


class TestMigrationRollout(unittest.TestCase):
    def setUp(self) -> None:
        self.binary = resolve_binary()
        self.temp_dir = tempfile.TemporaryDirectory(prefix="migration-rollout-test-")
        self.project_path = Path(self.temp_dir.name) / "test-app"
        self.project_path.mkdir(parents=True, exist_ok=True)
        # Create minimal package.json
        (self.project_path / "package.json").write_text(
            json.dumps({"name": "test-app", "version": "1.0.0"}),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def run_rollout(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        cmd = [str(self.binary), "migrate", "rollout"] + args
        return subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_missing_project_path_fails_closed_with_json_envelope(self) -> None:
        if not self.binary.is_file():
            self.skipTest(f"Binary not compiled at {self.binary}")

        proc = self.run_rollout(["--json"])
        self.assertNotEqual(proc.returncode, 0)

        data = json.loads(proc.stdout)
        self.assertEqual(data.get("schema_version"), "franken-node/migrate-error-cli/v1")
        self.assertEqual(data.get("command"), "migrate.rollout")
        self.assertFalse(data.get("ok", True))
        self.assertIn("requires a project path", data.get("error", ""))

    def test_rollout_lifecycle_shadow_to_default(self) -> None:
        if not self.binary.is_file():
            self.skipTest(f"Binary not compiled at {self.binary}")

        proj = str(self.project_path)

        # 1. Initial status query initializes in Shadow stage
        proc = self.run_rollout([proj, "--action", "status", "--json"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["stage"], "shadow")
        self.assertEqual(data["ramp_pct"], 0)

        # 2a. Leaving Shadow without lockstep evidence fails closed.
        proc = self.run_rollout([proj, "--action", "promote", "--json"])
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertFalse(data.get("ok", True))
        self.assertIn("requires lockstep evidence", data.get("error", ""))

        # 2b. A forced promotion proceeds but never claims lockstep verification
        # (bd-reality-20260923-26n9r.16: the flag was previously hard-coded true).
        proc = self.run_rollout([proj, "--action", "promote", "--force", "--json"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["stage"], "canary")
        self.assertEqual(data["ramp_pct"], 5)
        self.assertFalse(data["lockstep_verified"])
        self.assertIn("forced without lockstep evidence", data["message"])

        # 3. Promote Canary -> Ramp
        proc = self.run_rollout([proj, "--action", "promote", "--json"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["stage"], "ramp")
        self.assertEqual(data["ramp_pct"], 30)

        # 4. Promote Ramp with explicit 100%
        proc = self.run_rollout([proj, "--action", "promote", "--stage", "ramp", "--ramp-pct", "100", "--json"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["stage"], "ramp")
        self.assertEqual(data["ramp_pct"], 100)

        # 5. Promote Ramp 100% -> Default
        proc = self.run_rollout([proj, "--action", "promote", "--json"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["stage"], "default")
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["ramp_pct"], 100)

        # Verify durable state on disk
        state_dir = self.project_path / ".franken-node" / "state" / "rollout"
        self.assertTrue(state_dir.is_dir())
        state_files = list(state_dir.glob("*.json"))
        self.assertEqual(len(state_files), 1)

        saved_state = json.loads(state_files[0].read_text(encoding="utf-8"))
        self.assertEqual(saved_state["current_stage"], "default")
        self.assertEqual(saved_state["status"], "completed")
        self.assertGreaterEqual(len(saved_state["history"]), 4)

    def test_rollout_rollback_action(self) -> None:
        if not self.binary.is_file():
            self.skipTest(f"Binary not compiled at {self.binary}")

        proj = str(self.project_path)

        # Promote to Canary first (forced: no lockstep evidence in this test)
        self.run_rollout([proj, "--action", "promote", "--force", "--json"])

        # Execute Rollback
        proc = self.run_rollout([proj, "--action", "rollback", "--json"])
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["stage"], "aborted")
        self.assertEqual(data["status"], "rolled_back")
        self.assertTrue(data["rollback_triggered"])

        # Attempting to promote after rollback must fail
        proc2 = self.run_rollout([proj, "--action", "promote", "--json"])
        self.assertNotEqual(proc2.returncode, 0)
        data2 = json.loads(proc2.stdout)
        self.assertIn("cannot promote an aborted/rolled-back migration", data2.get("error", ""))


if __name__ == "__main__":
    unittest.main()
