#!/usr/bin/env python3
"""Unit tests for scripts/lockfile_drift_guard.py."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent / "lockfile_drift_guard.py"


class LockfileDriftGuardTests(unittest.TestCase):
    def run_guard(self, root: Path, command: list[str], *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root), *args, "--", *command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_json_passes_when_command_leaves_lockfile_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lockfile = root / "Cargo.lock"
            lockfile.write_text("stable\n", encoding="utf-8")

            proc = self.run_guard(root, [sys.executable, "-c", "pass"], "--json")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["verdict"], "PASS")
            self.assertEqual(report["command_exit_code"], 0)
            self.assertEqual(report["changed_paths"], [])
            self.assertEqual(lockfile.read_text(encoding="utf-8"), "stable\n")

    def test_json_fails_when_command_modifies_cargo_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.lock").write_text("before\n", encoding="utf-8")

            proc = self.run_guard(
                root,
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('Cargo.lock').write_text('after\\n', encoding='utf-8')",
                ],
                "--json",
            )

            self.assertEqual(proc.returncode, 20)
            report = json.loads(proc.stdout)
            self.assertEqual(report["verdict"], "FAIL")
            self.assertEqual(report["command_exit_code"], 0)
            self.assertEqual(report["changed_paths"], ["Cargo.lock"])
            self.assertEqual(report["lockfiles"][0]["status"], "modified")
            self.assertIn("Cargo.lock", report["next_action"])

    def test_human_output_names_command_and_changed_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.lock").write_text("before\n", encoding="utf-8")

            proc = self.run_guard(
                root,
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('Cargo.lock').write_text('after\\n', encoding='utf-8')",
                ],
                "--label",
                "synthetic metadata drift",
            )

            self.assertEqual(proc.returncode, 20)
            self.assertIn("lockfile drift guard: FAIL", proc.stdout)
            self.assertIn("label: synthetic metadata drift", proc.stdout)
            self.assertIn("command:", proc.stdout)
            self.assertIn("- Cargo.lock", proc.stdout)
            self.assertIn("next_action:", proc.stdout)

    def test_command_failure_without_drift_returns_command_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.lock").write_text("stable\n", encoding="utf-8")

            proc = self.run_guard(root, [sys.executable, "-c", "raise SystemExit(7)"], "--json")

            self.assertEqual(proc.returncode, 7)
            report = json.loads(proc.stdout)
            self.assertEqual(report["verdict"], "FAIL")
            self.assertEqual(report["command_exit_code"], 7)
            self.assertEqual(report["guard_exit_code"], 7)
            self.assertEqual(report["changed_paths"], [])

    def test_command_timeout_reports_failure_without_lockfile_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.lock").write_text("stable\n", encoding="utf-8")

            proc = self.run_guard(
                root,
                [sys.executable, "-c", "import time; time.sleep(2)"],
                "--json",
                "--timeout-seconds",
                "1",
            )

            self.assertEqual(proc.returncode, 124)
            report = json.loads(proc.stdout)
            self.assertEqual(report["command_exit_code"], 124)
            self.assertEqual(report["changed_paths"], [])
            self.assertIn("timed out", proc.stderr)

    def test_report_json_is_written_for_shell_gate_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report_path = root / "artifacts" / "lock_drift.json"
            (root / "Cargo.lock").write_text("stable\n", encoding="utf-8")

            proc = self.run_guard(
                root,
                [sys.executable, "-c", "pass"],
                "--report-json",
                str(report_path),
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["verdict"], "PASS")
            self.assertEqual(report["changed_paths"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
