"""Unit and adversarial tests for scripts/check_claims_registry_gates.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_claims_registry_gates.py"

spec = importlib.util.spec_from_file_location("check_claims_registry_gates", SCRIPT)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCheckClaimsRegistryGates(unittest.TestCase):
    def test_live_claims_registry_passes(self) -> None:
        report = mod.run_checks()
        self.assertTrue(report["overall_pass"], json.dumps(report, indent=2))
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["failing"], 0)

    def test_verified_claim_with_failing_gate_fails_closed(self) -> None:
        live = (ROOT / "docs" / "CLAIMS_REGISTRY.md").read_text(encoding="utf-8")
        # Flip CLAIM-003 (whose check_compromise_reduction_gate.py currently fails closed)
        # back to Status: verified and confirm our validator catches the lie immediately.
        tampered = live.replace(
            "- **Status**: pending (local 2026-09-29 snapshot measured 20.0×",
            "- **Status**: verified (tampered test; local 2026-09-29 snapshot measured 20.0×",
            1,
        )
        self.assertNotEqual(live, tampered)
        with tempfile.TemporaryDirectory() as tmp:
            reg_path = Path(tmp) / "CLAIMS_REGISTRY.md"
            reg_path.write_text(tampered, encoding="utf-8")
            report = mod.run_checks(registry_path=reg_path, repo_root=ROOT)
        self.assertFalse(report["overall_pass"])
        failing_names = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn(
            "CLAIM-003:verified_gate_passes:scripts/check_compromise_reduction_gate.py",
            failing_names,
        )

    def test_missing_charter_claim_022_fails_closed(self) -> None:
        live = (ROOT / "docs" / "CLAIMS_REGISTRY.md").read_text(encoding="utf-8")
        idx = live.index("### CLAIM-022:")
        truncated = live[:idx]
        with tempfile.TemporaryDirectory() as tmp:
            reg_path = Path(tmp) / "CLAIMS_REGISTRY.md"
            reg_path.write_text(truncated, encoding="utf-8")
            report = mod.run_checks(registry_path=reg_path, repo_root=ROOT)
        self.assertFalse(report["overall_pass"])
        failing_names = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("charter_claim_present:CLAIM-022", failing_names)

    def test_missing_referenced_gate_script_fails_closed(self) -> None:
        live = (ROOT / "docs" / "CLAIMS_REGISTRY.md").read_text(encoding="utf-8")
        tampered = live.replace(
            "scripts/check_independent_replications_gate.py",
            "scripts/check_nonexistent_replication_gate.py",
        )
        with tempfile.TemporaryDirectory() as tmp:
            reg_path = Path(tmp) / "CLAIMS_REGISTRY.md"
            reg_path.write_text(tampered, encoding="utf-8")
            report = mod.run_checks(registry_path=reg_path, repo_root=ROOT)
        self.assertFalse(report["overall_pass"])
        failing_names = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn(
            "CLAIM-022:gate_script_exists:scripts/check_nonexistent_replication_gate.py",
            failing_names,
        )

    def test_cli_json_and_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS")

        st = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(st.returncode, 0, st.stderr)
        self.assertTrue(json.loads(st.stdout)["self_test_passed"])


if __name__ == "__main__":
    unittest.main()
