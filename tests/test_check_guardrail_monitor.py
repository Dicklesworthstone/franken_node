"""Unit tests for scripts/check_guardrail_monitor.py (bd-3a3q)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_guardrail_monitor.py"


class TestCheckGuardrailMonitor(unittest.TestCase):
    """Tests for the guardrail monitor verification script."""

    def test_self_test_returns_tuple(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        result = mod.self_test()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_self_test_all_pass(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        all_pass, checks = mod.self_test()
        for c in checks:
            self.assertTrue(c["pass"], f"Check '{c['check']}' failed: {c['detail']}")
        self.assertTrue(all_pass)

    def test_impl_exists(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_impl_exists()
        self.assertTrue(ok, detail)

    def test_verdict_enum(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_verdict_enum()
        self.assertTrue(ok, detail)

    def test_system_state(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_system_state()
        self.assertTrue(ok, detail)

    def test_concrete_monitors(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_concrete_monitors()
        self.assertTrue(ok, detail)

    def test_monitor_set(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_monitor_set()
        self.assertTrue(ok, detail)

    def test_event_codes(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_event_codes()
        self.assertTrue(ok, detail)

    def test_anytime_valid(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_anytime_valid()
        self.assertTrue(ok, detail)

    def test_threshold_enforcement(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_threshold_enforcement()
        self.assertTrue(ok, detail)

    def test_test_count(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail, count = mod.count_tests()
        self.assertTrue(ok, detail)
        self.assertGreaterEqual(count, 35)

    def test_spec_exists(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_spec_exists()
        self.assertTrue(ok, detail)

    def test_telemetry_csv(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_guardrail_monitor as mod
        ok, detail = mod.check_telemetry_csv()
        self.assertTrue(ok, detail)

    def test_cli_human_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("PASS", result.stdout)

    def test_cli_json_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["bead_id"], "bd-3a3q")
        self.assertTrue(data["overall_pass"])

    def test_cli_json_checks_complete(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(result.stdout)
        check_names = {c["check"] for c in data["checks"]}
        required = {
            "impl_exists", "verdict_enum", "system_state",
            "concrete_monitors", "monitor_set", "event_codes",
            "anytime_valid", "threshold_enforcement", "test_count",
            "spec_exists", "telemetry_csv",
        }
        self.assertTrue(required.issubset(check_names), f"missing: {required - check_names}")


if __name__ == "__main__":
    unittest.main()
