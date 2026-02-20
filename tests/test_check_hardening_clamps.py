"""Unit tests for scripts/check_hardening_clamps.py (bd-1ayu)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_hardening_clamps.py"


class TestCheckHardeningClamps(unittest.TestCase):
    """Tests for the hardening clamps verification script."""

    # ---- self_test integration ----

    def test_self_test_returns_tuple(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        result = mod.self_test()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        all_pass, checks = result
        self.assertIsInstance(all_pass, bool)
        self.assertIsInstance(checks, list)

    def test_self_test_checks_are_dicts(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        _, checks = mod.self_test()
        for c in checks:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)

    def test_self_test_all_pass(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        all_pass, checks = mod.self_test()
        for c in checks:
            self.assertTrue(c["pass"], f"Check '{c['check']}' failed: {c['detail']}")
        self.assertTrue(all_pass)

    # ---- Individual check tests ----

    def test_impl_exists(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_impl_exists()
        self.assertTrue(ok, detail)

    def test_escalation_budget(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_escalation_budget()
        self.assertTrue(ok, detail)

    def test_clamp_result(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_clamp_result()
        self.assertTrue(ok, detail)

    def test_check_escalation_fn(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_check_escalation_fn()
        self.assertTrue(ok, detail)

    def test_clamp_event(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_clamp_event()
        self.assertTrue(ok, detail)

    def test_event_codes(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_event_codes()
        self.assertTrue(ok, detail)

    def test_rate_limit_logic(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_rate_limit_logic()
        self.assertTrue(ok, detail)

    def test_overhead_limit_logic(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_overhead_limit_logic()
        self.assertTrue(ok, detail)

    def test_determinism_test(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_determinism_test()
        self.assertTrue(ok, detail)

    def test_min_max_bounds(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_min_max_bounds()
        self.assertTrue(ok, detail)

    def test_test_count(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail, count = mod.count_tests()
        self.assertTrue(ok, detail)
        self.assertGreaterEqual(count, 25)

    def test_spec_exists(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_spec_exists()
        self.assertTrue(ok, detail)

    def test_metrics_csv(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_hardening_clamps as mod
        ok, detail = mod.check_metrics_csv()
        self.assertTrue(ok, detail)

    # ---- CLI interface tests ----

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
        self.assertEqual(data["bead_id"], "bd-1ayu")
        self.assertTrue(data["overall_pass"])
        self.assertIn("checks", data)
        self.assertIn("test_count", data)

    def test_cli_json_checks_complete(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(result.stdout)
        check_names = {c["check"] for c in data["checks"]}
        required = {
            "impl_exists", "escalation_budget", "clamp_result",
            "check_escalation_fn", "clamp_event", "event_codes",
            "rate_limit_logic", "overhead_limit_logic", "determinism_test",
            "min_max_bounds", "test_count", "spec_exists", "metrics_csv",
        }
        self.assertTrue(required.issubset(check_names), f"missing: {required - check_names}")


if __name__ == "__main__":
    unittest.main()
