"""Tests for scripts/check_scheduler_lanes.py (bd-lus)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_scheduler_lanes.py"

spec = importlib.util.spec_from_file_location("check_scheduler_lanes", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Unable to import scheduler lane checker from {SCRIPT}")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertIs(module.self_test(), True)


class TestChecks(unittest.TestCase):
    def test_all_checks_have_shape(self):
        checks = module._checks()
        self.assertIsInstance(checks, list)
        self.assertGreaterEqual(len(checks), 16)
        for c in checks:
            self.assertEqual(set(c.keys()), {"check", "passed", "detail"})
            self.assertIsInstance(c["check"], str)
            self.assertIsInstance(c["passed"], bool)
            self.assertIsInstance(c["detail"], str)

    def test_expected_checks_are_present(self):
        checks = module._checks()
        names = {c["check"] for c in checks}
        expected = {
            "lane_router_exists",
            "bulkhead_exists",
            "runtime_config_contract",
            "lane_event_codes",
            "metrics_contract",
            "mixed_workload_integration_test",
        }
        self.assertTrue(expected.issubset(names))

    def test_all_checks_pass(self):
        checks = module._checks()
        failed = [c for c in checks if not c["passed"]]
        self.assertEqual(failed, [], f"failed checks: {[c['check'] for c in failed]}")


class TestCli(unittest.TestCase):
    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.JSONDecoder().decode(result.stdout)
        self.assertEqual(payload["bead_id"], "bd-lus")
        self.assertEqual(payload["section"], "10.11")
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["checks_passed"], payload["checks_total"])

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("self_test:", result.stderr)


class TestRegressionCases(unittest.TestCase):
    def test_missing_lane_router_fails(self):
        original = module.LANE_ROUTER
        try:
            module.LANE_ROUTER = str(ROOT / "crates" / "franken-node" / "src" / "runtime" / "_missing_.rs")
            checks = module._checks()
        finally:
            module.LANE_ROUTER = original

        by_name = {c["check"]: c for c in checks}
        self.assertFalse(by_name["lane_router_exists"]["passed"])

    def test_missing_spec_fails(self):
        original = module.SPEC
        with tempfile.TemporaryDirectory() as tmpdir:
            module.SPEC = str(Path(tmpdir) / "missing.md")
            checks = module._checks()
        module.SPEC = original

        by_name = {c["check"]: c for c in checks}
        self.assertFalse(by_name["spec_exists"]["passed"])

    def test_comment_only_lane_router_markers_fail_closed(self):
        original = module.LANE_ROUTER
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                fake_router = Path(tmpdir) / "lane_router.rs"
                fake_router.write_text(
                    "\n".join(
                        [
                            '// pub const LANE_ASSIGNED: &str = "LANE_ASSIGNED";',
                            "// pub enum ProductLane { Cancel, Timed, Realtime, Background }",
                            "// pub struct LaneRouterConfig;",
                            "// pub struct LaneRouter;",
                            "// pub enum LaneRouterError {}",
                            "// pub fn assign_operation() {}",
                            "// #[test] fn integration_mixed_100_operations_respects_global_cap() {}",
                        ]
                    ),
                    encoding="utf-8",
                )
                module.LANE_ROUTER = str(fake_router)

                checks = module._checks()
        finally:
            module.LANE_ROUTER = original

        by_name = {c["check"]: c for c in checks}
        self.assertFalse(by_name["lane_event_codes"]["passed"])
        self.assertFalse(by_name["lane_core_types"]["passed"])
        self.assertFalse(by_name["lane_operations"]["passed"])
        self.assertFalse(by_name["mixed_workload_integration_test"]["passed"])

    def test_comment_only_config_markers_fail_closed(self):
        original = module.CONFIG
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                fake_config = Path(tmpdir) / "config.rs"
                fake_config.write_text(
                    "\n".join(
                        [
                            "// pub struct RuntimeConfig;",
                            "// pub struct RuntimeLaneConfig;",
                            "// pub enum LaneOverflowPolicy { Reject, EnqueueWithTimeout, ShedOldest }",
                            "// FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT",
                            "// FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS",
                        ]
                    ),
                    encoding="utf-8",
                )
                module.CONFIG = str(fake_config)

                checks = module._checks()
        finally:
            module.CONFIG = original

        by_name = {c["check"]: c for c in checks}
        self.assertFalse(by_name["overflow_policies"]["passed"])
        self.assertFalse(by_name["runtime_config_contract"]["passed"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
