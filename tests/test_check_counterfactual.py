"""Unit tests for scripts/check_counterfactual.py."""

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_counterfactual",
    ROOT / "scripts" / "check_counterfactual.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixture(TestCase):
    def test_fixture_exists(self):
        self.assertTrue(mod.FIXTURE.is_file())

    def test_fixture_vectors_non_empty(self):
        vectors = mod.load_fixture_vectors()
        self.assertGreater(len(vectors), 0)


class TestCounterfactualSimulation(TestCase):
    def setUp(self):
        vectors = mod.load_fixture_vectors()
        self.bundle = mod.fixture_to_bundle(vectors)

    def test_single_policy_swap_diverges(self):
        result = mod.run_counterfactual(
            self.bundle,
            mod.BASELINE_POLICY,
            mod.STRICT_POLICY,
        )
        self.assertGreater(len(result["divergence_points"]), 0)

    def test_single_mode_deterministic(self):
        first = mod.run_counterfactual(
            self.bundle,
            mod.BASELINE_POLICY,
            mod.STRICT_POLICY,
        )
        second = mod.run_counterfactual(
            self.bundle,
            mod.BASELINE_POLICY,
            mod.STRICT_POLICY,
        )
        self.assertEqual(mod.canonical_json(first), mod.canonical_json(second))

    def test_parameter_sweep_mode(self):
        results = mod.run_parameter_sweep(
            self.bundle,
            mod.BASELINE_POLICY,
            "quarantine_threshold",
            [60, 75, 90],
            mod.PolicyConfig("sweep", 85, 55, 10),
        )
        self.assertEqual(len(results), 3)
        self.assertTrue(any(len(item["divergence_points"]) > 0 for item in results))

    def test_timeout_guard_returns_partial(self):
        with self.assertRaises(mod.ReplayBoundExceeded) as ctx:
            mod.run_counterfactual(
                self.bundle,
                mod.BASELINE_POLICY,
                mod.STRICT_POLICY,
                max_wall_clock_ms=0,
            )
        self.assertEqual(ctx.exception.kind, "wall_clock")
        self.assertIsInstance(ctx.exception.partial_result, dict)

    def test_step_limit_guard_returns_partial(self):
        with self.assertRaises(mod.ReplayBoundExceeded) as ctx:
            mod.run_counterfactual(
                self.bundle,
                mod.BASELINE_POLICY,
                mod.STRICT_POLICY,
                max_steps=1,
            )
        self.assertEqual(ctx.exception.kind, "max_steps")
        self.assertIsInstance(ctx.exception.partial_result, dict)


class TestChecks(TestCase):
    def test_run_checks_passes(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2fa")
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)

    def test_check_contains_detects_pattern(self):
        results = mod.check_contains(mod.IMPL, ["pub struct CounterfactualReplayEngine"], "impl")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["pass"])


if __name__ == "__main__":
    main()
