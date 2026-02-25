"""Unit tests for scripts/check_replay_bundle.py."""

import importlib.util
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_replay_bundle",
    ROOT / "scripts" / "check_replay_bundle.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestFixture(TestCase):
    def test_fixture_exists(self):
        self.assertTrue(mod.FIXTURE.is_file())

    def test_fixture_has_vectors(self):
        vectors = mod.load_fixture_vectors()
        self.assertGreater(len(vectors), 0)


class TestBundleGeneration(TestCase):
    def test_generate_bundle(self):
        vectors = mod.load_fixture_vectors()
        bundle = mod.generate_sample_bundle("INC-TEST-001", vectors)
        self.assertEqual(bundle["incident_id"], "INC-TEST-001")
        self.assertIn("timeline", bundle)
        self.assertGreater(len(bundle["timeline"]), 0)

    def test_bundle_deterministic(self):
        vectors = mod.load_fixture_vectors()
        bundle_a = mod.generate_sample_bundle("INC-TEST-DET", vectors)
        bundle_b = mod.generate_sample_bundle("INC-TEST-DET", vectors)
        self.assertEqual(mod.canonical_json(bundle_a), mod.canonical_json(bundle_b))

    def test_bundle_integrity(self):
        vectors = mod.load_fixture_vectors()
        bundle = mod.generate_sample_bundle("INC-TEST-HASH", vectors)
        self.assertTrue(mod.validate_sample_bundle_integrity(bundle))

    def test_bundle_integrity_detects_tamper(self):
        vectors = mod.load_fixture_vectors()
        bundle = mod.generate_sample_bundle("INC-TEST-TAMPER", vectors)
        bundle["timeline"][0]["payload"]["class"] = "tampered"
        self.assertFalse(mod.validate_sample_bundle_integrity(bundle))


class TestCheckHelpers(TestCase):
    def test_check_file_positive(self):
        result = mod.check_file(mod.IMPL, "impl")
        self.assertTrue(result["pass"])

    def test_check_contains(self):
        results = mod.check_contains(mod.IMPL, ["pub struct ReplayBundle"], "impl")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["pass"])


class TestRunChecks(TestCase):
    def test_run_checks_shape(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-vll")
        self.assertEqual(result["section"], "10.5")
        self.assertIn("checks", result)
        self.assertIn("summary", result)

    def test_run_checks_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


class TestCanonical(TestCase):
    def test_canonical_sorts_keys(self):
        raw = {"b": 2, "a": 1}
        self.assertEqual(mod.canonical(raw), {"a": 1, "b": 2})

    def test_canonical_json_stable(self):
        a = {"z": 1, "a": {"y": 2, "x": 3}}
        b = {"a": {"x": 3, "y": 2}, "z": 1}
        self.assertEqual(mod.canonical_json(a), mod.canonical_json(b))


if __name__ == "__main__":
    main()
