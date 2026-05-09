"""Unit tests for scripts/check_canonical_serialization.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_canonical_serialization as mod


class TestConstants(unittest.TestCase):
    def test_required_structs_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_STRUCTS), 6)

    def test_required_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 3)

    def test_required_error_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 5)

    def test_required_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_required_functions_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_FUNCTIONS), 15)

    def test_trust_object_types_count(self):
        self.assertEqual(len(mod.TRUST_OBJECT_TYPES), 6)


class TestProductionEvidence(unittest.TestCase):
    def test_simulation_helper_removed(self):
        self.assertFalse(hasattr(mod, "simulate_canonical_serialization"))

    def test_registered_rust_targets_required(self):
        targets = mod._cargo_test_targets()
        self.assertEqual(
            targets["canonical_serializer_real_inputs"],
            "tests/canonical_serializer_real_inputs.rs",
        )
        self.assertEqual(
            targets["canonical_serializer_conformance"],
            "tests/canonical_serializer_conformance.rs",
        )
        self.assertEqual(
            targets["canonical_serializer_metamorphic"],
            "tests/canonical_serializer_metamorphic.rs",
        )

    def test_production_evidence_checks_pass(self):
        checks = mod.check_production_serializer_evidence()
        failures = [c for c in checks if not c["pass"]]
        self.assertFalse(failures, failures[:5])

    def test_run_checks_has_no_simulated_checks(self):
        result = mod.run_checks()
        self.assertFalse(
            [c for c in result["checks"] if c["check"].startswith("sim:")],
            "checker must not accept Python simulation as behavior evidence",
        )
        self.assertTrue(
            [c for c in result["checks"] if c["check"].startswith("prod:")],
            "checker must include production Rust evidence checks",
        )


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-jjm")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["total"], 95)

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestRunAll(unittest.TestCase):
    def test_run_all_alias(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-jjm")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok, "self_test failed")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-jjm")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result)


class TestHelpers(unittest.TestCase):
    def test_sha256_deterministic(self):
        h1 = mod._sha256_hex(b"test")
        h2 = mod._sha256_hex(b"test")
        self.assertEqual(h1, h2)

    def test_sha256_distinct(self):
        h1 = mod._sha256_hex(b"a")
        h2 = mod._sha256_hex(b"b")
        self.assertNotEqual(h1, h2)


class TestFileChecks(unittest.TestCase):
    def test_impl_exists(self):
        result = mod.run_checks()
        impl_check = next(c for c in result["checks"] if "canonical_serializer implementation" in c["check"])
        self.assertTrue(impl_check["pass"])

    def test_spec_exists(self):
        result = mod.run_checks()
        spec_check = next(c for c in result["checks"] if "contract spec" in c["check"])
        self.assertTrue(spec_check["pass"])


if __name__ == "__main__":
    unittest.main()
