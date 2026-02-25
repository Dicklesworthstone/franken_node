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


class TestSimulation(unittest.TestCase):
    def test_deterministic(self):
        result = mod.simulate_canonical_serialization()
        self.assertTrue(result["deterministic"])

    def test_round_trip(self):
        result = mod.simulate_canonical_serialization()
        self.assertTrue(result["round_trip_stable"])

    def test_preimage_domain_tag(self):
        result = mod.simulate_canonical_serialization()
        self.assertTrue(result["preimage_has_domain_tag"])

    def test_different_domains(self):
        result = mod.simulate_canonical_serialization()
        self.assertTrue(result["different_domains_differ"])

    def test_float_detected(self):
        result = mod.simulate_canonical_serialization()
        self.assertTrue(result["float_detected"])

    def test_object_type_count(self):
        result = mod.simulate_canonical_serialization()
        self.assertEqual(result["object_type_count"], 6)

    def test_event_code_count(self):
        result = mod.simulate_canonical_serialization()
        self.assertEqual(result["event_code_count"], 3)

    def test_error_code_count(self):
        result = mod.simulate_canonical_serialization()
        self.assertEqual(result["error_code_count"], 5)


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
        self.assertGreaterEqual(result["total"], 80)

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
