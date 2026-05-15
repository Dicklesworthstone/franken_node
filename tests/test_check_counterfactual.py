"""Unit tests for scripts/check_counterfactual.py."""

import importlib.util
import sys
from copy import deepcopy
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


class TestEvidenceAnalysis(TestCase):
    def _valid_evidence(self):
        data = mod.load_evidence()
        self.assertIsInstance(data, dict)
        return deepcopy(data)

    def test_valid_evidence_passes(self):
        checks = mod.check_evidence(self._valid_evidence())
        self.assertTrue(all(check["pass"] for check in checks), self._failing(checks))

    def test_missing_evidence_fails_closed(self):
        checks = mod.check_evidence({})
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(check["check"] == "evidence: bead id" and not check["pass"] for check in checks))

    def test_missing_required_file_fails_closed(self):
        data = self._valid_evidence()
        data["implementation"]["files"] = []
        checks = mod.check_evidence(data)
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(check["check"].startswith("evidence file:") and not check["pass"] for check in checks))

    def test_missing_acceptance_mapping_fails_closed(self):
        data = self._valid_evidence()
        data["acceptance_criteria_mapping"] = []
        checks = mod.check_evidence(data)
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(check["check"].startswith("evidence acceptance:") and not check["pass"] for check in checks))

    def test_missing_rch_command_fails_closed(self):
        data = self._valid_evidence()
        data["verification"]["commands"] = []
        checks = mod.check_evidence(data)
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(check["check"].startswith("evidence command recorded:") and not check["pass"] for check in checks))

    def _failing(self, checks):
        failures = [check for check in checks if not check["pass"]]
        return "\n".join(f"FAIL: {check['check']}: {check['detail']}" for check in failures[:10])


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

    def test_rust_test_markers_present(self):
        checks = mod.check_rust_tests()
        self.assertTrue(all(check["pass"] for check in checks))


if __name__ == "__main__":
    main()
