"""Unit tests for scripts/check_degraded_mode.py."""

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_degraded_mode",
    ROOT / "scripts" / "check_degraded_mode.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixture(TestCase):
    def test_impl_exists(self):
        self.assertTrue(mod.IMPL.is_file())

    def test_contract_exists(self):
        self.assertTrue(mod.SPEC.is_file())


class TestRealEvidence(TestCase):
    def test_real_evidence_requirements_present(self):
        self.assertGreaterEqual(len(mod.REAL_EVIDENCE_REQUIREMENTS), 6)

    def test_real_evidence_checks_pass(self):
        checks = mod.check_real_degraded_mode_evidence()
        self.assertGreaterEqual(len(checks), 6)
        self.assertTrue(all(check["pass"] for check in checks), checks)

    def test_legacy_python_model_removed(self):
        legacy_names = [
            "simulate_" + "mode_lifecycle",
            "base_" + "policy",
            "make_" + "state",
            "activate",
            "evaluate_" + "action",
            "tick_" + "mandatory",
            "maybe_" + "suspend",
            "observe_" + "recovery",
        ]
        for name in legacy_names:
            self.assertFalse(hasattr(mod, name), name)

    def test_run_checks_uses_real_evidence(self):
        result = mod.run_checks()
        names = [check["check"] for check in result["checks"]]
        legacy_prefix = "event " + "ordering:"
        self.assertTrue(any(name.startswith("real evidence:") for name in names))
        self.assertFalse(any(legacy_prefix in name for name in names))


class TestChecks(TestCase):
    def test_run_checks_passes(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-3nr")
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


if __name__ == "__main__":
    main()
