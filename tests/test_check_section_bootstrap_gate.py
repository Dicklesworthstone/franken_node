"""Unit tests for scripts/check_section_bootstrap_gate.py (bd-3ohj)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_section_bootstrap_gate",
    ROOT / "scripts" / "check_section_bootstrap_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestGateConstants(TestCase):
    def test_ids(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-3ohj")
        self.assertEqual(mod.SECTION, "bootstrap")

    def test_title(self) -> None:
        self.assertIn("verification gate", mod.TITLE.lower())

    def test_paths_use_root(self) -> None:
        self.assertTrue(str(mod.SECTION_ARTIFACTS_DIR).startswith(str(mod.ROOT)))
        self.assertTrue(str(mod.SUMMARY_PATH).startswith(str(mod.ROOT)))


class TestEvidencePassed(TestCase):
    def test_verdict_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({"verdict": "PASS"}))

    def test_verdict_fail(self) -> None:
        self.assertFalse(mod.evidence_passed({"verdict": "FAIL"}))

    def test_overall_pass_true(self) -> None:
        self.assertTrue(mod.evidence_passed({"overall_pass": True}))

    def test_overall_passed_true(self) -> None:
        self.assertTrue(mod.evidence_passed({"overall_passed": True}))

    def test_all_passed_true(self) -> None:
        self.assertTrue(mod.evidence_passed({"all_passed": True}))

    def test_status_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({"status": "pass"}))

    def test_implemented_with_baseline(self) -> None:
        self.assertTrue(mod.evidence_passed({"status": "implemented_with_baseline_quality_debt"}))

    def test_acceptance_criteria_all_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({
            "acceptance_criteria": [
                {"id": 1, "status": "pass"},
                {"id": 2, "status": "pass"},
            ]
        }))

    def test_acceptance_criteria_one_fail(self) -> None:
        self.assertFalse(mod.evidence_passed({
            "acceptance_criteria": [
                {"id": 1, "status": "pass"},
                {"id": 2, "status": "fail"},
            ]
        }))

    def test_nested_gate_verdict(self) -> None:
        self.assertTrue(mod.evidence_passed({
            "diagnostic_contract_gate": {"verdict": "PASS", "checks_passed": 34}
        }))

    def test_overall_status_contains_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({
            "overall_status": "pass_for_bd_2a3_scope_with_workspace_quality_failures_documented"
        }))

    def test_verifier_results(self) -> None:
        self.assertTrue(mod.evidence_passed({
            "verifier_results": {"check_report": {"verdict": "PASS"}}
        }))

    def test_checks_list_all_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({
            "checks": [
                {"id": "c1", "pass": True},
                {"id": "c2", "pass": True},
            ]
        }))

    def test_checks_list_one_fail(self) -> None:
        self.assertFalse(mod.evidence_passed({
            "checks": [
                {"id": "c1", "pass": True},
                {"id": "c2", "pass": False},
            ]
        }))

    def test_empty_payload(self) -> None:
        self.assertFalse(mod.evidence_passed({}))


class TestDiscoverBeads(TestCase):
    def test_discovers_real_beads(self) -> None:
        beads = mod.discover_beads()
        # Should find at least the known bootstrap beads
        self.assertGreaterEqual(len(beads), 4)
        self.assertNotIn("bd-3ohj", beads, "Gate bead should be excluded from discovery")

    def test_known_beads_present(self) -> None:
        beads = mod.discover_beads()
        for expected in ("bd-2a3", "bd-n9r", "bd-1pk", "bd-32e"):
            self.assertIn(expected, beads, f"{expected} should be discovered")


class TestBuildReport(TestCase):
    def test_report_shape(self) -> None:
        report = mod.build_report(write_outputs=False)
        self.assertEqual(report["bead_id"], "bd-3ohj")
        self.assertEqual(report["section"], "bootstrap")
        self.assertIn(report["verdict"], ("PASS", "FAIL"))
        self.assertIsInstance(report["bead_results"], list)
        self.assertIsInstance(report["gate_checks"], list)
        self.assertGreater(report["beads_discovered"], 0)

    def test_report_json_serializable(self) -> None:
        report = mod.build_report(write_outputs=False)
        blob = json.dumps(report, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-3ohj")

    def test_coverage_computed(self) -> None:
        report = mod.build_report(write_outputs=False)
        self.assertIsInstance(report["coverage_pct"], float)
        self.assertGreaterEqual(report["coverage_pct"], 0.0)
        self.assertLessEqual(report["coverage_pct"], 100.0)

    def test_content_hash_present(self) -> None:
        report = mod.build_report(write_outputs=False)
        self.assertIn("content_hash", report)
        self.assertEqual(len(report["content_hash"]), 64)


class TestSelfTest(TestCase):
    def test_self_test_passes(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok, f"self_test should pass; failing checks: {[c for c in checks if not c['pass']]}")
        self.assertGreaterEqual(len(checks), 10)


class TestCanonicalJson(TestCase):
    def test_deterministic(self) -> None:
        a = mod._canonical_json({"z": 1, "a": 2})
        b = mod._canonical_json({"a": 2, "z": 1})
        self.assertEqual(a, b)


if __name__ == "__main__":
    main()
