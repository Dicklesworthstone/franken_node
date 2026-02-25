"""Unit tests for scripts/check_section_12_gate.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_section_12_gate",
    ROOT / "scripts" / "check_section_12_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestGateConstants(TestCase):
    def test_bead_and_section(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-2x1e")
        self.assertEqual(mod.SECTION, "12")

    def test_entry_count(self) -> None:
        self.assertEqual(len(mod.SECTION_ENTRIES), 12)
        bead_ids = [entry.bead for entry in mod.SECTION_ENTRIES]
        self.assertIn("bd-s4cu", bead_ids)
        self.assertIn("bd-35m7", bead_ids)


class TestHelpers(TestCase):
    def test_parse_unittest_counts_ok(self) -> None:
        ran, failed = mod.parse_unittest_counts("Ran 20 tests in 0.003s\n\nOK")
        self.assertEqual(ran, 20)
        self.assertEqual(failed, 0)

    def test_parse_unittest_counts_failed(self) -> None:
        text = "Ran 7 tests in 0.002s\n\nFAILED (failures=1, errors=2)"
        ran, failed = mod.parse_unittest_counts(text)
        self.assertEqual(ran, 7)
        self.assertEqual(failed, 3)

    def test_evidence_passed_variants(self) -> None:
        self.assertTrue(mod.evidence_passed({"verdict": "PASS"}))
        self.assertTrue(mod.evidence_passed({"overall_pass": True}))
        self.assertTrue(mod.evidence_passed({"all_passed": True}))
        self.assertTrue(mod.evidence_passed({"status": "pass"}))
        self.assertTrue(mod.evidence_passed({"checks_total": 3, "checks_failed": 0}))
        self.assertFalse(mod.evidence_passed({"verdict": "FAIL"}))

    def test_has_self_test(self) -> None:
        entry = mod.SECTION_ENTRIES[0]
        self.assertTrue(mod.has_self_test(ROOT / entry.script))

    def test_self_test_passes(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 3)


class TestReportAssembly(TestCase):
    def test_build_report_no_execution_passes(self) -> None:
        report = mod.build_report(execute=False, write_outputs=False)
        self.assertTrue(report["gate_pass"])
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["bead_id"], "bd-2x1e")
        self.assertEqual(len(report["per_bead_results"]), 12)
        self.assertIn("content_hash", report)

    def test_report_is_json_serializable(self) -> None:
        report = mod.build_report(execute=False, write_outputs=False)
        blob = json.dumps(report, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["section"], "12")


if __name__ == "__main__":
    main()
