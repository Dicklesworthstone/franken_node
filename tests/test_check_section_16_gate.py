"""Unit tests for scripts/check_section_16_gate.py (bd-unkm)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_section_16_gate",
    ROOT / "scripts" / "check_section_16_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestConstants(TestCase):
    def test_ids(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-unkm")
        self.assertEqual(mod.SECTION, "16")

    def test_entry_count(self) -> None:
        self.assertEqual(len(mod.SECTION_ENTRIES), 8)
        bead_ids = [entry.bead for entry in mod.SECTION_ENTRIES]
        self.assertIn("bd-f955", bead_ids)
        self.assertIn("bd-33u2", bead_ids)


class TestHelpers(TestCase):
    def test_parse_unittest_counts_ok(self) -> None:
        ran, failed = mod.parse_unittest_counts("Ran 9 tests in 0.01s\n\nOK")
        self.assertEqual(ran, 9)
        self.assertEqual(failed, 0)

    def test_parse_unittest_counts_failed(self) -> None:
        ran, failed = mod.parse_unittest_counts("Ran 5 tests\nFAILED (failures=2, errors=1)")
        self.assertEqual(ran, 5)
        self.assertEqual(failed, 3)

    def test_evidence_passed_variants(self) -> None:
        self.assertTrue(mod.evidence_passed({"verdict": "PASS"}))
        self.assertTrue(mod.evidence_passed({"status": "completed_with_baseline_workspace_failures"}))
        self.assertTrue(
            mod.evidence_passed(
                {
                    "checks": [
                        {"status": "PASS"},
                        {"status": "FAIL_BASELINE"},
                    ]
                }
            )
        )
        self.assertFalse(mod.evidence_passed({"verdict": "FAIL"}))

    def test_publication_checklist_shape(self) -> None:
        evidence = {
            "bd-1sgr": mod._read_json(ROOT / "artifacts" / "section_16" / "bd-1sgr" / "verification_evidence.json"),
            "bd-e5cz": mod._read_json(ROOT / "artifacts" / "section_16" / "bd-e5cz" / "verification_evidence.json"),
            "bd-3id1": mod._read_json(ROOT / "artifacts" / "section_16" / "bd-3id1" / "verification_evidence.json"),
            "bd-2ad0": mod._read_json(ROOT / "artifacts" / "section_16" / "bd-2ad0" / "verification_evidence.json"),
            "bd-nbh7": mod._read_json(ROOT / "artifacts" / "section_16" / "bd-nbh7" / "verification_evidence.json"),
        }
        checklist = mod._publication_checklist(evidence)
        self.assertEqual(len(checklist), 4)
        ids = {item["id"] for item in checklist}
        reports = next(item for item in checklist if item["id"] == "PUB-16-REPORTS")
        self.assertEqual(reports["source"], "bd-1sgr publishable_report_count")
        self.assertGreaterEqual(reports["measured"], 3)
        self.assertEqual(
            ids,
            {
                "PUB-16-REPORTS",
                "PUB-16-REPLICATIONS",
                "PUB-16-REDTEAM",
                "PUB-16-DATASET-DOI",
            },
        )


class TestReportAssembly(TestCase):
    def test_build_report_no_execution(self) -> None:
        report = mod.build_report(execute=False, write_outputs=False)
        self.assertEqual(report["bead_id"], "bd-unkm")
        self.assertEqual(report["section"], "16")
        self.assertEqual(report["beads_expected"], 8)
        self.assertEqual(len(report["per_bead_results"]), 8)
        self.assertEqual(len(report["publication_checklist"]), 4)
        self.assertIn(report["verdict"], ("PASS", "FAIL"))

    def test_report_json_serializable(self) -> None:
        report = mod.build_report(execute=False, write_outputs=False)
        blob = json.dumps(report, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-unkm")

    def test_self_test(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 3)


if __name__ == "__main__":
    main()
