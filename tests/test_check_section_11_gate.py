"""Unit tests for scripts/check_section_11_gate.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_section_11_gate",
    ROOT / "scripts" / "check_section_11_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestGateConstants(TestCase):
    def test_has_all_expected_beads(self) -> None:
        bead_ids = [entry.bead for entry in mod.SECTION_ENTRIES]
        self.assertEqual(len(bead_ids), 9)
        self.assertIn("bd-3se1", bead_ids)
        self.assertIn("bd-2ut3", bead_ids)

    def test_required_field_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_CONTRACT_FIELDS), 15)


class TestHelpers(TestCase):
    def test_parse_passed_failed(self) -> None:
        passed, failed = mod._parse_passed_failed("Ran 8 tests in 0.1s\nFAILED (failures=2)\n8 passed, 2 failed")
        self.assertEqual(passed, 8)
        self.assertEqual(failed, 2)

    def test_self_test(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 4)

    def test_script_payload_accepts_status_pass(self) -> None:
        payload = {"status": "pass", "all_passed": True, "passed": 5, "total": 5}
        self.assertTrue(mod._is_script_payload_pass(payload))

    def test_script_payload_rejects_status_fail(self) -> None:
        payload = {"status": "failed", "all_passed": False, "passed": 4, "total": 5}
        self.assertFalse(mod._is_script_payload_pass(payload))

    def test_script_payload_rejects_unknown_status_without_counts(self) -> None:
        payload = {"status": "queued"}
        self.assertFalse(mod._is_script_payload_pass(payload))

    def test_script_payload_accepts_passed_equals_total(self) -> None:
        payload = {"passed": 7, "total": 7}
        self.assertTrue(mod._is_script_payload_pass(payload))

    def test_script_payload_rejects_non_numeric_counts(self) -> None:
        payload = {"passed": "many", "total": 7}
        self.assertFalse(mod._is_script_payload_pass(payload))


class TestRepositoryChecks(TestCase):
    def test_contract_coverage_passes_current_repo(self) -> None:
        result = mod.check_contract_coverage()
        self.assertEqual(result["status"], "PASS")

    def test_evidence_check_current_repo(self) -> None:
        result = mod.check_evidence_artifacts()
        self.assertIn(result["status"], {"PASS", "FAIL"})
        self.assertEqual(len(result["details"]["results"]), 9)


class TestReportAssembly(TestCase):
    def test_build_report_shape(self) -> None:
        script_results = [
            {
                "bead": entry.bead,
                "name": entry.name,
                "script": entry.script,
                "status": "PASS",
                "exit_code": 0,
                "payload": {"ok": True},
                "stderr": "",
            }
            for entry in mod.SECTION_ENTRIES
        ]
        test_results = [
            {
                "bead": entry.bead,
                "test": entry.test,
                "status": "PASS",
                "passed": 1,
                "failed": 0,
                "exit_code": 0,
            }
            for entry in mod.SECTION_ENTRIES
        ]
        evidence_results = [
            {
                "bead": entry.bead,
                "path": f"artifacts/section_11/{entry.bead}/verification_evidence.json",
                "status": "PASS",
                "verdict": "PASS",
            }
            for entry in mod.SECTION_ENTRIES
        ]

        script_check = {
            "id": "GATE11-SCRIPTS",
            "status": "PASS",
            "details": {
                "total": len(script_results),
                "passing": len(script_results),
                "results": script_results,
                "events": [
                    {
                        "event_code": "GATE_11_BEAD_CHECKED",
                        "severity": "info",
                        "bead": entry.bead,
                        "script": entry.script,
                        "status": "PASS",
                    }
                    for entry in mod.SECTION_ENTRIES
                ],
            },
        }
        test_check = {
            "id": "GATE11-TESTS",
            "status": "PASS",
            "details": {
                "results": test_results,
                "total_passed": len(test_results),
                "total_failed": 0,
                "companion_test_coverage_pct": 100.0,
                "threshold_pct": 100.0,
                "meets_threshold": True,
            },
        }
        evidence_check = {
            "id": "GATE11-EVIDENCE",
            "status": "PASS",
            "details": {
                "results": evidence_results,
                "missing_or_invalid": [],
            },
        }
        coverage_check = {
            "id": "GATE11-CONTRACT-COVERAGE",
            "status": "PASS",
            "details": {
                "required_fields": mod.REQUIRED_CONTRACT_FIELDS,
                "missing_or_invalid": [],
            },
        }

        with (
            patch.object(mod, "_ensure_changed_files_fixture", return_value=ROOT / "artifacts/section_11/bd-c781/changed_files_for_validation.txt"),
            patch.object(mod, "run_verification_scripts", return_value=script_check),
            patch.object(mod, "run_unit_tests", return_value=test_check),
            patch.object(mod, "check_evidence_artifacts", return_value=evidence_check),
            patch.object(mod, "check_contract_coverage", return_value=coverage_check),
        ):
            report = mod.build_report()

        self.assertTrue(report["gate_pass"])
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["bead_id"], "bd-c781")
        self.assertEqual(len(report["per_bead_results"]), 9)
        self.assertIn("content_hash", report)
        self.assertTrue(any(evt["event_code"] == "GATE_11_VERDICT_EMITTED" for evt in report["events"]))


if __name__ == "__main__":
    main()
