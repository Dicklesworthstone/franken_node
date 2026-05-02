#!/usr/bin/env python3
"""Unit tests for scripts/check_bpet_migration_gate.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_bpet_migration_gate as checker


def _write_pass_fixture(root: Path) -> None:
    for rel in checker.REQUIRED_FILES:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith(".json"):
            path.write_text(
                json.dumps(
                    {
                        "migration_id": "mig-123",
                        "admission": {
                            "verdict": "staged_rollout_required",
                            "baseline": {
                                "instability_score": 0.2,
                                "drift_score": 0.1,
                                "regime_shift_probability": 0.1,
                            },
                            "projected": {
                                "instability_score": 0.7,
                                "drift_score": 0.4,
                                "regime_shift_probability": 0.6,
                            },
                            "delta": {
                                "instability_delta": 0.5,
                                "drift_delta": 0.3,
                                "regime_shift_delta": 0.5,
                            },
                            "thresholds": {
                                "max_instability_delta_for_direct_admit": 0.08,
                                "max_drift_score_for_direct_admit": 0.30,
                                "max_regime_shift_probability_for_direct_admit": 0.22,
                                "max_instability_score_for_staged_rollout": 0.62,
                                "max_regime_shift_probability_for_staged_rollout": 0.45,
                            },
                            "additional_evidence_required": ["bpet.calibration_report"],
                            "staged_rollout": {
                                "steps": [],
                                "fallback": {
                                    "rollback_to_version": "v2-previous",
                                    "quarantine_window_minutes": 90,
                                    "required_artifacts": [],
                                },
                            },
                            "events": [
                                {"code": "BPET-MIGRATE-001"},
                                {"code": "BPET-MIGRATE-004"},
                            ],
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        elif rel.endswith("bpet_migration_gate.rs"):
            path.write_text(
                "\n".join(checker.REQUIRED_SYMBOLS + checker.REQUIRED_EVENT_CODES),
                encoding="utf-8",
            )
        else:
            path.write_text("ok", encoding="utf-8")


class TestRequiredFiles(unittest.TestCase):
    def test_missing_files_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = checker.check_required_files(Path(tmp))
            self.assertTrue(any(c["status"] == "FAIL" for c in checks))

    def test_present_files_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            checks = checker.check_required_files(root)
            self.assertTrue(all(c["status"] == "PASS" for c in checks))


class TestRustContract(unittest.TestCase):
    def test_missing_gate_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = checker.check_rust_contract(Path(tmp))
            self.assertEqual(checks[0]["status"], "FAIL")

    def test_contract_symbols_and_events_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            checks = checker.check_rust_contract(root)
            self.assertTrue(all(c["status"] == "PASS" for c in checks))


class TestReportValidation(unittest.TestCase):
    def test_missing_report_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = checker.check_report(Path(tmp))
            self.assertEqual(checks[0]["status"], "FAIL")

    def test_invalid_json_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "artifacts/10.21/bpet_migration_gate_results.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("{bad-json", encoding="utf-8")
            checks = checker.check_report(root)
            self.assertEqual(checks[0]["status"], "FAIL")

    def test_valid_report_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            checks = checker.check_report(root)
            self.assertTrue(all(c["status"] == "PASS" for c in checks))

    def test_invalid_verdict_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            report = root / "artifacts/10.21/bpet_migration_gate_results.json"
            data = json.JSONDecoder().decode(report.read_text(encoding="utf-8"))
            data["admission"]["verdict"] = "bad"
            report.write_text(json.dumps(data), encoding="utf-8")
            checks = checker.check_report(root)
            verdict = [c for c in checks if c["id"] == "BDAOQ6-ADMISSION-VERDICT"]
            self.assertEqual(verdict[0]["status"], "FAIL")


class TestRunChecks(unittest.TestCase):
    def test_run_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            result = checker.run_checks(root)
            self.assertEqual(result["verdict"], "PASS")

    def test_run_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = checker.run_checks(Path(tmp))
            self.assertEqual(result["verdict"], "FAIL")


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        result = checker.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
