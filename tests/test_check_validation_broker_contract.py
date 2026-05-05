"""Unit tests for scripts/check_validation_broker_contract.py."""

from __future__ import annotations

import copy
import json
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_validation_broker_contract.py"


class ScriptNamespace:
    def __init__(self, values: dict[str, object]) -> None:
        object.__setattr__(self, "_values", values)

    def __getattr__(self, name: str) -> object:
        return self._values[name]

    def __setattr__(self, name: str, value: object) -> None:
        self._values[name] = value


script_globals = runpy.run_path(str(SCRIPT_PATH))
mod = ScriptNamespace(script_globals["run_all"].__globals__)


class ValidationBrokerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = json.JSONDecoder().decode(mod.FIXTURES_FILE.read_text(encoding="utf-8"))
        self.valid_receipt = self.fixtures["valid_receipts"][0]
        self.validation_time = mod._parse_rfc3339(self.fixtures["validation_time"])

    def test_run_all_passes(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_result_shape(self) -> None:
        result = mod.run_all()
        for key in ["bead_id", "title", "schema_version", "verdict", "checks", "timestamp"]:
            self.assertIn(key, result)
        self.assertEqual(result["bead_id"], "bd-1khdi")
        self.assertGreaterEqual(result["total"], 40)

    def test_valid_receipt_has_no_errors(self) -> None:
        errors = mod.validate_receipt(
            self.valid_receipt,
            expected_bead_id="bd-1khdi",
            now=self.validation_time,
        )
        self.assertEqual(errors, [])

    def test_fixture_invalid_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_receipts"]:
            with self.subTest(case=case["case"]):
                receipt = case.get(
                    "receipt",
                    mod.apply_fixture_patch(self.valid_receipt, case.get("patch")),
                )
                errors = mod.validate_receipt(
                    receipt,
                    expected_bead_id="bd-1khdi",
                    now=self.validation_time,
                )
                self.assertIn(case["expected_error"], errors)

    def test_missing_command_digest_rejected(self) -> None:
        receipt = copy.deepcopy(self.valid_receipt)
        receipt.pop("command_digest")
        errors = mod.validate_receipt(receipt, expected_bead_id="bd-1khdi", now=self.validation_time)
        self.assertIn("ERR_VB_MISSING_COMMAND_DIGEST", errors)

    def test_bad_command_digest_rejected(self) -> None:
        receipt = copy.deepcopy(self.valid_receipt)
        receipt["command_digest"]["hex"] = "0" * 64
        errors = mod.validate_receipt(receipt, expected_bead_id="bd-1khdi", now=self.validation_time)
        self.assertIn("ERR_VB_MISSING_COMMAND_DIGEST", errors)

    def test_stale_receipt_rejected(self) -> None:
        receipt = mod.apply_fixture_patch(self.valid_receipt, {
            "set": {"timing.freshness_expires_at": "2026-05-04T00:00:00Z"}
        })
        errors = mod.validate_receipt(receipt, expected_bead_id="bd-1khdi", now=self.validation_time)
        self.assertIn("ERR_VB_STALE_RECEIPT", errors)

    def test_mismatched_bead_rejected(self) -> None:
        receipt = mod.apply_fixture_patch(self.valid_receipt, {"set": {"request_ref.bead_id": "bd-other"}})
        errors = mod.validate_receipt(receipt, expected_bead_id="bd-1khdi", now=self.validation_time)
        self.assertIn("ERR_VB_BEAD_MISMATCH", errors)

    def test_timeout_classes_are_allowed(self) -> None:
        for example in self.fixtures["timeout_class_examples"]:
            with self.subTest(timeout_class=example["timeout_class"]):
                receipt = mod.apply_fixture_patch(self.valid_receipt, {
                    "set": {
                        "exit.kind": example["exit_kind"],
                        "exit.timeout_class": example["timeout_class"],
                        "exit.error_class": "transport_timeout"
                        if example["exit_kind"] == "timeout"
                        else "none",
                        "exit.code": None if example["exit_kind"] == "timeout" else 0,
                    }
                })
                errors = mod.validate_receipt(receipt, expected_bead_id="bd-1khdi", now=self.validation_time)
                self.assertNotIn("ERR_VB_INVALID_TIMEOUT_CLASS", errors)

    def test_source_only_requires_allowed_reason(self) -> None:
        receipt = mod.apply_fixture_patch(self.valid_receipt, {
            "set": {
                "exit.kind": "source_only",
                "exit.error_class": "source_only",
                "classifications.source_only_fallback": True,
                "classifications.source_only_reason": None,
            }
        })
        errors = mod.validate_receipt(receipt, expected_bead_id="bd-1khdi", now=self.validation_time)
        self.assertIn("ERR_VB_UNDECLARED_SOURCE_ONLY", errors)

    def test_json_cli_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-1khdi")
        self.assertEqual(parsed["verdict"], "PASS")

    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")

    def _failures(self, result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])


if __name__ == "__main__":
    unittest.main()
