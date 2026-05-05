"""Unit tests for scripts/check_validation_proof_cache_contract.py."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_validation_proof_cache_contract.py"


class ScriptNamespace:
    def __init__(self, values: dict[str, object]) -> None:
        object.__setattr__(self, "_values", values)

    def __getattr__(self, name: str) -> object:
        return self._values[name]

    def __setattr__(self, name: str, value: object) -> None:
        self._values[name] = value


script_globals = runpy.run_path(str(SCRIPT_PATH), run_name="validation_proof_cache_contract")
mod = ScriptNamespace(script_globals["run_all"].__globals__)


class ValidationProofCacheContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = json.JSONDecoder().decode(mod.FIXTURES_FILE.read_text(encoding="utf-8"))
        self.valid_key = self.fixtures["valid_cache_keys"][0]
        self.valid_entry = self.fixtures["valid_entries"][0]
        self.valid_decision = self.fixtures["valid_decisions"][0]
        self.validation_time = mod._parse_rfc3339(self.fixtures["validation_time"])

    def test_run_all_passes(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_result_shape(self) -> None:
        result = mod.run_all()
        for key in ["bead_id", "title", "schema_version", "verdict", "checks", "timestamp"]:
            self.assertIn(key, result)
        self.assertEqual(result["bead_id"], "bd-jbkiq")
        self.assertGreaterEqual(result["total"], 40)

    def test_valid_cache_key_validates(self) -> None:
        errors = mod.validate_cache_key(self.valid_key)
        self.assertEqual(errors, [])

    def test_valid_entry_validates(self) -> None:
        errors = mod.validate_cache_entry(
            self.valid_entry,
            expected_bead_id="bd-jbkiq",
            now=self.validation_time,
        )
        self.assertEqual(errors, [])

    def test_valid_decision_validates(self) -> None:
        errors = mod.validate_cache_decision(
            self.valid_decision,
            expected_bead_id="bd-jbkiq",
            now=self.validation_time,
        )
        self.assertEqual(errors, [])

    def test_invalid_entry_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_entries"]:
            with self.subTest(case=case["name"]):
                entry = case.get("entry", mod.apply_fixture_patch(self.valid_entry, case.get("patch")))
                errors = mod.validate_cache_entry(entry, expected_bead_id="bd-jbkiq", now=self.validation_time)
                for expected in case["expected_errors"]:
                    self.assertIn(expected, errors)

    def test_invalid_decision_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_decisions"]:
            with self.subTest(case=case["name"]):
                decision = case.get(
                    "decision_payload",
                    mod.apply_fixture_patch(self.valid_decision, case.get("patch")),
                )
                errors = mod.validate_cache_decision(
                    decision,
                    expected_bead_id="bd-jbkiq",
                    now=self.validation_time,
                )
                for expected in case["expected_errors"]:
                    self.assertIn(expected, errors)

    def test_bad_cache_key_digest_fails_closed(self) -> None:
        cache_key = copy.deepcopy(self.valid_key)
        cache_key["hex"] = "0" * 64
        errors = mod.validate_cache_key(cache_key)
        self.assertIn("ERR_VPC_BAD_CACHE_KEY", errors)

    def test_receipt_digest_mismatch_fails_closed(self) -> None:
        entry = copy.deepcopy(self.valid_entry)
        entry["receipt_digest"]["hex"] = "f" * 64
        errors = mod.validate_cache_entry(entry, expected_bead_id="bd-jbkiq", now=self.validation_time)
        self.assertIn("ERR_VPC_RECEIPT_DIGEST_MISMATCH", errors)

    def test_command_digest_mismatch_fails_closed(self) -> None:
        entry = copy.deepcopy(self.valid_entry)
        entry["receipt_ref"]["command_digest"]["hex"] = "1" * 64
        errors = mod.validate_cache_entry(entry, expected_bead_id="bd-jbkiq", now=self.validation_time)
        self.assertIn("ERR_VPC_COMMAND_DIGEST_MISMATCH", errors)

    def test_input_digest_mismatch_fails_closed(self) -> None:
        entry = copy.deepcopy(self.valid_entry)
        entry["receipt_ref"]["input_digests"][0]["hex"] = "2" * 64
        errors = mod.validate_cache_entry(entry, expected_bead_id="bd-jbkiq", now=self.validation_time)
        self.assertIn("ERR_VPC_INPUT_DIGEST_MISMATCH", errors)

    def test_stale_entry_fails_closed(self) -> None:
        entry = copy.deepcopy(self.valid_entry)
        entry["freshness_expires_at"] = "2026-05-05T19:00:00Z"
        errors = mod.validate_cache_entry(entry, expected_bead_id="bd-jbkiq", now=self.validation_time)
        self.assertIn("ERR_VPC_STALE_ENTRY", errors)

    def test_dirty_state_mismatch_fails_closed(self) -> None:
        entry = copy.deepcopy(self.valid_entry)
        entry["receipt_ref"]["dirty_worktree"] = True
        errors = mod.validate_cache_entry(entry, expected_bead_id="bd-jbkiq", now=self.validation_time)
        self.assertIn("ERR_VPC_DIRTY_STATE_MISMATCH", errors)

    def test_policy_mismatch_fails_closed(self) -> None:
        entry = copy.deepcopy(self.valid_entry)
        entry["receipt_ref"]["target_dir_policy_id"] = "validation-broker/target-dir/repo-local/v1"
        errors = mod.validate_cache_entry(entry, expected_bead_id="bd-jbkiq", now=self.validation_time)
        self.assertIn("ERR_VPC_POLICY_MISMATCH", errors)

    def test_corrupted_entry_fails_closed(self) -> None:
        entry = copy.deepcopy(self.valid_entry)
        entry["invalidation"]["active"] = True
        entry["invalidation"]["corrupted"] = True
        errors = mod.validate_cache_entry(entry, expected_bead_id="bd-jbkiq", now=self.validation_time)
        self.assertIn("ERR_VPC_CORRUPTED_ENTRY", errors)

    def test_json_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))
        self.assertEqual(payload["bead_id"], "bd-jbkiq")

    def test_self_test_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))
        self.assertEqual(payload["contract_result"]["verdict"], "PASS", self._failures(payload["contract_result"]))

    @staticmethod
    def _failures(result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])


if __name__ == "__main__":
    unittest.main()
