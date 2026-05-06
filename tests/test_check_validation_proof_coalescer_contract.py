"""Unit tests for scripts/check_validation_proof_coalescer_contract.py."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_validation_proof_coalescer_contract.py"


class ScriptNamespace:
    def __init__(self, values: dict[str, object]) -> None:
        object.__setattr__(self, "_values", values)

    def __getattr__(self, name: str) -> object:
        return self._values[name]

    def __setattr__(self, name: str, value: object) -> None:
        self._values[name] = value


script_globals = runpy.run_path(str(SCRIPT_PATH), run_name="validation_proof_coalescer_contract")
mod = ScriptNamespace(script_globals["run_all"].__globals__)


class ValidationProofCoalescerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = json.JSONDecoder().decode(mod.FIXTURES_FILE.read_text(encoding="utf-8"))
        self.valid_work_key = self.fixtures["valid_work_keys"][0]
        self.valid_lease = self.fixtures["valid_leases"][0]
        self.completed_lease = self.fixtures["valid_leases"][1]
        self.valid_decision = self.fixtures["valid_decisions"][0]
        self.valid_policy = self.fixtures["valid_admission_policies"][0]
        self.validation_time = mod._parse_rfc3339(self.fixtures["validation_time"])

    def test_run_all_passes(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_result_shape(self) -> None:
        result = mod.run_all()
        for key in ["bead_id", "title", "schema_version", "verdict", "checks", "timestamp"]:
            self.assertIn(key, result)
        self.assertEqual(result["bead_id"], "bd-ov7ca")
        self.assertGreaterEqual(result["total"], 55)

    def test_valid_work_key_validates(self) -> None:
        errors = mod.validate_work_key(self.valid_work_key)
        self.assertEqual(errors, [])

    def test_valid_lease_validates(self) -> None:
        errors = mod.validate_lease(
            self.valid_lease,
            expected_bead_id="bd-ov7ca",
            now=self.validation_time,
        )
        self.assertEqual(errors, [])

    def test_completed_lease_validates_receipt_handoff(self) -> None:
        errors = mod.validate_lease(
            self.completed_lease,
            expected_bead_id="bd-ov7ca",
            now=self.validation_time,
        )
        self.assertEqual(errors, [])

    def test_valid_decision_validates(self) -> None:
        errors = mod.validate_decision(
            self.valid_decision,
            expected_bead_id="bd-ov7ca",
            now=self.validation_time,
        )
        self.assertEqual(errors, [])

    def test_valid_admission_policy_validates(self) -> None:
        errors = mod.validate_admission_policy(self.valid_policy)
        self.assertEqual(errors, [])

    def test_invalid_lease_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_leases"]:
            with self.subTest(case=case["name"]):
                lease = case.get("lease", mod.apply_fixture_patch(self.valid_lease, case.get("patch")))
                errors = mod.validate_lease(lease, expected_bead_id="bd-ov7ca", now=self.validation_time)
                for expected in case["expected_errors"]:
                    self.assertIn(expected, errors)

    def test_invalid_decision_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_decisions"]:
            with self.subTest(case=case["name"]):
                decision = case.get(
                    "decision_payload",
                    mod.apply_fixture_patch(self.valid_decision, case.get("patch")),
                )
                errors = mod.validate_decision(
                    decision,
                    expected_bead_id="bd-ov7ca",
                    now=self.validation_time,
                )
                for expected in case["expected_errors"]:
                    self.assertIn(expected, errors)

    def test_bad_work_key_digest_fails_closed(self) -> None:
        work_key = copy.deepcopy(self.valid_work_key)
        work_key["hex"] = "0" * 64
        errors = mod.validate_work_key(work_key)
        self.assertIn("ERR_VPCO_BAD_WORK_KEY", errors)

    def test_command_digest_mismatch_fails_closed(self) -> None:
        lease = copy.deepcopy(self.valid_lease)
        lease["rch_command"]["command_digest"]["hex"] = "1" * 64
        errors = mod.validate_lease(lease, expected_bead_id="bd-ov7ca", now=self.validation_time)
        self.assertIn("ERR_VPCO_COMMAND_DIGEST_MISMATCH", errors)

    def test_input_digest_mismatch_fails_closed(self) -> None:
        work_key = copy.deepcopy(self.valid_work_key)
        work_key["input_digests"][0]["hex"] = "2" * 64
        errors = mod.validate_work_key(work_key)
        self.assertIn("ERR_VPCO_INPUT_DIGEST_MISMATCH", errors)

    def test_stale_lease_fails_closed(self) -> None:
        lease = copy.deepcopy(self.valid_lease)
        lease["expires_at"] = "2026-05-06T01:00:00Z"
        errors = mod.validate_lease(lease, expected_bead_id="bd-ov7ca", now=self.validation_time)
        self.assertIn("ERR_VPCO_STALE_LEASE", errors)

    def test_fenced_owner_fails_closed(self) -> None:
        lease = copy.deepcopy(self.valid_lease)
        lease["state"] = "fenced"
        lease["diagnostics"]["fencing_owner_mismatch"] = True
        errors = mod.validate_lease(lease, expected_bead_id="bd-ov7ca", now=self.validation_time)
        self.assertIn("ERR_VPCO_FENCED_OWNER", errors)

    def test_dirty_policy_rejection_is_fixture_backed(self) -> None:
        dirty_cases = [
            case
            for case in self.fixtures["invalid_leases"]
            if case["name"] == "dirty_policy_rejection"
        ]
        self.assertEqual(len(dirty_cases), 1)
        lease = mod.apply_fixture_patch(self.valid_lease, dirty_cases[0]["patch"])
        errors = mod.validate_lease(lease, expected_bead_id="bd-ov7ca", now=self.validation_time)
        self.assertIn("ERR_VPCO_DIRTY_POLICY", errors)

    def test_capacity_rejection_is_fixture_backed(self) -> None:
        capacity_cases = [
            case
            for case in self.fixtures["invalid_leases"]
            if case["name"] == "capacity_rejection"
        ]
        self.assertEqual(len(capacity_cases), 1)
        lease = mod.apply_fixture_patch(self.valid_lease, capacity_cases[0]["patch"])
        errors = mod.validate_lease(lease, expected_bead_id="bd-ov7ca", now=self.validation_time)
        self.assertIn("ERR_VPCO_CAPACITY_REJECTED", errors)

    def test_scenarios_cover_acceptance(self) -> None:
        names = {scenario["name"] for scenario in self.fixtures["scenarios"]}
        self.assertTrue(mod.REQUIRED_SCENARIOS.issubset(names))

    def test_decision_examples_cover_all_decisions(self) -> None:
        decisions = {example["decision"] for example in self.fixtures["decision_examples"]}
        reasons = {example["reason_code"] for example in self.fixtures["decision_examples"]}
        actions = {example["required_action"] for example in self.fixtures["decision_examples"]}
        self.assertEqual(decisions, mod.DECISION_KINDS)
        self.assertEqual(reasons, mod.REASON_CODES)
        self.assertEqual(actions, mod.REQUIRED_ACTIONS)

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
        self.assertEqual(payload["bead_id"], "bd-ov7ca")

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
