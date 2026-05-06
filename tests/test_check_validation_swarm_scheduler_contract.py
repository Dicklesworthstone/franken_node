"""Unit tests for scripts/check_validation_swarm_scheduler_contract.py."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_validation_swarm_scheduler_contract.py"


class ScriptNamespace:
    def __init__(self, values: dict[str, object]) -> None:
        object.__setattr__(self, "_values", values)

    def __getattr__(self, name: str) -> object:
        return self._values[name]

    def __setattr__(self, name: str, value: object) -> None:
        self._values[name] = value


script_globals = runpy.run_path(str(SCRIPT_PATH), run_name="validation_swarm_scheduler_contract")
mod = ScriptNamespace(script_globals["run_all"].__globals__)


class ValidationSwarmSchedulerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = json.JSONDecoder().decode(mod.FIXTURES_FILE.read_text(encoding="utf-8"))
        self.base_input = self.fixtures["base_input"]
        self.base_policy = self.fixtures["base_policy"]
        self.base_decision = self.fixtures["decision_examples"][0]
        self.validation_time = mod._parse_rfc3339(self.fixtures["validation_time"])

    def test_run_all_passes(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_result_shape(self) -> None:
        result = mod.run_all()
        for key in ["bead_id", "title", "schema_version", "verdict", "checks", "timestamp"]:
            self.assertIn(key, result)
        self.assertEqual(result["bead_id"], "bd-4iy4h")
        self.assertGreaterEqual(result["total"], 55)

    def test_base_input_validates(self) -> None:
        self.assertEqual(mod.validate_input(self.base_input), [])

    def test_base_policy_validates(self) -> None:
        self.assertEqual(mod.validate_policy(self.base_policy), [])

    def test_decision_examples_validate_and_cover_contract(self) -> None:
        decisions = {example["decision"] for example in self.fixtures["decision_examples"]}
        reasons = {example["reason_code"] for example in self.fixtures["decision_examples"]}
        actions = {example["required_action"] for example in self.fixtures["decision_examples"]}
        self.assertEqual(decisions, mod.DECISION_KINDS)
        self.assertEqual(reasons, mod.REASON_CODES)
        self.assertEqual(actions, mod.REQUIRED_ACTIONS)
        for example in self.fixtures["decision_examples"]:
            with self.subTest(decision=example["decision"]):
                errors = mod.validate_decision(example, now=self.validation_time)
                self.assertEqual(errors, [])

    def test_invalid_input_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_inputs"]:
            with self.subTest(case=case["name"]):
                payload = mod.apply_fixture_patch(self.base_input, case.get("patch"))
                errors = mod.validate_input(payload)
                for expected in case["expected_errors"]:
                    self.assertIn(expected, errors)

    def test_invalid_decision_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_decisions"]:
            with self.subTest(case=case["name"]):
                decision = mod.apply_fixture_patch(self.base_decision, case.get("patch"))
                errors = mod.validate_decision(decision, now=self.validation_time)
                for expected in case["expected_errors"]:
                    self.assertIn(expected, errors)

    def test_product_failure_cannot_be_retried_as_worker_infra(self) -> None:
        payload = copy.deepcopy(self.base_input)
        payload["product_failure"] = True
        payload["worker_infra_retryable"] = True
        errors = mod.validate_input(payload)
        self.assertIn("ERR_VSS_PRODUCT_RETRIED_AS_INFRA", errors)

    def test_worker_infra_cannot_be_green_proof(self) -> None:
        decision = copy.deepcopy(self.base_decision)
        decision["green_proof_eligible"] = True
        decision["diagnostics"]["proof_debt_class"] = "worker_infra"
        errors = mod.validate_decision(decision, now=self.validation_time)
        self.assertIn("ERR_VSS_WORKER_INFRA_GREEN", errors)

    def test_scenarios_cover_acceptance(self) -> None:
        names = {scenario["name"] for scenario in self.fixtures["scenarios"]}
        self.assertTrue(mod.REQUIRED_SCENARIOS.issubset(names))

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
        self.assertEqual(payload["bead_id"], "bd-4iy4h")

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
