"""Unit tests for scripts/check_validation_flight_recorder.py."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_validation_flight_recorder.py"


class ScriptNamespace:
    def __init__(self, values: dict[str, object]) -> None:
        object.__setattr__(self, "_values", values)

    def __getattr__(self, name: str) -> object:
        return self._values[name]

    def __setattr__(self, name: str, value: object) -> None:
        self._values[name] = value


script_globals = runpy.run_path(str(SCRIPT_PATH), run_name="validation_flight_recorder_contract")
mod = ScriptNamespace(script_globals["run_all"].__globals__)


class ValidationFlightRecorderContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = json.JSONDecoder().decode(mod.FIXTURES_FILE.read_text(encoding="utf-8"))
        self.base_attempt = self.fixtures["base_attempt"]
        self.base_recovery = self.fixtures["base_recovery"]
        self.validation_time = mod._parse_rfc3339(self.fixtures["validation_time"])

    def test_run_all_passes(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_result_shape(self) -> None:
        result = mod.run_all()
        for key in ["bead_id", "title", "schema_version", "verdict", "checks", "timestamp"]:
            self.assertIn(key, result)
        self.assertEqual(result["bead_id"], "bd-2zn9k")
        self.assertGreaterEqual(result["total"], 370)

    def test_base_attempt_and_recovery_validate(self) -> None:
        self.assertEqual(
            mod.validate_attempt(self.base_attempt, expected_bead_id="bd-2zn9k", now=self.validation_time),
            [],
        )
        self.assertEqual(
            mod.validate_recovery(self.base_recovery, attempt=self.base_attempt, now=self.validation_time),
            [],
        )

    def test_invalid_fixture_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_cases"]:
            with self.subTest(case=case["case"]):
                attempt, recovery = mod._fixture_attempt_and_recovery(self.fixtures, case)
                errors = mod.validate_attempt(attempt, expected_bead_id="bd-2zn9k", now=self.validation_time)
                errors.extend(mod.validate_recovery(recovery, attempt=attempt, now=self.validation_time))
                self.assertIn(case["expected_error"], sorted(set(errors)))

    def test_stale_attempt_and_recovery_fail_closed(self) -> None:
        attempt = mod.apply_fixture_patch(
            self.base_attempt,
            {"set": {"freshness_expires_at": "2026-05-04T00:00:00Z"}},
        )
        recovery = mod.apply_fixture_patch(
            self.base_recovery,
            {"set": {"freshness_expires_at": "2026-05-04T00:00:00Z"}},
        )
        self.assertIn(
            "ERR_VFR_STALE_ATTEMPT",
            mod.validate_attempt(attempt, expected_bead_id="bd-2zn9k", now=self.validation_time),
        )
        self.assertIn(
            "ERR_VFR_STALE_ATTEMPT",
            mod.validate_recovery(recovery, attempt=self.base_attempt, now=self.validation_time),
        )

    def test_malformed_command_digest_fails_closed(self) -> None:
        attempt = copy.deepcopy(self.base_attempt)
        attempt["command"]["command_digest"]["hex"] = "0" * 64
        errors = mod.validate_attempt(attempt, expected_bead_id="bd-2zn9k", now=self.validation_time)
        self.assertIn("ERR_VFR_MISSING_COMMAND_DIGEST", errors)

    def test_unsafe_artifact_path_fails_closed(self) -> None:
        attempt = copy.deepcopy(self.base_attempt)
        attempt["artifacts"]["attempt_path"] = "/tmp/attempt.json"
        errors = mod.validate_attempt(attempt, expected_bead_id="bd-2zn9k", now=self.validation_time)
        self.assertIn("ERR_VFR_INVALID_ARTIFACT_PATH", errors)

    def test_product_failure_cannot_be_retried_as_worker_infra(self) -> None:
        attempt = mod.apply_fixture_patch(
            self.base_attempt,
            {
                "set": {
                    "exit.kind": "worker_infra",
                    "exit.error_class": "transport_timeout",
                    "exit.retryable": True,
                    "exit.product_failure": True,
                }
            },
        )
        errors = mod.validate_attempt(attempt, expected_bead_id="bd-2zn9k", now=self.validation_time)
        self.assertIn("ERR_VFR_MALFORMED_ATTEMPT", errors)

    def test_explanation_bundle_cases_cover_green_and_negative_paths(self) -> None:
        expected_cases = {
            "green_proof_reuse",
            "missing_agent_mail_thread",
            "corrupt_missing_artifact",
            "mismatched_bead_id",
            "malformed_command_digest",
            "stale_receipt",
            "worker_infra_marked_green",
            "product_failure_hidden_as_infra",
        }
        seen = {case["case"] for case in self.fixtures["explanation_bundle_cases"]}
        self.assertTrue(expected_cases.issubset(seen))
        for case in self.fixtures["explanation_bundle_cases"]:
            with self.subTest(case=case["case"]):
                bundle = mod.validation_explanation_bundle(case["input"])
                self.assertEqual(bundle["final_status"], case["expected_final_status"])
                self.assertEqual(bundle["complete"], case["expected_complete"])
                expected_error = case.get("expected_field_error")
                if expected_error is not None:
                    self.assertIn(expected_error, bundle["field_errors"])
                else:
                    self.assertEqual(bundle["field_errors"], [])

    def test_explanation_markdown_is_bounded_and_omits_raw_output(self) -> None:
        case = next(
            item for item in self.fixtures["explanation_bundle_cases"] if item["case"] == "green_proof_reuse"
        )
        payload = copy.deepcopy(case["input"])
        payload["stdout_snippet"] = "RAW_OUTPUT_THAT_MUST_NOT_APPEAR"
        bundle = mod.validation_explanation_bundle(payload)
        markdown = bundle["operator_markdown"]
        self.assertLessEqual(len(markdown.encode("utf-8")), mod.MAX_EXPLANATION_MARKDOWN_BYTES)
        self.assertNotIn("RAW_OUTPUT_THAT_MUST_NOT_APPEAR", markdown)
        self.assertIn("raw_output_snippet_present", bundle["field_errors"])

    def test_json_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))
        self.assertEqual(payload["bead_id"], "bd-2zn9k")

    def test_self_test_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))

    @staticmethod
    def _failures(result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])

if __name__ == "__main__":
    unittest.main()
