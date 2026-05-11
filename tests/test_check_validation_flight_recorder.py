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

    def test_worker_reliability_cases_cover_valid_and_fail_closed_paths(self) -> None:
        required_cases = {
            "remote_success_healthy",
            "repeated_stale_progress_drain",
            "product_failures_excluded",
            "fresh_heartbeat_ambiguity_degraded",
            "filesystem_pressure_drain",
            "missing_toolchain_degraded",
            "local_fallback_blocked",
        }
        seen = {case["case"] for case in self.fixtures["worker_reliability_cases"]}
        self.assertTrue(required_cases.issubset(seen))

        attempts_by_case = self._valid_attempts_by_case()
        for case in self.fixtures["worker_reliability_cases"]:
            with self.subTest(case=case["case"]):
                attempts = [attempts_by_case[name] for name in case["attempt_cases"]]
                ledger = mod.worker_reliability_ledger(attempts)
                worker_row = next(row for row in ledger if row["worker_id"] == case["worker_id"])
                self.assertEqual(worker_row["class"], case["expected_class"])
                self.assertEqual(worker_row["next_action"], case["expected_next_action"])
                self.assertTrue(set(case["expected_reasons"]).issubset(worker_row["reasons"]))
                if case["case"] == "product_failures_excluded":
                    self.assertEqual(worker_row["class"], "healthy")
                    self.assertGreater(worker_row["product_failure_count"], 0)

    def test_proof_debt_slo_cases_cover_green_stop_and_blocker_paths(self) -> None:
        required_cases = {
            "fresh_green_proof",
            "repeated_worker_infra_budget_exhausted",
            "product_failure_fail_closed",
            "saturated_rch_queue",
            "no_healthy_workers",
            "stale_coalescer_lease",
            "source_only_not_green",
        }
        seen = {case["case"] for case in self.fixtures["proof_debt_slo_cases"]}
        self.assertTrue(required_cases.issubset(seen))

        for case in self.fixtures["proof_debt_slo_cases"]:
            with self.subTest(case=case["case"]):
                decision = mod.proof_debt_slo_decision(case["input"])
                self.assertEqual(decision["next_action"], case["expected_next_action"])
                self.assertEqual(decision["complete"], case["expected_complete"])
                self.assertEqual(decision["escalation_reason"], case["expected_escalation_reason"])
                if "expected_budget_remaining" in case:
                    self.assertEqual(decision["budget_remaining"], case["expected_budget_remaining"])
                self.assertIn(decision["next_action"], decision["operator_summary"])
                if case["input"]["debt_class"] in {"source_only", "worker_infra", "waiting_for_capacity"}:
                    self.assertFalse(decision["complete"])

    def test_proof_lane_reroute_cases_reject_unsafe_validation_shortcuts(self) -> None:
        required_cases = {
            "alternate_worker_reroute",
            "drain_before_retry",
            "wait_for_capacity",
            "join_existing_proof",
            "fence_stale_lease",
            "source_only_blocker",
            "product_failure_fail_closed",
            "remote_required_local_fallback_refusal",
            "active_cargo_contention_above_threshold",
        }
        seen = {case["case"] for case in self.fixtures["proof_lane_reroute_cases"]}
        self.assertTrue(required_cases.issubset(seen))

        for case in self.fixtures["proof_lane_reroute_cases"]:
            with self.subTest(case=case["case"]):
                decision = mod.proof_lane_reroute_decision(case["input"])
                self.assertEqual(decision["selected_action"], case["expected_selected_action"])
                self.assertEqual(
                    decision["green_proof_eligible"],
                    case["expected_green_proof_eligible"],
                )
                self.assertIn(case["expected_reason"], decision["reason_codes"])
                self.assertTrue(
                    set(case["expected_rejected_actions"]).issubset(decision["rejected_actions"])
                )
                self.assertIn(decision["selected_action"], decision["operator_summary"])
                if case["input"]["worker_class"] in {"degraded", "drain", "blocked"}:
                    self.assertNotEqual(decision["selected_action"], "retry_same_worker")
                if case["input"]["product_failure"]:
                    self.assertEqual(decision["selected_action"], "fail_closed_product")
                if case["input"]["source_only"]:
                    self.assertEqual(decision["selected_action"], "record_source_only_blocker")

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

    def _valid_attempts_by_case(self) -> dict[str, dict[str, object]]:
        attempts: dict[str, dict[str, object]] = {}
        for case in self.fixtures["valid_cases"]:
            attempt, _ = mod._fixture_attempt_and_recovery(self.fixtures, case)
            attempts[case["case"]] = attempt
        return attempts


if __name__ == "__main__":
    unittest.main()
