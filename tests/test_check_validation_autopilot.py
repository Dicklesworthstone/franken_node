"""Unit tests for scripts/check_validation_autopilot.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess  # nosec B404 - fixed-argv CLI smoke tests with no shell.
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_validation_autopilot.py"

spec = importlib.util.spec_from_file_location("check_validation_autopilot", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
if spec.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

JSON_DECODER = json.JSONDecoder()
NOW = datetime(2026, 6, 18, 15, 45, tzinfo=timezone.utc)


class ValidationAutopilotTests(unittest.TestCase):
    def test_self_test_matrix_covers_expected_decisions(self) -> None:
        result = mod._run_self_test(NOW)

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertEqual(result["summary"]["decisions"]["ready"], "claim_ready")
        self.assertEqual(result["summary"]["decisions"]["followup"], "create_followup_bead")
        self.assertEqual(result["summary"]["decisions"]["stale"], "refresh_blocker")
        self.assertEqual(result["summary"]["decisions"]["rch"], "retry_rch_bounded")
        self.assertEqual(result["summary"]["decisions"]["repeated"], "handoff_only")
        self.assertEqual(result["summary"]["decisions"]["stale_progress"], "retry_rch_bounded")
        self.assertEqual(result["summary"]["decisions"]["dependency"], "create_followup_bead")
        self.assertEqual(result["summary"]["decisions"]["product"], "handoff_only")
        self.assertEqual(result["summary"]["decisions"]["success"], "handoff_only")
        self.assertEqual(result["summary"]["decisions"]["external"], "coordinate_owner")
        self.assertEqual(result["summary"]["decisions"]["parent"], "handoff_only")
        self.assertEqual(result["summary"]["decisions"]["unsafe"], "blocked")

    def test_ready_claim_wins_with_claimable_ready_bead(self) -> None:
        payload = mod._self_test_payloads()["ready"]

        result = mod.plan_decision(payload, now=NOW)

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        decision = result["decision"]
        self.assertEqual(decision["decision"], "claim_ready")
        self.assertEqual(decision["reason_code"], "VALAUTO_READY_CLAIMABLE")
        self.assertEqual(decision["selected_bead_id"], "bd-ready")
        self.assertFalse(decision["mutation_allowed"])

    def test_no_ready_state_proposes_followup_without_mutating(self) -> None:
        payload = mod._self_test_payloads()["followup"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "create_followup_bead")
        self.assertEqual(decision["reason_code"], "VALAUTO_NO_READY_CREATE_CHILD")
        self.assertFalse(decision["mutation_allowed"])
        proposed = decision["proposed_bead"]
        self.assertIn("overlap_search_terms", proposed)
        self.assertIn("dedupe_rationale", proposed)
        self.assertIn("validation_plan", proposed)
        preview = result["action_preview"]
        self.assertEqual(preview["mode"], "dry_run")
        self.assertEqual(preview["br_create_preview"]["argv"][:3], ["br", "create", "--title"])
        self.assertIn("--dry-run", preview["br_create_preview"]["argv"])
        self.assertIn("## What", preview["br_create_preview"]["body_md"])
        self.assertIn("bd-blocked", preview["dedupe"]["overlap_search_terms"])
        handoff = result["handoff_markdown"]
        self.assertIn("ready_count: 0", handoff)
        self.assertIn("## Active Agents", handoff)
        self.assertIn("## Exact Blockers", handoff)
        self.assertIn("## Reservation Scope", handoff)
        self.assertIn("## Validation Commands", handoff)
        self.assertIn("proposed_next_action:", handoff)

    def test_stale_blocker_refresh_preserves_first_blocker_and_comment_command(self) -> None:
        payload = mod._self_test_payloads()["stale"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "refresh_blocker")
        self.assertEqual(decision["reason_code"], "VALAUTO_BLOCKER_STALE")
        self.assertEqual(decision["selected_bead_id"], "bd-stale")
        self.assertEqual(decision["recommended_command"], ["br", "comment", "bd-stale", "--stdin"])
        self.assertIn("first blocker", decision["first_blocker"])
        preview = result["action_preview"]
        self.assertEqual(preview["br_comment_preview"]["argv"], ["br", "comment", "bd-stale", "--stdin"])
        self.assertIn("Validation-autopilot dry-run blocker refresh", preview["br_comment_preview"]["body_md"])
        self.assertIn("first_blocker", preview["br_comment_preview"]["body_md"])
        self.assertIn("current first blocker: timeout", result["handoff_markdown"])

    def test_rch_timeout_retry_requires_remote_prefix(self) -> None:
        payload = mod._self_test_payloads()["rch"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "retry_rch_bounded")
        self.assertEqual(decision["reason_code"], "VALAUTO_RCH_TIMEOUT_RETRY")
        self.assertTrue(decision["requires_rch"])
        self.assertEqual(decision["recommended_command"][:3], ["rch", "exec", "--"])
        self.assertEqual(decision["recommended_rch_command"][:3], ["rch", "exec", "--"])
        self.assertEqual(decision["worker_action"], "retry_different_worker")
        self.assertIsNone(decision["stop_reason"])
        self.assertTrue(decision["retry_allowed"])
        self.assertEqual(decision["retry_budget_remaining"], 1)
        preview = result["action_preview"]
        self.assertEqual(preview["retry_preview"]["recommended_rch_command"]["argv"][:3], ["rch", "exec", "--"])
        self.assertEqual(preview["retry_preview"]["worker_action"], "retry_different_worker")
        self.assertIn("recommended_rch_command", preview["br_comment_preview"]["body_md"])
        self.assertIn("rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_valauto", result["handoff_markdown"])

    def test_stale_progress_after_cancellation_retries_with_stale_progress_reason(self) -> None:
        payload = mod._self_test_payloads()["stale_progress"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "retry_rch_bounded")
        self.assertEqual(decision["reason_code"], "VALAUTO_RCH_STALE_PROGRESS_RETRY")
        self.assertEqual(decision["worker_action"], "retry_after_clean_cancellation")
        self.assertTrue(decision["retry_allowed"])

    def test_repeated_worker_timeout_recommends_quarantine_without_retry(self) -> None:
        payload = mod._self_test_payloads()["repeated"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "handoff_only")
        self.assertEqual(decision["worker_action"], "quarantine_or_drain_worker")
        self.assertEqual(decision["stop_reason"], "worker_quarantine_recommended")
        self.assertFalse(decision["retry_allowed"])
        self.assertEqual(decision["diagnostics"]["worker_failure_count"], 2)

    def test_dependency_resolver_creates_dependency_convergence_followup(self) -> None:
        payload = mod._self_test_payloads()["dependency"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "create_followup_bead")
        self.assertEqual(decision["stop_reason"], "dependency_convergence_required")
        self.assertEqual(decision["worker_action"], "none")
        self.assertFalse(decision["retry_allowed"])
        self.assertIn("dependency-convergence", decision["proposed_bead"]["labels"])

    def test_product_diagnostic_stops_retry_and_preserves_blocker(self) -> None:
        payload = mod._self_test_payloads()["product"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "handoff_only")
        self.assertEqual(decision["stop_reason"], "product_diagnostic_reached")
        self.assertEqual(decision["worker_action"], "none")
        self.assertFalse(decision["retry_allowed"])
        self.assertIn("emit_receipt", decision["first_blocker"])

    def test_clean_rch_success_has_no_retry(self) -> None:
        payload = mod._self_test_payloads()["success"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "handoff_only")
        self.assertEqual(decision["stop_reason"], "clean_success")
        self.assertEqual(decision["worker_action"], "none")
        self.assertFalse(decision["retry_allowed"])

    def test_local_cargo_retry_fails_closed(self) -> None:
        payload = mod._self_test_payloads()["unsafe"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "blocked")
        self.assertEqual(decision["reason_code"], "VALAUTO_UNSAFE_LOCAL_CARGO")
        self.assertFalse(decision["retry_allowed"])
        self.assertIn("cargo test", decision["diagnostics"]["command"])

    def test_cross_repo_external_blocker_coordinates_owner(self) -> None:
        payload = mod._self_test_payloads()["external"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "coordinate_owner")
        self.assertEqual(decision["reason_code"], "VALAUTO_EXTERNAL_BLOCKER")
        self.assertEqual(decision["selected_bead_id"], "bd-engine")
        self.assertIn("franken_engine", decision["first_blocker"])
        preview = result["action_preview"]
        self.assertIsNone(preview["br_create_preview"])
        self.assertIsNone(preview["br_comment_preview"])
        self.assertIn("Coordination required", preview["coordination_preview"]["subject"])
        self.assertIn("franken_engine", preview["coordination_preview"]["body_md"])
        self.assertIn("franken_engine", result["agent_mail_handoff"]["body_md"])

    def test_parent_epic_never_becomes_claim_ready(self) -> None:
        payload = mod._self_test_payloads()["parent"]

        result = mod.plan_decision(payload, now=NOW)

        decision = result["decision"]
        self.assertEqual(decision["decision"], "handoff_only")
        self.assertEqual(decision["reason_code"], "VALAUTO_NO_SAFE_MUTATION")
        self.assertEqual(decision["selected_bead_id"], "bd-epic")
        self.assertNotEqual(decision["decision"], "claim_ready")

    def test_ready_claim_preview_does_not_generate_mutation_commands(self) -> None:
        payload = mod._self_test_payloads()["ready"]

        result = mod.plan_decision(payload, now=NOW)

        preview = result["action_preview"]
        self.assertEqual(preview["action_kind"], "claim_ready")
        self.assertFalse(preview["mutation_allowed"])
        self.assertIsNone(preview["br_create_preview"])
        self.assertIsNone(preview["br_comment_preview"])
        self.assertIsNone(preview["coordination_preview"])
        self.assertIn("Claim the selected ready Bead", result["handoff_markdown"])

    def test_stale_input_fails_closed_before_planning(self) -> None:
        payload = mod._self_test_payloads()["ready"]
        payload["generated_at"] = "2026-06-18T00:00:00+00:00"

        result = mod.plan_decision(payload, now=NOW)

        self.assertEqual(result["decision"]["decision"], "blocked")
        self.assertEqual(result["decision"]["reason_code"], "VALAUTO_STALE_INPUT")

    def test_cli_self_test_json_passes(self) -> None:
        proc = subprocess.run(  # nosec B603
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--self-test",
                "--json",
                "--now",
                "2026-06-18T15:45:00+00:00",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))
        self.assertEqual(payload["summary"]["case_count"], 12)

    def test_cli_fixture_input_passes(self) -> None:
        payload = mod._self_test_payloads()["ready"]
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "valauto-input.json"
            input_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--input",
                    str(input_path),
                    "--json",
                    "--now",
                    "2026-06-18T15:45:00+00:00",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(result["decision"]["decision"], "claim_ready")

    def test_cli_individual_evidence_files_pass(self) -> None:
        payload = mod._self_test_payloads()["ready"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ready_path = self._write_json(root / "ready.json", payload["br_ready"])
            items_path = self._write_json(root / "items.json", payload["br_active"])
            bv_path = self._write_json(root / "bv-plan.json", payload["bv_plan"])
            policy_path = self._write_json(root / "policy.json", payload["policy"])
            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--ready",
                    str(ready_path),
                    "--items",
                    str(items_path),
                    "--bv-plan",
                    str(bv_path),
                    "--policy",
                    str(policy_path),
                    "--agent-name",
                    "NavyTurtle",
                    "--generated-at",
                    "2026-06-18T15:45:00+00:00",
                    "--json",
                    "--now",
                    "2026-06-18T15:45:00+00:00",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(result["decision"]["decision"], "claim_ready")

    def test_cli_input_from_stdin_passes(self) -> None:
        payload = mod._self_test_payloads()["ready"]
        proc = subprocess.run(  # nosec B603
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--input",
                "-",
                "--json",
                "--now",
                "2026-06-18T15:45:00+00:00",
            ],
            cwd=ROOT,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(result["decision"]["decision"], "claim_ready")

    def test_cli_non_json_output_renders_handoff_markdown(self) -> None:
        payload = mod._self_test_payloads()["stale"]
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "valauto-input.json"
            input_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--input",
                    str(input_path),
                    "--now",
                    "2026-06-18T15:45:00+00:00",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Validation autopilot source-only planner: PASS", proc.stdout)
        self.assertIn("# Validation Autopilot Handoff", proc.stdout)
        self.assertIn("current first blocker: timeout", proc.stdout)

    def test_cli_apply_guard_fails_closed(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, str(SCRIPT_PATH), "--apply"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 2)
        self.assertIn("intentionally unimplemented", proc.stderr)

    def test_cli_missing_required_inputs_returns_usage_error(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, str(SCRIPT_PATH), "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 2)
        self.assertIn("missing required inputs", proc.stderr)

    @staticmethod
    def _write_json(path: Path, payload: object) -> Path:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    @staticmethod
    def _failures(result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])


if __name__ == "__main__":
    unittest.main()
