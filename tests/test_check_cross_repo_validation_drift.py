"""Unit tests for scripts/check_cross_repo_validation_drift.py."""

from __future__ import annotations

import copy
import hashlib
import json
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_cross_repo_validation_drift.py"


class ScriptNamespace:
    def __init__(self, values: dict[str, object]) -> None:
        object.__setattr__(self, "_values", values)

    def __getattr__(self, name: str) -> object:
        return self._values[name]

    def __setattr__(self, name: str, value: object) -> None:
        self._values[name] = value


script_globals = runpy.run_path(str(SCRIPT_PATH))
mod = ScriptNamespace(script_globals["run_all"].__globals__)


class CrossRepoValidationDriftTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = json.JSONDecoder().decode(mod.FIXTURES_FILE.read_text(encoding="utf-8"))
        self.valid_snapshot = self.fixtures["valid_snapshots"][0]

    def test_run_all_passes(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertGreaterEqual(result["total"], 24)

    def test_valid_snapshots_have_no_errors(self) -> None:
        for snapshot in self.fixtures["valid_snapshots"]:
            with self.subTest(snapshot=snapshot["snapshot_id"]):
                self.assertEqual(mod.validate_snapshot(snapshot), [])

    def test_derive_classification_matches_valid_fixtures(self) -> None:
        seen_codes = set()
        for snapshot in self.fixtures["valid_snapshots"]:
            with self.subTest(snapshot=snapshot["snapshot_id"]):
                derived = mod.derive_classification(snapshot)
                self.assertEqual(derived["code"], snapshot["classification"]["code"])
                self.assertEqual(derived["action"], snapshot["recommended_action"]["action"])
                seen_codes.add(derived["code"])
        self.assertEqual(
            seen_codes,
            {
                "CRVD_SAFE_TO_RUN",
                "CRVD_BLOCKED_CARGO_PRESSURE",
                "CRVD_BLOCKED_SIBLING_DIRTY_RELEVANT",
                "CRVD_BLOCKED_SIBLING_API_DRIFT",
                "CRVD_BLOCKED_SIBLING_BEADS_LOCK",
                "CRVD_BLOCKED_AGENT_MAIL_CORRUPT",
                "CRVD_NEEDS_RCH_REPROOF",
            },
        )

    def test_bd_famte_shape_prioritizes_dirty_sibling_over_mail_and_cargo(self) -> None:
        famte = next(
            snapshot
            for snapshot in self.fixtures["valid_snapshots"]
            if snapshot["snapshot_id"] == "crvd-dirty-relevant-absent-symbols"
        )
        derived = mod.derive_classification(famte)
        self.assertEqual(derived["code"], "CRVD_BLOCKED_SIBLING_DIRTY_RELEVANT")
        self.assertEqual(derived["action"], "record_beads_blocker")

    def test_valid_command_digests_match_canonical_material(self) -> None:
        for snapshot in self.fixtures["valid_snapshots"]:
            with self.subTest(snapshot=snapshot["snapshot_id"]):
                material = snapshot["command_digest"]["canonical_material"]
                expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
                self.assertEqual(snapshot["command_digest"]["hex"], expected)

    def test_handoff_payloads_are_valid_and_deterministic(self) -> None:
        for snapshot in self.fixtures["valid_snapshots"]:
            with self.subTest(snapshot=snapshot["snapshot_id"]):
                first = mod.build_handoff_payload(snapshot)
                second = mod.build_handoff_payload(snapshot)
                self.assertEqual(first, second)
                self.assertEqual(mod.validate_handoff_payload(first), [])

    def test_mail_corrupt_handoff_uses_beads_soft_lock(self) -> None:
        snapshot = next(
            item
            for item in self.fixtures["valid_snapshots"]
            if item["snapshot_id"] == "crvd-mail-corrupt"
        )
        handoff = mod.build_handoff_payload(snapshot)
        self.assertTrue(handoff["ownership_uncertainty"]["requires_beads_soft_lock"])
        self.assertFalse(handoff["mail_targeting"]["broadcast"])
        self.assertIn("Agent Mail", handoff["markdown"])

    def test_ack_failure_handoff_uses_beads_soft_lock(self) -> None:
        snapshot = mod.apply_fixture_patch(
            self.valid_snapshot,
            {
                "set": {
                    "agent_mail.status": "unavailable",
                    "agent_mail.detail": "acknowledge_message failed: sqlite schema missing messages table",
                    "classification.code": "CRVD_BLOCKED_AGENT_MAIL_CORRUPT",
                    "classification.operator_message": "Agent Mail ack failed; use Beads-visible handoff.",
                    "classification.reasons": ["Agent Mail ack failure"],
                    "recommended_action.action": "source_only_handoff",
                    "recommended_action.exact_command": "br comments add <id> --message <handoff>",
                }
            },
        )
        self.assertEqual(mod.validate_snapshot(snapshot), [])
        handoff = mod.build_handoff_payload(snapshot)
        self.assertTrue(handoff["ownership_uncertainty"]["requires_beads_soft_lock"])
        self.assertIn("acknowledge_message failed", handoff["ownership_uncertainty"]["agent_mail_detail"])

    def test_safe_to_run_handoff_keeps_deferred_rch_command(self) -> None:
        handoff = mod.build_handoff_payload(self.valid_snapshot)
        self.assertEqual(handoff["next_safest_action"], "run_rch_validation")
        self.assertTrue(handoff["exact_deferred_rch_command"].startswith("rch exec --"))
        self.assertIn("cargo clippy", handoff["exact_deferred_rch_command"])
        self.assertIn(handoff["exact_deferred_rch_command"], handoff["markdown"])

    def test_invalid_fixture_cases_emit_expected_errors(self) -> None:
        for case in self.fixtures["invalid_snapshots"]:
            with self.subTest(case=case["case"]):
                snapshot = case.get(
                    "snapshot",
                    mod.apply_fixture_patch(self.valid_snapshot, case.get("patch")),
                )
                errors = mod.validate_snapshot(snapshot)
                self.assertIn(case["expected_error"], errors)

    def test_dirty_relevant_sibling_cannot_recommend_rch_run(self) -> None:
        snapshot = mod.apply_fixture_patch(
            self.valid_snapshot,
            {
                "set": {
                    "sibling_repo.dirty_state": "dirty_relevant",
                    "sibling_repo.dirty_files": ["crates/fsqlite-core/src/connection.rs"],
                    "recommended_action.action": "run_rch_validation",
                }
            },
        )
        errors = mod.validate_snapshot(snapshot)
        self.assertIn("ERR_CRVD_DIRTY_RELEVANT_RUN", errors)

    def test_cargo_pressure_cannot_recommend_rch_run(self) -> None:
        snapshot = copy.deepcopy(self.valid_snapshot)
        snapshot["cargo_pressure"]["process_count"] = snapshot["cargo_pressure"]["threshold"] + 1
        errors = mod.validate_snapshot(snapshot)
        self.assertIn("ERR_CRVD_CARGO_PRESSURE_RUN", errors)

    def test_missing_referenced_symbol_cannot_recommend_rch_run(self) -> None:
        snapshot = mod.apply_fixture_patch(
            self.valid_snapshot,
            {
                "set": {
                    "symbol_probes.0.status": "missing_referenced",
                    "symbol_probes.0.referenced_paths": [
                        "crates/fsqlite-core/src/connection.rs"
                    ],
                }
            },
        )
        errors = mod.validate_snapshot(snapshot)
        self.assertIn("ERR_CRVD_API_DRIFT_RUN", errors)

    def test_absent_symbol_rejects_references(self) -> None:
        snapshot = mod.apply_fixture_patch(
            self.valid_snapshot,
            {"set": {"symbol_probes.0.status": "absent_from_call_sites"}},
        )
        errors = mod.validate_snapshot(snapshot)
        self.assertIn("ERR_CRVD_SYMBOL_STATE_MISMATCH", errors)

    def test_command_digest_mismatch_fails_closed(self) -> None:
        snapshot = mod.apply_fixture_patch(
            self.valid_snapshot,
            {"set": {"command_digest.hex": "0" * 64}},
        )
        errors = mod.validate_snapshot(snapshot)
        self.assertIn("ERR_CRVD_COMMAND_DIGEST_MISMATCH", errors)

    def test_remote_required_local_fallback_fails_closed(self) -> None:
        snapshot = mod.apply_fixture_patch(
            self.valid_snapshot,
            {
                "set": {
                    "validation_command.program": "cargo",
                    "validation_command.argv": ["cargo", "clippy"],
                    "validation_command.remote_required": True,
                }
            },
        )
        errors = mod.validate_snapshot(snapshot)
        self.assertIn("ERR_CRVD_REMOTE_REQUIRED_LOCAL_FALLBACK", errors)

    def test_handoff_path_inputs_must_be_sorted(self) -> None:
        snapshot = mod.apply_fixture_patch(
            self.valid_snapshot,
            {"set": {"sibling_repo.dirty_files": ["z-last.rs", "a-first.rs"]}},
        )
        errors = mod.validate_snapshot(snapshot)
        self.assertIn("ERR_CRVD_UNSORTED_LIST", errors)

    def test_too_many_symbol_probes_fail_closed(self) -> None:
        base_probe = copy.deepcopy(self.valid_snapshot["symbol_probes"][0])
        probes = []
        for index in range(mod.MAX_SYMBOL_PROBES + 1):
            probe = copy.deepcopy(base_probe)
            probe["symbol"] = f"Symbol{index:02}"
            probes.append(probe)
        snapshot = mod.apply_fixture_patch(self.valid_snapshot, {"set": {"symbol_probes": probes}})
        errors = mod.validate_snapshot(snapshot)
        self.assertIn("ERR_CRVD_BAD_SYMBOL_PROBES", errors)

    def test_patch_helper_supports_list_paths(self) -> None:
        snapshot = mod.apply_fixture_patch(
            self.valid_snapshot,
            {"set": {"symbol_probes.0.status": "not_checked"}},
        )
        self.assertEqual(snapshot["symbol_probes"][0]["status"], "not_checked")

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
        self.assertEqual(parsed["bead_id"], "bd-7vk3p.1")
        self.assertEqual(parsed["verdict"], "PASS")

    def test_handoff_json_cli_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--handoff", "crvd-mail-corrupt", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["schema_version"], mod.HANDOFF_SCHEMA_VERSION)
        self.assertEqual(parsed["classification_code"], "CRVD_BLOCKED_AGENT_MAIL_CORRUPT")

    def test_handoff_markdown_cli_output(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--handoff",
                "crvd-dirty-relevant-absent-symbols",
                "--handoff-format",
                "markdown",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("# Cross-Repo Validation Handoff", proc.stdout)
        self.assertIn("bd-famte", proc.stdout)
        self.assertIn("CRVD_BLOCKED_SIBLING_DIRTY_RELEVANT", proc.stdout)

    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["verdict"], "PASS")

    def _failures(self, result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])


if __name__ == "__main__":
    unittest.main()
