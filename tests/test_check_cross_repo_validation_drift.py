"""Unit tests for scripts/check_cross_repo_validation_drift.py."""

from __future__ import annotations

import copy
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
