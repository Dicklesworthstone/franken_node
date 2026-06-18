"""Unit tests for scripts/check_tracker_actionability.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess  # nosec B404 - fixed-argv CLI smoke tests with no shell.
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_tracker_actionability.py"

spec = importlib.util.spec_from_file_location("check_tracker_actionability", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
if spec.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
spec.loader.exec_module(mod)

JSON_DECODER = json.JSONDecoder()


def plan_with(*items: dict[str, object]) -> dict[str, object]:
    return {"plan": {"tracks": [{"track_id": "track-A", "items": list(items)}]}}


class TrackerActionabilityTests(unittest.TestCase):
    def test_self_test_fixture_classifies_no_ready_recovery(self) -> None:
        ready, bv_plan, issues = mod._self_test_payloads()

        result = mod.run_checks(ready, bv_plan, issues, expected_agent="NavyTurtle")

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertTrue(result["summary"]["no_ready_recovery"])
        self.assertEqual(result["summary"]["recommended_next_action"], "create-new-bead")
        classes = {item["id"]: item["classification"] for item in result["classifications"]}
        self.assertEqual(classes["bd-f5b04.2"], "parent_epic")
        self.assertEqual(classes["bd-f5b04.2.6"], "external_blocker")
        self.assertEqual(classes["bd-famte"], "external_blocker")
        self.assertEqual(classes["bd-other-agent"], "assigned_elsewhere")
        self.assertEqual(classes["bd-child"], "blocked")

    def test_ready_item_wins_over_bv_uncertainty(self) -> None:
        ready = [{"id": "bd-ready", "title": "Ready task", "status": "open"}]
        bv_plan = plan_with({"id": "bd-ready", "title": "Ready task", "status": "open"})

        result = mod.run_checks(ready, bv_plan, [], expected_agent="NavyTurtle")

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertEqual(result["summary"]["claimable_count"], 1)
        self.assertEqual(result["summary"]["recommended_next_action"], "claim")
        self.assertEqual(result["classifications"][0]["classification"], "claimable")

    def test_related_dependency_does_not_block_claimability(self) -> None:
        ready = [{"id": "bd-task", "title": "Task", "status": "open"}]
        bv_plan = plan_with({"id": "bd-task", "title": "Task", "status": "open"})
        issues = [
            {
                "id": "bd-task",
                "title": "Task",
                "status": "open",
                "issue_type": "task",
                "dependencies": [
                    {
                        "id": "bd-epic",
                        "title": "Rollup",
                        "status": "blocked",
                        "dependency_type": "related",
                    }
                ],
            }
        ]

        result = mod.run_checks(ready, bv_plan, issues)

        self.assertEqual(result["classifications"][0]["classification"], "claimable")

    def test_blocking_dependency_is_reported_with_blocker_details(self) -> None:
        bv_plan = plan_with({"id": "bd-child", "title": "Child", "status": "open"})
        issues = [
            {
                "id": "bd-child",
                "title": "Child",
                "status": "open",
                "issue_type": "task",
                "dependencies": [
                    {
                        "id": "bd-parent",
                        "title": "Parent gate",
                        "status": "blocked",
                        "dependency_type": "blocks",
                    }
                ],
            }
        ]

        result = mod.run_checks([], bv_plan, issues)

        item = result["classifications"][0]
        self.assertEqual(item["classification"], "blocked")
        self.assertEqual(item["recommended_action"], "refresh-blocker")
        self.assertEqual(item["blockers"][0]["id"], "bd-parent")

    def test_blocked_without_external_hints_remains_plain_blocked(self) -> None:
        bv_plan = plan_with({"id": "bd-blocked", "title": "Blocked", "status": "blocked"})
        issues = [{"id": "bd-blocked", "title": "Blocked", "status": "blocked", "issue_type": "task"}]

        result = mod.run_checks([], bv_plan, issues)

        self.assertEqual(result["classifications"][0]["classification"], "blocked")
        self.assertEqual(result["classifications"][0]["recommended_action"], "wait")

    def test_blocked_assigned_item_preserves_external_blocker_classification(self) -> None:
        bv_plan = plan_with({"id": "bd-rch", "title": "RCH blocked", "status": "blocked"})
        issues = [
            {
                "id": "bd-rch",
                "title": "RCH blocked",
                "status": "blocked",
                "issue_type": "bug",
                "assignee": "OtherAgent",
                "notes": "Current first blocker: [RCH-E104] SSH command timed out",
            }
        ]

        result = mod.run_checks([], bv_plan, issues, expected_agent="NavyTurtle")

        self.assertEqual(result["classifications"][0]["classification"], "external_blocker")
        self.assertEqual(result["classifications"][0]["recommended_action"], "refresh-blocker")

    def test_missing_bv_items_fails_closed(self) -> None:
        result = mod.run_checks([], {"plan": {"tracks": []}}, [])

        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("BV plan must contain at least one item", self._failures(result))

    def test_cli_self_test_json_passes(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))
        self.assertTrue(payload["summary"]["no_ready_recovery"])

    def test_cli_fixture_inputs_pass(self) -> None:
        ready, bv_plan, issues = mod._self_test_payloads()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ready_path = self._write_json(root / "ready.json", ready)
            bv_path = self._write_json(root / "bv.json", bv_plan)
            issues_path = self._write_json(root / "issues.json", issues)

            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--ready",
                    str(ready_path),
                    "--bv-plan",
                    str(bv_path),
                    "--items",
                    str(issues_path),
                    "--expected-agent",
                    "NavyTurtle",
                    "--json",
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
