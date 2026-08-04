"""Unit tests for scripts/check_blocked_bead_freshness.py."""

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
SCRIPT_PATH = ROOT / "scripts" / "check_blocked_bead_freshness.py"

spec = importlib.util.spec_from_file_location("check_blocked_bead_freshness", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
if spec.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
spec.loader.exec_module(mod)

JSON_DECODER = json.JSONDecoder()
NOW = datetime(2026, 6, 18, 13, 0, tzinfo=timezone.utc)


class BlockedBeadFreshnessTests(unittest.TestCase):
    def test_self_test_fixture_passes(self) -> None:
        result = mod.run_checks(mod._self_test_payload(), now=NOW)

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertEqual(result["summary"]["blocked_count"], 2)
        self.assertEqual(result["summary"]["fresh_count"], 2)

    def test_missing_evidence_fails_closed(self) -> None:
        result = mod.run_checks([{"id": "bd-empty", "status": "blocked", "updated_at": NOW.isoformat()}], now=NOW)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["audits"][0]["classification"], "missing_evidence")
        self.assertIn("evidence_text", result["audits"][0]["missing"])

    def test_missing_command_or_symbol_is_incomplete(self) -> None:
        issue = {
            "id": "bd-no-command",
            "status": "blocked",
            "updated_at": NOW.isoformat(),
            "notes": "Current first blocker: [RCH-E104] SSH command timed out on remote worker.",
        }

        result = mod.run_checks([issue], now=NOW)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["audits"][0]["classification"], "incomplete_evidence")
        self.assertIn("command_or_symbol", result["audits"][0]["missing"])

    def test_missing_first_blocker_is_incomplete(self) -> None:
        issue = {
            "id": "bd-no-first-blocker",
            "status": "blocked",
            "updated_at": NOW.isoformat(),
            "notes": "Exact command: rch exec -- cargo test -p frankenengine-node.",
        }

        result = mod.run_checks([issue], now=NOW)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["audits"][0]["classification"], "incomplete_evidence")
        self.assertIn("first_blocker", result["audits"][0]["missing"])

    def test_stale_evidence_fails(self) -> None:
        issue = {
            "id": "bd-stale",
            "status": "blocked",
            "updated_at": "2026-06-01T00:00:00Z",
            "notes": "Exact command: rch exec -- cargo check. Current first blocker: RCH timeout.",
        }

        result = mod.run_checks([issue], now=NOW, max_age_hours=24)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["audits"][0]["classification"], "stale")
        self.assertGreater(result["audits"][0]["evidence_age_hours"], 24)

    def test_comments_count_as_timestamped_evidence(self) -> None:
        issue = {
            "id": "bd-comment",
            "status": "blocked",
            "updated_at": "2026-06-01T00:00:00Z",
            "comments": [
                {
                    "created_at": "2026-06-18T12:45:00Z",
                    "text": "Exact command: br update bd-child --claim. Validation failed: claim: cannot claim blocked issue.",
                }
            ],
        }

        result = mod.run_checks([issue], now=NOW, max_age_hours=24)

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertEqual(result["audits"][0]["classification"], "fresh")

    def test_non_blocked_items_are_ignored(self) -> None:
        result = mod.run_checks(
            [
                {"id": "bd-open", "status": "open"},
                {
                    "id": "bd-blocked",
                    "status": "blocked",
                    "updated_at": NOW.isoformat(),
                    "notes": "Exact command: rch exec -- cargo check. Current first blocker: timeout.",
                },
            ],
            now=NOW,
        )

        self.assertEqual(result["summary"]["blocked_count"], 1)
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_cli_self_test_json_passes(self) -> None:
        proc = subprocess.run(  # nosec B603
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--self-test",
                "--now",
                "2026-06-18T13:00:00Z",
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

    def test_cli_fixture_inputs_fail_on_stale(self) -> None:
        payload = [
            {
                "id": "bd-stale",
                "status": "blocked",
                "updated_at": "2026-06-01T00:00:00Z",
                "notes": "Exact command: rch exec -- cargo check. Current first blocker: timeout.",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "items.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--items",
                    str(path),
                    "--now",
                    "2026-06-18T13:00:00Z",
                    "--max-age-hours",
                    "24",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )

        self.assertEqual(proc.returncode, 1)
        payload = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(payload["audits"][0]["classification"], "stale")

    @staticmethod
    def _failures(result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])


if __name__ == "__main__":
    unittest.main()
