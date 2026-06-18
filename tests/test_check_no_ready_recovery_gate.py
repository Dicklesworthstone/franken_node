"""Unit tests for scripts/check_no_ready_recovery_gate.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess  # nosec B404 - fixed-argv CLI smoke tests with no shell.
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_no_ready_recovery_gate.py"
FIXTURE_PATH = ROOT / "artifacts" / "validation_broker" / "bd-z1q8l" / "no_ready_recovery_fixtures.v1.json"

spec = importlib.util.spec_from_file_location("check_no_ready_recovery_gate", SCRIPT_PATH)
mod = importlib.util.module_from_spec(spec)
if spec.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

JSON_DECODER = json.JSONDecoder()


class NoReadyRecoveryGateTests(unittest.TestCase):
    def test_checked_in_fixture_passes(self) -> None:
        result = mod.run_gate(JSON_DECODER.decode(FIXTURE_PATH.read_text(encoding="utf-8")))

        self.assertEqual(result["verdict"], "PASS", self._failures(result))
        self.assertEqual(result["summary"]["scenario_count"], 2)
        self.assertEqual(result["summary"]["final_decisions"]["no-ready-blocked-graph"], "create-new-bead")
        self.assertEqual(result["summary"]["final_decisions"]["ready-item-claim"], "claim")

    def test_no_ready_scenario_does_not_recommend_claim(self) -> None:
        result = mod.run_gate(JSON_DECODER.decode(FIXTURE_PATH.read_text(encoding="utf-8")))
        scenario = self._scenario(result, "no-ready-blocked-graph")

        self.assertEqual(scenario["final_decision"], "create-new-bead")
        self.assertNotEqual(scenario["final_decision"], "claim")
        self.assertEqual(scenario["trace"]["actionability_classes"]["bd-f5b04.2.6"], "external_blocker")
        self.assertEqual(scenario["trace"]["actionability_classes"]["bd-famte"], "external_blocker")

    def test_ready_scenario_recommends_claim(self) -> None:
        result = mod.run_gate(JSON_DECODER.decode(FIXTURE_PATH.read_text(encoding="utf-8")))
        scenario = self._scenario(result, "ready-item-claim")

        self.assertEqual(scenario["final_decision"], "claim")
        self.assertEqual(scenario["trace"]["actionability_classes"]["bd-ready"], "claimable")

    def test_golden_catches_rch_class_regression(self) -> None:
        fixture = JSON_DECODER.decode(FIXTURE_PATH.read_text(encoding="utf-8"))
        fixture["scenarios"][0]["expected"]["rch"]["rch-ssh-timeout"]["classification"] = "product_failure"

        result = mod.run_gate(fixture)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("rch-class:rch-ssh-timeout", self._failures(result))

    def test_golden_catches_first_blocker_regression(self) -> None:
        fixture = JSON_DECODER.decode(FIXTURE_PATH.read_text(encoding="utf-8"))
        fixture["scenarios"][0]["expected"]["rch"]["rch-stale-progress"]["first_blocker"] = "summary only"

        result = mod.run_gate(fixture)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("rch-first-blocker:rch-stale-progress", self._failures(result))

    def test_cli_json_passes(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, str(SCRIPT_PATH), "--fixture", str(FIXTURE_PATH), "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = JSON_DECODER.decode(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS", self._failures(payload))

    def test_cli_human_output_names_scenarios(self) -> None:
        proc = subprocess.run(  # nosec B603
            [sys.executable, str(SCRIPT_PATH), "--fixture", str(FIXTURE_PATH)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("No-ready recovery fixture gate: PASS", proc.stdout)
        self.assertIn("no-ready-blocked-graph: PASS -> create-new-bead", proc.stdout)
        self.assertIn("ready-item-claim: PASS -> claim", proc.stdout)

    @staticmethod
    def _scenario(result: dict[str, object], scenario_id: str) -> dict[str, object]:
        scenarios = result.get("scenarios", [])
        for scenario in scenarios:
            if isinstance(scenario, dict) and scenario.get("scenario_id") == scenario_id:
                return scenario
        raise AssertionError(f"missing scenario {scenario_id}")

    @staticmethod
    def _failures(result: dict[str, object]) -> str:
        checks = result.get("checks", [])
        failures = [check for check in checks if isinstance(check, dict) and not check.get("passed")]
        return "\n".join(f"{check['check']}: {check['detail']}" for check in failures[:20])


if __name__ == "__main__":
    unittest.main()
