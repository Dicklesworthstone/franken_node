"""Unit tests for check_repair_controller.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_repair_controller.py"
CSV_PATH = ROOT / "artifacts/section_10_13/bd-91gg/repair_cycle_telemetry.csv"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-91gg/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestRepairTelemetry(unittest.TestCase):

    def test_csv_exists(self):
        self.assertTrue(CSV_PATH.is_file())

    def test_csv_has_data(self):
        lines = [line for line in CSV_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 4)


class TestRepairControllerImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/repair_controller.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_repair_config(self):
        self.assertIn("struct RepairConfig", self.content)

    def test_has_repair_item(self):
        self.assertIn("struct RepairItem", self.content)

    def test_has_repair_allocation(self):
        self.assertIn("struct RepairAllocation", self.content)

    def test_has_repair_cycle_audit(self):
        self.assertIn("struct RepairCycleAudit", self.content)

    def test_has_run_cycle(self):
        self.assertIn("fn run_cycle", self.content)

    def test_has_all_error_codes(self):
        for code in ["BRC_CAP_EXCEEDED", "BRC_INVALID_CONFIG",
                     "BRC_NO_PENDING", "BRC_STARVATION"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestRepairControllerSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-91gg_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-BRC-BOUNDED", "INV-BRC-FAIRNESS",
                    "INV-BRC-AUDITABLE", "INV-BRC-DETERMINISTIC"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["BRC_CAP_EXCEEDED", "BRC_INVALID_CONFIG",
                     "BRC_NO_PENDING", "BRC_STARVATION"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestRepairIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/repair_fairness.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_bounded(self):
        self.assertIn("inv_brc_bounded", self.content)

    def test_covers_fairness(self):
        self.assertIn("inv_brc_fairness", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_brc_auditable", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_brc_deterministic", self.content)


class TestRepairControllerCli(unittest.TestCase):

    def test_json_mode_is_structural_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "repair_controller_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["BRC-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-91gg:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
