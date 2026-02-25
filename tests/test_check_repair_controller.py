"""Unit tests for check_repair_controller.py verification logic."""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestRepairTelemetry(unittest.TestCase):

    def test_csv_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-91gg/repair_cycle_telemetry.csv")
        self.assertTrue(os.path.isfile(path))

    def test_csv_has_data(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-91gg/repair_cycle_telemetry.csv")
        with open(path) as f:
            lines = [l for l in f if l.strip()]
        self.assertGreaterEqual(len(lines), 4)


class TestRepairControllerImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/repair_controller.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

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
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-91gg_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

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
        self.integ_path = os.path.join(ROOT, "tests/integration/repair_fairness.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_bounded(self):
        self.assertIn("inv_brc_bounded", self.content)

    def test_covers_fairness(self):
        self.assertIn("inv_brc_fairness", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_brc_auditable", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_brc_deterministic", self.content)


if __name__ == "__main__":
    unittest.main()
