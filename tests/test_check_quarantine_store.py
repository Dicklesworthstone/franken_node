"""Unit tests for check_quarantine_store.py verification logic."""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestQuarantineMetrics(unittest.TestCase):

    def test_csv_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2eun/quarantine_usage_metrics.csv")
        self.assertTrue(os.path.isfile(path))

    def test_csv_has_data(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2eun/quarantine_usage_metrics.csv")
        with open(path) as f:
            lines = [l for l in f if l.strip()]
        self.assertGreaterEqual(len(lines), 4)


class TestQuarantineStoreImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/quarantine_store.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_quarantine_config(self):
        self.assertIn("struct QuarantineConfig", self.content)

    def test_has_quarantine_entry(self):
        self.assertIn("struct QuarantineEntry", self.content)

    def test_has_quarantine_store(self):
        self.assertIn("struct QuarantineStore", self.content)

    def test_has_quarantine_stats(self):
        self.assertIn("struct QuarantineStats", self.content)

    def test_has_ingest(self):
        self.assertIn("fn ingest", self.content)

    def test_has_evict_expired(self):
        self.assertIn("fn evict_expired", self.content)

    def test_has_promote(self):
        self.assertIn("fn promote", self.content)

    def test_has_all_error_codes(self):
        for code in ["QDS_QUOTA_EXCEEDED", "QDS_TTL_EXPIRED", "QDS_DUPLICATE",
                     "QDS_NOT_FOUND", "QDS_INVALID_CONFIG"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestQuarantineStoreSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2eun_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-QDS-DEFAULT", "INV-QDS-BOUNDED",
                    "INV-QDS-TTL", "INV-QDS-EXCLUDED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["QDS_QUOTA_EXCEEDED", "QDS_TTL_EXPIRED", "QDS_DUPLICATE",
                     "QDS_NOT_FOUND", "QDS_INVALID_CONFIG"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestQuarantineIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/quarantine_retention.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_default(self):
        self.assertIn("inv_qds_default", self.content)

    def test_covers_bounded(self):
        self.assertIn("inv_qds_bounded", self.content)

    def test_covers_ttl(self):
        self.assertIn("inv_qds_ttl", self.content)

    def test_covers_excluded(self):
        self.assertIn("inv_qds_excluded", self.content)


if __name__ == "__main__":
    unittest.main()
