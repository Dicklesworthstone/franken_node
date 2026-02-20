"""Unit tests for check_telemetry_namespace.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestTelemetryCatalog(unittest.TestCase):

    def test_catalog_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1ugy/telemetry_schema_catalog.json")
        self.assertTrue(os.path.isfile(path))

    def test_catalog_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1ugy/telemetry_schema_catalog.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("metrics", data)
        self.assertGreaterEqual(len(data["metrics"]), 4)

    def test_catalog_has_planes(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1ugy/telemetry_schema_catalog.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("planes", data)
        for p in ["protocol", "capability", "egress", "security"]:
            self.assertIn(p, data["planes"])


class TestTelemetryImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/telemetry_namespace.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_schema_registry(self):
        self.assertIn("struct SchemaRegistry", self.content)

    def test_has_metric_schema(self):
        self.assertIn("struct MetricSchema", self.content)

    def test_has_plane_enum(self):
        self.assertIn("enum Plane", self.content)

    def test_has_register_fn(self):
        self.assertIn("fn register", self.content)

    def test_has_all_error_codes(self):
        for code in ["TNS_INVALID_NAMESPACE", "TNS_VERSION_MISSING", "TNS_FROZEN_CONFLICT",
                     "TNS_ALREADY_DEPRECATED", "TNS_NOT_FOUND"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestTelemetrySpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1ugy_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-TNS-VERSIONED", "INV-TNS-FROZEN",
                    "INV-TNS-DEPRECATED", "INV-TNS-NAMESPACE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestTelemetryIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/metric_schema_stability.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_versioned(self):
        self.assertIn("inv_tns_versioned", self.content)

    def test_covers_frozen(self):
        self.assertIn("inv_tns_frozen", self.content)

    def test_covers_deprecated(self):
        self.assertIn("inv_tns_deprecated", self.content)

    def test_covers_namespace(self):
        self.assertIn("inv_tns_namespace", self.content)


if __name__ == "__main__":
    unittest.main()
