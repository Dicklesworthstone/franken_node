"""Unit tests for check_telemetry_namespace.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_telemetry_namespace.py"
CATALOG_PATH = ROOT / "artifacts/section_10_13/bd-1ugy/telemetry_schema_catalog.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-1ugy/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestTelemetryCatalog(unittest.TestCase):

    def test_catalog_exists(self):
        self.assertTrue(CATALOG_PATH.is_file())

    def test_catalog_valid_json(self):
        data = decode_json_object(CATALOG_PATH.read_text(encoding="utf-8"))
        self.assertIn("metrics", data)
        self.assertGreaterEqual(len(data["metrics"]), 4)

    def test_catalog_has_planes(self):
        data = decode_json_object(CATALOG_PATH.read_text(encoding="utf-8"))
        self.assertIn("planes", data)
        for p in ["protocol", "capability", "egress", "security"]:
            self.assertIn(p, data["planes"])


class TestTelemetryImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/telemetry_namespace.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

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
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-1ugy_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-TNS-VERSIONED", "INV-TNS-FROZEN",
                    "INV-TNS-DEPRECATED", "INV-TNS-NAMESPACE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestTelemetryIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/metric_schema_stability.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_versioned(self):
        self.assertIn("inv_tns_versioned", self.content)

    def test_covers_frozen(self):
        self.assertIn("inv_tns_frozen", self.content)

    def test_covers_deprecated(self):
        self.assertIn("inv_tns_deprecated", self.content)

    def test_covers_namespace(self):
        self.assertIn("inv_tns_namespace", self.content)


class TestTelemetryCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "telemetry_namespace_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["TNS-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-1ugy:", result.stdout)

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
