"""Unit tests for check_manifest_negotiation.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_manifest_negotiation.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-17mb/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestManifestNegotiationFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = ROOT / "fixtures/manifest_negotiation/negotiation_scenarios.json"
        self.assertTrue(path.is_file())

    def test_fixture_has_cases(self):
        path = ROOT / "fixtures/manifest_negotiation/negotiation_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 5)

    def test_fixture_has_accepted_and_rejected(self):
        path = ROOT / "fixtures/manifest_negotiation/negotiation_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        outcomes = [c["expected_outcome"] for c in data["cases"]]
        self.assertIn("accepted", outcomes)
        self.assertIn("rejected", outcomes)

    def test_fixture_cases_have_manifest_fields(self):
        path = ROOT / "fixtures/manifest_negotiation/negotiation_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        for case in data["cases"]:
            self.assertIn("manifest", case)
            self.assertIn("host", case)
            self.assertIn("expected_outcome", case)
            m = case["manifest"]
            self.assertIn("version", m)
            self.assertIn("required_features", m)
            self.assertIn("transport_caps", m)


class TestManifestNegotiationTrace(unittest.TestCase):

    def test_trace_exists(self):
        path = ROOT / "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json"
        self.assertTrue(path.is_file())

    def test_trace_valid_json(self):
        path = ROOT / "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("negotiations", data)
        self.assertGreaterEqual(len(data["negotiations"]), 2)

    def test_trace_has_both_outcomes(self):
        path = ROOT / "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        outcomes = [n["outcome"] for n in data["negotiations"]]
        self.assertIn("accepted", outcomes)
        self.assertIn("rejected", outcomes)

    def test_trace_has_trace_ids(self):
        path = ROOT / "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        for n in data["negotiations"]:
            self.assertIn("trace_id", n)


class TestManifestNegotiationImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/manifest_negotiation.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_semver(self):
        self.assertIn("struct SemVer", self.content)

    def test_has_connector_manifest(self):
        self.assertIn("struct ConnectorManifest", self.content)

    def test_has_host_capabilities(self):
        self.assertIn("struct HostCapabilities", self.content)

    def test_has_negotiation_result(self):
        self.assertIn("struct NegotiationResult", self.content)

    def test_has_negotiate_fn(self):
        self.assertIn("fn negotiate", self.content)

    def test_has_check_version(self):
        self.assertIn("fn check_version", self.content)

    def test_has_check_features(self):
        self.assertIn("fn check_features", self.content)

    def test_has_check_transport(self):
        self.assertIn("fn check_transport", self.content)

    def test_has_semantic_ordering(self):
        self.assertIn("impl Ord for SemVer", self.content)

    def test_has_all_transport_caps(self):
        for cap in ["Http1", "Http2", "Http3", "WebSocket", "Grpc"]:
            self.assertIn(cap, self.content, f"Missing transport cap {cap}")

    def test_has_all_error_codes(self):
        for code in ["MANIFEST_VERSION_UNSUPPORTED", "MANIFEST_FEATURE_MISSING",
                     "MANIFEST_TRANSPORT_MISMATCH", "MANIFEST_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestManifestNegotiationSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-17mb_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-MANIFEST-SEMVER", "INV-MANIFEST-FAIL-CLOSED",
                    "INV-MANIFEST-FEATURES", "INV-MANIFEST-TRANSPORT"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["MANIFEST_VERSION_UNSUPPORTED", "MANIFEST_FEATURE_MISSING",
                     "MANIFEST_TRANSPORT_MISMATCH", "MANIFEST_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_outcome_types(self):
        self.assertIn("Accepted", self.content)
        self.assertIn("Rejected", self.content)


class TestManifestNegotiationCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "manifest_negotiation_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["MN-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-17mb:", result.stdout)

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
