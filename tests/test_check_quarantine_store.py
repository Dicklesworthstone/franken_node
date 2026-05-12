"""Unit tests for check_quarantine_store.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import check_quarantine_store

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_quarantine_store.py"
CSV_PATH = ROOT / "artifacts/section_10_13/bd-2eun/quarantine_usage_metrics.csv"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-2eun/verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts/section_10_13/bd-2eun/verification_summary.md"
PLAN_PATH = ROOT / "docs/plans/PLAN_TO_CREATE_FRANKEN_NODE.md"
CANONICAL_IMPL_PATH = "crates/franken-node/src/connector/quarantine_store.rs"
STALE_IMPL_PATH = "src/admission/" + "quarantine_store.rs"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestQuarantineMetrics(unittest.TestCase):

    def test_csv_exists(self):
        self.assertTrue(CSV_PATH.is_file())

    def test_csv_has_data(self):
        lines = [line for line in CSV_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 4)


class TestQuarantineReadHelpers(unittest.TestCase):

    def test_read_utf8_invalid_utf8_returns_none(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.csv"
            path.write_bytes(b"\xff")

            self.assertIsNone(check_quarantine_store.read_utf8(path))


class TestQuarantineStoreImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/quarantine_store.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

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

    def test_checker_uses_canonical_connector_path(self):
        self.assertEqual(check_quarantine_store.IMPL_PATH, ROOT / CANONICAL_IMPL_PATH)


class TestQuarantineStoreSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-2eun_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-QDS-DEFAULT", "INV-QDS-BOUNDED",
                    "INV-QDS-TTL", "INV-QDS-EXCLUDED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["QDS_QUOTA_EXCEEDED", "QDS_TTL_EXPIRED", "QDS_DUPLICATE",
                     "QDS_NOT_FOUND", "QDS_INVALID_CONFIG"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_spec_cites_canonical_connector_path(self):
        self.assertIn(CANONICAL_IMPL_PATH, self.content)
        self.assertNotIn(STALE_IMPL_PATH, self.content)


class TestQuarantinePathTruth(unittest.TestCase):

    def test_plan_cites_live_connector_artifact_path(self):
        content = PLAN_PATH.read_text(encoding="utf-8")

        self.assertIn(CANONICAL_IMPL_PATH, content)
        self.assertNotIn(STALE_IMPL_PATH, content)

    def test_summary_cites_live_connector_artifact_path(self):
        content = SUMMARY_PATH.read_text(encoding="utf-8")

        self.assertIn(CANONICAL_IMPL_PATH, content)
        self.assertNotIn(STALE_IMPL_PATH, content)

    def test_evidence_cites_live_connector_artifact_path(self):
        content = EVIDENCE_PATH.read_text(encoding="utf-8")

        self.assertIn(CANONICAL_IMPL_PATH, content)
        self.assertNotIn(STALE_IMPL_PATH, content)


class TestQuarantineIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/quarantine_retention.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_default(self):
        self.assertIn("inv_qds_default", self.content)

    def test_covers_bounded(self):
        self.assertIn("inv_qds_bounded", self.content)

    def test_covers_ttl(self):
        self.assertIn("inv_qds_ttl", self.content)

    def test_covers_excluded(self):
        self.assertIn("inv_qds_excluded", self.content)


class TestQuarantineStoreCli(unittest.TestCase):

    def test_json_mode_requests_full_proof_by_default(self):
        args = check_quarantine_store.parse_args(["--json"])

        self.assertTrue(check_quarantine_store.should_run_rust_tests(args))

    def test_structural_json_mode_is_partial_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "quarantine_store_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        self.assertEqual(statuses["QDS-TESTS"], "SKIP")
        self.assertEqual(statuses["QDS-PATH-TRUTH"], "PASS")
        self.assertEqual(evidence["summary"]["total_checks"], 7)
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("bd-2eun:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
