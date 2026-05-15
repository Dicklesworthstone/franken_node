"""Unit tests for scripts/check_vef_execution_receipt.py (bd-p73r)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_execution_receipt.py"

spec = importlib.util.spec_from_file_location("check_vef_execution_receipt", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-p73r")
        self.assertEqual(result["section"], "10.18")
        self.assertIn(result["verdict"], ("PASS", "FAIL"))
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertEqual(result["total"], len(result["checks"]))

    def test_check_entries_shape(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)
            self.assertIsInstance(check["check"], str)
            self.assertIsInstance(check["pass"], bool)
            self.assertIsInstance(check["detail"], str)


class TestVerdict(unittest.TestCase):
    def test_verdict_pass(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_text(result))

    @staticmethod
    def _failure_text(result: dict) -> str:
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in failures[:12])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_shape(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["mode"], "self-test")
        self.assertGreaterEqual(result["total"], 6)
        self.assertEqual(result["failed"], result["total"] - result["passed"])


class TestCli(unittest.TestCase):
    def test_json_cli_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-p73r")
        self.assertIn("checks", parsed)

    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class TestFailureInjection(unittest.TestCase):
    def test_missing_summary_fails(self) -> None:
        original = mod.SUMMARY
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                mod.SUMMARY = Path(temp_dir) / "missing-summary.md"
                result = mod.run_all()
                self.assertEqual(result["verdict"], "FAIL")
                failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
                self.assertIn("summary_exists", failed_checks)
            finally:
                mod.SUMMARY = original

    def test_vector_hash_mismatch_fails(self) -> None:
        original = mod.VECTORS
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                vector_copy = json.JSONDecoder().decode(original.read_text(encoding="utf-8"))
                vector_copy["vectors"][0]["expected_hash"] = (
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                )
                mutated_vectors = Path(temp_dir) / "vef_receipt_schema_vectors.json"
                mutated_vectors.write_text(json.dumps(vector_copy), encoding="utf-8")
                mod.VECTORS = mutated_vectors

                result = mod.run_all()

                self.assertEqual(result["verdict"], "FAIL")
                failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
                self.assertIn("vector_0_expected_hash_matches_canonical_bytes", failed_checks)
            finally:
                mod.VECTORS = original


class TestCommentOnlyRegressions(unittest.TestCase):
    def test_comment_only_impl_markers_fail_closed(self) -> None:
        comment_only_impl = """
// pub enum ExecutionActionType { NetworkAccess, FilesystemOperation, ProcessSpawn, SecretAccess, PolicyTransition, ArtifactPromotion }
// pub struct ExecutionReceipt {
//   pub schema_version: String,
//   pub action_type: ExecutionActionType,
//   pub capability_context: BTreeMap<String, String>,
//   pub actor_identity: String,
//   pub artifact_identity: String,
//   pub policy_snapshot_hash: String,
//   pub timestamp_millis: u64,
//   pub sequence_number: u64,
//   pub witness_references: Vec<String>,
//   pub trace_id: String,
// }
// pub struct ExecutionReceiptError;
// pub fn validate_receipt() {}
// pub fn serialize_canonical() {}
// pub fn receipt_hash_sha256() {}
// pub fn verify_hash() {}
// pub fn round_trip_canonical_bytes() {}
// pub fn canonicalized() {}
// pub const VEF_RECEIPT_001_CREATED: &str = "VEF-RECEIPT-001";
// pub const VEF_RECEIPT_002_SERIALIZED: &str = "VEF-RECEIPT-002";
// pub const ERR_VEF_RECEIPT_MISSING_FIELD: &str = "VEF-RECEIPT-ERR-001";
// pub const ERR_VEF_RECEIPT_INVALID_VALUE: &str = "VEF-RECEIPT-ERR-002";
// pub const ERR_VEF_RECEIPT_SCHEMA_VERSION: &str = "VEF-RECEIPT-ERR-003";
// pub const ERR_VEF_RECEIPT_HASH_MISMATCH: &str = "VEF-RECEIPT-ERR-004";
// pub const ERR_VEF_RECEIPT_INTERNAL: &str = "VEF-RECEIPT-ERR-005";
// pub const INV_VEF_RECEIPT_DETERMINISTIC: &str = "INV-VEF-RECEIPT-DETERMINISTIC";
// pub const INV_VEF_RECEIPT_HASH_STABLE: &str = "INV-VEF-RECEIPT-HASH-STABLE";
// pub const INV_VEF_RECEIPT_VERSIONED: &str = "INV-VEF-RECEIPT-VERSIONED";
// pub const INV_VEF_RECEIPT_TRACEABLE: &str = "INV-VEF-RECEIPT-TRACEABLE";
// Sha256
// sha256:
// witness_references.sort()
// #[test]
// #[test]
// #[test]
"""
        with patch.object(mod, "_impl_code", lambda: mod._strip_rust_comments(comment_only_impl)):
            mod.RESULTS.clear()
            mod.check_impl_symbols()
            results = {entry["check"]: entry for entry in mod.RESULTS}

        for check in (
            "impl_symbol_pub enum ExecutionActionType",
            "impl_symbol_pub struct ExecutionReceipt",
            "impl_symbol_pub fn validate_receipt",
            "impl_field_schema_version",
            "impl_action_type_network_access",
            "impl_event_VEF-RECEIPT-001",
            "impl_error_VEF-RECEIPT-ERR-001",
            "impl_invariant_INV-VEF-RECEIPT-DETERMINISTIC",
            "impl_minimum_unit_tests",
        ):
            self.assertFalse(results[check]["pass"], check)

    def test_comment_only_mod_wiring_fails_closed(self) -> None:
        with patch.object(mod, "_mod_code", lambda: mod._strip_rust_comments("// pub mod vef_execution_receipt;")):
            mod.RESULTS.clear()
            mod.check_mod_wiring()
            results = {entry["check"]: entry for entry in mod.RESULTS}

        self.assertFalse(results["connector_mod_wires_vef_execution_receipt"]["pass"])


if __name__ == "__main__":
    unittest.main()
