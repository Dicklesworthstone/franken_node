"""Tests for scripts/check_idempotency_key_derivation.py (bd-12n3)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_idempotency_key_derivation.py"
sys.path.insert(0, str(ROOT / "scripts"))

import check_idempotency_key_derivation as checker


def decode_json(payload: str) -> dict:
    decoded = json.JSONDecoder().decode(payload)
    if not isinstance(decoded, dict):
        raise TypeError("expected JSON object")
    return decoded


class SelfTestTests(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(checker.self_test())


class JsonOutputTests(unittest.TestCase):
    def test_json_output_shape(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = decode_json(result.stdout)
        self.assertEqual(payload["bead_id"], "bd-12n3")
        self.assertEqual(payload["section"], "10.14")
        self.assertIn(payload["verdict"], {"PASS", "FAIL"})
        self.assertIsInstance(payload["checks"], list)


class VectorValidationTests(unittest.TestCase):
    def test_missing_vectors_file_fails(self):
        original = checker.VECTORS
        try:
            checker.VECTORS = ROOT / "artifacts" / "10.14" / "_missing_vectors_.json"
            checks = checker._check_vectors_document()
        finally:
            checker.VECTORS = original
        check_map = {c["check"]: c for c in checks}
        self.assertFalse(check_map["vectors_exists"]["passed"])

    def test_non_object_vectors_json_fails_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vectors_path = Path(tmpdir) / "vectors.json"
            vectors_path.write_text("[]", encoding="utf-8")

            original = checker.VECTORS
            try:
                checker.VECTORS = vectors_path
                checks = checker._check_vectors_document()
            finally:
                checker.VECTORS = original

        self.assertEqual(checks[1]["check"], "vectors_parse_json")
        self.assertFalse(checks[1]["passed"])

    def test_out_of_range_epoch_is_invalid_row_not_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vectors_path = Path(tmpdir) / "vectors.json"
            vectors_doc = {
                "schema_version": "ik-v1.1",
                "domain_prefix": "franken_node.idempotency.v1",
                "vectors": [
                    {
                        "computation_name": "core.remote_compute.v1",
                        "epoch": -1,
                        "request_bytes_hex": "00",
                        "expected_key_hex": "00" * 32,
                    },
                    {
                        "computation_name": "core.remote_compute.v1",
                        "epoch": 2**64,
                        "request_bytes_hex": "00",
                        "expected_key_hex": "00" * 32,
                    },
                ],
            }
            vectors_path.write_text(json.dumps(vectors_doc), encoding="utf-8")

            original = checker.VECTORS
            try:
                checker.VECTORS = vectors_path
                checks = checker._check_vectors_document()
            finally:
                checker.VECTORS = original

        check_map = {c["check"]: c for c in checks}
        self.assertFalse(check_map["vectors_count"]["passed"])
        self.assertFalse(check_map["vectors_row_shape"]["passed"])
        self.assertEqual(check_map["vectors_row_shape"]["detail"], "invalid_rows=2")

    def test_recompute_mismatch_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vectors_path = Path(tmpdir) / "vectors.json"
            vectors_doc = {
                "schema_version": "ik-v1.1",
                "domain_prefix": "franken_node.idempotency.v1",
                "vectors": [
                    {
                        "computation_name": "core.remote_compute.v1",
                        "epoch": 1,
                        "request_bytes_hex": "00",
                        "expected_key_hex": "00" * 32,
                    }
                ],
            }
            vectors_path.write_text(json.dumps(vectors_doc), encoding="utf-8")

            original = checker.VECTORS
            try:
                checker.VECTORS = vectors_path
                checks = checker._check_vectors_document()
            finally:
                checker.VECTORS = original

        check_map = {c["check"]: c for c in checks}
        self.assertFalse(check_map["vectors_count"]["passed"])
        self.assertFalse(check_map["vectors_recompute_match"]["passed"])


class OverallTests(unittest.TestCase):
    def test_injective_canonical_framing_check_passes(self):
        checks = checker._checks()
        check_map = {c["check"]: c for c in checks}
        self.assertTrue(
            check_map["injective_canonical_framing"]["passed"],
            check_map["injective_canonical_framing"]["detail"],
        )

    def test_all_checks_pass(self):
        checks = checker._checks()
        failed = [c for c in checks if not c["passed"]]
        self.assertEqual([], failed, f"failed checks: {[c['check'] for c in failed]}")

    def test_script_verdict_is_pass(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = decode_json(result.stdout)
        self.assertEqual(payload["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
