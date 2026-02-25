"""Tests for scripts/check_idempotency_key_derivation.py (bd-12n3)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_idempotency_key_derivation.py"

spec = importlib.util.spec_from_file_location("check_idempotency_key_derivation", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec is not None
assert spec.loader is not None
spec.loader.exec_module(module)


class TestSelfTest:
    def test_self_test_passes(self):
        assert module.self_test() is True


class TestJsonOutput:
    def test_json_output_shape(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        payload = json.loads(result.stdout)
        assert payload["bead_id"] == "bd-12n3"
        assert payload["section"] == "10.14"
        assert payload["verdict"] in {"PASS", "FAIL"}
        assert isinstance(payload["checks"], list)


class TestVectorValidation:
    def test_missing_vectors_file_fails(self):
        original = module.VECTORS
        try:
            module.VECTORS = str(ROOT / "artifacts" / "10.14" / "_missing_vectors_.json")
            checks = module._check_vectors_document()
        finally:
            module.VECTORS = original
        check_map = {c["check"]: c for c in checks}
        assert not check_map["vectors_exists"]["passed"]

    def test_recompute_mismatch_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vectors_path = Path(tmpdir) / "vectors.json"
            vectors_doc = {
                "schema_version": "ik-v1.0",
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

            original = module.VECTORS
            try:
                module.VECTORS = str(vectors_path)
                checks = module._check_vectors_document()
            finally:
                module.VECTORS = original

        check_map = {c["check"]: c for c in checks}
        assert not check_map["vectors_count"]["passed"]
        assert not check_map["vectors_recompute_match"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        checks = module._checks()
        failed = [c for c in checks if not c["passed"]]
        assert failed == [], f"failed checks: {[c['check'] for c in failed]}"

    def test_script_verdict_is_pass(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        payload = json.loads(result.stdout)
        assert payload["verdict"] == "PASS"
