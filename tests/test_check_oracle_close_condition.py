"""Tests for scripts/check_oracle_close_condition.py (dual-oracle gate)."""

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_oracle_close_condition.py"

spec = importlib.util.spec_from_file_location("check_oracle_close_condition", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_required_dimensions_count():
    assert len(mod.REQUIRED_DIMENSIONS) == 3


def test_dimension_ids():
    ids = {d["id"] for d in mod.REQUIRED_DIMENSIONS}
    assert ids == {"l1_product", "l2_engine_boundary", "release_policy_linkage"}


def l1_proof_evidence():
    return {
        "evidence": {
            "proof_carrying_effects": {
                "schema_version": "franken-node/l1-proof-carrying-effects/v1",
                "required_subjects": ["fs.read", "fs.write", "http.request"],
                "verified_subjects": ["fs.read", "fs.write", "http.request"],
                "effect_receipts_verified": 3,
                "invalid_receipts": 0,
                "receipt_chain_verified": True,
            }
        }
    }


def green_payload(dim_id):
    payload = {"verdict": "GREEN"}
    if dim_id == "l1_product":
        payload.update(l1_proof_evidence())
    return payload


# ---------------------------------------------------------------------------
# check_dimension
# ---------------------------------------------------------------------------

class TestCheckDimension:
    def _dim(self, dim_id="l1_product"):
        return next(d for d in mod.REQUIRED_DIMENSIONS if d["id"] == dim_id)

    def test_green_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps(green_payload(dim["id"])))
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert result["verdict"] == "GREEN"
        assert result["error"] is None

    def test_yellow_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        payload = green_payload(dim["id"])
        payload["verdict"] = "YELLOW"
        artifact.write_text(json.dumps(payload))
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert result["verdict"] == "YELLOW"
        assert result["error"] is not None
        assert "YELLOW" in result["error"]

    def test_red_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        payload = green_payload(dim["id"])
        payload["verdict"] = "RED"
        artifact.write_text(json.dumps(payload))
        result = mod.check_dimension(tmp_path, dim)
        assert result["verdict"] == "RED"
        assert "RED" in result["error"]

    def test_missing_artifact(self, tmp_path):
        dim = self._dim()
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is False
        assert result["verdict"] is None
        assert "not found" in result["error"]

    def test_malformed_json(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text("not json")
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert "Malformed" in result["error"]

    def test_invalid_verdict_value(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "BLUE"}))
        result = mod.check_dimension(tmp_path, dim)
        assert "Invalid verdict" in result["error"]

    def test_missing_verdict_key(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"status": "ok"}))
        result = mod.check_dimension(tmp_path, dim)
        assert "Invalid verdict" in result["error"]

    def test_all_dimensions_green(self, tmp_path):
        for dim in mod.REQUIRED_DIMENSIONS:
            artifact = tmp_path / dim["artifact"]
            artifact.write_text(json.dumps(green_payload(dim["id"])))
        results = [mod.check_dimension(tmp_path, d) for d in mod.REQUIRED_DIMENSIONS]
        assert all(r["verdict"] == "GREEN" for r in results)
        assert all(r["error"] is None for r in results)

    def test_result_structure(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps(green_payload(dim["id"])))
        result = mod.check_dimension(tmp_path, dim)
        expected_keys = {"dimension", "label", "owner_track", "present", "verdict"}
        missing_keys = expected_keys.difference(result)
        if missing_keys:
            raise AssertionError(f"missing result keys: {sorted(missing_keys)}")
        assert result["dimension"] == "l1_product"

    def test_l2_engine_boundary_dimension(self, tmp_path):
        dim = self._dim("l2_engine_boundary")
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps(green_payload(dim["id"])))
        result = mod.check_dimension(tmp_path, dim)
        assert result["dimension"] == "l2_engine_boundary"
        assert result["verdict"] == "GREEN"

    def test_l1_green_without_proof_carrying_effects_fails_closed(self, tmp_path):
        dim = self._dim("l1_product")
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "GREEN", "evidence": {}}))
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert result["verdict"] == "GREEN"
        assert "proof_carrying_effects evidence missing" in result["error"]

    def test_l1_incomplete_proof_carrying_effects_fails_closed(self, tmp_path):
        dim = self._dim("l1_product")
        artifact = tmp_path / dim["artifact"]
        payload = green_payload("l1_product")
        proof = payload["evidence"]["proof_carrying_effects"]
        proof["verified_subjects"] = ["fs.read", "fs.write"]
        proof["effect_receipts_verified"] = 2
        proof["receipt_chain_verified"] = False
        artifact.write_text(json.dumps(payload))
        result = mod.check_dimension(tmp_path, dim)
        assert "missing subject http.request" in result["error"]
        assert "effect_receipts_verified below required 3" in result["error"]
        assert "receipt_chain_verified is not true" in result["error"]
