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


# ---------------------------------------------------------------------------
# check_dimension
# ---------------------------------------------------------------------------

class TestCheckDimension:
    def _dim(self, dim_id="l1_product"):
        return next(d for d in mod.REQUIRED_DIMENSIONS if d["id"] == dim_id)

    def test_green_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "GREEN"}))
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert result["verdict"] == "GREEN"
        assert result["error"] is None

    def test_yellow_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "YELLOW"}))
        result = mod.check_dimension(tmp_path, dim)
        assert result["present"] is True
        assert result["verdict"] == "YELLOW"
        assert result["error"] is not None
        assert "YELLOW" in result["error"]

    def test_red_verdict(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "RED"}))
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
            artifact.write_text(json.dumps({"verdict": "GREEN"}))
        results = [mod.check_dimension(tmp_path, d) for d in mod.REQUIRED_DIMENSIONS]
        assert all(r["verdict"] == "GREEN" for r in results)
        assert all(r["error"] is None for r in results)

    def test_result_structure(self, tmp_path):
        dim = self._dim()
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "GREEN"}))
        result = mod.check_dimension(tmp_path, dim)
        assert "dimension" in result
        assert "label" in result
        assert "owner_track" in result
        assert "present" in result
        assert "verdict" in result
        assert result["dimension"] == "l1_product"

    def test_l2_engine_boundary_dimension(self, tmp_path):
        dim = self._dim("l2_engine_boundary")
        artifact = tmp_path / dim["artifact"]
        artifact.write_text(json.dumps({"verdict": "GREEN"}))
        result = mod.check_dimension(tmp_path, dim)
        assert result["dimension"] == "l2_engine_boundary"
        assert result["verdict"] == "GREEN"
