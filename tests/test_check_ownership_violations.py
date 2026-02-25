"""Tests for scripts/check_ownership_violations.py (duplicate-implementation CI gate)."""

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_ownership_violations.py"

spec = importlib.util.spec_from_file_location("check_ownership_violations", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_track_path_patterns_populated():
    assert len(mod.TRACK_PATH_PATTERNS) > 0
    assert "10.13" in mod.TRACK_PATH_PATTERNS
    assert "10.14" in mod.TRACK_PATH_PATTERNS


def test_implementation_indicators_populated():
    assert len(mod.IMPLEMENTATION_INDICATORS) > 0


# ---------------------------------------------------------------------------
# load_waivers
# ---------------------------------------------------------------------------

class TestLoadWaivers:
    def test_none_path(self):
        assert mod.load_waivers(None) == []

    def test_missing_file(self):
        assert mod.load_waivers("/nonexistent/waiver.json") == []

    def test_valid_waiver_file(self, tmp_path):
        waiver = {
            "waivers": [
                {"file": "crates/foo/src/bar.rs", "rule_id": "OWNERSHIP-C1"}
            ]
        }
        p = tmp_path / "waivers.json"
        p.write_text(json.dumps(waiver))
        result = mod.load_waivers(str(p))
        assert len(result) == 1
        assert result[0]["rule_id"] == "OWNERSHIP-C1"

    def test_empty_waiver_file(self, tmp_path):
        p = tmp_path / "waivers.json"
        p.write_text(json.dumps({"waivers": []}))
        result = mod.load_waivers(str(p))
        assert result == []


# ---------------------------------------------------------------------------
# check_file_ownership
# ---------------------------------------------------------------------------

class TestCheckFileOwnership:
    MOCK_REGISTRY = {
        "capabilities": [
            {
                "id": "C1",
                "domain": "revocation, fencing",
                "canonical_owner": "10.13",
                "integration_tracks": [],
            },
            {
                "id": "C2",
                "domain": "epoch, evidence",
                "canonical_owner": "10.14",
                "integration_tracks": ["10.15"],
            },
        ]
    }

    def test_file_in_canonical_track_no_violation(self, tmp_path):
        # File in 10.13 track implementing 10.13 domain -> no violation
        filepath = ROOT / "crates" / "franken-node" / "src" / "fcp_revocation.rs"
        violations = mod.check_file_ownership(filepath, self.MOCK_REGISTRY)
        # It's in the 10.13 track and implements revocation which is 10.13's domain
        # So it should NOT have a violation for C1
        c1_violations = [v for v in violations if v["capability"] == "C1"]
        assert len(c1_violations) == 0

    def test_file_not_matching_any_track_no_violation(self, tmp_path):
        # File that doesn't match any track pattern
        filepath = ROOT / "crates" / "franken-node" / "src" / "main.rs"
        violations = mod.check_file_ownership(filepath, self.MOCK_REGISTRY)
        assert len(violations) == 0

    def test_file_in_integration_track_no_violation(self):
        # File in 10.15 track (integration_track for C2) -> no violation for C2
        filepath = ROOT / "crates" / "franken-node" / "src" / "control_plane_epoch.rs"
        violations = mod.check_file_ownership(filepath, self.MOCK_REGISTRY)
        c2_violations = [v for v in violations if v["capability"] == "C2"]
        assert len(c2_violations) == 0

    def test_violation_structure(self):
        # Create a file that would trigger a violation
        filepath = ROOT / "crates" / "franken-node" / "src" / "epoch_revocation.rs"
        violations = mod.check_file_ownership(filepath, self.MOCK_REGISTRY)
        for v in violations:
            assert "rule_id" in v
            assert "file" in v
            assert "file_track" in v
            assert "capability" in v
            assert "canonical_owner" in v
            assert "severity" in v
            assert "remediation" in v

    def test_empty_registry_no_violations(self):
        filepath = ROOT / "crates" / "franken-node" / "src" / "fcp_revocation.rs"
        violations = mod.check_file_ownership(filepath, {"capabilities": []})
        assert len(violations) == 0


# ---------------------------------------------------------------------------
# TRACK_PATH_PATTERNS coverage
# ---------------------------------------------------------------------------

class TestTrackPathPatterns:
    def test_section_10_13_patterns(self):
        patterns = mod.TRACK_PATH_PATTERNS["10.13"]
        assert any("fcp" in p for p in patterns)
        assert any("revocation" in p for p in patterns)

    def test_section_10_14_patterns(self):
        patterns = mod.TRACK_PATH_PATTERNS["10.14"]
        assert any("evidence" in p for p in patterns)
        assert any("epoch" in p for p in patterns)

    def test_all_tracks_have_patterns(self):
        for track, patterns in mod.TRACK_PATH_PATTERNS.items():
            assert len(patterns) > 0, f"Track {track} has no path patterns"
