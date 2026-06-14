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


def test_semantic_boundary_families_populated():
    assert len(mod.SEMANTIC_BOUNDARY_FAMILIES) > 0
    family_ids = {family["family_id"] for family in mod.SEMANTIC_BOUNDARY_FAMILIES}
    assert "cancellation-protocol" in family_ids
    assert "lane-semantics" in family_ids


def test_rule_catalog_populated():
    assert [rule["rule_id"] for rule in mod.RULE_CATALOG] == [
        "OWN-SEMB-001",
        "OWN-SEMB-002",
        "OWN-SEMB-003",
        "OWN-SEMB-004",
    ]


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
# semantic-boundary anti-drift checks
# ---------------------------------------------------------------------------

class TestSemanticBoundaryDrift:
    def test_documented_path_no_violation(self):
        filepath = ROOT / "crates" / "franken-node" / "src" / "connector" / "cancellation_protocol.rs"
        violations = mod.check_semantic_boundary_drift(filepath)
        assert violations == []

    def test_duplicate_family_path_detected(self, tmp_path):
        project_root = tmp_path
        filepath = project_root / "crates" / "franken-node" / "src" / "runtime" / "cancellation_protocol.rs"
        filepath.parent.mkdir(parents=True)
        filepath.write_text("// duplicate family path\n")

        violations = mod.check_semantic_boundary_drift(filepath, project_root=project_root)

        assert len(violations) == 1
        violation = violations[0]
        assert violation["rule_id"] == "OWN-SEMB-002"
        assert violation["reason_code"] == "UNDOCUMENTED_SEMANTIC_FAMILY"
        assert violation["family_id"] == "cancellation-protocol"
        assert "connector/cancellation_protocol.rs" in " ".join(violation["documented_paths"])

    def test_contract_alignment_accepts_current_contract(self):
        contract_text = mod.load_policy_contract_text()
        violations = mod.check_contract_alignment(contract_text)
        assert violations == []


class TestForbiddenInternalImports:
    def test_internal_import_detected(self, tmp_path):
        project_root = tmp_path
        filepath = project_root / "crates" / "franken-node" / "src" / "connector" / "internal_probe.rs"
        filepath.parent.mkdir(parents=True)
        filepath.write_text("use franken_engine::scheduler_internal::Queue;\n")

        violations = mod.check_forbidden_internal_imports(filepath, project_root=project_root)

        assert len(violations) == 1
        violation = violations[0]
        assert violation["rule_id"] == "OWN-SEMB-003"
        assert violation["reason_code"] == "FORBIDDEN_INTERNAL_BOUNDARY_CROSSING"
        assert "scheduler_internal" in violation["import_snippet"]

    def test_public_import_allowed(self, tmp_path):
        project_root = tmp_path
        filepath = project_root / "crates" / "franken-node" / "src" / "connector" / "public_probe.rs"
        filepath.parent.mkdir(parents=True)
        filepath.write_text("use franken_engine::control_plane::Cx;\n")

        violations = mod.check_forbidden_internal_imports(filepath, project_root=project_root)

        assert violations == []


class TestEngineEffectProducerBoundary:
    def test_current_contracts_align_with_engine_effect_handoff(self):
        split_contract = mod.load_engine_split_contract_text()
        ownership_contract = mod.load_policy_contract_text()

        assert (
            mod.check_engine_effect_producer_contract_alignment(
                split_contract,
                ownership_contract,
            )
            == []
        )

    def test_missing_engine_effect_contract_term_fails_closed(self):
        split_contract = mod.load_engine_split_contract_text().replace("compat:http:request", "")
        ownership_contract = mod.load_policy_contract_text()

        violations = mod.check_engine_effect_producer_contract_alignment(
            split_contract,
            ownership_contract,
        )

        assert any(v["rule_id"] == "OWN-SEMB-004" for v in violations)
        assert any(v.get("required_term") == "compat:http:request" for v in violations)

    def test_local_engine_hostcall_producer_marker_detected(self, tmp_path):
        project_root = tmp_path
        filepath = (
            project_root
            / "crates"
            / "franken-node"
            / "src"
            / "runtime"
            / "hostcall_effects_migration.rs"
        )
        filepath.parent.mkdir(parents=True)
        filepath.write_text(
            'pub struct FullCapsHandler;\nconst TAG: &str = "hostcall:fs:read";\n'
        )

        violations = mod.check_engine_effect_producer_duplicate(filepath, project_root=project_root)

        assert len(violations) == 1
        violation = violations[0]
        assert violation["rule_id"] == "OWN-SEMB-004"
        assert violation["reason_code"] == "ENGINE_EFFECT_PRODUCER_BOUNDARY_VIOLATION"
        assert "pub struct FullCapsHandler" in violation["markers"]

    def test_receipt_contract_path_allowed_to_mention_effects(self):
        filepath = ROOT / "crates" / "franken-node" / "src" / "runtime" / "effect_receipt.rs"

        violations = mod.check_engine_effect_producer_duplicate(filepath)

        assert violations == []


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
