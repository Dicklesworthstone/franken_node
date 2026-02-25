"""Tests for scripts/check_migration_cohort_validation.py (bd-sxt5)."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_migration_cohort_validation.py"

# Import the check module dynamically (filename has hyphens-incompatible name)
spec = importlib.util.spec_from_file_location("check_mcv", str(SCRIPT))
mcv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcv)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REQUIRED_ARCHETYPES = mcv.REQUIRED_ARCHETYPES


def _make_project(archetype="web-server-express", pass_rate=100.0, flaky=0.0,
                  runs=5, known_incompat=None):
    return {
        "archetype": archetype,
        "pinned_ref": {"repo": "https://example.com/repo", "commit": "abc123def456"},
        "baseline": {"total_tests": 100, "passed": 100, "failed": 0, "status": "pass"},
        "migration": {
            "audit_report": "a.json",
            "rewrite_report": "r.json",
            "lockstep_report": "l.json",
            "rollback_artifact": "rb.json",
        },
        "post_migration": {
            "pass_rate_pct": pass_rate,
            "known_incompatibilities": known_incompat or [],
        },
        "repeated_runs": {
            "runs": runs,
            "identical_outcomes_runs": runs,
            "flaky_rate_pct": flaky,
        },
    }


def _make_valid_data():
    return {
        "projects": [_make_project(archetype=a) for a in REQUIRED_ARCHETYPES],
        "aggregate": {
            "cohort_size": 10,
            "cohort_success_rate_pct": 100.0,
            "determinism_verified": True,
            "ci_reproducible": True,
        },
    }


# ---------------------------------------------------------------------------
# self_test
# ---------------------------------------------------------------------------

def test_self_test_passes():
    assert mcv.self_test() is True


# ---------------------------------------------------------------------------
# _canonical_json determinism
# ---------------------------------------------------------------------------

def test_canonical_json_key_order():
    h1 = mcv._canonical_json({"z": 1, "a": 2})
    h2 = mcv._canonical_json({"a": 2, "z": 1})
    assert h1 == h2


# ---------------------------------------------------------------------------
# _check_results_structure
# ---------------------------------------------------------------------------

class TestCheckResultsStructure:
    def test_valid_data_all_pass(self):
        checks = mcv._check_results_structure(_make_valid_data())
        assert all(c["pass"] for c in checks), [c for c in checks if not c["pass"]]

    def test_too_few_projects(self):
        data = _make_valid_data()
        data["projects"] = data["projects"][:5]
        checks = mcv._check_results_structure(data)
        cohort_check = next(c for c in checks if c["id"] == "cohort_size")
        assert not cohort_check["pass"]

    def test_missing_archetype(self):
        data = _make_valid_data()
        # Replace one archetype with a duplicate
        data["projects"][0]["archetype"] = data["projects"][1]["archetype"]
        checks = mcv._check_results_structure(data)
        arch_check = next(c for c in checks if c["id"] == "archetype_coverage")
        assert not arch_check["pass"]

    def test_missing_pinned_ref(self):
        data = _make_valid_data()
        data["projects"][0]["pinned_ref"] = {"repo": "", "commit": ""}
        checks = mcv._check_results_structure(data)
        pin_check = next(c for c in checks if c["id"] == "version_pinning")
        assert not pin_check["pass"]

    def test_missing_baseline(self):
        data = _make_valid_data()
        data["projects"][0]["baseline"]["total_tests"] = 0
        checks = mcv._check_results_structure(data)
        bl_check = next(c for c in checks if c["id"] == "baseline_complete")
        assert not bl_check["pass"]

    def test_baseline_fail_status(self):
        data = _make_valid_data()
        data["projects"][0]["baseline"]["status"] = "fail"
        checks = mcv._check_results_structure(data)
        bl_check = next(c for c in checks if c["id"] == "baseline_complete")
        assert not bl_check["pass"]

    def test_missing_migration_artifact(self):
        data = _make_valid_data()
        data["projects"][0]["migration"]["audit_report"] = ""
        checks = mcv._check_results_structure(data)
        mig_check = next(c for c in checks if c["id"] == "migration_artifacts")
        assert not mig_check["pass"]

    def test_non_deterministic_runs(self):
        data = _make_valid_data()
        data["projects"][0]["repeated_runs"]["flaky_rate_pct"] = 5.0
        checks = mcv._check_results_structure(data)
        det_check = next(c for c in checks if c["id"] == "deterministic_runs")
        assert not det_check["pass"]

    def test_too_few_runs(self):
        data = _make_valid_data()
        data["projects"][0]["repeated_runs"]["runs"] = 1
        checks = mcv._check_results_structure(data)
        det_check = next(c for c in checks if c["id"] == "deterministic_runs")
        assert not det_check["pass"]

    def test_low_pass_rate_with_incompatibilities_passes(self):
        data = _make_valid_data()
        data["projects"][0]["post_migration"]["pass_rate_pct"] = 90.0
        data["projects"][0]["post_migration"]["known_incompatibilities"] = [
            {"test": "test_x", "reason": "known issue"}
        ]
        checks = mcv._check_results_structure(data)
        pps_check = next(c for c in checks if c["id"] == "per_project_success")
        assert pps_check["pass"]

    def test_low_pass_rate_without_incompatibilities_fails(self):
        data = _make_valid_data()
        data["projects"][0]["post_migration"]["pass_rate_pct"] = 90.0
        data["projects"][0]["post_migration"]["known_incompatibilities"] = []
        checks = mcv._check_results_structure(data)
        pps_check = next(c for c in checks if c["id"] == "per_project_success")
        assert not pps_check["pass"]

    def test_low_cohort_success_rate(self):
        data = _make_valid_data()
        data["aggregate"]["cohort_success_rate_pct"] = 50.0
        checks = mcv._check_results_structure(data)
        csr_check = next(c for c in checks if c["id"] == "cohort_success_rate")
        assert not csr_check["pass"]

    def test_ci_flags_missing(self):
        data = _make_valid_data()
        data["aggregate"]["determinism_verified"] = False
        checks = mcv._check_results_structure(data)
        ci_check = next(c for c in checks if c["id"] == "ci_reproducibility")
        assert not ci_check["pass"]


# ---------------------------------------------------------------------------
# build_report (no execution)
# ---------------------------------------------------------------------------

def test_build_report_no_execution_structure():
    report = mcv.build_report(execute=False)
    assert "bead_id" in report
    assert report["bead_id"] == "bd-sxt5"
    assert "verdict" in report
    assert "checks" in report
    assert "content_hash" in report
    assert isinstance(report["checks_passed"], int)
    assert isinstance(report["checks_total"], int)


def test_build_report_no_execution_passes():
    """If all artifacts exist, no-exec report should pass."""
    report = mcv.build_report(execute=False)
    # This depends on whether artifacts exist on disk; skip if missing
    if not mcv.RESULTS_FILE.exists():
        pytest.skip("artifacts not present")
    assert report["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# Integration: E2E execution
# ---------------------------------------------------------------------------

def test_build_report_with_execution():
    """Full report with E2E execution."""
    if not mcv.E2E_SCRIPT.exists() or not mcv.RESULTS_FILE.exists():
        pytest.skip("artifacts or E2E script not present")
    report = mcv.build_report(execute=True)
    assert report["verdict"] == "PASS"
    e2e_check = next((c for c in report["checks"] if c["id"] == "e2e_execution"), None)
    assert e2e_check is not None
    assert e2e_check["pass"]
