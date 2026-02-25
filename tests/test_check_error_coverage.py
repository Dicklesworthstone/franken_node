"""Tests for scripts/check_error_coverage.py (bd-13q error coverage audit)."""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_error_coverage.py"

spec = importlib.util.spec_from_file_location("check_error_coverage", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MOCK_REGISTRY = {
    "error_codes": [
        {"code": "FRANKEN_PROTOCOL_AUTH_FAILED"},
        {"code": "FRANKEN_CONNECTOR_LEASE_EXPIRED"},
    ]
}

MOCK_AUDIT_PASS = {
    "surfaces": [
        {
            "surface": "cli",
            "mapped_errors": [
                {
                    "canonical_code": "FRANKEN_PROTOCOL_AUTH_FAILED",
                    "surface_code": "FN-CTRL-FRANKEN_PROTOCOL_AUTH_FAILED",
                }
            ],
            "unmapped_errors": [],
        },
        {
            "surface": "json_api",
            "mapped_errors": [
                {
                    "canonical_code": "FRANKEN_CONNECTOR_LEASE_EXPIRED",
                    "surface_code": "FN-AUTH-FRANKEN_CONNECTOR_LEASE_EXPIRED",
                }
            ],
            "unmapped_errors": [],
        },
        {"surface": "protocol", "mapped_errors": [], "unmapped_errors": []},
        {"surface": "log", "mapped_errors": [], "unmapped_errors": []},
        {"surface": "sdk", "mapped_errors": [], "unmapped_errors": []},
    ]
}


# ---------------------------------------------------------------------------
# self_test
# ---------------------------------------------------------------------------

def test_self_test_passes():
    assert mod.self_test() is True


# ---------------------------------------------------------------------------
# coverage_report
# ---------------------------------------------------------------------------

class TestCoverageReport:
    def test_valid_audit_passes(self):
        report = mod.coverage_report(MOCK_AUDIT_PASS, MOCK_REGISTRY)
        assert report["verdict"] == "PASS"
        assert report["summary"]["passed"] == report["summary"]["total_checks"]

    def test_missing_surface_fails(self):
        audit = {
            "surfaces": [
                {"surface": "cli", "mapped_errors": [], "unmapped_errors": []},
                # missing json_api, protocol, log, sdk
            ]
        }
        report = mod.coverage_report(audit, MOCK_REGISTRY)
        surface_check = next(c for c in report["checks"] if c["check"] == "required_surfaces_present")
        assert not surface_check["pass"]
        assert "missing surfaces" in surface_check["detail"]

    def test_all_surfaces_present_passes(self):
        report = mod.coverage_report(MOCK_AUDIT_PASS, MOCK_REGISTRY)
        surface_check = next(c for c in report["checks"] if c["check"] == "required_surfaces_present")
        assert surface_check["pass"]

    def test_unmapped_errors_fail(self):
        audit = {
            "surfaces": [
                {"surface": "cli", "mapped_errors": [], "unmapped_errors": ["oops"]},
                {"surface": "json_api", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "protocol", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "log", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "sdk", "mapped_errors": [], "unmapped_errors": []},
            ]
        }
        report = mod.coverage_report(audit, MOCK_REGISTRY)
        unmap_check = next(c for c in report["checks"] if c["check"] == "zero_unmapped_errors")
        assert not unmap_check["pass"]

    def test_invalid_canonical_code_fails(self):
        audit = {
            "surfaces": [
                {
                    "surface": "cli",
                    "mapped_errors": [
                        {"canonical_code": "UNKNOWN_CODE", "surface_code": "FN-CTRL-UNKNOWN"}
                    ],
                    "unmapped_errors": [],
                },
                {"surface": "json_api", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "protocol", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "log", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "sdk", "mapped_errors": [], "unmapped_errors": []},
            ]
        }
        report = mod.coverage_report(audit, MOCK_REGISTRY)
        code_check = next(c for c in report["checks"] if c["check"] == "canonical_code_registry_coverage")
        assert not code_check["pass"]

    def test_invalid_surface_code_prefix_fails(self):
        audit = {
            "surfaces": [
                {
                    "surface": "cli",
                    "mapped_errors": [
                        {
                            "canonical_code": "FRANKEN_PROTOCOL_AUTH_FAILED",
                            "surface_code": "BAD-PREFIX-CODE",
                        }
                    ],
                    "unmapped_errors": [],
                },
                {"surface": "json_api", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "protocol", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "log", "mapped_errors": [], "unmapped_errors": []},
                {"surface": "sdk", "mapped_errors": [], "unmapped_errors": []},
            ]
        }
        report = mod.coverage_report(audit, MOCK_REGISTRY)
        prefix_check = next(c for c in report["checks"] if c["check"] == "surface_code_prefix_coverage")
        assert not prefix_check["pass"]

    def test_report_structure(self):
        report = mod.coverage_report(MOCK_AUDIT_PASS, MOCK_REGISTRY)
        assert report["bead_id"] == "bd-13q"
        assert report["check"] == "error_coverage_audit"
        assert "verdict" in report
        assert "summary" in report
        assert "checks" in report
        assert isinstance(report["checks"], list)

    def test_empty_audit_fails_surfaces(self):
        report = mod.coverage_report({"surfaces": []}, MOCK_REGISTRY)
        surface_check = next(c for c in report["checks"] if c["check"] == "required_surfaces_present")
        assert not surface_check["pass"]

    def test_mapped_error_count_in_summary(self):
        report = mod.coverage_report(MOCK_AUDIT_PASS, MOCK_REGISTRY)
        assert report["summary"]["mapped_error_count"] == 2
        assert report["summary"]["unmapped_error_count"] == 0


# ---------------------------------------------------------------------------
# _check_impl_prefix_registry (depends on filesystem)
# ---------------------------------------------------------------------------

def test_impl_prefix_check_missing_file(monkeypatch, tmp_path):
    fake_path = tmp_path / "error_surface.rs"
    monkeypatch.setattr(mod, "IMPL_PATH", fake_path)
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    ok, detail = mod._check_impl_prefix_registry()
    assert not ok
    assert "missing implementation file" in detail
