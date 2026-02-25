"""Tests for scripts/check_error_compat.py (bd-13q error compatibility policy)."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_error_compat.py"

spec = importlib.util.spec_from_file_location("check_error_compat", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(code, severity="transient", retryable=True,
           description="test desc", recovery_hint="Retry the operation with backoff and jitter settings"):
    return {
        "code": code,
        "severity": severity,
        "retryable": retryable,
        "description": description,
        "recovery_hint": recovery_hint,
    }


OLD_ENTRIES = [
    _entry("FRANKEN_PROTOCOL_AUTH_FAILED"),
    _entry("FRANKEN_CONNECTOR_LEASE_EXPIRED"),
]


# ---------------------------------------------------------------------------
# self_test
# ---------------------------------------------------------------------------

def test_self_test_passes():
    assert mod.self_test() is True


# ---------------------------------------------------------------------------
# _category
# ---------------------------------------------------------------------------

class TestCategory:
    def test_transient(self):
        assert mod._category({"severity": "transient"}) == "TRANSIENT"

    def test_fatal(self):
        assert mod._category({"severity": "fatal"}) == "PERMANENT"

    def test_degraded(self):
        assert mod._category({"severity": "degraded"}) == "CONFIGURATION"

    def test_unknown_severity(self):
        assert mod._category({"severity": "other"}) == "UNKNOWN"

    def test_missing_severity(self):
        assert mod._category({}) == "UNKNOWN"


# ---------------------------------------------------------------------------
# _code_map
# ---------------------------------------------------------------------------

class TestCodeMap:
    def test_normal(self):
        entries = [_entry("CODE_A"), _entry("CODE_B")]
        m = mod._code_map(entries)
        assert set(m.keys()) == {"CODE_A", "CODE_B"}

    def test_skips_empty_code(self):
        entries = [_entry("CODE_A"), {"severity": "transient"}]
        m = mod._code_map(entries)
        assert set(m.keys()) == {"CODE_A"}


# ---------------------------------------------------------------------------
# compatibility_report
# ---------------------------------------------------------------------------

class TestCompatibilityReport:
    def test_identical_registries_pass(self):
        report = mod.compatibility_report(OLD_ENTRIES, OLD_ENTRIES)
        assert report["verdict"] == "PASS"
        assert report["summary"]["added"] == 0
        assert report["summary"]["removed"] == 0

    def test_added_code_with_metadata_passes(self):
        new = OLD_ENTRIES + [
            _entry("FRANKEN_NEW_CODE", description="new code", recovery_hint="Retry with proper configuration settings")
        ]
        report = mod.compatibility_report(OLD_ENTRIES, new)
        assert report["verdict"] == "PASS"
        assert "FRANKEN_NEW_CODE" in report["added"]

    def test_removed_code_fails(self):
        new = [OLD_ENTRIES[0]]  # drop second entry
        report = mod.compatibility_report(OLD_ENTRIES, new)
        assert report["verdict"] == "FAIL"
        assert report["summary"]["removed"] == 1
        assert "FRANKEN_CONNECTOR_LEASE_EXPIRED" in report["violations"]["removed"]

    def test_category_change_fails(self):
        new = [
            _entry("FRANKEN_PROTOCOL_AUTH_FAILED", severity="fatal"),
            _entry("FRANKEN_CONNECTOR_LEASE_EXPIRED"),
        ]
        report = mod.compatibility_report(OLD_ENTRIES, new)
        assert report["verdict"] == "FAIL"
        assert report["summary"]["category_changes"] == 1

    def test_retryable_change_fails(self):
        new = [
            _entry("FRANKEN_PROTOCOL_AUTH_FAILED", retryable=False),
            _entry("FRANKEN_CONNECTOR_LEASE_EXPIRED"),
        ]
        report = mod.compatibility_report(OLD_ENTRIES, new)
        assert report["verdict"] == "FAIL"
        assert report["summary"]["retryable_changes"] == 1

    def test_new_code_missing_description_fails(self):
        new = OLD_ENTRIES + [
            _entry("FRANKEN_BAD", description="")
        ]
        report = mod.compatibility_report(OLD_ENTRIES, new)
        assert report["verdict"] == "FAIL"
        assert any(
            v["code"] == "FRANKEN_BAD" and "description" in v["reason"]
            for v in report["violations"]["metadata_violations"]
        )

    def test_new_code_missing_severity_fails(self):
        new = OLD_ENTRIES + [
            {"code": "FRANKEN_NO_SEV", "retryable": True, "description": "x", "recovery_hint": "Retry the operation with backoff settings"}
        ]
        report = mod.compatibility_report(OLD_ENTRIES, new)
        assert report["verdict"] == "FAIL"
        assert any(
            v["code"] == "FRANKEN_NO_SEV" and "severity" in v["reason"]
            for v in report["violations"]["metadata_violations"]
        )

    def test_new_non_fatal_short_hint_fails(self):
        new = OLD_ENTRIES + [
            _entry("FRANKEN_SHORT", recovery_hint="short")
        ]
        report = mod.compatibility_report(OLD_ENTRIES, new)
        assert report["verdict"] == "FAIL"
        assert any(
            v["code"] == "FRANKEN_SHORT" and "recovery_hint" in v["reason"]
            for v in report["violations"]["metadata_violations"]
        )

    def test_new_fatal_code_skips_hint_check(self):
        new = OLD_ENTRIES + [
            _entry("FRANKEN_FATAL", severity="fatal", recovery_hint="")
        ]
        report = mod.compatibility_report(OLD_ENTRIES, new)
        # Fatal codes don't need recovery hints
        hint_violations = [
            v for v in report["violations"]["metadata_violations"]
            if v["code"] == "FRANKEN_FATAL" and "recovery_hint" in v["reason"]
        ]
        assert len(hint_violations) == 0

    def test_report_structure(self):
        report = mod.compatibility_report(OLD_ENTRIES, OLD_ENTRIES)
        assert report["bead_id"] == "bd-13q"
        assert report["check"] == "error_compatibility_policy"
        assert "added" in report
        assert "unchanged" in report
        assert "violations" in report
        assert "summary" in report

    def test_empty_registries_pass(self):
        report = mod.compatibility_report([], [])
        assert report["verdict"] == "PASS"

    def test_custom_min_hint_len(self):
        new = OLD_ENTRIES + [
            _entry("FRANKEN_HINT", recovery_hint="short hint here")
        ]
        # Default min_hint_len is 20, "short hint here" is 15 chars
        report = mod.compatibility_report(OLD_ENTRIES, new, min_hint_len=10)
        hint_violations = [
            v for v in report["violations"]["metadata_violations"]
            if v["code"] == "FRANKEN_HINT" and "recovery_hint" in v["reason"]
        ]
        assert len(hint_violations) == 0


# ---------------------------------------------------------------------------
# _load_registry
# ---------------------------------------------------------------------------

def test_load_registry_valid(tmp_path):
    reg = {"error_codes": [_entry("CODE_A")]}
    p = tmp_path / "reg.json"
    p.write_text(json.dumps(reg))
    entries = mod._load_registry(p)
    assert len(entries) == 1
    assert entries[0]["code"] == "CODE_A"


def test_load_registry_invalid_type(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"error_codes": "not-a-list"}))
    with pytest.raises(ValueError, match="error_codes must be a list"):
        mod._load_registry(p)
