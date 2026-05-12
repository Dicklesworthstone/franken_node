"""Tests for scripts/check_compat_registry.py."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_compat_registry import (
    build_report,
    check_registry_exists,
    check_schema_exists,
    check_registry_structure,
    check_entry_fields,
    check_unique_ids,
    check_band_coverage,
    VALID_BANDS,
    VALID_SHIM_TYPES,
    VALID_ORACLE_STATUSES,
    EVIDENCE_PATHS,
    ID_PATTERN,
)


def test_registry_exists():
    result = check_registry_exists()
    assert result["status"] == "PASS"


def test_schema_exists():
    result = check_schema_exists()
    assert result["status"] == "PASS"


def test_registry_structure():
    result = check_registry_structure()
    assert result["status"] == "PASS"
    assert result["details"]["behavior_count"] >= 1


def test_entry_fields_valid():
    result = check_entry_fields()
    assert result["status"] == "PASS"
    assert len(result["details"]["errors"]) == 0
    for entry in result["details"]["entries"]:
        assert entry["valid"]


def test_unique_ids():
    result = check_unique_ids()
    assert result["status"] == "PASS"
    assert result["details"]["total_ids"] == result["details"]["unique_ids"]


def test_band_coverage():
    result = check_band_coverage()
    assert result["status"] == "PASS"
    assert result["details"]["bands_represented"]["core"]


def test_valid_bands_set():
    assert VALID_BANDS == {"core", "high-value", "edge", "unsafe"}


def test_valid_shim_types_set():
    assert VALID_SHIM_TYPES == {"native", "polyfill", "bridge", "stub"}


def test_valid_oracle_statuses_set():
    expected = {"validated", "pending", "not-applicable"}
    if VALID_ORACLE_STATUSES != expected:
        raise AssertionError(f"unexpected oracle statuses: {VALID_ORACLE_STATUSES}")


def test_id_pattern_valid():
    assert ID_PATTERN.match("compat:fs:readFile")
    assert ID_PATTERN.match("compat:http:createServer")
    assert not ID_PATTERN.match("invalid-id")
    assert not ID_PATTERN.match("compat:fs")


def test_registry_json_parses():
    data = json.loads((ROOT / "docs" / "COMPATIBILITY_REGISTRY.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert isinstance(data["behaviors"], list)
    assert len(data["behaviors"]) >= 5


def test_report_cites_primary_registry_implementation():
    report = build_report("2026-05-12T00:00:00+00:00")
    assert report["evidence_paths"] == EVIDENCE_PATHS
    assert report["evidence_paths"]["primary_registry"] == "docs/COMPATIBILITY_REGISTRY.json"
    assert report["evidence_paths"]["verifier"] == "scripts/check_compat_registry.py"
    assert report["evidence_paths"]["regression_tests"] == "tests/test_check_compat_registry.py"
    commands = {entry["command"] for entry in report["verification_commands"]}
    assert "python3 scripts/check_compat_registry.py --json" in commands
    assert "python3 -m pytest tests/test_check_compat_registry.py" in commands


def test_checked_in_evidence_cites_primary_registry_implementation():
    evidence_path = ROOT / "artifacts" / "section_10_2" / "bd-2qf" / "verification_evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert evidence["evidence_paths"]["primary_registry"] == "docs/COMPATIBILITY_REGISTRY.json"
    assert evidence["evidence_paths"]["verifier"] == "scripts/check_compat_registry.py"
    assert evidence["evidence_paths"]["regression_tests"] == "tests/test_check_compat_registry.py"
