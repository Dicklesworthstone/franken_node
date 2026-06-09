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
    check_first_tranche_contracts,
    check_error_parity_table,
    VALID_BANDS,
    VALID_SHIM_TYPES,
    VALID_ORACLE_STATUSES,
    VALID_SIDE_EFFECT_CATEGORIES,
    VALID_POLICY_HOOKS,
    FIRST_TRANCHE_REQUIRED_IDS,
    EVIDENCE_PATHS,
    ID_PATTERN,
    SCHEMA_ID_PATTERN,
    ERROR_CODE_PATTERN,
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


def test_first_tranche_contracts():
    result = check_first_tranche_contracts()
    assert result["status"] == "PASS"
    assert set(result["details"]["present_ids"]) == FIRST_TRANCHE_REQUIRED_IDS


def test_error_parity_table():
    result = check_error_parity_table()
    assert result["status"] == "PASS"
    assert result["details"]["errors"] == []


def test_valid_bands_set():
    assert VALID_BANDS == {"core", "high-value", "edge", "unsafe"}


def test_valid_shim_types_set():
    assert VALID_SHIM_TYPES == {"native", "polyfill", "bridge", "stub"}


def test_valid_oracle_statuses_set():
    expected = {"validated", "pending", "not-applicable"}
    if VALID_ORACLE_STATUSES != expected:
        raise AssertionError(f"unexpected oracle statuses: {VALID_ORACLE_STATUSES}")


def test_valid_side_effect_categories_set():
    expected = {
        "pure",
        "filesystem_read",
        "filesystem_write",
        "network_egress",
        "network_listener",
        "environment_read",
        "module_graph_read",
    }
    assert VALID_SIDE_EFFECT_CATEGORIES == expected


def test_valid_policy_hooks_set():
    assert VALID_POLICY_HOOKS == {"capability", "ssrf", "profile"}


def test_id_pattern_valid():
    assert ID_PATTERN.match("compat:fs:readFile")
    assert ID_PATTERN.match("compat:http:createServer")
    assert not ID_PATTERN.match("invalid-id")
    assert not ID_PATTERN.match("compat:fs")


def test_schema_and_error_code_patterns_valid():
    assert SCHEMA_ID_PATTERN.match("compat-fs-read-file-args-v1")
    assert SCHEMA_ID_PATTERN.match("ccm-v1.0")
    assert not SCHEMA_ID_PATTERN.match("CompatFsReadFileArgsV1")
    assert ERROR_CODE_PATTERN.match("ERR_INVALID_ARG_TYPE")
    assert ERROR_CODE_PATTERN.match("MODULE_NOT_FOUND")
    assert ERROR_CODE_PATTERN.match("ENOENT")
    assert not ERROR_CODE_PATTERN.match("err_invalid_arg_type")


def test_registry_json_parses():
    data = json.loads((ROOT / "docs" / "COMPATIBILITY_REGISTRY.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert isinstance(data["behaviors"], list)
    assert len(data["behaviors"]) >= 5
    by_id = {entry["id"]: entry for entry in data["behaviors"]}
    assert FIRST_TRANCHE_REQUIRED_IDS.issubset(by_id)
    assert by_id["compat:http:request"]["policy_hooks"] == ["capability", "ssrf", "profile"]
    assert by_id["compat:http:request"]["side_effect_category"] == "network_egress"


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
