"""Tests for scripts/check_divergence_ledger.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_divergence_ledger import (  # noqa: E402
    check_ledger_exists,
    check_schema_exists,
    check_traceability,
    check_ledger_structure,
    check_entry_count_floor,
    check_entry_fields,
    check_rationale_present,
    check_unique_ids,
    implementation_artifacts,
    MIN_DIVERGENCE_ENTRIES,
    VALID_BANDS,
    VALID_RISK_TIERS,
    VALID_STATUSES,
    ID_PATTERN,
    load_ledger,
)


def test_ledger_exists():
    result = check_ledger_exists()
    assert result["status"] == "PASS"


def test_schema_exists():
    result = check_schema_exists()
    assert result["status"] == "PASS"


def test_traceability_exposes_source_module_and_git_xref():
    result = check_traceability()
    assert result["status"] == "PASS"
    assert result["details"]["source_module"] == "scripts/check_divergence_ledger.py"
    assert result["details"]["git_xref"]


def test_implementation_artifacts_name_canonical_paths():
    artifacts = implementation_artifacts()
    assert artifacts["ledger_path"] == "docs/DIVERGENCE_LEDGER.json"
    assert artifacts["schema_path"] == "schemas/divergence_ledger.schema.json"
    assert artifacts["test_path"] == "tests/test_check_divergence_ledger.py"
    assert artifacts["evidence_path"] == "artifacts/section_10_2/bd-38l/verification_evidence.json"
    assert artifacts["min_entry_count"] == MIN_DIVERGENCE_ENTRIES


def test_ledger_structure():
    result = check_ledger_structure()
    assert result["status"] == "PASS"
    assert result["details"]["entry_count"] >= MIN_DIVERGENCE_ENTRIES


def test_entry_count_floor_rejects_thin_ledger():
    result = check_entry_count_floor()
    assert result["status"] == "PASS"
    assert result["details"]["entry_count"] >= result["details"]["minimum"]


def test_entry_fields_valid():
    result = check_entry_fields()
    assert result["status"] == "PASS"
    assert len(result["details"]["errors"]) == 0


def test_rationale_present():
    result = check_rationale_present()
    assert result["status"] == "PASS"
    assert result["details"]["entries_with_rationale"] == result["details"]["total_entries"]


def test_unique_ids():
    result = check_unique_ids()
    assert result["status"] == "PASS"
    assert result["details"]["total"] == result["details"]["unique"]


def test_id_pattern():
    assert ID_PATTERN.match("DIV-001")
    assert ID_PATTERN.match("DIV-999")
    assert not ID_PATTERN.match("DIV-01")
    assert not ID_PATTERN.match("div-001")


def test_valid_enums():
    assert VALID_BANDS == {"core", "high-value", "edge", "unsafe"}
    assert VALID_RISK_TIERS == {"critical", "high", "medium", "low"}
    assert VALID_STATUSES == {"accepted", "under-review", "deprecated"}


def test_ledger_json_content():
    data, err = load_ledger()
    assert err is None
    assert data is not None
    assert data["schema_version"] == "1.0"
    assert len(data["entries"]) >= MIN_DIVERGENCE_ENTRIES
    # Verify first entry has rationale
    assert len(data["entries"][0]["rationale"]) > 10
