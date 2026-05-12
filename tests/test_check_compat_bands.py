"""Tests for scripts/check_compat_bands.py."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_compat_bands import (  # noqa: E402
    build_report,
    check_bands_doc_exists,
    check_all_bands_defined,
    check_band_content,
    check_modes_defined,
    check_mode_band_matrix,
    check_plan_reference,
    check_primary_implementation_cited,
    EVIDENCE_PATHS,
    PRIMARY_IMPLEMENTATION_PATHS,
    REQUIRED_BANDS,
    REQUIRED_MODES,
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def require_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON in {path}") from exc


def test_bands_doc_exists():
    result = check_bands_doc_exists()
    require_equal(result["status"], "PASS", "bands doc check status")


def test_all_four_bands_defined():
    result = check_all_bands_defined()
    require_equal(result["status"], "PASS", "band definition check status")
    for band in REQUIRED_BANDS:
        require(result["details"]["bands"][band], f"Band '{band}' not found")


def test_primary_implementation_cited():
    result = check_primary_implementation_cited()
    require_equal(result["status"], "PASS", "primary implementation check status")
    require_equal(result["details"]["paths"], PRIMARY_IMPLEMENTATION_PATHS, "implementation paths")
    for path_exists in result["details"]["existing_paths"].values():
        require(path_exists, "implementation path must exist")
    for band_doc_cited in result["details"]["band_doc_citations"].values():
        require(band_doc_cited, "band doc must cite implementation path")
    for contract_cited in result["details"]["contract_citations"].values():
        require(contract_cited, "contract must cite implementation path")


def test_required_bands_count():
    require_equal(len(REQUIRED_BANDS), 4, "required band count")
    require("core" in REQUIRED_BANDS, "core band missing")
    require("unsafe" in REQUIRED_BANDS, "unsafe band missing")


def test_band_content_complete():
    result = check_band_content()
    require_equal(result["status"], "PASS", "band content check status")
    for band in REQUIRED_BANDS:
        entry = result["details"]["bands"][band]
        require(entry["has_priority"], f"Band '{band}' missing priority")
        require(entry["has_examples"], f"Band '{band}' missing examples")
        require(entry["has_divergence"], f"Band '{band}' missing divergence handling")


def test_all_three_modes_defined():
    result = check_modes_defined()
    require_equal(result["status"], "PASS", "mode definition check status")
    for mode in REQUIRED_MODES:
        require(result["details"]["modes"][mode], f"Mode '{mode}' not found")


def test_required_modes_count():
    require_equal(len(REQUIRED_MODES), 3, "required mode count")
    require("strict" in REQUIRED_MODES, "strict mode missing")
    require("balanced" in REQUIRED_MODES, "balanced mode missing")
    require("legacy-risky" in REQUIRED_MODES, "legacy-risky mode missing")


def test_mode_band_matrix_complete():
    result = check_mode_band_matrix()
    require_equal(result["status"], "PASS", "mode-band matrix check status")
    require(result["details"]["matrix_cells"] >= 12, "mode-band matrix must have at least 12 cells")


def test_plan_reference():
    result = check_plan_reference()
    require_equal(result["status"], "PASS", "plan reference check status")
    require(result["details"]["plan_referenced"], "plan reference missing")


def test_bands_doc_has_oracle_section():
    text = (ROOT / "docs" / "COMPATIBILITY_BANDS.md").read_text(encoding="utf-8")
    require(
        "Oracle Integration" in text or "oracle" in text.lower(),
        "oracle integration section missing",
    )


def test_bands_doc_has_configuration():
    text = (ROOT / "docs" / "COMPATIBILITY_BANDS.md").read_text(encoding="utf-8")
    require("[compatibility]" in text, "compatibility config example missing")
    require('mode = "balanced"' in text, "balanced mode config example missing")


def test_report_cites_primary_band_implementation():
    report = build_report("2026-05-12T00:00:00+00:00")
    require_equal(report["evidence_paths"], EVIDENCE_PATHS, "report evidence paths")
    require_equal(
        report["evidence_paths"]["primary_policy_gate"],
        "crates/franken-node/src/policy/compat_gates.rs",
        "primary policy gate path",
    )
    require_equal(
        report["evidence_paths"]["compatibility_mode_config"],
        "crates/franken-node/src/config.rs",
        "compatibility mode config path",
    )
    commands = {entry["command"] for entry in report["verification_commands"]}
    require("python3 scripts/check_compat_bands.py --json" in commands, "checker command missing")
    require("python3 -m pytest tests/test_check_compat_bands.py" in commands, "pytest command missing")


def test_checked_in_evidence_cites_primary_band_implementation():
    evidence_path = ROOT / "artifacts" / "section_10_2" / "bd-2wz" / "verification_evidence.json"
    evidence = read_json(evidence_path)
    require_equal(
        evidence["evidence_paths"]["primary_policy_gate"],
        "crates/franken-node/src/policy/compat_gates.rs",
        "checked-in primary policy gate path",
    )
    require_equal(
        evidence["evidence_paths"]["compatibility_mode_config"],
        "crates/franken-node/src/config.rs",
        "checked-in compatibility mode config path",
    )
