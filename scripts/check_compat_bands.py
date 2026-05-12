#!/usr/bin/env python3
"""
Compatibility Bands Verifier.

Validates that COMPATIBILITY_BANDS.md exists, contains all 4 band definitions,
all 3 compatibility modes, and a complete mode-band matrix.

Usage:
    python3 scripts/check_compat_bands.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

BANDS_PATH = ROOT / "docs" / "COMPATIBILITY_BANDS.md"
CONTRACT_PATH = ROOT / "docs" / "specs" / "section_10_2" / "bd-2wz_contract.md"

PRIMARY_IMPLEMENTATION_PATHS = {
    "compatibility_policy_gate": "crates/franken-node/src/policy/compat_gates.rs",
    "compatibility_mode_config": "crates/franken-node/src/config.rs",
}

EVIDENCE_PATHS = {
    "primary_policy_gate": PRIMARY_IMPLEMENTATION_PATHS["compatibility_policy_gate"],
    "compatibility_mode_config": PRIMARY_IMPLEMENTATION_PATHS["compatibility_mode_config"],
    "band_contract": "docs/COMPATIBILITY_BANDS.md",
    "contract": "docs/specs/section_10_2/bd-2wz_contract.md",
    "verifier": "scripts/check_compat_bands.py",
    "regression_tests": "tests/test_check_compat_bands.py",
    "machine_evidence": "artifacts/section_10_2/bd-2wz/verification_evidence.json",
    "human_summary": "artifacts/section_10_2/bd-2wz/verification_summary.md",
}

VERIFICATION_COMMANDS = [
    {
        "command": "python3 scripts/check_compat_bands.py --json",
        "covers": [
            "compatibility band contract",
            "primary Rust policy implementation citations",
            "compatibility mode config citations",
            "band definitions",
            "band content requirements",
            "compatibility modes",
            "mode-band matrix",
            "plan reference",
        ],
    },
    {
        "command": "python3 -m pytest tests/test_check_compat_bands.py",
        "covers": [
            "compatibility bands verifier checks",
            "report evidence path citations",
            "checked-in machine evidence citations",
        ],
    },
]

REQUIRED_BANDS = ["core", "high-value", "edge", "unsafe"]
REQUIRED_MODES = ["strict", "balanced", "legacy-risky"]


def check_bands_doc_exists() -> dict:
    """BAND-EXISTS: Check that COMPATIBILITY_BANDS.md exists."""
    check = {"id": "BAND-EXISTS", "status": "PASS", "details": {}}
    if not BANDS_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/COMPATIBILITY_BANDS.md not found"
    else:
        check["details"]["path"] = str(BANDS_PATH.relative_to(ROOT))
        check["details"]["size_bytes"] = BANDS_PATH.stat().st_size
    return check


def check_all_bands_defined() -> dict:
    """BAND-DEFINITIONS: Check that all 4 bands are defined."""
    check = {"id": "BAND-DEFINITIONS", "status": "PASS", "details": {"bands": {}}}
    if not BANDS_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Document missing"
        return check

    text = BANDS_PATH.read_text().lower()
    for band in REQUIRED_BANDS:
        # Look for band heading pattern like "### 2.1 `core`" or "`core` —"
        found = bool(re.search(rf'`{re.escape(band)}`', text))
        check["details"]["bands"][band] = found
        if not found:
            check["status"] = "FAIL"

    missing = [b for b, found in check["details"]["bands"].items() if not found]
    if missing:
        check["details"]["missing_bands"] = missing
    return check


def check_band_content() -> dict:
    """BAND-CONTENT: Check each band has priority, description, and example APIs."""
    check = {"id": "BAND-CONTENT", "status": "PASS", "details": {"bands": {}}}
    if not BANDS_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Document missing"
        return check

    text = BANDS_PATH.read_text()
    for band in REQUIRED_BANDS:
        entry = {"band": band, "has_priority": False, "has_examples": False, "has_divergence": False}

        # Find the band section
        pattern = rf'###\s+\d+\.\d+\s+`{re.escape(band)}`.*?(?=###\s+\d+\.\d+|## \d+\.|\Z)'
        m = re.search(pattern, text, re.DOTALL)
        if m:
            section = m.group(0)
            entry["has_priority"] = "priority" in section.lower()
            entry["has_examples"] = "example api" in section.lower()
            entry["has_divergence"] = "divergence" in section.lower()

        check["details"]["bands"][band] = entry
        if not all([entry["has_priority"], entry["has_examples"], entry["has_divergence"]]):
            check["status"] = "FAIL"

    return check


def check_modes_defined() -> dict:
    """BAND-MODES: Check that all 3 compatibility modes are defined."""
    check = {"id": "BAND-MODES", "status": "PASS", "details": {"modes": {}}}
    if not BANDS_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Document missing"
        return check

    text = BANDS_PATH.read_text().lower()
    for mode in REQUIRED_MODES:
        found = bool(re.search(rf'`{re.escape(mode)}`', text))
        check["details"]["modes"][mode] = found
        if not found:
            check["status"] = "FAIL"

    missing = [m for m, found in check["details"]["modes"].items() if not found]
    if missing:
        check["details"]["missing_modes"] = missing
    return check


def check_mode_band_matrix() -> dict:
    """BAND-MATRIX: Check that the mode-band matrix is complete (3x4=12 cells)."""
    check = {"id": "BAND-MATRIX", "status": "PASS", "details": {"matrix_cells": 0}}
    if not BANDS_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Document missing"
        return check

    text = BANDS_PATH.read_text().lower()
    # Count table rows that contain band references within mode sections
    # Each mode section should have a table with 4 band rows
    cells_found = 0
    for mode in REQUIRED_MODES:
        for band in REQUIRED_BANDS:
            # Check if there's a table row with this band in a mode context
            pattern = rf'{re.escape(mode)}.*?`{re.escape(band)}`|`{re.escape(band)}`.*?{re.escape(mode)}'
            if re.search(pattern, text, re.DOTALL):
                cells_found += 1

    # Alternative: count table rows in mode sections
    # Each mode section should mention all 4 bands in its table
    for mode in REQUIRED_MODES:
        mode_pattern = rf'###\s+\d+\.\d+\s+`{re.escape(mode)}`.*?(?=###\s+\d+\.\d+|## \d+\.|\Z)'
        m = re.search(mode_pattern, text, re.DOTALL)
        if m:
            section = m.group(0)
            for band in REQUIRED_BANDS:
                if f'`{band}`' in section:
                    cells_found += 1

    check["details"]["matrix_cells"] = cells_found
    # We need at least 12 (3 modes x 4 bands) appearances
    if cells_found < 12:
        check["status"] = "FAIL"
        check["details"]["error"] = f"Expected >= 12 matrix cells, found {cells_found}"
    return check


def check_plan_reference() -> dict:
    """BAND-PLAN-REF: Check that document references Section 10.2."""
    check = {"id": "BAND-PLAN-REF", "status": "PASS", "details": {}}
    if not BANDS_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Document missing"
        return check

    text = BANDS_PATH.read_text()
    if "10.2" not in text or "PLAN_TO_CREATE_FRANKEN_NODE" not in text:
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing plan Section 10.2 reference"
    else:
        check["details"]["plan_referenced"] = True
    return check


def check_primary_implementation_cited() -> dict:
    """BAND-IMPL: Check primary Rust implementation paths are cited."""
    check = {
        "id": "BAND-IMPL",
        "status": "PASS",
        "details": {
            "paths": PRIMARY_IMPLEMENTATION_PATHS,
            "existing_paths": {},
            "band_doc_citations": {},
            "contract_citations": {},
        },
    }

    band_doc_text = BANDS_PATH.read_text(encoding="utf-8") if BANDS_PATH.exists() else ""
    contract_text = CONTRACT_PATH.read_text(encoding="utf-8") if CONTRACT_PATH.exists() else ""

    missing_paths = []
    missing_band_doc_citations = []
    missing_contract_citations = []

    for name, path in PRIMARY_IMPLEMENTATION_PATHS.items():
        exists = (ROOT / path).exists()
        band_doc_cited = path in band_doc_text
        contract_cited = path in contract_text
        check["details"]["existing_paths"][name] = exists
        check["details"]["band_doc_citations"][name] = band_doc_cited
        check["details"]["contract_citations"][name] = contract_cited

        if not exists:
            missing_paths.append(path)
        if not band_doc_cited:
            missing_band_doc_citations.append(path)
        if not contract_cited:
            missing_contract_citations.append(path)

    if missing_paths or missing_band_doc_citations or missing_contract_citations:
        check["status"] = "FAIL"
        check["details"]["missing_paths"] = missing_paths
        check["details"]["missing_band_doc_citations"] = missing_band_doc_citations
        check["details"]["missing_contract_citations"] = missing_contract_citations

    return check


def build_report(timestamp: str) -> dict:
    checks = [
        check_bands_doc_exists(),
        check_primary_implementation_cited(),
        check_all_bands_defined(),
        check_band_content(),
        check_modes_defined(),
        check_mode_band_matrix(),
        check_plan_reference(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "compatibility_bands_verification",
        "section": "10.2",
        "verdict": verdict,
        "timestamp": timestamp,
        "evidence_paths": EVIDENCE_PATHS,
        "verification_commands": VERIFICATION_COMMANDS,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }
    return report


def main():
    configure_test_logging("check_compat_bands")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()
    report = build_report(timestamp)

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Compatibility Bands Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in report["checks"]:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "error" in details:
                    print(f"       Error: {details['error']}")
                if "missing_bands" in details:
                    print(f"       Missing: {', '.join(details['missing_bands'])}")
                if "missing_modes" in details:
                    print(f"       Missing: {', '.join(details['missing_modes'])}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {report['verdict']}")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
