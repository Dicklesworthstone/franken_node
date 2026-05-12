"""Tests for scripts/verify_adr_hybrid_baseline.py."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from verify_adr_hybrid_baseline import (
    check_adr_exists,
    check_adr_status,
    check_adr_rules,
    check_adr_references,
    check_charter_xref,
    REQUIRED_RULES,
)


def test_adr_exists():
    result = check_adr_exists()
    assert result["status"] == "PASS"
    assert result["id"] == "ADR-EXISTS"
    assert "size_bytes" in result["details"]


def test_adr_status_accepted():
    result = check_adr_status()
    assert result["status"] == "PASS"
    assert result["details"]["status"] == "Accepted"


def test_adr_all_rules_present():
    result = check_adr_rules()
    assert result["status"] == "PASS"
    for rule_name, found in result["details"]["rules"].items():
        assert found, f"Rule '{rule_name}' not found in ADR"


def test_required_rules_count():
    assert len(REQUIRED_RULES) == 6


def test_adr_references_plan():
    result = check_adr_references()
    assert result["status"] == "PASS"
    refs = {r["name"]: r["found"] for r in result["details"]["references"]}
    assert refs["PLAN_TO_CREATE_FRANKEN_NODE"]
    assert refs["PRODUCT_CHARTER"]
    assert refs["ENGINE_SPLIT_CONTRACT"]


def test_charter_cross_references_adr():
    result = check_charter_xref()
    assert result["status"] == "PASS"
    assert result["details"]["cross_referenced"]


def test_adr_file_content_has_title():
    adr_path = ROOT / "docs" / "adr" / "ADR-001-hybrid-baseline-strategy.md"
    text = adr_path.read_text()
    assert "# ADR-001: Hybrid Baseline Strategy" in text


def test_adr_file_has_consequences_section():
    adr_path = ROOT / "docs" / "adr" / "ADR-001-hybrid-baseline-strategy.md"
    text = adr_path.read_text()
    assert "## Consequences" in text


def test_adr_hybrid_baseline_checker_e2e_json_passes():
    result = subprocess.run(  # nosec B603 - fixed verifier command under repo root.
        [sys.executable, "scripts/verify_adr_hybrid_baseline.py", "--json"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["gate"] == "adr_hybrid_baseline_verification"
    assert payload["verdict"] == "PASS"
    assert payload["summary"]["total_checks"] == 5
    assert payload["summary"]["failing_checks"] == 0
