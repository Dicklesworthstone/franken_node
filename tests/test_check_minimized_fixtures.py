"""Tests for scripts/check_minimized_fixtures.py."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_minimized_fixtures import (
    build_report,
    check_spec_exists,
    check_dir_exists,
    check_strategies,
    check_fixture_format,
    check_integration,
    EVIDENCE_PATHS,
    REQUIRED_STRATEGIES,
)


def test_spec_exists():
    assert check_spec_exists()["status"] == "PASS"


def test_dir_exists():
    assert check_dir_exists()["status"] == "PASS"


def test_strategies_documented():
    result = check_strategies()
    assert result["status"] == "PASS"
    for s in REQUIRED_STRATEGIES:
        assert result["details"]["strategies"][s]


def test_required_strategies_count():
    assert len(REQUIRED_STRATEGIES) == 3


def test_fixture_format():
    result = check_fixture_format()
    assert result["status"] == "PASS"
    assert result["details"]["extra_fields_documented"]


def test_integration():
    result = check_integration()
    assert result["status"] == "PASS"
    assert result["details"]["l1_integration"]
    assert result["details"]["ledger_integration"]


def test_spec_has_storage_section():
    text = (ROOT / "docs" / "MINIMIZED_FIXTURE_SPEC.md").read_text(encoding="utf-8")
    assert "## 4. Storage" in text


def test_report_cites_fixture_generation_paths():
    report = build_report("2026-05-12T00:00:00+00:00")
    assert report["evidence_paths"] == EVIDENCE_PATHS
    assert report["evidence_paths"]["verifier"] == "scripts/check_minimized_fixtures.py"
    assert report["evidence_paths"]["regression_tests"] == "tests/test_check_minimized_fixtures.py"
    commands = {entry["command"] for entry in report["verification_commands"]}
    assert "python3 scripts/check_minimized_fixtures.py --json" in commands
    assert "python3 -m pytest tests/test_check_minimized_fixtures.py" in commands


def test_checked_in_evidence_cites_fixture_generation_paths():
    evidence_path = ROOT / "artifacts" / "section_10_2" / "bd-32v" / "verification_evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert evidence["evidence_paths"]["verifier"] == "scripts/check_minimized_fixtures.py"
    assert evidence["evidence_paths"]["regression_tests"] == "tests/test_check_minimized_fixtures.py"
    assert evidence["evidence_paths"]["contract"] == "docs/specs/section_10_2/bd-32v_contract.md"
