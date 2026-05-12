"""Tests for scripts/check_impl_governance.py."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_impl_governance import (
    check_policy_exists,
    check_policy_rules,
    check_adr_reference,
    check_charter_xref,
    check_enforcement_section,
    REQUIRED_RULES,
)


def test_policy_exists():
    result = check_policy_exists()
    assert result["status"] == "PASS"
    assert result["id"] == "GOV-EXISTS"


def test_policy_all_rules_present():
    result = check_policy_rules()
    assert result["status"] == "PASS"
    for rule_name, found in result["details"]["rules"].items():
        assert found, f"Rule '{rule_name}' not found"


def test_required_rules_count():
    assert len(REQUIRED_RULES) == 4


def test_adr_reference():
    result = check_adr_reference()
    assert result["status"] == "PASS"
    assert result["details"]["adr_referenced"]


def test_charter_xref():
    result = check_charter_xref()
    assert result["status"] == "PASS"
    assert result["details"]["cross_referenced"]


def test_enforcement_section():
    result = check_enforcement_section()
    assert result["status"] == "PASS"
    assert result["details"]["enforcement_section"]
    assert result["details"]["ci_gate_documented"]
    assert result["details"]["review_checklist"]


def test_policy_file_has_scope():
    text = (ROOT / "docs" / "IMPLEMENTATION_GOVERNANCE.md").read_text()
    if "## 1. Scope" not in text:
        raise AssertionError("implementation governance policy must define a Scope section")


def test_policy_file_has_no_exceptions():
    text = (ROOT / "docs" / "IMPLEMENTATION_GOVERNANCE.md").read_text()
    assert "No exceptions" in text


def test_impl_governance_checker_e2e_json_passes():
    result = subprocess.run(  # nosec B603 - fixed verifier command under repo root.
        [sys.executable, "scripts/check_impl_governance.py", "--json"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as err:
        raise AssertionError(f"expected JSON verifier output, got: {result.stdout}") from err
    assert payload["gate"] == "implementation_governance_verification"
    assert payload["verdict"] == "PASS"
    assert payload["summary"]["total_checks"] == 5
    assert payload["summary"]["failing_checks"] == 0
