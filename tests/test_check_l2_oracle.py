"""Tests for scripts/check_l2_oracle.py."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_l2_oracle import (
    check_design_exists,
    check_boundary_coverage,
    check_always_blocks,
    check_split_reference,
    check_l1_complement,
    REQUIRED_SECTIONS,
)


def require_pass(result, label):
    if result.get("status") not in {"PASS"}:
        raise AssertionError(f"{label} failed: {result}")


def require_true(value, label):
    if not value:
        raise AssertionError(f"{label} must be true")


def test_design_exists():
    require_pass(check_design_exists(), "design existence")


def test_boundary_coverage():
    result = check_boundary_coverage()
    require_pass(result, "boundary coverage")
    for s in REQUIRED_SECTIONS:
        require_true(result["details"]["sections"][s], f"boundary section {s}")


def test_always_blocks():
    result = check_always_blocks()
    require_pass(result, "always-blocks policy")
    require_true(result["details"]["always_blocks"], "always-blocks release flag")


def test_split_reference():
    require_pass(check_split_reference(), "split contract reference")


def test_l1_complement():
    result = check_l1_complement()
    require_pass(result, "L1 complement")
    require_true(result["details"]["l1_referenced"], "L1 reference")
    require_true(result["details"]["both_required"], "both layers required")


def test_design_has_integration():
    text = (ROOT / "docs" / "L2_ENGINE_BOUNDARY_ORACLE.md").read_text()
    require_true("Integration" in text, "integration section")


def test_l2_oracle_checker_e2e_json_passes():
    result = subprocess.run(  # nosec B603 - fixed verifier command under repo root.
        [sys.executable, "scripts/check_l2_oracle.py", "--json"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )

    if result.returncode not in {0}:
        raise AssertionError(result.stderr)
    try:
        payload = json.JSONDecoder().decode(result.stdout)
    except json.JSONDecodeError as err:
        raise AssertionError(f"expected JSON verifier output, got: {result.stdout}") from err
    if payload.get("gate") not in {"l2_oracle_verification"}:
        raise AssertionError(f"unexpected gate: {payload.get('gate')}")
    if payload.get("verdict") not in {"PASS"}:
        raise AssertionError(f"unexpected verdict: {payload.get('verdict')}")
    if payload["summary"].get("total_checks") not in {5}:
        raise AssertionError(f"unexpected check count: {payload['summary']}")
    if payload["summary"].get("failing_checks") not in {0}:
        raise AssertionError(f"unexpected failures: {payload['summary']}")
