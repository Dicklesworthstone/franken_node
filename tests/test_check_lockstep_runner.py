"""Tests for scripts/check_lockstep_runner.py."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_lockstep_runner import (  # noqa: E402
    build_report,
    check_design_exists,
    check_config_schema,
    check_primary_implementation_cited,
    check_phases_documented,
    check_delta_format,
    check_release_gating,
    EVIDENCE_PATHS,
    PRIMARY_IMPLEMENTATION_PATHS,
    REQUIRED_PHASES,
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


def test_design_exists():
    require_equal(check_design_exists()["status"], "PASS", "design check status")


def test_config_schema():
    result = check_config_schema()
    require_equal(result["status"], "PASS", "config check status")
    require("runtimes" in result["details"]["required_fields"], "runtimes must be required")


def test_primary_implementation_cited():
    result = check_primary_implementation_cited()
    require_equal(result["status"], "PASS", "primary implementation check status")
    require_equal(result["details"]["paths"], PRIMARY_IMPLEMENTATION_PATHS, "implementation paths")
    for path_exists in result["details"]["existing_paths"].values():
        require(path_exists, "implementation path must exist")
    for design_cited in result["details"]["design_citations"].values():
        require(design_cited, "design must cite implementation path")
    for contract_cited in result["details"]["contract_citations"].values():
        require(contract_cited, "contract must cite implementation path")


def test_phases_documented():
    result = check_phases_documented()
    require_equal(result["status"], "PASS", "phase check status")
    for phase in REQUIRED_PHASES:
        require(result["details"]["phases"][phase], f"Phase '{phase}' not found")


def test_required_phases_count():
    require_equal(len(REQUIRED_PHASES), 5, "required phase count")


def test_delta_format():
    result = check_delta_format()
    require_equal(result["status"], "PASS", "delta format check status")
    require(result["details"]["report_documented"], "delta report must be documented")
    require(result["details"]["json_format"], "delta report JSON format must be documented")


def test_release_gating():
    result = check_release_gating()
    require_equal(result["status"], "PASS", "release gating check status")
    require(result["details"]["core_blocks_release"], "core divergences must block release")


def test_config_schema_json_valid():
    data = read_json(ROOT / "schemas" / "lockstep_runner_config.schema.json")
    require_equal(data["properties"]["runtimes"]["type"], "array", "runtime schema type")


def test_design_has_architecture_section():
    text = (ROOT / "docs" / "L1_LOCKSTEP_RUNNER.md").read_text(encoding="utf-8")
    require("## 2. Architecture" in text, "architecture section missing")


def test_report_cites_primary_lockstep_implementation():
    report = build_report("2026-05-12T00:00:00+00:00")
    require_equal(report["evidence_paths"], EVIDENCE_PATHS, "report evidence paths")
    require_equal(
        report["evidence_paths"]["primary_lockstep_harness"],
        "crates/franken-node/src/runtime/lockstep_harness.rs",
        "primary lockstep harness path",
    )
    require_equal(
        report["evidence_paths"]["verify_cli_dispatch"],
        "crates/franken-node/src/main.rs",
        "verify CLI dispatch path",
    )
    require_equal(
        report["evidence_paths"]["verify_cli_args"],
        "crates/franken-node/src/cli.rs",
        "verify CLI args path",
    )
    commands = {entry["command"] for entry in report["verification_commands"]}
    require("python3 scripts/check_lockstep_runner.py --json" in commands, "checker command missing")
    require("python3 -m pytest tests/test_check_lockstep_runner.py" in commands, "pytest command missing")


def test_checked_in_evidence_cites_primary_lockstep_implementation():
    evidence_path = ROOT / "artifacts" / "section_10_2" / "bd-2vi" / "verification_evidence.json"
    evidence = read_json(evidence_path)
    require_equal(
        evidence["evidence_paths"]["primary_lockstep_harness"],
        "crates/franken-node/src/runtime/lockstep_harness.rs",
        "checked-in primary lockstep harness path",
    )
    require_equal(
        evidence["evidence_paths"]["verify_cli_dispatch"],
        "crates/franken-node/src/main.rs",
        "checked-in verify CLI dispatch path",
    )
    require_equal(
        evidence["evidence_paths"]["verify_cli_args"],
        "crates/franken-node/src/cli.rs",
        "checked-in verify CLI args path",
    )
