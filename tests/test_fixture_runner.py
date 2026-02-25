"""Tests for scripts/fixture_runner.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fixture_runner import (
    canonicalize,
    validate_fixture,
    check_schema_exists,
    check_fixtures_dir,
    check_fixtures_valid,
    check_canonicalizer_determinism,
    check_fixture_ids_unique,
)


# ── canonicalize ─────────────────────────────────────────────


def test_canonicalize_sorts_keys():
    assert canonicalize({"b": 1, "a": 2}) == {"a": 2, "b": 1}


def test_canonicalize_replaces_timestamps():
    result = canonicalize({"ts": "2025-01-15T12:00:00+00:00"})
    assert result == {"ts": "<TIMESTAMP>"}


def test_canonicalize_rounds_floats():
    assert canonicalize(3.14159265358979) == 3.141593


def test_canonicalize_preserves_list_order():
    assert canonicalize([3, 1, 2]) == [3, 1, 2]


def test_canonicalize_normalizes_pids():
    result = canonicalize("pid=12345")
    assert result == "pid=<PID>"


def test_canonicalize_nested():
    inp = {"z": {"b": 2, "a": 1}, "a": [1, 2]}
    expected = {"a": [1, 2], "z": {"a": 1, "b": 2}}
    assert canonicalize(inp) == expected


def test_canonicalize_deterministic():
    inp = {"z": [1, {"b": 2, "a": 1}]}
    assert canonicalize(inp) == canonicalize(inp)


# ── validate_fixture ─────────────────────────────────────────


def test_validate_valid_fixture():
    fixture = {
        "id": "fixture:fs:readFile:basic",
        "api_family": "fs",
        "api_name": "readFile",
        "band": "core",
        "input": {"args": ["test.txt"]},
        "expected_output": {"return_value": "data"},
    }
    assert validate_fixture(fixture) == []


def test_validate_missing_fields():
    errors = validate_fixture({})
    assert any("missing required field 'id'" in e for e in errors)


def test_validate_bad_id():
    fixture = {
        "id": "bad-id",
        "api_family": "fs",
        "api_name": "readFile",
        "band": "core",
        "input": {},
        "expected_output": {},
    }
    errors = validate_fixture(fixture)
    assert any("invalid id format" in e for e in errors)


def test_validate_bad_band():
    fixture = {
        "id": "fixture:fs:readFile:x",
        "api_family": "fs",
        "api_name": "readFile",
        "band": "invalid",
        "input": {},
        "expected_output": {},
    }
    errors = validate_fixture(fixture)
    assert any("invalid band" in e for e in errors)


# ── Integration checks ───────────────────────────────────────


def test_schema_exists():
    assert check_schema_exists()["status"] == "PASS"


def test_fixtures_dir():
    result = check_fixtures_dir()
    assert result["status"] == "PASS"
    assert result["details"]["fixture_count"] >= 2


def test_fixtures_valid():
    assert check_fixtures_valid()["status"] == "PASS"


def test_canonicalizer_determinism():
    assert check_canonicalizer_determinism()["status"] == "PASS"


def test_fixture_ids_unique():
    assert check_fixture_ids_unique()["status"] == "PASS"
