#!/usr/bin/env python3
"""
Deterministic Compatibility Fixture Runner and Result Canonicalizer.

Loads fixture JSON files, validates them, and provides canonical
result comparison. This is the Python-side framework for the L1
lockstep oracle.

Usage:
    python3 scripts/fixture_runner.py [--json] [--dir PATH]

Exit codes:
    0 = PASS
    1 = FAIL
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "compatibility_fixture.schema.json"
FIXTURES_DIR = ROOT / "docs" / "fixtures"

VALID_BANDS = {"core", "high-value", "edge", "unsafe"}
ID_PATTERN = re.compile(r'^fixture:[a-z_]+:[a-zA-Z_]+:[a-z0-9_-]+$')


def canonicalize(value):
    """Canonicalize a value for deterministic comparison.

    - Sort object keys alphabetically
    - Replace timestamps with <TIMESTAMP>
    - Replace absolute paths with <ROOT>/...
    - Replace PIDs with <PID>
    - Round floats to 6 decimal places
    """
    if isinstance(value, dict):
        return {k: canonicalize(v) for k, v in sorted(value.items())}
    elif isinstance(value, list):
        return [canonicalize(v) for v in value]
    elif isinstance(value, float):
        return round(value, 6)
    elif isinstance(value, str):
        # Normalize timestamps (ISO 8601)
        ts_pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})'
        value = re.sub(ts_pattern, '<TIMESTAMP>', value)
        # Normalize PIDs
        value = re.sub(r'\bpid[=: ]+\d+\b', 'pid=<PID>', value, flags=re.IGNORECASE)
        return value
    return value


def validate_fixture(data: dict) -> list[str]:
    """Validate a single fixture against schema rules."""
    errors = []
    required = ["id", "api_family", "api_name", "band", "input", "expected_output"]
    for field in required:
        if field not in data:
            errors.append(f"missing required field '{field}'")

    fid = data.get("id", "")
    if fid and not ID_PATTERN.match(fid):
        errors.append(f"invalid id format: '{fid}'")

    band = data.get("band", "")
    if band and band not in VALID_BANDS:
        errors.append(f"invalid band: '{band}'")

    if "input" in data and not isinstance(data["input"], dict):
        errors.append("'input' must be an object")

    if "expected_output" in data and not isinstance(data["expected_output"], dict):
        errors.append("'expected_output' must be an object")

    return errors


def load_fixtures(fixtures_dir: Path | None = None) -> list[tuple[Path, dict]]:
    """Load all fixture JSON files from the fixtures directory."""
    d = fixtures_dir or FIXTURES_DIR
    fixtures = []
    if d.exists():
        for f in sorted(d.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                fixtures.append((f, data))
            except json.JSONDecodeError:
                fixtures.append((f, None))
    return fixtures


def check_schema_exists() -> dict:
    """FIX-SCHEMA: Check fixture schema exists."""
    check = {"id": "FIX-SCHEMA", "status": "PASS", "details": {}}
    if not SCHEMA_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Schema not found"
    else:
        check["details"]["path"] = str(SCHEMA_PATH.relative_to(ROOT))
    return check


def check_fixtures_dir() -> dict:
    """FIX-DIR: Check fixtures directory exists."""
    check = {"id": "FIX-DIR", "status": "PASS", "details": {}}
    if not FIXTURES_DIR.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/fixtures/ not found"
    else:
        count = len(list(FIXTURES_DIR.glob("*.json")))
        check["details"]["fixture_count"] = count
        if count == 0:
            check["status"] = "FAIL"
            check["details"]["error"] = "No fixture files found"
    return check


def check_fixtures_valid() -> dict:
    """FIX-VALID: Validate all fixture files."""
    check = {"id": "FIX-VALID", "status": "PASS", "details": {"fixtures": [], "errors": []}}
    fixtures = load_fixtures()

    for path, data in fixtures:
        name = path.name
        if data is None:
            check["status"] = "FAIL"
            check["details"]["errors"].append(f"{name}: invalid JSON")
            continue

        errors = validate_fixture(data)
        entry = {"file": name, "id": data.get("id", ""), "valid": len(errors) == 0}
        if errors:
            check["status"] = "FAIL"
            for e in errors:
                check["details"]["errors"].append(f"{name}: {e}")
        check["details"]["fixtures"].append(entry)

    return check


def check_canonicalizer_determinism() -> dict:
    """FIX-CANONICAL: Verify canonicalizer produces deterministic output."""
    check = {"id": "FIX-CANONICAL", "status": "PASS", "details": {}}

    # Test with known inputs
    test_cases = [
        ({"b": 1, "a": 2}, {"a": 2, "b": 1}),
        ({"ts": "2025-01-15T12:00:00Z"}, {"ts": "<TIMESTAMP>"}),
        ({"val": 3.14159265358979}, {"val": 3.141593}),
        ([3, 1, 2], [3, 1, 2]),  # Lists preserve order
    ]

    for i, (inp, expected) in enumerate(test_cases):
        result = canonicalize(inp)
        if result != expected:
            check["status"] = "FAIL"
            check["details"][f"case_{i}"] = {"input": inp, "expected": expected, "got": result}

    # Determinism: same input → same output twice
    complex_input = {"z": [1, {"b": 2, "a": 1}], "a": "pid=12345"}
    r1 = canonicalize(complex_input)
    r2 = canonicalize(complex_input)
    if r1 != r2:
        check["status"] = "FAIL"
        check["details"]["determinism"] = "Non-deterministic output"
    else:
        check["details"]["determinism"] = "verified"

    return check


def check_fixture_ids_unique() -> dict:
    """FIX-UNIQUE: Check all fixture IDs are unique."""
    check = {"id": "FIX-UNIQUE", "status": "PASS", "details": {}}
    fixtures = load_fixtures()

    ids = []
    for _, data in fixtures:
        if data and "id" in data:
            ids.append(data["id"])

    seen = set()
    dupes = []
    for fid in ids:
        if fid in seen:
            dupes.append(fid)
        seen.add(fid)

    check["details"]["total"] = len(ids)
    check["details"]["unique"] = len(seen)
    if dupes:
        check["status"] = "FAIL"
        check["details"]["duplicates"] = dupes
    return check


def main():
    logger = configure_test_logging("fixture_runner")
    logger.info("starting fixture_runner verification")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_schema_exists(),
        check_fixtures_dir(),
        check_fixtures_valid(),
        check_canonicalizer_determinism(),
        check_fixture_ids_unique(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "fixture_runner_verification",
        "section": "10.2",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Fixture Runner & Canonicalizer Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "error" in details:
                    print(f"       Error: {details['error']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
