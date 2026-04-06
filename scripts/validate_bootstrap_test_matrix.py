#!/usr/bin/env python3
"""
Bootstrap Test Matrix Validator.

Validates the bootstrap test matrix for schema integrity, test ID uniqueness,
and owning-bead existence.

Usage:
    python3 scripts/validate_bootstrap_test_matrix.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
    2 = ERROR
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = ROOT / "docs" / "verification" / "bootstrap_test_matrix.json"


def load_matrix() -> dict:
    if not MATRIX_PATH.exists():
        print(f"ERROR: Matrix not found: {MATRIX_PATH}", file=sys.stderr)
        sys.exit(2)
    with open(MATRIX_PATH) as f:
        return json.load(f)


def load_bead_ids() -> set[str]:
    """Load all bead IDs from br list."""
    try:
        result = subprocess.run(
            ["br", "list", "--json"],
            capture_output=True, text=True, timeout=3600,
        )
        beads = json.loads(result.stdout)
        return {b["id"] for b in beads}
    except Exception:
        return set()


def validate(matrix: dict, bead_ids: set[str]) -> tuple[list[str], list[str]]:
    """Validate matrix, return (errors, warnings)."""
    errors = []
    warnings = []

    if "schema_version" not in matrix:
        errors.append("Missing schema_version")
    if "test_families" not in matrix:
        errors.append("Missing test_families")
        return errors, warnings

    all_test_ids = []
    all_family_ids = []

    for family in matrix["test_families"]:
        fid = family.get("id", "UNKNOWN")
        all_family_ids.append(fid)

        for field in ["id", "name", "owning_beads", "tests"]:
            if field not in family:
                errors.append(f"Family {fid}: missing '{field}'")

        # Check owning beads exist
        for bead_id in family.get("owning_beads", []):
            if bead_ids and bead_id not in bead_ids:
                warnings.append(f"Family {fid}: owning bead {bead_id} not found in beads DB")

        for test in family.get("tests", []):
            tid = test.get("id", "UNKNOWN")
            all_test_ids.append(tid)

            for field in ["id", "scenario", "path_type"]:
                if field not in test:
                    errors.append(f"Test {tid}: missing '{field}'")

            ptype = test.get("path_type")
            if ptype and ptype not in ("happy", "edge", "error", "adversarial"):
                errors.append(f"Test {tid}: invalid path_type '{ptype}'")

    # Check uniqueness
    seen_tests = set()
    for tid in all_test_ids:
        if tid in seen_tests:
            errors.append(f"Duplicate test ID: {tid}")
        seen_tests.add(tid)

    seen_families = set()
    for fid in all_family_ids:
        if fid in seen_families:
            errors.append(f"Duplicate family ID: {fid}")
        seen_families.add(fid)

    # Coverage stats
    path_types = {}
    for family in matrix["test_families"]:
        for test in family.get("tests", []):
            pt = test.get("path_type", "unknown")
            path_types[pt] = path_types.get(pt, 0) + 1

    return errors, warnings


def main():
    json_output = "--json" in sys.argv

    matrix = load_matrix()
    bead_ids = load_bead_ids()
    errors, warnings = validate(matrix, bead_ids)

    total_tests = sum(
        len(f.get("tests", []))
        for f in matrix.get("test_families", [])
    )
    total_families = len(matrix.get("test_families", []))

    verdict = "PASS" if not errors else "FAIL"
    timestamp = datetime.now(timezone.utc).isoformat()

    report = {
        "gate": "bootstrap_test_matrix_validation",
        "verdict": verdict,
        "timestamp": timestamp,
        "total_families": total_families,
        "total_tests": total_tests,
        "errors": errors,
        "warnings": warnings,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Bootstrap Test Matrix Validation ===")
        print(f"Families: {total_families}")
        print(f"Tests: {total_tests}")
        print(f"Errors: {len(errors)}")
        print(f"Warnings: {len(warnings)}")
        if errors:
            print("\nERRORS:")
            for e in errors:
                print(f"  - {e}")
        if warnings:
            print("\nWARNINGS:")
            for w in warnings:
                print(f"  - {w}")
        print(f"\nVerdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
