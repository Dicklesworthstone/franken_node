#!/usr/bin/env python3
"""
Journey Matrix Validator.

Validates the cross-section integration journey matrix for:
  1. Schema integrity (required fields, types)
  2. Capability coverage (all registry capabilities referenced)
  3. Section coverage (all execution tracks appear in at least one journey)
  4. Fixture contract consistency
  5. Failure taxonomy uniqueness

Usage:
    python3 scripts/validate_journey_matrix.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL (validation errors)
    2 = ERROR (missing files)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = ROOT / "docs" / "verification" / "journey_matrix.json"
REGISTRY_PATH = ROOT / "docs" / "capability_ownership_registry.json"


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"ERROR: Not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path) as f:
        return json.load(f)


def validate_schema(matrix: dict) -> list[str]:
    """Validate journey matrix schema."""
    errors = []
    if "schema_version" not in matrix:
        errors.append("Missing schema_version")
    if "journeys" not in matrix:
        errors.append("Missing journeys array")
        return errors

    for j in matrix["journeys"]:
        jid = j.get("id", "UNKNOWN")
        for field in ["id", "name", "sections", "capabilities", "phases", "failure_taxonomy"]:
            if field not in j:
                errors.append(f"{jid}: missing field '{field}'")

        for i, phase in enumerate(j.get("phases", [])):
            if "section" not in phase:
                errors.append(f"{jid} phase {i}: missing 'section'")
            if "fixture" not in phase:
                errors.append(f"{jid} phase {i}: missing 'fixture'")

    return errors


def validate_capability_coverage(matrix: dict, registry: dict) -> list[str]:
    """Check that all registry capabilities appear in at least one journey."""
    warnings = []
    all_caps = {c["id"] for c in registry.get("capabilities", [])}
    referenced_caps = set()

    for j in matrix.get("journeys", []):
        referenced_caps.update(j.get("capabilities", []))

    missing = all_caps - referenced_caps
    for cap_id in sorted(missing):
        cap = next((c for c in registry["capabilities"] if c["id"] == cap_id), None)
        domain = cap["domain"][:50] if cap else "?"
        warnings.append(f"Capability {cap_id} ({domain}) not in any journey")

    return warnings


def validate_section_coverage(matrix: dict) -> list[str]:
    """Check that execution tracks appear in journeys."""
    warnings = []
    # Execution tracks from the plan
    exec_tracks = {f"10.{i}" for i in range(22)}  # 10.0 through 10.21
    referenced = set()

    for j in matrix.get("journeys", []):
        for s in j.get("sections", []):
            referenced.add(s)
        for phase in j.get("phases", []):
            referenced.add(phase.get("section", ""))

    missing = exec_tracks - referenced
    for s in sorted(missing, key=lambda x: float(x.replace("10.", ""))):
        warnings.append(f"Section {s} not referenced in any journey")

    return warnings


def validate_failure_taxonomy(matrix: dict) -> list[str]:
    """Check failure taxonomy uniqueness."""
    errors = []
    all_codes = {}

    for j in matrix.get("journeys", []):
        jid = j.get("id", "?")
        for code in j.get("failure_taxonomy", []):
            if code in all_codes:
                errors.append(
                    f"Duplicate failure code '{code}' in {jid} "
                    f"(already in {all_codes[code]})"
                )
            else:
                all_codes[code] = jid

    return errors


def main():
    logger = configure_test_logging("validate_journey_matrix")
    logger.info("starting validate_journey_matrix", extra={"argv": sys.argv[1:]})
    json_output = "--json" in sys.argv

    matrix = load_json(MATRIX_PATH)
    registry = load_json(REGISTRY_PATH)

    schema_errors = validate_schema(matrix)
    cap_warnings = validate_capability_coverage(matrix, registry)
    section_warnings = validate_section_coverage(matrix)
    taxonomy_errors = validate_failure_taxonomy(matrix)

    all_errors = schema_errors + taxonomy_errors
    all_warnings = cap_warnings + section_warnings

    verdict = "PASS" if not all_errors else "FAIL"
    timestamp = datetime.now(timezone.utc).isoformat()

    report = {
        "gate": "journey_matrix_validation",
        "verdict": verdict,
        "timestamp": timestamp,
        "journey_count": len(matrix.get("journeys", [])),
        "errors": all_errors,
        "warnings": all_warnings,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Journey Matrix Validation ===")
        print(f"Journeys: {report['journey_count']}")
        print(f"Errors: {len(all_errors)}")
        print(f"Warnings: {len(all_warnings)}")
        if all_errors:
            print("\nERRORS:")
            for e in all_errors:
                print(f"  - {e}")
        if all_warnings:
            print("\nWARNINGS:")
            for w in all_warnings:
                print(f"  - {w}")
        print(f"\nVerdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
