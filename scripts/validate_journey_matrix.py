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
FIXTURE_SUITE_PATH = ROOT / "docs" / "verification" / "cross_section_fixture_suite.json"


def load_json(path: Path) -> dict:
    if not path.exists():
        print(f"ERROR: Not found: {path}", file=sys.stderr)
        sys.exit(2)
    with path.open(encoding="utf-8") as f:
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


def _fixture_map(fixture_suite: dict) -> tuple[dict[str, dict], list[str]]:
    errors = []
    fixtures_by_id = {}

    if fixture_suite.get("schema_version") != "1.0":
        errors.append("fixture suite: schema_version must be 1.0")
    if fixture_suite.get("owner_bead") != matrix_owner_bead():
        errors.append("fixture suite: owner_bead must match bd-295v")

    fixtures = fixture_suite.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        errors.append("fixture suite: fixtures must be a non-empty array")
        return fixtures_by_id, errors

    for index, fixture in enumerate(fixtures):
        fixture_id = fixture.get("id")
        if not fixture_id:
            errors.append(f"fixture suite entry {index}: missing id")
            continue
        if fixture_id in fixtures_by_id:
            errors.append(f"fixture suite: duplicate fixture id {fixture_id}")
        fixtures_by_id[fixture_id] = fixture

    return fixtures_by_id, errors


def matrix_owner_bead() -> str:
    return "bd-295v"


def validate_fixture_contract(matrix: dict, fixture_suite: dict) -> tuple[list[str], list[str]]:
    """Validate that every matrix phase points at an executable fixture."""
    errors = []
    warnings = []
    fixtures_by_id, map_errors = _fixture_map(fixture_suite)
    errors.extend(map_errors)

    referenced = set()
    required_fields = [
        "id",
        "journey_id",
        "phase",
        "section",
        "capability",
        "fixture_version",
        "deterministic",
        "self_contained",
        "machine_indexed",
        "inputs",
        "expected",
        "assertions",
        "failure_code",
        "replay_step",
    ]

    for journey in matrix.get("journeys", []):
        jid = journey.get("id", "UNKNOWN")
        for index, phase in enumerate(journey.get("phases", [])):
            fixture_id = phase.get("fixture")
            if not fixture_id:
                errors.append(f"{jid} phase {index}: missing fixture id")
                continue

            referenced.add(fixture_id)
            fixture = fixtures_by_id.get(fixture_id)
            if fixture is None:
                errors.append(f"{jid} phase {index}: fixture '{fixture_id}' missing from catalog")
                continue

            for field in required_fields:
                if field not in fixture:
                    errors.append(f"{fixture_id}: missing fixture field '{field}'")

            if fixture.get("journey_id") != jid:
                errors.append(f"{fixture_id}: journey_id does not match {jid}")
            if fixture.get("section") != phase.get("section"):
                errors.append(f"{fixture_id}: section does not match matrix phase")
            if fixture.get("capability") != phase.get("capability"):
                errors.append(f"{fixture_id}: capability does not match matrix phase")
            if fixture.get("deterministic") is not True:
                errors.append(f"{fixture_id}: deterministic must be true")
            if fixture.get("self_contained") is not True:
                errors.append(f"{fixture_id}: self_contained must be true")
            if fixture.get("machine_indexed") is not True:
                errors.append(f"{fixture_id}: machine_indexed must be true")

            assertions = fixture.get("assertions")
            if not isinstance(assertions, list) or not assertions:
                errors.append(f"{fixture_id}: assertions must be a non-empty array")

            replay_step = fixture.get("replay_step", {})
            if replay_step.get("method") not in {"GET", "POST", "DELETE"}:
                errors.append(f"{fixture_id}: replay_step.method must be GET, POST, or DELETE")
            if not replay_step.get("path", "").startswith("/v1/"):
                errors.append(f"{fixture_id}: replay_step.path must be a /v1 API path")
            if "expect_field" not in replay_step and "expect_ok" not in replay_step:
                errors.append(f"{fixture_id}: replay_step must declare expect_field or expect_ok")

    unused = set(fixtures_by_id) - referenced
    for fixture_id in sorted(unused):
        warnings.append(f"Fixture {fixture_id} is not referenced by the journey matrix")

    return errors, warnings


def main():
    logger = configure_test_logging("validate_journey_matrix")
    logger.info("starting validate_journey_matrix", extra={"argv": sys.argv[1:]})
    json_output = "--json" in sys.argv

    matrix = load_json(MATRIX_PATH)
    registry = load_json(REGISTRY_PATH)
    fixture_suite = load_json(FIXTURE_SUITE_PATH)

    schema_errors = validate_schema(matrix)
    cap_warnings = validate_capability_coverage(matrix, registry)
    section_warnings = validate_section_coverage(matrix)
    taxonomy_errors = validate_failure_taxonomy(matrix)
    fixture_errors, fixture_warnings = validate_fixture_contract(matrix, fixture_suite)

    all_errors = schema_errors + taxonomy_errors + fixture_errors
    all_warnings = cap_warnings + section_warnings + fixture_warnings

    verdict = "PASS" if not all_errors else "FAIL"
    timestamp = datetime.now(timezone.utc).isoformat()
    fixture_count = len(fixture_suite.get("fixtures", []))

    report = {
        "gate": "journey_matrix_validation",
        "verdict": verdict,
        "timestamp": timestamp,
        "journey_count": len(matrix.get("journeys", [])),
        "fixture_count": fixture_count,
        "errors": all_errors,
        "warnings": all_warnings,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Journey Matrix Validation ===")
        print(f"Journeys: {report['journey_count']}")
        print(f"Fixtures: {report['fixture_count']}")
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
