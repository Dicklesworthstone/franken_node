#!/usr/bin/env python3
"""bd-2ja gate: Compatibility Golden Corpus and Fixture Metadata Schema (Section 10.7).

Validates that:
- corpus_manifest.json exists and is valid JSON
- All fixtures have required fields per the fixture_metadata_schema.json
- Band distribution covers at least core and high_value
- At least 8 fixtures are present
- All fixtures are deterministic
- fixture_metadata_schema.json exists
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


CORPUS = ROOT / "fixtures" / "conformance" / "corpus_manifest.json"
SCHEMA = ROOT / "fixtures" / "conformance" / "fixture_metadata_schema.json"
SPEC = ROOT / "docs" / "specs" / "section_10_7" / "bd-2ja_contract.md"

BEAD = "bd-2ja"
SECTION = "10.7"

REQUIRED_FIXTURE_FIELDS = [
    "fixture_id", "api_surface", "band", "expected_behavior",
    "node_version", "inputs", "expected_outputs",
]

VALID_BANDS = ["core", "high_value", "edge", "unsafe"]
REQUIRED_BANDS = ["core", "high_value"]
MIN_FIXTURES = 8


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _rel(path: Path) -> str:
    """Return path relative to ROOT, or the absolute path if outside ROOT."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _load_json_object(path: Path) -> tuple[dict[str, object] | None, str]:
    try:
        data = json.JSONDecoder().decode(_read(path))
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"
    except OSError as exc:
        return None, f"read failed: {exc}"

    if not isinstance(data, dict):
        return None, f"expected JSON object, got {type(data).__name__}"

    return data, f"{path.name} parses as JSON"


def _configure_logging() -> None:
    from scripts.lib.test_logger import configure_test_logging

    configure_test_logging("check_compatibility_corpus")


def _checks() -> list[dict[str, object]]:
    results = []

    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    # 1. Schema file exists
    ok("schema_exists", SCHEMA.is_file(), _rel(SCHEMA))

    # 2. Schema is valid JSON
    schema_valid = False
    schema_data = None
    if SCHEMA.is_file():
        schema_data, schema_detail = _load_json_object(SCHEMA)
        schema_valid = schema_data is not None
    else:
        schema_detail = "fixture_metadata_schema.json missing"
    ok("schema_valid_json", schema_valid, schema_detail)

    # 3. Schema has $schema field (Draft 2020-12)
    has_draft = False
    if schema_data:
        has_draft = "2020-12" in schema_data.get("$schema", "")
    ok("schema_draft_2020_12", has_draft, "JSON Schema Draft 2020-12")

    # 4. Schema has required fields definition
    schema_required = []
    if schema_data:
        schema_required = schema_data.get("required", [])
    ok("schema_required_fields",
       all(f in schema_required for f in REQUIRED_FIXTURE_FIELDS),
       f"{len(schema_required)} required fields defined")

    # 5. Corpus manifest exists
    ok("corpus_exists", CORPUS.is_file(), _rel(CORPUS))

    # 6. Corpus is valid JSON
    corpus_valid = False
    corpus_data = None
    if CORPUS.is_file():
        corpus_data, corpus_detail = _load_json_object(CORPUS)
        corpus_valid = corpus_data is not None
    else:
        corpus_detail = "corpus_manifest.json missing"
    ok("corpus_valid_json", corpus_valid, corpus_detail)

    # 7. Corpus has schema_version
    has_version = False
    if corpus_data:
        has_version = "schema_version" in corpus_data
    ok("corpus_schema_version", has_version,
       corpus_data.get("schema_version", "missing") if corpus_data else "missing")

    # 8. Corpus has bead_id
    has_bead = False
    if corpus_data:
        has_bead = corpus_data.get("bead_id") == BEAD
    ok("corpus_bead_id", has_bead, BEAD)

    # 9. Corpus has fixtures array
    fixtures = []
    if corpus_data:
        fixtures = corpus_data.get("fixtures", [])
    ok("corpus_has_fixtures", isinstance(fixtures, list) and len(fixtures) > 0,
       f"{len(fixtures)} fixtures")

    # 10. At least MIN_FIXTURES fixtures
    ok("min_fixtures", len(fixtures) >= MIN_FIXTURES,
       f"{len(fixtures)} fixtures (>={MIN_FIXTURES} required)")

    # 11. All fixtures have required fields
    missing_fields = []
    for fix in fixtures:
        for field in REQUIRED_FIXTURE_FIELDS:
            if field not in fix:
                missing_fields.append(f"{fix.get('fixture_id', '?')}.{field}")
    ok("fixtures_required_fields", len(missing_fields) == 0,
       f"{len(missing_fields)} missing fields" if missing_fields else "all present")

    # 12. All fixture_id values match pattern FIX-[A-Z0-9]+-[0-9]+
    id_pattern = re.compile(r"^FIX-[A-Z0-9]+-[0-9]+$")
    bad_ids = [f.get("fixture_id", "?") for f in fixtures
               if not id_pattern.match(f.get("fixture_id", ""))]
    ok("fixture_id_pattern", len(bad_ids) == 0,
       f"{len(bad_ids)} invalid IDs" if bad_ids else "all match pattern")

    # 13. All bands are valid
    invalid_bands = [f.get("fixture_id", "?") for f in fixtures
                     if f.get("band") not in VALID_BANDS]
    ok("valid_bands", len(invalid_bands) == 0,
       f"{len(invalid_bands)} invalid bands" if invalid_bands else "all valid")

    # 14. Band distribution covers required bands
    present_bands = set(f.get("band") for f in fixtures)
    ok("required_bands_covered",
       all(b in present_bands for b in REQUIRED_BANDS),
       f"bands present: {sorted(present_bands)}")

    # 15. All fixtures are deterministic
    non_deterministic = [f.get("fixture_id", "?") for f in fixtures
                         if f.get("deterministic") is not True]
    ok("all_deterministic", len(non_deterministic) == 0,
       f"{len(non_deterministic)} non-deterministic" if non_deterministic else "all deterministic")

    # 16. Summary section matches fixture count
    summary_ok = False
    if corpus_data and "summary" in corpus_data:
        summary = corpus_data["summary"]
        summary_ok = summary.get("total_fixtures") == len(fixtures)
    ok("summary_consistent", summary_ok,
       f"summary total={corpus_data.get('summary', {}).get('total_fixtures', '?')}, actual={len(fixtures)}" if corpus_data else "missing")

    # 17. Band distribution in summary matches actual
    band_dist_ok = False
    if corpus_data and "summary" in corpus_data:
        by_band = corpus_data["summary"].get("by_band", {})
        actual_dist = {}
        for f in fixtures:
            b = f.get("band", "unknown")
            actual_dist[b] = actual_dist.get(b, 0) + 1
        band_dist_ok = by_band == actual_dist
    ok("summary_band_distribution", band_dist_ok, "band counts match")

    # 18. Spec contract exists
    ok("spec_exists", SPEC.is_file(), _rel(SPEC))

    return results


def self_test():
    """Smoke-test that all checks produce output."""
    results = _checks()
    if len(results) < 15:
        raise RuntimeError(f"Expected >=15 checks, got {len(results)}")
    for r in results:
        if "check" not in r or "passed" not in r:
            raise RuntimeError(f"Malformed check result: {r!r}")
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    _configure_logging()
    as_json = "--json" in sys.argv

    if "--self-test" in sys.argv:
        self_test()
        return

    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"

    if as_json:
        print(json.dumps({
            "bead_id": BEAD,
            "section": SECTION,
            "gate_script": "check_compatibility_corpus.py",
            "checks_passed": passed,
            "checks_total": total,
            "verdict": verdict,
            "checks": results,
        }, indent=2))
    else:
        for r in results:
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['check']}: {r['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks -- {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
