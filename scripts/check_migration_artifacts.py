#!/usr/bin/env python3
"""bd-3hm: Verification script for migration singularity artifact contract.

Usage:
    python3 scripts/check_migration_artifacts.py           # human-readable
    python3 scripts/check_migration_artifacts.py --json     # machine-readable
    python3 scripts/check_migration_artifacts.py --self-test # internal consistency
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


# -- File paths ----------------------------------------------------------------

IMPL_FILE = ROOT / "crates/franken-node/src/connector/migration_artifact.rs"
MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
SCHEMA_FILE = ROOT / "spec/migration_artifact_schema.json"
VECTORS_FILE = ROOT / "vectors/migration_artifacts.json"
SPEC_FILE = ROOT / "docs/specs/section_10_12/bd-3hm_contract.md"
TEST_FILE = ROOT / "tests/test_check_migration_artifacts.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_12/bd-3hm/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_12/bd-3hm/verification_summary.md"

# -- Required elements ---------------------------------------------------------

REQUIRED_STRUCTS = [
    "MigrationArtifact",
    "MigrationStep",
    "RollbackReceipt",
    "ConfidenceInterval",
    "VerifierMetadata",
    "ArtifactVersion",
    "ValidationResult",
    "MigrationArtifactEvent",
]

REQUIRED_EVENT_CODES = [
    "MA-001",
    "MA-002",
    "MA-003",
    "MA-004",
    "MA-005",
    "MA-006",
    "MA-007",
    "MA-008",
]

REQUIRED_ERROR_CODES = [
    "ERR_MA_INVALID_SCHEMA",
    "ERR_MA_SIGNATURE_INVALID",
    "ERR_MA_MISSING_ROLLBACK",
    "ERR_MA_CONFIDENCE_LOW",
    "ERR_MA_VERSION_UNSUPPORTED",
]

REQUIRED_INVARIANTS = [
    "INV-MA-SIGNED",
    "INV-MA-ROLLBACK-PRESENT",
    "INV-MA-CONFIDENCE-CALIBRATED",
    "INV-MA-VERSIONED",
    "INV-MA-VERIFIER-COMPLETE",
    "INV-MA-DETERMINISTIC",
]

SCHEMA_REQUIRED_FIELDS = [
    "schema_version",
    "plan_id",
    "plan_version",
    "preconditions",
    "steps",
    "rollback_receipt",
    "confidence_interval",
    "verifier_metadata",
    "signature",
    "content_hash",
    "created_at",
]

# -- Helpers -------------------------------------------------------------------


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read(path))


def _strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = _rust_block_comment_end(text, i + 2)
            continue

        raw_end = _rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = _rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def _rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def _rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


# -- Check functions -----------------------------------------------------------


def _checks() -> list:
    """Return list of {check, passed, detail} dicts."""
    checks = []
    src = _read_rust_source(IMPL_FILE)
    mod_src = _read_rust_source(MOD_FILE)

    # 1. Rust module exists
    checks.append(_check(
        "Rust module exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))

    # 2. Wired into mod.rs
    checks.append(_check(
        "Wired into connector/mod.rs",
        "pub mod migration_artifact;" in mod_src,
        "migration_artifact in mod.rs",
    ))

    # 3. JSON schema exists
    checks.append(_check(
        "JSON schema exists",
        SCHEMA_FILE.exists(),
        str(SCHEMA_FILE),
    ))

    # 4. Reference vectors exist
    checks.append(_check(
        "Reference vectors exist",
        VECTORS_FILE.exists(),
        str(VECTORS_FILE),
    ))

    # 5. Spec exists
    checks.append(_check(
        "Spec contract exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))

    # 6. Test file exists
    checks.append(_check(
        "Test file exists",
        TEST_FILE.exists(),
        str(TEST_FILE),
    ))

    # 7. Evidence exists with PASS verdict
    evidence_pass = False
    if EVIDENCE_FILE.exists():
        try:
            ev = json.JSONDecoder().decode(EVIDENCE_FILE.read_text(encoding="utf-8"))
            evidence_pass = ev.get("verdict") == "PASS"
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Evidence exists with PASS verdict",
        evidence_pass,
        str(EVIDENCE_FILE),
    ))

    # 8. Event codes defined
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code} defined",
            code in src,
        ))

    # 9. Error codes defined
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code} defined",
            code in src,
        ))

    # 10. Invariants defined
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv} defined",
            inv in src,
        ))

    # 11. Required structs/enums
    for s in REQUIRED_STRUCTS:
        found = f"pub struct {s}" in src or f"pub enum {s}" in src
        checks.append(_check(f"Struct/enum {s} defined", found))

    # 12. Schema has required fields
    if SCHEMA_FILE.exists():
        try:
            schema = json.JSONDecoder().decode(SCHEMA_FILE.read_text(encoding="utf-8"))
            schema_props = list(schema.get("properties", {}).keys())
            for field in SCHEMA_REQUIRED_FIELDS:
                checks.append(_check(
                    f"Schema field '{field}'",
                    field in schema_props,
                ))
            # Check $defs
            defs = schema.get("$defs", {})
            for def_name in ["MigrationStep", "RollbackReceipt", "ConfidenceInterval", "VerifierMetadata"]:
                checks.append(_check(
                    f"Schema $def '{def_name}'",
                    def_name in defs,
                ))
        except (json.JSONDecodeError, OSError):
            checks.append(_check("Schema parseable", False, "JSON parse error"))
    else:
        checks.append(_check("Schema parseable", False, "file not found"))

    # 13. Reference artifacts validate against schema (structural check)
    if VECTORS_FILE.exists():
        try:
            vectors = json.JSONDecoder().decode(VECTORS_FILE.read_text(encoding="utf-8"))
            artifacts = vectors.get("artifacts", [])
            checks.append(_check(
                "Reference vectors has artifacts",
                len(artifacts) > 0,
                f"{len(artifacts)} artifacts",
            ))
            for i, art in enumerate(artifacts):
                has_all = all(f in art for f in SCHEMA_REQUIRED_FIELDS)
                checks.append(_check(
                    f"Artifact {i} has required fields",
                    has_all,
                ))
                # Check nested structures
                if "rollback_receipt" in art:
                    rb = art["rollback_receipt"]
                    rb_ok = all(k in rb for k in ["original_state_ref", "rollback_procedure_hash", "max_rollback_time_ms", "signer_identity", "signature"])
                    checks.append(_check(f"Artifact {i} rollback receipt complete", rb_ok))
                if "confidence_interval" in art:
                    ci = art["confidence_interval"]
                    ci_ok = all(k in ci for k in ["probability", "dry_run_success_rate", "historical_similarity", "precondition_coverage", "rollback_validation"])
                    checks.append(_check(f"Artifact {i} confidence interval complete", ci_ok))
                if "verifier_metadata" in art:
                    vm = art["verifier_metadata"]
                    vm_ok = all(k in vm for k in ["replay_capsule_refs", "expected_state_hashes", "assertion_schemas", "verification_procedures"])
                    checks.append(_check(f"Artifact {i} verifier metadata complete", vm_ok))
        except (json.JSONDecodeError, OSError):
            checks.append(_check("Vectors parseable", False, "JSON parse error"))
    else:
        checks.append(_check("Vectors parseable", False, "file not found"))

    # 14. Schema version constant
    checks.append(_check(
        "Schema version ma-v1.0",
        'ma-v1.0' in src,
    ))

    # 15. BTreeMap usage for determinism
    checks.append(_check(
        "BTreeMap usage for determinism",
        "BTreeMap" in src,
    ))

    # 16. Serde derives
    checks.append(_check(
        "Serialize/Deserialize derives",
        "Serialize" in src and "Deserialize" in src,
    ))

    # 17. Tests present
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests ({test_count})",
        test_count >= 30,
        f"{test_count} tests found",
    ))

    # 18. validate_artifact function
    checks.append(_check(
        "validate_artifact function",
        "fn validate_artifact" in src,
    ))

    # 19. generate_reference_artifact function
    checks.append(_check(
        "generate_reference_artifact function",
        "fn generate_reference_artifact" in src,
    ))

    # 20. compute_content_hash function
    checks.append(_check(
        "compute_content_hash function",
        "fn compute_content_hash" in src,
    ))

    # 21. Summary file exists
    checks.append(_check(
        "Verification summary exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))

    return checks


def self_test() -> dict:
    """Internal consistency checks for the gate script itself."""
    checks = []

    # Constants
    checks.append(_check("REQUIRED_STRUCTS >= 8", len(REQUIRED_STRUCTS) >= 8))
    checks.append(_check("REQUIRED_EVENT_CODES == 8", len(REQUIRED_EVENT_CODES) == 8))
    checks.append(_check("REQUIRED_ERROR_CODES == 5", len(REQUIRED_ERROR_CODES) == 5))
    checks.append(_check("REQUIRED_INVARIANTS == 6", len(REQUIRED_INVARIANTS) == 6))
    checks.append(_check("SCHEMA_REQUIRED_FIELDS == 11", len(SCHEMA_REQUIRED_FIELDS) == 11))

    # _checks returns list
    result = _checks()
    checks.append(_check("_checks returns list", isinstance(result, list)))
    checks.append(_check("_checks returns dicts", all(isinstance(c, dict) for c in result)))
    checks.append(_check("_checks >= 30 checks", len(result) >= 30))

    # Check structure
    for c in result[:5]:
        checks.append(_check(
            f"check '{c['check']}' has required keys",
            all(k in c for k in ["check", "passed", "detail"]),
        ))

    # Full run
    full = run_all()
    checks.append(_check("run_all has bead_id", full.get("bead_id") == "bd-3hm"))
    checks.append(_check("run_all has section", full.get("section") == "10.12"))
    checks.append(_check("run_all has verdict", full.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has events", isinstance(full.get("events"), list)))
    checks.append(_check("run_all has summary", isinstance(full.get("summary"), str)))
    checks.append(_check("run_all has timestamp", isinstance(full.get("timestamp"), str)))

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def run_all() -> dict:
    """Run all checks and return structured result."""
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failed == 0 else "FAIL"

    events = []
    for code in REQUIRED_EVENT_CODES:
        events.append({"code": code, "status": "defined"})

    summary_lines = [
        "bd-3hm: Migration Singularity Artifact Contract",
        f"Checks: {passed}/{len(checks)} passing",
        f"Verdict: {verdict}",
    ]
    if failed > 0:
        failing = [c for c in checks if not c["passed"]]
        for c in failing[:5]:
            summary_lines.append(f"  FAIL: {c['check']}: {c['detail']}")

    return {
        "bead_id": "bd-3hm",
        "title": "Migration Singularity Artifact Contract and Verifier Format",
        "section": "10.12",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "events": events,
        "summary": "\n".join(summary_lines),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# -- CLI -----------------------------------------------------------------------


def main():
    configure_test_logging("check_migration_artifacts")
    if "--self-test" in sys.argv:
        result = self_test()
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {result['passed']}/{result['total']} {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
