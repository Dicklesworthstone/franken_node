#!/usr/bin/env python3
"""bd-3j4: Verification script for end-to-end migration singularity pipeline.

Usage:
    python3 scripts/check_migration_pipeline.py           # human-readable
    python3 scripts/check_migration_pipeline.py --json     # machine-readable
    python3 scripts/check_migration_pipeline.py --self-test # internal consistency
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


# -- File paths ----------------------------------------------------------------

IMPL_FILE = ROOT / "crates/franken-node/src/connector/migration_pipeline.rs"
MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_12/bd-3j4_contract.md"
TEST_FILE = ROOT / "tests/test_check_migration_pipeline.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_12/bd-3j4/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_12/bd-3j4/verification_summary.md"

# -- Required elements ---------------------------------------------------------

REQUIRED_STAGE_TYPES = [
    "Intake",
    "Analysis",
    "PlanGeneration",
    "PlanReview",
    "Execution",
    "Verification",
    "ReceiptIssuance",
    "Complete",
    "Rollback",
]

REQUIRED_STRUCTS = [
    "PipelineState",
    "CohortDefinition",
    "ExtensionSpec",
    "CompatibilityReport",
    "MigrationPlan",
    "TransformationStep",
    "ExecutionTrace",
    "VerificationReport",
    "MigrationReceipt",
    "CohortSummary",
    "PipelineError",
    "PipelineEvent",
    "StageTransition",
]

REQUIRED_PIPELINE_OPS = [
    "fn new(",
    "fn advance(",
    "fn rollback(",
    "fn is_idempotent(",
]

REQUIRED_EVENT_CODES = [
    "PIPE-001",
    "PIPE-002",
    "PIPE-003",
    "PIPE-004",
    "PIPE-005",
    "PIPE-006",
    "PIPE-007",
    "PIPE-008",
    "PIPE-009",
    "PIPE-010",
    "PIPE-011",
    "PIPE-012",
    "PIPE-013",
]

REQUIRED_ERROR_CODES = [
    "ERR_PIPE_INVALID_TRANSITION",
    "ERR_PIPE_VERIFICATION_FAILED",
    "ERR_PIPE_IDEMPOTENCY_VIOLATED",
    "ERR_PIPE_ROLLBACK_FAILED",
    "ERR_PIPE_THRESHOLD_NOT_MET",
    "ERR_PIPE_DUPLICATE_EXTENSION",
]

REQUIRED_INVARIANTS = [
    "INV-PIPE-DETERMINISTIC",
    "INV-PIPE-IDEMPOTENT",
    "INV-PIPE-THRESHOLD-ENFORCED",
    "INV-PIPE-ROLLBACK-ANY-STAGE",
    "INV-PIPE-RECEIPT-SIGNED",
    "INV-PIPE-STAGE-MONOTONIC",
]

# -- Helpers -------------------------------------------------------------------


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


# -- Check functions -----------------------------------------------------------


def _checks() -> list:
    """Return list of {check, passed, detail} dicts."""
    checks = []
    src = _read(IMPL_FILE)
    mod_src = _read(MOD_FILE)

    # 1. Rust module exists
    checks.append(_check(
        "Rust module exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))

    # 2. Wired into mod.rs
    checks.append(_check(
        "Wired into connector/mod.rs",
        "pub mod migration_pipeline;" in mod_src,
        "migration_pipeline in mod.rs",
    ))

    # 3. Spec exists
    checks.append(_check(
        "Spec contract exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))

    # 4. Test file exists
    checks.append(_check(
        "Test file exists",
        TEST_FILE.exists(),
        str(TEST_FILE),
    ))

    # 5. Evidence exists with PASS verdict
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

    # 6. All stage types defined
    for stage in REQUIRED_STAGE_TYPES:
        checks.append(_check(
            f"Stage type {stage} defined",
            stage in src,
        ))

    # 7. Pipeline operations defined
    for op in REQUIRED_PIPELINE_OPS:
        checks.append(_check(
            f"Pipeline operation '{op.strip()}' defined",
            op in src,
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

    # 12. PipelineStage enum
    checks.append(_check(
        "PipelineStage enum defined",
        "pub enum PipelineStage" in src,
    ))

    # 13. TransformAction enum
    checks.append(_check(
        "TransformAction enum defined",
        "pub enum TransformAction" in src,
    ))

    # 14. Schema version pipe-v1.0
    checks.append(_check(
        "Schema version pipe-v1.0",
        'pipe-v1.0' in src,
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

    # 17. Tests present (>= 25)
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests ({test_count})",
        test_count >= 25,
        f"{test_count} tests found",
    ))

    # 18. Deterministic test
    checks.append(_check(
        "Deterministic pipeline test",
        "test_deterministic" in src,
    ))

    # 19. Idempotency test
    checks.append(_check(
        "Idempotency test",
        "test_idempotency" in src or "idempotent" in src.lower(),
    ))

    # 20. Rollback test
    checks.append(_check(
        "Rollback test",
        "test_rollback" in src,
    ))

    # 21. 95% threshold test
    checks.append(_check(
        "95% threshold test",
        "test_verification_threshold" in src,
    ))

    # 22. Receipt signing test
    checks.append(_check(
        "Receipt signing test",
        "test_receipt_signed" in src,
    ))

    # 23. Summary file exists
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
    checks.append(_check("REQUIRED_STAGE_TYPES == 9", len(REQUIRED_STAGE_TYPES) == 9))
    checks.append(_check("REQUIRED_STRUCTS >= 12", len(REQUIRED_STRUCTS) >= 12))
    checks.append(_check("REQUIRED_PIPELINE_OPS == 4", len(REQUIRED_PIPELINE_OPS) == 4))
    checks.append(_check("REQUIRED_EVENT_CODES == 13", len(REQUIRED_EVENT_CODES) == 13))
    checks.append(_check("REQUIRED_ERROR_CODES == 6", len(REQUIRED_ERROR_CODES) == 6))
    checks.append(_check("REQUIRED_INVARIANTS == 6", len(REQUIRED_INVARIANTS) == 6))

    # _checks returns list
    result = _checks()
    checks.append(_check("_checks returns list", isinstance(result, list)))
    checks.append(_check("_checks returns dicts", all(isinstance(c, dict) for c in result)))
    checks.append(_check("_checks >= 20 checks", len(result) >= 20))

    # Check structure
    for c in result[:5]:
        checks.append(_check(
            f"check '{c['check']}' has required keys",
            all(k in c for k in ["check", "passed", "detail"]),
        ))

    # Full run
    full = run_all()
    checks.append(_check("run_all has bead_id", full.get("bead_id") == "bd-3j4"))
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
        "bd-3j4: End-to-End Migration Singularity Pipeline",
        f"Checks: {passed}/{len(checks)} passing",
        f"Verdict: {verdict}",
    ]
    if failed > 0:
        failing = [c for c in checks if not c["passed"]]
        for c in failing[:5]:
            summary_lines.append(f"  FAIL: {c['check']}: {c['detail']}")

    return {
        "bead_id": "bd-3j4",
        "title": "End-to-End Migration Singularity Pipeline for Pilot Cohorts",
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
    configure_test_logging("check_migration_pipeline")
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
