#!/usr/bin/env python3
"""bd-1xbc: Deterministic time-travel runtime capture/replay -- verification gate.

Usage:
    python scripts/check_time_travel_replay.py            # human-readable
    python scripts/check_time_travel_replay.py --json     # machine-readable JSON
    python scripts/check_time_travel_replay.py --self-test # self-test mode

Implementation lives at crates/franken-node/src/replay/time_travel_engine.rs
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


# Implementation is in the replay/ subdirectory, not runtime/
SRC = ROOT / "crates" / "franken-node" / "src" / "replay" / "time_travel_engine.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "replay" / "mod.rs"
MAIN = ROOT / "crates" / "franken-node" / "src" / "main.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_17" / "bd-1xbc_contract.md"
TEST_SUITE = ROOT / "tests" / "test_check_time_travel_replay.py"
EVIDENCE = ROOT / "artifacts" / "section_10_17" / "bd-1xbc" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_17" / "bd-1xbc" / "verification_summary.md"

BEAD = "bd-1xbc"
SECTION = "10.17"

# Event codes use dashes (TTR-001) matching the Rust const values
EVENT_CODES = [
    "TTR-001", "TTR-002", "TTR-003", "TTR-004", "TTR-005",
    "TTR-006", "TTR-007", "TTR-008", "TTR-009", "TTR-010",
]

ERROR_CODES = [
    "ERR_TTR_EMPTY_TRACE",
    "ERR_TTR_SEQ_GAP",
    "ERR_TTR_DIGEST_MISMATCH",
    "ERR_TTR_ENV_MISSING",
    "ERR_TTR_REPLAY_FAILED",
    "ERR_TTR_DUPLICATE_TRACE",
    "ERR_TTR_STEP_ORDER_VIOLATION",
    "ERR_TTR_TRACE_NOT_FOUND",
]

INVARIANTS = [
    "INV-TTR-DETERMINISM",
    "INV-TTR-DIVERGENCE-DETECT",
    "INV-TTR-TRACE-COMPLETE",
    "INV-TTR-STEP-ORDER",
    "INV-TTR-ENV-SEALED",
    "INV-TTR-AUDIT-COMPLETE",
]


def _safe_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "passed": passed, "detail": detail or ("found" if passed else "missing")}


def _read(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text()


def _checks() -> list:
    results = []
    src = _read(SRC)
    mod_src = _read(MOD)
    main_src = _read(MAIN)

    # --- File existence ---
    results.append(_check("source file exists", SRC.exists(), _safe_rel(SRC)))
    results.append(_check("module wired in replay/mod.rs",
                          "pub mod time_travel_engine;" in mod_src,
                          "replay/mod.rs contains pub mod time_travel_engine"))
    
    lib_src = _read(ROOT / "crates" / "franken-node" / "src" / "lib.rs")
    results.append(_check("replay module wired in lib.rs",
                          "pub mod replay;" in lib_src,
                          "lib.rs contains pub mod replay"))
    
    results.append(_check("spec contract exists", SPEC.exists(), _safe_rel(SPEC)))
    results.append(_check("test suite exists", TEST_SUITE.exists(), _safe_rel(TEST_SUITE)))
    results.append(_check("verification evidence exists", EVIDENCE.exists(), _safe_rel(EVIDENCE)))
    results.append(_check("verification summary exists", SUMMARY.exists(), _safe_rel(SUMMARY)))

    # --- Key types ---
    results.append(_check("WorkflowTrace struct", "struct WorkflowTrace" in src))
    results.append(_check("TraceStep struct", "struct TraceStep" in src))
    results.append(_check("EnvironmentSnapshot struct", "struct EnvironmentSnapshot" in src))
    results.append(_check("SideEffect struct", "struct SideEffect" in src))
    results.append(_check("TraceBuilder struct", "struct TraceBuilder" in src))
    results.append(_check("ReplayEngine struct", "struct ReplayEngine" in src))
    results.append(_check("ReplayResult struct", "struct ReplayResult" in src))
    results.append(_check("ReplayVerdict enum", "enum ReplayVerdict" in src))
    results.append(_check("Divergence struct", "struct Divergence" in src))
    results.append(_check("DivergenceKind enum", "enum DivergenceKind" in src))
    results.append(_check("TimeTravelError enum", "enum TimeTravelError" in src))
    results.append(_check("AuditEntry struct", "struct AuditEntry" in src))

    # --- Key methods ---
    results.append(_check("compute_digest method", "fn compute_digest" in src))
    results.append(_check("validate method", "fn validate" in src))
    results.append(_check("record_step method", "fn record_step" in src))
    results.append(_check("register_trace method", "fn register_trace" in src))
    results.append(_check("replay method", "fn replay(" in src))
    results.append(_check("replay_identity method", "fn replay_identity" in src))
    results.append(_check("identity_replay function", "fn identity_replay" in src))
    results.append(_check("build method", "fn build(" in src))
    results.append(_check("output_digest method", "fn output_digest" in src))
    results.append(_check("side_effects_digest method", "fn side_effects_digest" in src))

    # --- Event codes ---
    ec_found = sum(1 for ec in EVENT_CODES if ec in src)
    results.append(_check(
        f"event codes ({ec_found}/{len(EVENT_CODES)})",
        ec_found == len(EVENT_CODES),
        f"{ec_found}/{len(EVENT_CODES)}"))

    # --- Error codes ---
    err_found = sum(1 for ec in ERROR_CODES if ec in src)
    results.append(_check(
        f"error codes ({err_found}/{len(ERROR_CODES)})",
        err_found == len(ERROR_CODES),
        f"{err_found}/{len(ERROR_CODES)}"))

    # --- Invariant constants ---
    inv_found = sum(1 for inv in INVARIANTS if inv in src)
    results.append(_check(
        f"invariant constants ({inv_found}/{len(INVARIANTS)})",
        inv_found == len(INVARIANTS),
        f"{inv_found}/{len(INVARIANTS)}"))

    # --- Schema version ---
    results.append(_check("schema version ttr-v1.0", "ttr-v1.0" in src))

    # --- Serde derives ---
    results.append(_check("Serialize/Deserialize derives",
                          "Serialize" in src and "Deserialize" in src))

    # --- BTreeMap usage ---
    results.append(_check("BTreeMap for deterministic ordering",
                          "BTreeMap" in src))

    # --- SHA-256 digest ---
    results.append(_check("SHA-256 digest computation",
                          "Sha256" in src and "sha2" in src))

    # --- Unit tests ---
    test_count = len(re.findall(r"#\[test\]", src))
    results.append(_check(f"unit tests >= 25 ({test_count})", test_count >= 25, f"{test_count} tests"))

    # --- cfg(test) module ---
    results.append(_check("#[cfg(test)] module", "#[cfg(test)]" in src))

    # --- Divergence kinds ---
    results.append(_check("OutputMismatch variant", "OutputMismatch" in src))
    results.append(_check("SideEffectMismatch variant", "SideEffectMismatch" in src))
    results.append(_check("FullMismatch variant", "FullMismatch" in src))

    # --- ReplayVerdict variants ---
    results.append(_check("Identical verdict variant", "Identical" in src))
    results.append(_check("Diverged verdict variant", "Diverged" in src))

    return results


def self_test():
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    return {
        "name": "time_travel_replay_verification",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": len(checks) - passed,
        "checks": checks,
        "verdict": "PASS" if all(c["passed"] for c in checks) else "FAIL",
    }


def run_all() -> dict:
    """Alias for run_checks for compatibility."""
    return run_checks()


def run_checks() -> dict:
    checks = _checks()
    passing = sum(1 for c in checks if c["passed"])
    failing = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "schema_version": "time-travel-replay-v1.0",
        "bead_id": BEAD,
        "title": "Deterministic time-travel runtime capture/replay for extension-host workflows",
        "section": SECTION,
        "overall_pass": failing == 0,
        "verdict": verdict,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "total": passing + failing,
        "passed": passing,
        "failed": failing,
        "checks": checks,
        "events": EVENT_CODES,
        "event_codes": EVENT_CODES,
        "error_codes": ERROR_CODES,
        "invariants": INVARIANTS,
    }


def main():
    logger = configure_test_logging("check_time_travel_replay")
    if "--self-test" in sys.argv:
        result = self_test()
        if result["verdict"] == "PASS":
            print("self_test passed")
            sys.exit(0)
        else:
            failures = [c for c in result["checks"] if not c["passed"]]
            detail = "; ".join(f"{c['check']}: {c['detail']}" for c in failures[:5])
            print(f"self_test failed: {detail}")
            sys.exit(1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["overall_pass"] else 1)

    for c in result["checks"]:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"  [{status}] {c['check']}: {c['detail']}")

    passing = result["summary"]["passing"]
    total = result["summary"]["total"]
    print(f"\n{BEAD} verification: {result['verdict']} ({passing}/{total} checks pass)")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
