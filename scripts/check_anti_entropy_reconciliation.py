#!/usr/bin/env python3
"""Verification script for bd-390: Anti-Entropy Reconciliation.

Checks:
  - Specification document exists and contains required sections
  - Rust module exists with required types, methods, event codes, invariants
  - Module registered in runtime/mod.rs
  - >= 30 Rust unit tests
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD_ID = "bd-390"
SECTION = "10.11"
TITLE = "Anti-Entropy Reconciliation"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_11" / "bd-390_contract.md"
RUST_MODULE = ROOT / "crates" / "franken-node" / "src" / "runtime" / "anti_entropy.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
REPLACEMENT_BEAD_ID = "bd-23x2"
COMPLETION_DEBT_BEAD = "bd-23x2.1"
REPLACEMENT_EVIDENCE_DIR = ROOT / "artifacts" / "replacement_gap" / REPLACEMENT_BEAD_ID
REPLACEMENT_EVIDENCE = REPLACEMENT_EVIDENCE_DIR / "verification_evidence.json"
REPLACEMENT_SUMMARY = REPLACEMENT_EVIDENCE_DIR / "verification_summary.md"
DIVERGENCE_FIXTURE_INDEX = REPLACEMENT_EVIDENCE_DIR / "divergence_fixture_index.json"
OPERATOR_E2E = ROOT / "tests" / "e2e" / "anti_entropy_operator_suite.sh"
OPERATOR_LOG = REPLACEMENT_EVIDENCE_DIR / "operator_e2e_log.jsonl"
OPERATOR_SUMMARY_JSON = REPLACEMENT_EVIDENCE_DIR / "operator_e2e_summary.json"
OPERATOR_SUMMARY_MD = REPLACEMENT_EVIDENCE_DIR / "operator_e2e_summary.md"
MMR_CONFORMANCE_TEST = ROOT / "tests" / "conformance" / "mmr_proof_verification.rs"
MARKER_DIVERGENCE_TEST = ROOT / "tests" / "integration" / "marker_divergence_detection.rs"
MMR_E2E_TEST = ROOT / "crates" / "franken-node" / "tests" / "e2e_mmr_proofs_lifecycle.rs"
MARKER_STREAM_E2E_TEST = ROOT / "crates" / "franken-node" / "tests" / "e2e_marker_stream_lifecycle.rs"

COMPLETION_DEBT_REQUIRED_SPEC_ITEMS = {
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
}
REQUIRED_TELEMETRY_FIELDS = [
    "trace_id",
    "peer_id",
    "epoch",
    "root_digest",
    "delta_mode",
    "proof_mode",
    "decision",
    "reason_code",
    "certificate_id",
]
COMPLETION_DEBT_OBLIGATIONS = [
    {
        "spec_item": "tests.unit.primary",
        "category": "unit",
        "status": "covered",
        "description": "static checker and Python tests cover canonical anti-entropy verifier wiring, completion-debt evidence drift, and missing-evidence failure modes",
        "evidence_paths": [
            "scripts/check_anti_entropy_reconciliation.py",
            "tests/test_check_anti_entropy_reconciliation.py",
            "crates/franken-node/src/runtime/anti_entropy.rs",
        ],
        "commands": [
            "python3 scripts/check_anti_entropy_reconciliation.py --json",
            "python3 scripts/check_anti_entropy_reconciliation.py --self-test",
            "python3 -m pytest -q tests/test_check_anti_entropy_reconciliation.py",
        ],
    },
    {
        "spec_item": "tests.integration.primary",
        "category": "integration",
        "status": "covered",
        "description": "cargo-visible conformance and integration suites exercise canonical MMR inclusion proof verification and exact divergence-boundary detection",
        "evidence_paths": [
            "tests/conformance/mmr_proof_verification.rs",
            "tests/integration/marker_divergence_detection.rs",
            "crates/franken-node/tests/e2e_mmr_proofs_lifecycle.rs",
            "crates/franken-node/tests/e2e_marker_stream_lifecycle.rs",
        ],
        "commands": [
            "rch exec -- cargo test -p frankenengine-node --test mmr_proof_verification",
            "rch exec -- cargo test -p frankenengine-node --test marker_divergence_detection",
            "rch exec -- cargo test -p frankenengine-node --test e2e_mmr_proofs_lifecycle",
            "rch exec -- cargo test -p frankenengine-node --test e2e_marker_stream_lifecycle",
        ],
    },
    {
        "spec_item": "tests.e2e.primary",
        "category": "e2e",
        "status": "covered",
        "description": "operator shell harness runs the anti-entropy checker end to end and emits partition/proof-failure/certificate/reconvergence telemetry artifacts",
        "evidence_paths": [
            "tests/e2e/anti_entropy_operator_suite.sh",
            "artifacts/replacement_gap/bd-23x2/operator_e2e_log.jsonl",
            "artifacts/replacement_gap/bd-23x2/operator_e2e_summary.json",
            "artifacts/replacement_gap/bd-23x2/operator_e2e_summary.md",
            "artifacts/replacement_gap/bd-23x2/divergence_fixture_index.json",
        ],
        "required_fields": REQUIRED_TELEMETRY_FIELDS,
        "commands": [
            "tests/e2e/anti_entropy_operator_suite.sh",
        ],
    },
]

EVENT_CODES = [
    "FN-AE-001", "FN-AE-002", "FN-AE-003", "FN-AE-004",
    "FN-AE-005", "FN-AE-006", "FN-AE-007", "FN-AE-008",
]

INVARIANTS = [
    "INV-AE-DELTA",
    "INV-AE-ATOMIC",
    "INV-AE-EPOCH",
    "INV-AE-PROOF",
]

ERROR_CODES = [
    "ERR_AE_INVALID_CONFIG",
    "ERR_AE_EPOCH_VIOLATION",
    "ERR_AE_PROOF_INVALID",
    "ERR_AE_FORK_DETECTED",
    "ERR_AE_CANCELLED",
    "ERR_AE_BATCH_EXCEEDED",
]

REQUIRED_STRUCTS = [
    "ReconciliationConfig",
    "TrustRecord",
    "TrustState",
    "ReconciliationResult",
    "ReconciliationEvent",
    "ReconciliationError",
    "AntiEntropyReconciler",
]

REQUIRED_METHODS = [
    "new",
    "validate",
    "compute_delta",
    "detect_fork",
    "reconcile",
    "events",
    "reconciliation_count",
    "insert",
    "root_digest",
    "current_epoch",
    "record_ids",
    "verify_mmr_proof",
    "digest",
]

MIN_TEST_COUNT = 30


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


# ── Spec checks ──────────────────────────────────────────────────────────

def check_spec_exists() -> dict:
    ok = SPEC_PATH.is_file()
    return _check("spec_exists", ok,
                   f"{SPEC_PATH.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_spec_event(code: str) -> dict:
    text = _read(SPEC_PATH)
    ok = code in text
    return _check(f"spec_event:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in spec")


def check_spec_invariant(inv: str) -> dict:
    text = _read(SPEC_PATH)
    ok = inv in text
    return _check(f"spec_invariant:{inv}", ok,
                  f"{inv} {'found' if ok else 'MISSING'} in spec")


def check_spec_error(code: str) -> dict:
    text = _read(SPEC_PATH)
    ok = code in text
    return _check(f"spec_error:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in spec")


# ── Rust checks ──────────────────────────────────────────────────────────

def check_rust_module_exists() -> dict:
    ok = RUST_MODULE.is_file()
    return _check("rust_module_exists", ok,
                   f"{RUST_MODULE.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_rust_module_registered() -> dict:
    text = _read(MOD_RS)
    ok = "pub mod anti_entropy;" in text
    return _check("rust_module_registered", ok,
                   f"pub mod anti_entropy; {'found' if ok else 'MISSING'} in mod.rs")


def check_rust_struct(name: str) -> dict:
    text = _read(RUST_MODULE)
    patterns = [
        rf"pub\s+struct\s+{name}\b",
        rf"pub\s+enum\s+{name}\b",
        rf"struct\s+{name}\b",
    ]
    ok = any(re.search(p, text) for p in patterns)
    return _check(f"rust_struct:{name}", ok,
                  f"{name} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_method(name: str) -> dict:
    text = _read(RUST_MODULE)
    ok = bool(re.search(rf"fn\s+{name}\b", text))
    return _check(f"rust_method:{name}", ok,
                  f"fn {name} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_event(code: str) -> dict:
    text = _read(RUST_MODULE)
    ok = code in text
    return _check(f"rust_event:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_invariant(inv: str) -> dict:
    text = _read(RUST_MODULE)
    ok = inv in text
    return _check(f"rust_invariant:{inv}", ok,
                  f"{inv} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_error(code: str) -> dict:
    text = _read(RUST_MODULE)
    ok = code in text
    return _check(f"rust_error:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_test_count() -> dict:
    text = _read(RUST_MODULE)
    tests = re.findall(r"#\[test\]", text)
    count = len(tests)
    ok = count >= MIN_TEST_COUNT
    return _check("rust_test_count", ok,
                  f"{count} tests (>= {MIN_TEST_COUNT} required)")


def check_rust_two_phase() -> dict:
    text = _read(RUST_MODULE)
    ok = "phase" in text.lower() or "atomic" in text.lower()
    return _check("rust_two_phase", ok,
                  f"Two-phase/atomic logic {'found' if ok else 'MISSING'}")


def check_rust_cancellation() -> dict:
    text = _read(RUST_MODULE)
    ok = "cancel" in text.lower()
    return _check("rust_cancellation", ok,
                  f"Cancellation support {'found' if ok else 'MISSING'}")


def check_rust_mmr_proof() -> dict:
    text = _read(RUST_MODULE)
    ok = "mmr_proof" in text
    return _check("rust_mmr_proof", ok,
                  f"MMR proof handling {'found' if ok else 'MISSING'}")


def check_rust_epoch_enforcement() -> dict:
    text = _read(RUST_MODULE)
    ok = "epoch" in text and "current_epoch" in text
    return _check("rust_epoch_enforcement", ok,
                  f"Epoch enforcement {'found' if ok else 'MISSING'}")


def check_canonical_mmr_verifier() -> dict:
    text = _read(RUST_MODULE)
    checks = [
        "use crate::control_plane::mmr_proofs" in text,
        "mmr_proofs::verify_inclusion(" in text,
        "let computed_marker_hash = hex::encode(record.digest())" in text,
        "record.inclusion_proof" in text,
        "ReconciliationError::ProofInvalid" in text,
    ]
    ok = all(checks)
    return _check(
        "bd_23x2_canonical_mmr_verifier",
        ok,
        f"Canonical MMR verifier wiring: {sum(checks)}/5 checks",
    )


def check_replacement_evidence_files() -> dict:
    required = [
        REPLACEMENT_EVIDENCE,
        REPLACEMENT_SUMMARY,
        DIVERGENCE_FIXTURE_INDEX,
        OPERATOR_E2E,
        OPERATOR_LOG,
        OPERATOR_SUMMARY_JSON,
        OPERATOR_SUMMARY_MD,
        MMR_CONFORMANCE_TEST,
        MARKER_DIVERGENCE_TEST,
        MMR_E2E_TEST,
        MARKER_STREAM_E2E_TEST,
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    ok = not missing
    detail = (
        f"All {len(required)} bd-23x2 evidence files present"
        if ok
        else f"Missing evidence files: {missing}"
    )
    return _check("bd_23x2_evidence_files", ok, detail)


def check_operator_e2e_telemetry() -> dict:
    texts = []
    for path in (OPERATOR_E2E, OPERATOR_LOG, OPERATOR_SUMMARY_JSON):
        if path.exists():
            texts.append(_read(path))
    combined = "\n".join(texts)
    missing_fields = [field for field in REQUIRED_TELEMETRY_FIELDS if field not in combined]
    missing_families = [
        family
        for family in (
            "ANTI_ENTROPY_PARTITION_",
            "ANTI_ENTROPY_PROOF_",
            "ANTI_ENTROPY_CERTIFICATE_",
            "ANTI_ENTROPY_RECONVERGENCE_",
        )
        if family not in combined
    ]
    ok = not missing_fields and not missing_families
    detail = (
        "Anti-entropy operator E2E telemetry contract present"
        if ok
        else json.dumps(
            {"missing_fields": missing_fields, "missing_event_families": missing_families},
            sort_keys=True,
        )
    )
    return _check("bd_23x2_operator_e2e_telemetry", ok, detail)


def check_completion_debt_coverage() -> dict:
    coverage_by_item = {
        obligation.get("spec_item"): obligation
        for obligation in COMPLETION_DEBT_OBLIGATIONS
        if isinstance(obligation, dict)
    }
    missing_items = sorted(COMPLETION_DEBT_REQUIRED_SPEC_ITEMS - set(coverage_by_item))
    noncovered_items = sorted(
        str(item)
        for item, obligation in coverage_by_item.items()
        if obligation.get("status") != "covered"
    )
    missing_paths: list[str] = []
    for obligation in coverage_by_item.values():
        for rel_path in obligation.get("evidence_paths", []):
            if isinstance(rel_path, str) and not (ROOT / rel_path).exists():
                missing_paths.append(rel_path)
    ok = not missing_items and not noncovered_items and not missing_paths
    detail = (
        "all bd-23x2.1 completion-debt obligations covered"
        if ok
        else json.dumps(
            {
                "missing_items": missing_items,
                "noncovered_items": noncovered_items,
                "missing_paths": sorted(missing_paths),
            },
            sort_keys=True,
        )
    )
    return _check("bd_23x2_1_completion_debt", ok, detail)


def completion_debt_contract() -> dict:
    return {
        "parent_bead": REPLACEMENT_BEAD_ID,
        "completion_bead": COMPLETION_DEBT_BEAD,
        "required_spec_items": sorted(COMPLETION_DEBT_REQUIRED_SPEC_ITEMS),
        "coverage_obligations": COMPLETION_DEBT_OBLIGATIONS,
    }


# ── Run all checks ───────────────────────────────────────────────────────

def run_all() -> dict:
    checks = []

    # Spec checks
    checks.append(check_spec_exists())
    for code in EVENT_CODES:
        checks.append(check_spec_event(code))
    for inv in INVARIANTS:
        checks.append(check_spec_invariant(inv))
    for code in ERROR_CODES:
        checks.append(check_spec_error(code))

    # Rust checks
    checks.append(check_rust_module_exists())
    checks.append(check_rust_module_registered())
    for s in REQUIRED_STRUCTS:
        checks.append(check_rust_struct(s))
    for m in REQUIRED_METHODS:
        checks.append(check_rust_method(m))
    for code in EVENT_CODES:
        checks.append(check_rust_event(code))
    for inv in INVARIANTS:
        checks.append(check_rust_invariant(inv))
    for code in ERROR_CODES:
        checks.append(check_rust_error(code))
    checks.append(check_rust_test_count())
    checks.append(check_rust_two_phase())
    checks.append(check_rust_cancellation())
    checks.append(check_rust_mmr_proof())
    checks.append(check_rust_epoch_enforcement())
    checks.append(check_canonical_mmr_verifier())
    checks.append(check_replacement_evidence_files())
    checks.append(check_operator_e2e_telemetry())
    checks.append(check_completion_debt_coverage())

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    total = len(checks)
    summary = {"passing": passed, "failing": failed, "total": total}

    return {
        "bead_id": BEAD_ID,
        "replacement_bead_id": REPLACEMENT_BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": total,
        "summary": summary,
        "completion_debt": completion_debt_contract(),
        "verdict": "PASS" if failed == 0 else "FAIL",
        "all_passed": failed == 0,
        "status": "pass" if failed == 0 else "fail",
    }


def self_test() -> bool:
    """Smoke test: ensure run_all returns a valid structure."""
    result = run_all()
    return (
        isinstance(result, dict)
        and "checks" in result
        and "verdict" in result
        and isinstance(result["checks"], list)
        and all(
            "name" in c and "passed" in c and "detail" in c
            for c in result["checks"]
        )
    )


def main():
    configure_test_logging("check_anti_entropy_reconciliation")
    import argparse
    parser = argparse.ArgumentParser(description=f"Verify {BEAD_ID}")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        print("self_test passed" if ok else "self_test FAILED")
        sys.exit(0 if ok else 1)

    result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-390 Anti-Entropy Reconciliation — {result['verdict']}"
              f" ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
