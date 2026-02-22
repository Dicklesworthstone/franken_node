#!/usr/bin/env python3
"""Verification script for bd-1u8m: VEF backend-agnostic proof service."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "crates" / "franken-node" / "src" / "vef" / "proof_service.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
INTEGRATION_TEST = ROOT / "crates" / "franken-node" / "tests" / "vef_proof_service.rs"
DOC = ROOT / "docs" / "specs" / "vef_proof_service_contract.md"
CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-1u8m_contract.md"
MATRIX = ROOT / "artifacts" / "10.18" / "vef_proof_service_matrix.json"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-1u8m" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-1u8m" / "verification_summary.md"
CHECKER_TEST = ROOT / "tests" / "test_check_vef_proof_service.py"

REQUIRED_EVENT_CODES = [
    "VEF-PROOF-001",
    "VEF-PROOF-002",
    "VEF-PROOF-003",
    "VEF-PROOF-ERR-001",
    "VEF-PROOF-ERR-002",
    "VEF-PROOF-ERR-003",
    "VEF-PROOF-ERR-004",
]

REQUIRED_ERROR_CODES = [
    "ERR-VEF-PROOF-TIMEOUT",
    "ERR-VEF-PROOF-BACKEND-CRASH",
    "ERR-VEF-PROOF-MALFORMED-OUTPUT",
    "ERR-VEF-PROOF-BACKEND-UNAVAILABLE",
    "ERR-VEF-PROOF-INPUT",
    "ERR-VEF-PROOF-VERIFY",
]

REQUIRED_SYMBOLS = [
    "pub struct ProofInputEnvelope",
    "pub struct ProofOutputEnvelope",
    "pub struct ProofServiceConfig",
    "pub struct VefProofService",
    "pub struct ProofServiceError",
    "pub struct ProofServiceEvent",
    "pub enum ProofBackendId",
    "pub trait ProofBackend",
    "pub fn from_scheduler_job",
    "pub fn commitment_hash",
    "pub fn validate_against",
    "pub fn generate_proof",
    "pub fn verify_proof",
]

RESULTS: list[dict[str, Any]] = []


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _safe_rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if str(path).startswith(str(ROOT)) else str(path)


def _check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append({
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("ok" if passed else "NOT FOUND"),
    })


def _load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def check_presence() -> None:
    files = [
        ("impl_exists", IMPL),
        ("mod_exists", MOD),
        ("integration_test_exists", INTEGRATION_TEST),
        ("doc_exists", DOC),
        ("contract_exists", CONTRACT),
        ("matrix_exists", MATRIX),
        ("evidence_exists", EVIDENCE),
        ("summary_exists", SUMMARY),
        ("checker_test_exists", CHECKER_TEST),
    ]
    for name, path in files:
        _check(name, path.is_file(), _safe_rel(path))


def check_impl() -> None:
    src = _read(IMPL)
    for symbol in REQUIRED_SYMBOLS:
        _check(f"impl_symbol_{symbol}", symbol in src, symbol)

    _check("impl_schema_version", "vef-proof-service-v1" in src, "vef-proof-service-v1")
    _check(
        "impl_has_reference_backends",
        "HashAttestationBackend" in src and "DoubleHashAttestationBackend" in src,
        "two reference backends",
    )
    _check("impl_has_backend_swap_test_hint", "backend_swap" in src.lower(), "backend swap")
    _check(
        "impl_has_simulated_failure_modes",
        all(token in src for token in ("timeout", "crash", "malformed_output")),
        "timeout/crash/malformed_output",
    )

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_{code}", code in src, code)
    for code in REQUIRED_ERROR_CODES:
        _check(f"impl_error_{code}", code in src, code)

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 10, f"{test_count} tests")


def check_wiring() -> None:
    mod_text = _read(MOD)
    _check("mod_wires_proof_service", "pub mod proof_service;" in mod_text, "pub mod proof_service;")


def check_docs() -> None:
    doc = _read(DOC).lower()
    contract = _read(CONTRACT).lower()
    _check("doc_mentions_bead", "bd-1u8m" in doc, "bd-1u8m")
    _check("doc_mentions_backend_agnostic", "backend-agnostic" in doc, "backend-agnostic")
    _check("doc_mentions_fail_closed", "fail-closed" in doc, "fail-closed")
    _check("doc_mentions_trace", "trace" in doc, "trace")
    _check("contract_mentions_acceptance", "acceptance" in contract, "acceptance")
    _check("contract_mentions_validation", "validation" in contract, "validation")


def check_matrix() -> None:
    matrix = _load_json(MATRIX)
    if matrix is None:
        _check("matrix_parseable_json", False, "invalid or missing JSON")
        return

    _check("matrix_parseable_json", True, "valid JSON")
    _check("matrix_bead_id", matrix.get("bead_id") == "bd-1u8m", str(matrix.get("bead_id")))
    _check("matrix_section", matrix.get("section") == "10.18", str(matrix.get("section")))

    backends = matrix.get("backends", [])
    _check("matrix_backends_list", isinstance(backends, list) and len(backends) >= 2, str(len(backends)))
    backend_ids = {backend.get("backend_id") for backend in backends if isinstance(backend, dict)}
    _check(
        "matrix_backend_id_coverage",
        {"hash_attestation_v1", "double_hash_attestation_v1"}.issubset(backend_ids),
        str(sorted(backend_ids)),
    )


def check_evidence_summary() -> None:
    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check("evidence_bead_id", evidence.get("bead_id") == "bd-1u8m", str(evidence.get("bead_id")))
        _check(
            "evidence_verdict_domain",
            evidence.get("verdict") in ("PASS", "FAIL", "PENDING"),
            str(evidence.get("verdict")),
        )
        _check("evidence_checks_list", isinstance(evidence.get("checks"), list), "checks list")

    summary = _read(SUMMARY)
    _check("summary_mentions_bead", "bd-1u8m" in summary.lower(), "bd-1u8m")
    _check("summary_mentions_verdict", any(x in summary for x in ("PASS", "FAIL", "PENDING")), "verdict")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_presence()
    check_impl()
    check_wiring()
    check_docs()
    check_matrix()
    check_evidence_summary()

    total = len(RESULTS)
    passed = sum(1 for row in RESULTS if row["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-1u8m",
        "title": "VEF backend-agnostic proof generation service",
        "section": "10.18",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append({
            "check": name,
            "pass": bool(ok),
            "detail": detail or ("ok" if ok else "FAIL"),
        })

    push("event_code_count", len(REQUIRED_EVENT_CODES) == 7, str(len(REQUIRED_EVENT_CODES)))
    push("error_code_count", len(REQUIRED_ERROR_CODES) == 6, str(len(REQUIRED_ERROR_CODES)))
    push("symbol_count", len(REQUIRED_SYMBOLS) >= 12, str(len(REQUIRED_SYMBOLS)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push(
        "run_all_total_matches",
        report.get("total") == len(report.get("checks", [])),
        "total vs checks",
    )

    passed = sum(1 for row in checks if row["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": "bd-1u8m",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify bd-1u8m artifacts")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--self-test", action="store_true", help="run checker self-test")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['bead_id']}] {result['verdict']} ({result['passed']}/{result['total']})")
        for row in result["checks"]:
            mark = "PASS" if row["pass"] else "FAIL"
            print(f"- {mark} {row['check']}: {row['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
