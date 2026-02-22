#!/usr/bin/env python3
"""Verification script for bd-1u8m: Proof-generation service interface (backend-agnostic).

Usage:
    python3 scripts/check_proof_generator.py
    python3 scripts/check_proof_generator.py --json
    python3 scripts/check_proof_generator.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "crates" / "franken-node" / "src" / "vef" / "proof_generator.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-1u8m_contract.md"
UNIT_TEST = ROOT / "tests" / "test_check_proof_generator.py"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-1u8m" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-1u8m" / "verification_summary.md"

REQUIRED_EVENT_CODES = [
    "PGN-001",
    "PGN-002",
    "PGN-003",
    "PGN-004",
    "PGN-005",
    "PGN-006",
]

REQUIRED_ERROR_CODES = [
    "ERR-PGN-BACKEND-UNAVAILABLE",
    "ERR-PGN-WINDOW-EMPTY",
    "ERR-PGN-TIMEOUT",
    "ERR-PGN-INTERNAL",
]

REQUIRED_INVARIANTS = [
    "INV-PGN-BACKEND-AGNOSTIC",
    "INV-PGN-VERSIONED-FORMAT",
    "INV-PGN-DETERMINISTIC",
]

REQUIRED_IMPL_SYMBOLS = [
    "pub trait ProofBackend",
    "pub struct MockProofBackend",
    "pub struct ComplianceProof",
    "pub struct ProofGenerator",
    "pub struct ProofRequest",
    "pub enum ProofStatus",
    "pub struct ProofGeneratorError",
    "pub struct ProofGeneratorEvent",
    "pub struct ProofGeneratorConfig",
    "pub struct ProofRequestStatus",
    "pub struct ConcurrentProofGenerator",
    "pub fn submit_request",
    "pub fn generate_proof",
    "pub fn verify_proof",
    "pub fn enforce_timeouts",
    "pub fn status_counts",
    "pub fn swap_backend",
    "fn backend_name",
    "fn generate(",
    "fn verify(",
]

REQUIRED_PROOF_STATUSES = [
    "Pending",
    "Generating",
    "Complete",
    "Failed",
]

REQUIRED_COMPLIANCE_PROOF_FIELDS = [
    "proof_id",
    "format_version",
    "receipt_window_ref",
    "proof_data",
    "proof_data_hash",
    "generated_at_millis",
    "backend_name",
    "metadata",
    "trace_id",
]

REQUIRED_PROOF_REQUEST_FIELDS = [
    "request_id",
    "window",
    "entries",
    "timeout_millis",
    "trace_id",
    "created_at_millis",
]

REQUIRED_CONFIG_FIELDS = [
    "default_timeout_millis",
    "max_entries_per_request",
    "max_pending_requests",
]

RESULTS: list[dict[str, Any]] = []


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _safe_rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if str(path).startswith(str(ROOT)) else str(path)


def _check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("ok" if passed else "NOT FOUND"),
        }
    )


def _load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def check_file_presence() -> None:
    files = [
        ("impl_exists", IMPL),
        ("mod_exists", MOD_RS),
        ("spec_contract_exists", SPEC_CONTRACT),
        ("unit_test_exists", UNIT_TEST),
        ("evidence_exists", EVIDENCE),
        ("summary_exists", SUMMARY),
    ]
    for name, path in files:
        _check(name, path.is_file(), _safe_rel(path))


def check_impl_symbols() -> None:
    src = _read(IMPL)

    for symbol in REQUIRED_IMPL_SYMBOLS:
        label = symbol.split()[-1].rstrip("(")
        _check(f"impl_symbol_{label}", symbol in src, symbol)

    for status in REQUIRED_PROOF_STATUSES:
        _check(f"impl_proof_status_{status}", status in src, status)

    for field in REQUIRED_COMPLIANCE_PROOF_FIELDS:
        _check(f"impl_proof_field_{field}", field in src, field)

    for field in REQUIRED_PROOF_REQUEST_FIELDS:
        _check(f"impl_request_field_{field}", field in src, field)

    for field in REQUIRED_CONFIG_FIELDS:
        _check(f"impl_config_field_{field}", field in src, field)

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_{code}", code in src, code)

    for code in REQUIRED_ERROR_CODES:
        _check(f"impl_error_{code}", code in src, code)

    for inv in REQUIRED_INVARIANTS:
        _check(f"impl_invariant_{inv}", inv in src, inv)

    _check(
        "impl_schema_version",
        "vef-proof-generator-v1" in src,
        "vef-proof-generator-v1",
    )
    _check(
        "impl_format_version",
        "PROOF_FORMAT_VERSION" in src,
        "PROOF_FORMAT_VERSION constant",
    )
    _check(
        "impl_uses_btreemap",
        "BTreeMap" in src,
        "BTreeMap for deterministic ordering",
    )
    _check(
        "impl_serde_derive",
        "Serialize" in src and "Deserialize" in src,
        "Serialize + Deserialize",
    )
    _check(
        "impl_uses_sha256",
        "Sha256" in src,
        "SHA-256 hashing for proof data",
    )
    _check(
        "impl_uses_arc",
        "Arc<dyn ProofBackend>" in src,
        "Arc<dyn ProofBackend> for backend injection",
    )
    _check(
        "impl_uses_mutex",
        "Mutex" in src,
        "Mutex for thread safety",
    )

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 25, f"{test_count} tests")


def check_mod_wiring() -> None:
    mod_text = _read(MOD_RS)
    _check(
        "vef_mod_wires_proof_generator",
        "pub mod proof_generator;" in mod_text,
        "pub mod proof_generator;",
    )


def check_backend_agnostic() -> None:
    """Verify the backend-agnostic design (INV-PGN-BACKEND-AGNOSTIC)."""
    src = _read(IMPL)

    _check(
        "contract_backend_trait",
        "pub trait ProofBackend" in src,
        "ProofBackend trait defined",
    )
    _check(
        "contract_mock_backend",
        "pub struct MockProofBackend" in src,
        "MockProofBackend implementation",
    )
    _check(
        "contract_backend_name_method",
        "fn backend_name" in src,
        "backend_name() method",
    )
    _check(
        "contract_generate_method",
        "fn generate(" in src,
        "generate() method on trait",
    )
    _check(
        "contract_verify_method",
        "fn verify(" in src,
        "verify() method on trait",
    )
    _check(
        "contract_swap_backend",
        "pub fn swap_backend" in src,
        "swap_backend for hot-swapping",
    )
    _check(
        "contract_send_sync",
        "Send + Sync" in src,
        "ProofBackend is Send + Sync",
    )


def check_versioned_format() -> None:
    """Verify versioned format (INV-PGN-VERSIONED-FORMAT)."""
    src = _read(IMPL)

    _check(
        "contract_format_version_field",
        "format_version" in src,
        "format_version in ComplianceProof",
    )
    _check(
        "contract_backend_name_field",
        "backend_name" in src,
        "backend_name in ComplianceProof",
    )
    _check(
        "contract_proof_data_hash",
        "proof_data_hash" in src,
        "proof_data_hash for integrity",
    )
    _check(
        "contract_receipt_window_ref",
        "receipt_window_ref" in src,
        "receipt_window_ref for traceability",
    )


def check_deterministic() -> None:
    """Verify deterministic proof generation (INV-PGN-DETERMINISTIC)."""
    src = _read(IMPL)

    _check(
        "contract_deterministic_test",
        "deterministic_proof_generation" in src,
        "deterministic proof generation test",
    )
    _check(
        "contract_hash_chain",
        "compute_proof_bytes" in src,
        "deterministic hash computation",
    )


def check_event_tracing() -> None:
    """Verify event tracing coverage."""
    src = _read(IMPL)

    event_push_count = src.count("self.events.push")
    _check(
        "contract_event_tracing",
        event_push_count >= 6,
        f"{event_push_count} event emission points",
    )

    trace_id_count = src.count("trace_id")
    _check(
        "contract_trace_id_propagation",
        trace_id_count >= 10,
        f"{trace_id_count} trace_id references",
    )


def check_evidence_summary() -> None:
    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check(
            "evidence_bead_id",
            evidence.get("bead_id") == "bd-1u8m",
            str(evidence.get("bead_id")),
        )
        _check(
            "evidence_verdict_pass",
            evidence.get("verdict") == "PASS",
            str(evidence.get("verdict")),
        )

    summary = _read(SUMMARY)
    _check("summary_mentions_bead", "bd-1u8m" in summary, "bd-1u8m")
    _check("summary_mentions_pass", "PASS" in summary, "PASS")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_impl_symbols()
    check_mod_wiring()
    check_backend_agnostic()
    check_versioned_format()
    check_deterministic()
    check_event_tracing()
    check_evidence_summary()

    total = len(RESULTS)
    passed = sum(1 for entry in RESULTS if entry["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-1u8m",
        "title": "Proof-generation service interface (backend-agnostic) for receipt-window compliance proofs",
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
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("event_code_count", len(REQUIRED_EVENT_CODES) == 6, str(len(REQUIRED_EVENT_CODES)))
    push("error_code_count", len(REQUIRED_ERROR_CODES) == 4, str(len(REQUIRED_ERROR_CODES)))
    push("invariant_count", len(REQUIRED_INVARIANTS) == 3, str(len(REQUIRED_INVARIANTS)))
    push("impl_symbol_count", len(REQUIRED_IMPL_SYMBOLS) >= 20, str(len(REQUIRED_IMPL_SYMBOLS)))
    push("proof_status_count", len(REQUIRED_PROOF_STATUSES) == 4, str(len(REQUIRED_PROOF_STATUSES)))
    push("proof_field_count", len(REQUIRED_COMPLIANCE_PROOF_FIELDS) >= 9, str(len(REQUIRED_COMPLIANCE_PROOF_FIELDS)))
    push("request_field_count", len(REQUIRED_PROOF_REQUEST_FIELDS) >= 6, str(len(REQUIRED_PROOF_REQUEST_FIELDS)))
    push("config_field_count", len(REQUIRED_CONFIG_FIELDS) >= 3, str(len(REQUIRED_CONFIG_FIELDS)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")
    push("run_all_has_bead_id", report.get("bead_id") == "bd-1u8m", str(report.get("bead_id")))

    passed = sum(1 for entry in checks if entry["pass"])
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
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    parser.add_argument("--self-test", action="store_true", help="run checker self-test")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['bead_id']}] {result['verdict']} ({result['passed']}/{result['total']})")
        for check in result["checks"]:
            mark = "PASS" if check["pass"] else "FAIL"
            print(f"- {mark} {check['check']}: {check['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
