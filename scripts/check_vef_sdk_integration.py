#!/usr/bin/env python3
"""Verification script for bd-3pds: VEF SDK integration (capsule embedding + external API).

Usage:
    python3 scripts/check_vef_sdk_integration.py
    python3 scripts/check_vef_sdk_integration.py --json
    python3 scripts/check_vef_sdk_integration.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "crates" / "franken-node" / "src" / "vef" / "sdk_integration.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-3pds_contract.md"
UNIT_TEST = ROOT / "tests" / "test_check_vef_sdk_integration.py"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-3pds" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-3pds" / "verification_summary.md"

# ── Required symbols ────────────────────────────────────────────────────────

REQUIRED_EVENT_CODES = [
    "VSI-001",
    "VSI-002",
    "VSI-003",
    "VSI-004",
    "VSI-005",
    "VSI-006",
]

REQUIRED_ERROR_CODES = [
    "ERR-VSI-PROOF-REF-MISSING",
    "ERR-VSI-CAPSULE-INVALID",
    "ERR-VSI-VERSION-UNSUPPORTED",
    "ERR-VSI-BINDING-MISMATCH",
    "ERR-VSI-SUBMISSION-REJECTED",
    "ERR-VSI-INTERNAL",
]

REQUIRED_INVARIANTS = [
    "INV-VSI-VERSIONED",
    "INV-VSI-BACKWARD-COMPAT",
    "INV-VSI-EMBED-COMPLETE",
]

REQUIRED_IMPL_SYMBOLS = [
    "pub struct VefCapsuleEmbed",
    "pub struct ExternalVerificationEndpoint",
    "pub struct CapsuleEmbedding",
    "pub struct VersionNegotiator",
    "pub struct NegotiationResult",
    "pub struct EvidenceSubmission",
    "pub struct SubmissionResponse",
    "pub struct EvidenceRecord",
    "pub struct ExportedEvidenceBundle",
    "pub struct VsiEvent",
    "pub struct VsiError",
    "pub struct EvidenceQuery",
    "pub enum EvidenceStatus",
    "pub fn embed(",
    "pub fn validate_embedding(",
    "pub fn negotiate(",
    "pub fn submit(",
    "pub fn query(",
    "pub fn export_evidence(",
    "pub fn update_status(",
    "pub fn is_supported(",
]

REQUIRED_EVIDENCE_STATUS_VARIANTS = [
    "Pending",
    "Accepted",
    "Rejected",
    "Expired",
]

REQUIRED_CAPSULE_EMBEDDING_FIELDS = [
    "format_version",
    "proof_ref",
    "embed_metadata",
    "binding_hash",
    "trace_id",
    "created_at_millis",
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


# ── Check groups ────────────────────────────────────────────────────────────


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
        label = symbol.replace("pub ", "").split("(")[0].strip().split()[-1]
        _check(f"impl_symbol_{label}", symbol in src, symbol)

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_{code}", code in src, code)

    for code in REQUIRED_ERROR_CODES:
        _check(f"impl_error_{code}", code in src, code)

    for inv in REQUIRED_INVARIANTS:
        _check(f"impl_invariant_{inv}", inv in src, inv)

    for variant in REQUIRED_EVIDENCE_STATUS_VARIANTS:
        _check(f"impl_status_{variant}", variant in src, variant)

    for field in REQUIRED_CAPSULE_EMBEDDING_FIELDS:
        _check(f"impl_embed_field_{field}", field in src, field)

    _check(
        "impl_schema_version",
        "vef-sdk-integration-v1" in src,
        "vef-sdk-integration-v1",
    )
    _check(
        "impl_serde_derive",
        "#[derive(" in src and "Serialize" in src and "Deserialize" in src,
        "Serialize + Deserialize",
    )
    _check("impl_uses_btreemap", "BTreeMap" in src, "BTreeMap for deterministic ordering")
    _check("impl_uses_sha256", "Sha256" in src or "sha256" in src, "SHA-256 binding hash")
    _check(
        "impl_binding_hash_fn",
        "compute_binding_hash" in src,
        "compute_binding_hash function",
    )
    _check(
        "impl_version_negotiation",
        "negotiate" in src and "supported_versions" in src,
        "version negotiation logic",
    )
    _check(
        "impl_backward_compat_logic",
        "is_supported" in src,
        "backward compatibility check",
    )

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 25, f"{test_count} tests")


def check_mod_wiring() -> None:
    mod_text = _read(MOD_RS)
    _check(
        "vef_mod_wires_sdk_integration",
        "pub mod sdk_integration;" in mod_text,
        "pub mod sdk_integration;",
    )


def check_contract() -> None:
    """Verify implementation satisfies key contract requirements."""
    src = _read(IMPL)

    # Deterministic binding hash
    _check(
        "contract_deterministic_binding",
        "binding_hash" in src and "sha256" in src.lower(),
        "deterministic SHA-256 binding hash",
    )

    # Version negotiation selects highest mutual
    _check(
        "contract_version_highest_mutual",
        "highest" in src.lower() or "newest" in src.lower() or "server_ver" in src,
        "highest mutual version selection",
    )

    # Embed validation
    _check(
        "contract_embed_validation",
        "validate_embedding" in src,
        "capsule embedding validation",
    )

    # Evidence submission and query
    _check(
        "contract_submit_and_query",
        "submit" in src and "query" in src and "export_evidence" in src,
        "submit + query + export API",
    )

    # Trace ID propagation
    trace_count = src.count("trace_id")
    _check(
        "contract_trace_id_propagation",
        trace_count >= 15,
        f"{trace_count} trace_id references",
    )

    # Event tracing
    event_push_count = src.count("self.events.push")
    _check(
        "contract_event_tracing",
        event_push_count >= 5,
        f"{event_push_count} event emission points",
    )

    # Classified errors
    error_constructor_count = sum(
        1 for name in [
            "proof_ref_missing",
            "capsule_invalid",
            "version_unsupported",
            "binding_mismatch",
            "submission_rejected",
            "internal",
        ]
        if f"fn {name}(" in src
    )
    _check(
        "contract_classified_errors",
        error_constructor_count >= 6,
        f"{error_constructor_count} error constructors",
    )


def check_evidence_summary() -> None:
    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check(
            "evidence_bead_id",
            evidence.get("bead_id") == "bd-3pds",
            str(evidence.get("bead_id")),
        )
        _check(
            "evidence_verdict_pass",
            evidence.get("verdict") == "PASS",
            str(evidence.get("verdict")),
        )

    summary = _read(SUMMARY)
    _check("summary_mentions_bead", "bd-3pds" in summary, "bd-3pds")
    _check("summary_mentions_pass", "PASS" in summary, "PASS")


# ── Runners ─────────────────────────────────────────────────────────────────


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_impl_symbols()
    check_mod_wiring()
    check_contract()
    check_evidence_summary()

    total = len(RESULTS)
    passed = sum(1 for entry in RESULTS if entry["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3pds",
        "title": "Integrate VEF evidence into verifier SDK replay capsules and external verification APIs",
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
    push("error_code_count", len(REQUIRED_ERROR_CODES) == 6, str(len(REQUIRED_ERROR_CODES)))
    push("invariant_count", len(REQUIRED_INVARIANTS) == 3, str(len(REQUIRED_INVARIANTS)))
    push("impl_symbol_count", len(REQUIRED_IMPL_SYMBOLS) >= 20, str(len(REQUIRED_IMPL_SYMBOLS)))
    push("status_variant_count", len(REQUIRED_EVIDENCE_STATUS_VARIANTS) == 4, str(len(REQUIRED_EVIDENCE_STATUS_VARIANTS)))
    push("embed_field_count", len(REQUIRED_CAPSULE_EMBEDDING_FIELDS) == 6, str(len(REQUIRED_CAPSULE_EMBEDDING_FIELDS)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": "bd-3pds",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify bd-3pds artifacts")
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
