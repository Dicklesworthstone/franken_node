#!/usr/bin/env python3
"""Verification script for bd-1ah provenance attestation chain."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs/specs/section_10_4/bd-1ah_contract.md"
SCHEMA_PATH = ROOT / "schemas/provenance_attestation.schema.json"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/provenance.rs"
INTEGRATION_TEST_PATH = ROOT / "tests/integration/provenance_verification_chain.rs"
FIXTURE_PATH = ROOT / "fixtures/provenance/attestation_chain_cases.json"
CHAIN_REPORT_PATH = ROOT / "artifacts/section_10_4/bd-1ah/attestation_chain_report.json"

EVIDENCE_DIR = ROOT / "artifacts/section_10_4/bd-1ah"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-PAT-REQUIRED-FIELDS",
    "INV-PAT-CHAIN-ORDER",
    "INV-PAT-FAIL-CLOSED",
    "INV-PAT-FORMAT-CANONICAL",
    "INV-PAT-PROFILE-DEPTH",
    "INV-PAT-FRESHNESS",
    "INV-PAT-DOWNSTREAM-GATES",
    "INV-PAT-STRUCTURED-EVENTS",
]

REQUIRED_SCHEMA_FIELDS = [
    "source_repository_url",
    "build_system_identifier",
    "builder_identity",
    "builder_version",
    "reproducibility_hash",
    "vcs_commit_sha",
    "build_timestamp_epoch",
    "slsa_level_claim",
]

REQUIRED_ENVELOPE_FORMATS = [
    "in_toto",
    "franken_node_envelope_v1",
]

REQUIRED_RUST_SYMBOLS = [
    "pub struct ProvenanceAttestation",
    "pub struct VerificationPolicy",
    "pub enum VerificationMode",
    "pub fn verify_attestation_chain",
    "pub fn verify_and_project_gates",
    "pub fn enforce_fail_closed",
    "pub fn sign_links_in_place",
    "pub fn required_downstream_gates",
]

REQUIRED_EVENT_CODES = [
    "AttestationVerified",
    "AttestationRejected",
    "ProvenanceLevelAssigned",
    "ChainIncomplete",
    "ChainStale",
    "ProvenanceChainBroken",
    "ProvenanceDegradedModeEntered",
]

REQUIRED_ERROR_CODES = [
    "AttestationMissingField",
    "ChainIncomplete",
    "ChainStale",
    "ChainLinkRevoked",
    "InvalidSignature",
    "ChainLinkOrderInvalid",
    "LevelInsufficient",
]

REQUIRED_INTEGRATION_TESTS = [
    "inv_pat_full_chain_verifies_fail_closed",
    "inv_pat_missing_source_vcs_link_rejected_with_chain_incomplete",
    "inv_pat_broken_signature_marks_specific_link",
    "inv_pat_cached_window_allows_soft_stale_but_emits_event",
    "inv_pat_downstream_gate_projection_requires_10_13_checks",
]



def _check(
    check_id: str,
    description: str,
    passed: bool,
    details: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": check_id,
        "description": description,
        "status": "PASS" if passed else "FAIL",
    }
    if details:
        record["details"] = details
    return record



def check_spec_contract() -> dict[str, Any]:
    if not SPEC_PATH.exists():
        return _check("PAT-SPEC", "Spec contract exists with required invariants", False, "missing spec file")

    content = SPEC_PATH.read_text(encoding="utf-8")
    missing = [inv for inv in REQUIRED_INVARIANTS if inv not in content]
    return _check(
        "PAT-SPEC",
        "Spec contract exists with required invariants",
        not missing,
        None if not missing else f"missing invariants: {', '.join(missing)}",
    )



def check_schema_fields() -> dict[str, Any]:
    if not SCHEMA_PATH.exists():
        return _check("PAT-SCHEMA", "Schema includes required provenance fields", False, "missing schema file")

    try:
        data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _check("PAT-SCHEMA", "Schema includes required provenance fields", False, f"invalid json: {exc}")

    required = set(data.get("required", []))
    missing = [field for field in REQUIRED_SCHEMA_FIELDS if field not in required]
    schema_ok = data.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
    extras_closed = data.get("additionalProperties") is False

    passed = not missing and schema_ok and extras_closed
    details = None
    if not passed:
        details = (
            f"missing_required={missing}, schema={data.get('$schema')}, "
            f"additionalProperties={data.get('additionalProperties')}"
        )

    return _check("PAT-SCHEMA", "Schema includes required provenance fields", passed, details)



def check_schema_envelope_formats() -> dict[str, Any]:
    try:
        data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return _check("PAT-ENVELOPE", "Schema supports in-toto and franken envelope formats", False)

    enum_values = data.get("properties", {}).get("envelope_format", {}).get("enum", [])
    missing = [fmt for fmt in REQUIRED_ENVELOPE_FORMATS if fmt not in enum_values]
    return _check(
        "PAT-ENVELOPE",
        "Schema supports in-toto and franken envelope formats",
        not missing,
        None if not missing else f"missing formats: {', '.join(missing)}",
    )



def check_rust_implementation() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return _check("PAT-RUST", "Rust implementation exposes required verifier API", False, "missing rust module")

    content = RUST_IMPL_PATH.read_text(encoding="utf-8")
    missing_symbols = [symbol for symbol in REQUIRED_RUST_SYMBOLS if symbol not in content]
    missing_events = [event for event in REQUIRED_EVENT_CODES if event not in content]
    missing_errors = [code for code in REQUIRED_ERROR_CODES if code not in content]

    passed = not missing_symbols and not missing_events and not missing_errors
    details_parts: list[str] = []
    if missing_symbols:
        details_parts.append(f"symbols: {', '.join(missing_symbols)}")
    if missing_events:
        details_parts.append(f"events: {', '.join(missing_events)}")
    if missing_errors:
        details_parts.append(f"errors: {', '.join(missing_errors)}")

    return _check(
        "PAT-RUST",
        "Rust implementation exposes required verifier API",
        passed,
        None if passed else " | ".join(details_parts),
    )



def check_integration_surface() -> dict[str, Any]:
    if not INTEGRATION_TEST_PATH.exists():
        return _check("PAT-INTEG", "Integration tests cover chain verification scenarios", False, "missing integration test")

    content = INTEGRATION_TEST_PATH.read_text(encoding="utf-8")
    missing = [name for name in REQUIRED_INTEGRATION_TESTS if name not in content]
    return _check(
        "PAT-INTEG",
        "Integration tests cover chain verification scenarios",
        not missing,
        None if not missing else f"missing tests: {', '.join(missing)}",
    )



def check_fixture_cases() -> dict[str, Any]:
    if not FIXTURE_PATH.exists():
        return _check("PAT-FIXTURE", "Fixture corpus includes pass/fail and envelope variants", False, "missing fixture file")

    try:
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _check("PAT-FIXTURE", "Fixture corpus includes pass/fail and envelope variants", False, f"invalid json: {exc}")

    cases = fixture.get("cases", [])
    if not isinstance(cases, list):
        return _check("PAT-FIXTURE", "Fixture corpus includes pass/fail and envelope variants", False, "cases is not a list")

    has_pass = any(case.get("expected_valid") is True for case in cases)
    has_fail = any(case.get("expected_valid") is False for case in cases)

    formats = {
        case.get("attestation", {}).get("envelope_format")
        for case in cases
        if isinstance(case, dict)
    }
    has_formats = all(fmt in formats for fmt in REQUIRED_ENVELOPE_FORMATS)

    passed = len(cases) >= 5 and has_pass and has_fail and has_formats
    details = None
    if not passed:
        details = f"count={len(cases)}, has_pass={has_pass}, has_fail={has_fail}, formats={sorted(f for f in formats if f)}"

    return _check("PAT-FIXTURE", "Fixture corpus includes pass/fail and envelope variants", passed, details)



def check_chain_report_artifact() -> dict[str, Any]:
    if not CHAIN_REPORT_PATH.exists():
        return _check("PAT-ARTIFACT", "Attestation chain report artifact is present and structured", False, "missing report")

    try:
        report = json.loads(CHAIN_REPORT_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _check("PAT-ARTIFACT", "Attestation chain report artifact is present and structured", False, f"invalid json: {exc}")

    decisions = report.get("decisions", [])
    has_decisions = isinstance(decisions, list) and len(decisions) >= 3
    has_both = has_decisions and any(d.get("chain_valid") for d in decisions) and any(
        not d.get("chain_valid") for d in decisions
    )

    return _check(
        "PAT-ARTIFACT",
        "Attestation chain report artifact is present and structured",
        has_decisions and has_both,
        None if has_decisions and has_both else f"decision_count={len(decisions) if isinstance(decisions, list) else 'n/a'}",
    )



def collect_checks() -> list[dict[str, Any]]:
    return [
        check_spec_contract(),
        check_schema_fields(),
        check_schema_envelope_formats(),
        check_rust_implementation(),
        check_integration_surface(),
        check_fixture_cases(),
        check_chain_report_artifact(),
    ]



def _make_summary_md(report: dict[str, Any]) -> str:
    lines = [
        "# bd-1ah: Provenance Attestation Chain — Verification Summary",
        "",
        f"## Verdict: {report['verdict']}",
        "",
        f"## Checks ({report['summary']['passing_checks']}/{report['summary']['total_checks']})",
        "",
        "| Check | Description | Status |",
        "|-------|-------------|--------|",
    ]
    for check in report["checks"]:
        lines.append(f"| {check['id']} | {check['description']} | {check['status']} |")

    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            "- Spec: `docs/specs/section_10_4/bd-1ah_contract.md`",
            "- Schema: `schemas/provenance_attestation.schema.json`",
            "- Impl: `crates/franken-node/src/supply_chain/provenance.rs`",
            "- Integration: `tests/integration/provenance_verification_chain.rs`",
            "- Fixture corpus: `fixtures/provenance/attestation_chain_cases.json`",
            "- Chain report: `artifacts/section_10_4/bd-1ah/attestation_chain_report.json`",
            "- Evidence: `artifacts/section_10_4/bd-1ah/verification_evidence.json`",
        ]
    )
    return "\n".join(lines) + "\n"



def self_test() -> bool:
    return all(check["status"] == "PASS" for check in collect_checks())



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="also print machine-readable verification evidence to stdout",
    )
    args = parser.parse_args()

    checks = collect_checks()
    passing = sum(1 for check in checks if check["status"] == "PASS")
    total = len(checks)
    verdict = "PASS" if passing == total else "FAIL"

    report: dict[str, Any] = {
        "gate": "provenance_attestation_verification",
        "bead": "bd-1ah",
        "section": "10.4",
        "verdict": verdict,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": total - passing,
        },
    }

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    SUMMARY_PATH.write_text(_make_summary_md(report), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("bd-1ah: Provenance attestation chain verification")
        for check in checks:
            print(f"  [{check['status']}] {check['id']}: {check['description']}")
            if "details" in check:
                print(f"         {check['details']}")
        print(f"\nResult: {passing}/{total} checks passed")
        print(f"Verdict: {verdict}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
