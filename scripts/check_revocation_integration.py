#!/usr/bin/env python3
"""Verification script for bd-12q revocation integration."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs/specs/section_10_4/bd-12q_contract.md"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/revocation_integration.rs"
MODULE_EXPORT_PATH = ROOT / "crates/franken-node/src/supply_chain/mod.rs"
INTEGRATION_TEST_PATH = ROOT / "tests/integration/revocation_integration_workflow.rs"
FIXTURE_PATH = ROOT / "fixtures/provenance/revocation_integration_cases.json"
DECISIONS_PATH = ROOT / "artifacts/section_10_4/bd-12q/revocation_integration_decisions.json"

EVIDENCE_DIR = ROOT / "artifacts/section_10_4/bd-12q"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-REVI-REGISTRY-CANONICAL",
    "INV-REVI-MONOTONIC-HEAD",
    "INV-REVI-FRESHNESS-TIERS",
    "INV-REVI-HIGH-STALE-DENY",
    "INV-REVI-LOW-STALE-WARN",
    "INV-REVI-PROPAGATION-SLA",
    "INV-REVI-CASCADE",
    "INV-REVI-EVIDENCE-LEDGER",
]

REQUIRED_RUST_SYMBOLS = [
    "pub struct RevocationIntegrationEngine",
    "pub struct RevocationIntegrationPolicy",
    "pub enum ExtensionOperation",
    "pub enum ExtensionSafetyTier",
    "pub struct ExtensionOperationContext",
    "pub fn process_propagation",
    "pub fn evaluate_operation",
]

REQUIRED_EVENTS = [
    "ExtensionRevocationCheckPassed",
    "ExtensionRevocationCheckFailed",
    "ExtensionRevocationStaleWarning",
    "RevocationPropagationReceived",
    "RevocationCascadeInitiated",
]

REQUIRED_ERROR_CODES = [
    "REVOCATION_DATA_STALE",
    "REVOCATION_EXTENSION_REVOKED",
    "REVOCATION_DATA_UNAVAILABLE",
    "REVOCATION_HEAD_REGRESSION",
    "REVOCATION_PROPAGATION_SLA_MISSED",
]

REQUIRED_TESTS = [
    "inv_revi_high_stale_denied",
    "inv_revi_low_stale_warns",
    "inv_revi_revoked_extension_blocked_with_cascade",
    "inv_revi_monotonic_head_regression_rejected",
    "inv_revi_propagation_sla_recorded",
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
        return _check("REV-SPEC", "Spec contract exists with required invariants", False, "missing spec file")

    content = SPEC_PATH.read_text(encoding="utf-8")
    missing = [inv for inv in REQUIRED_INVARIANTS if inv not in content]
    return _check(
        "REV-SPEC",
        "Spec contract exists with required invariants",
        not missing,
        None if not missing else f"missing invariants: {', '.join(missing)}",
    )



def check_rust_implementation() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return _check("REV-RUST", "Rust module exposes revocation integration APIs", False, "missing rust module")

    content = RUST_IMPL_PATH.read_text(encoding="utf-8")
    missing_symbols = [symbol for symbol in REQUIRED_RUST_SYMBOLS if symbol not in content]
    missing_events = [event for event in REQUIRED_EVENTS if event not in content]
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
        "REV-RUST",
        "Rust module exposes revocation integration APIs",
        passed,
        None if passed else " | ".join(details_parts),
    )



def check_module_export() -> dict[str, Any]:
    if not MODULE_EXPORT_PATH.exists():
        return _check("REV-MOD", "Supply-chain module exports revocation integration", False)

    content = MODULE_EXPORT_PATH.read_text(encoding="utf-8")
    passed = "pub mod revocation_integration;" in content
    return _check(
        "REV-MOD",
        "Supply-chain module exports revocation integration",
        passed,
    )



def check_integration_surface() -> dict[str, Any]:
    if not INTEGRATION_TEST_PATH.exists():
        return _check("REV-INTEG", "Integration tests cover revocation workflow invariants", False, "missing integration test")

    content = INTEGRATION_TEST_PATH.read_text(encoding="utf-8")
    missing = [name for name in REQUIRED_TESTS if name not in content]
    return _check(
        "REV-INTEG",
        "Integration tests cover revocation workflow invariants",
        not missing,
        None if not missing else f"missing tests: {', '.join(missing)}",
    )



def check_fixture_cases() -> dict[str, Any]:
    if not FIXTURE_PATH.exists():
        return _check("REV-FIXTURE", "Fixture corpus contains stale/revoked/warn scenarios", False, "missing fixture file")

    try:
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _check("REV-FIXTURE", "Fixture corpus contains stale/revoked/warn scenarios", False, f"invalid json: {exc}")

    cases = fixture.get("cases", [])
    if not isinstance(cases, list):
        return _check("REV-FIXTURE", "Fixture corpus contains stale/revoked/warn scenarios", False, "cases is not a list")

    statuses = {case.get("expected_status") for case in cases}
    has_warn = "warn_stale" in statuses
    has_stale_fail = "failed_stale" in statuses
    has_revoked_fail = "failed_revoked" in statuses

    passed = len(cases) >= 4 and has_warn and has_stale_fail and has_revoked_fail
    details = None
    if not passed:
        details = f"count={len(cases)}, statuses={sorted(s for s in statuses if s)}"

    return _check(
        "REV-FIXTURE",
        "Fixture corpus contains stale/revoked/warn scenarios",
        passed,
        details,
    )



def check_decision_artifact() -> dict[str, Any]:
    if not DECISIONS_PATH.exists():
        return _check("REV-ARTIFACT", "Decision artifact captures pass/fail outcomes", False, "missing decisions artifact")

    try:
        artifact = json.loads(DECISIONS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _check("REV-ARTIFACT", "Decision artifact captures pass/fail outcomes", False, f"invalid json: {exc}")

    decisions = artifact.get("decisions", [])
    has_pass = isinstance(decisions, list) and any(decision.get("allowed") for decision in decisions)
    has_fail = isinstance(decisions, list) and any(not decision.get("allowed") for decision in decisions)

    passed = isinstance(decisions, list) and len(decisions) >= 3 and has_pass and has_fail
    details = None if passed else f"decision_count={len(decisions) if isinstance(decisions, list) else 'n/a'}"

    return _check("REV-ARTIFACT", "Decision artifact captures pass/fail outcomes", passed, details)



def collect_checks() -> list[dict[str, Any]]:
    return [
        check_spec_contract(),
        check_rust_implementation(),
        check_module_export(),
        check_integration_surface(),
        check_fixture_cases(),
        check_decision_artifact(),
    ]



def _make_summary_md(report: dict[str, Any]) -> str:
    lines = [
        "# bd-12q: Revocation Integration — Verification Summary",
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
            "- Spec: `docs/specs/section_10_4/bd-12q_contract.md`",
            "- Impl: `crates/franken-node/src/supply_chain/revocation_integration.rs`",
            "- Integration: `tests/integration/revocation_integration_workflow.rs`",
            "- Fixture: `fixtures/provenance/revocation_integration_cases.json`",
            "- Decisions: `artifacts/section_10_4/bd-12q/revocation_integration_decisions.json`",
            "- Evidence: `artifacts/section_10_4/bd-12q/verification_evidence.json`",
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
        "gate": "revocation_integration_verification",
        "bead": "bd-12q",
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
        print("bd-12q: Revocation integration verification")
        for check in checks:
            print(f"  [{check['status']}] {check['id']}: {check['description']}")
            if "details" in check:
                print(f"         {check['details']}")
        print(f"\nResult: {passing}/{total} checks passed")
        print(f"Verdict: {verdict}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
