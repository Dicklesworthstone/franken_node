#!/usr/bin/env python3
"""Verification script for bd-m8p: Verifier economy portal and attestation publishing flow.

Usage:
    python3 scripts/check_verifier_economy.py              # human-readable
    python3 scripts/check_verifier_economy.py --json        # machine-readable JSON
    python3 scripts/check_verifier_economy.py --self-test   # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_10_9" / "bd-m8p_contract.md"
POLICY = ROOT / "docs" / "policy" / "verifier_economy.md"
RUST_IMPL = ROOT / "crates" / "franken-node" / "src" / "verifier_economy" / "mod.rs"
MAIN_RS = ROOT / "crates" / "franken-node" / "src" / "main.rs"

EVIDENCE_DIR = ROOT / "artifacts" / "section_10_9" / "bd-m8p"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

EVENT_CODES = ["VEP-001", "VEP-002", "VEP-003", "VEP-004", "VEP-005", "VEP-006", "VEP-007", "VEP-008"]

INVARIANTS = ["INV-VEP-ATTESTATION", "INV-VEP-SIGNATURE", "INV-VEP-REPUTATION", "INV-VEP-PUBLISH"]

ERROR_CODES = [
    "ERR-VEP-INVALID-SIGNATURE",
    "ERR-VEP-DUPLICATE-SUBMISSION",
    "ERR-VEP-UNREGISTERED-VERIFIER",
    "ERR-VEP-INCOMPLETE-PAYLOAD",
    "ERR-VEP-ANTI-GAMING",
]

REQUIRED_RUST_TYPES = [
    "pub enum VerificationDimension",
    "pub enum VerifierTier",
    "pub enum ReputationTier",
    "pub enum AttestationState",
    "pub enum DisputeOutcome",
    "pub struct AttestationClaim",
    "pub struct AttestationEvidence",
    "pub struct AttestationSignature",
    "pub struct Attestation",
    "pub struct AttestationSubmission",
    "pub struct Verifier",
    "pub struct VerifierRegistration",
    "pub struct ReputationDimensions",
    "pub struct Dispute",
    "pub struct ReplayCapsule",
    "pub struct ScoreboardEntry",
    "pub struct TrustScoreboard",
    "pub struct VerifierEconomyEvent",
    "pub struct VepError",
    "pub struct VerifierEconomyRegistry",
]

REQUIRED_RUST_METHODS = [
    "pub fn register_verifier(",
    "pub fn get_verifier(",
    "pub fn list_verifiers(",
    "pub fn verifier_count(",
    "pub fn submit_attestation(",
    "pub fn review_attestation(",
    "pub fn publish_attestation(",
    "pub fn reject_attestation(",
    "pub fn get_attestation(",
    "pub fn list_attestations(",
    "pub fn published_attestations(",
    "pub fn attestation_count(",
    "pub fn verify_signature(",
    "pub fn compute_reputation(",
    "pub fn update_reputation(",
    "pub fn file_dispute(",
    "pub fn resolve_dispute(",
    "pub fn get_dispute(",
    "pub fn list_disputes(",
    "pub fn register_replay_capsule(",
    "pub fn access_replay_capsule(",
    "pub fn verify_capsule_integrity(",
    "pub fn build_scoreboard(",
    "pub fn check_selective_reporting(",
    "pub fn reset_submission_counts(",
    "pub fn reputation_tier_from_score(",
]

REQUIRED_RUST_TESTS = [
    "test_register_verifier",
    "test_register_emits_vep005",
    "test_duplicate_public_key_rejected",
    "test_verifier_count",
    "test_get_verifier",
    "test_list_verifiers",
    "test_submit_attestation",
    "test_submit_emits_vep001",
    "test_submit_unregistered_verifier_rejected",
    "test_submit_invalid_signature_rejected",
    "test_submit_empty_statement_rejected",
    "test_submit_empty_suite_id_rejected",
    "test_submit_duplicate_rejected",
    "test_publish_flow_submit_review_publish",
    "test_publish_emits_vep002",
    "test_cannot_publish_without_review",
    "test_cannot_review_already_published",
    "test_reject_attestation",
    "test_reject_emits_vep008",
    "test_compute_reputation_deterministic",
    "test_compute_reputation_all_ones",
    "test_compute_reputation_all_zeros",
    "test_compute_reputation_mixed",
    "test_update_reputation",
    "test_update_reputation_emits_vep004",
    "test_reputation_tier_novice",
    "test_reputation_tier_active",
    "test_reputation_tier_established",
    "test_reputation_tier_trusted",
    "test_file_dispute",
    "test_file_dispute_emits_vep003",
    "test_cannot_dispute_unpublished",
    "test_resolve_dispute_upheld",
    "test_resolve_dispute_rejected",
    "test_register_and_access_capsule",
    "test_access_capsule_emits_vep007",
    "test_capsule_integrity_valid",
    "test_capsule_integrity_invalid_empty_hash",
    "test_empty_scoreboard",
    "test_scoreboard_with_published_attestation",
    "test_sybil_rate_limiting",
    "test_sybil_rate_limit_emits_vep006",
    "test_selective_reporting_check_passes",
    "test_reset_submission_counts",
    "test_take_events_drains",
    "test_dimension_display",
    "test_verifier_tier_display",
    "test_reputation_tier_display",
    "test_attestation_state_display",
    "test_dispute_outcome_display",
    "test_vep_error_display",
    "test_verify_signature_valid",
    "test_verify_signature_wrong_key",
    "test_verify_signature_wrong_algorithm",
    "test_verify_signature_empty_value",
    "test_default_registry",
    "test_published_attestations_filter",
    "test_event_code_constants",
    "test_invariant_constants",
    "test_error_code_constants",
]

REPUTATION_TIERS = ["Novice", "Active", "Established", "Trusted"]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    """Return a relative path string, guarding against non-ROOT paths."""
    s_path = str(path)
    s_root = str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


def _file_exists(path: Path, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = _safe_rel(path)
    return _check(
        f"file_exists: {label}",
        exists,
        f"exists: {rel}" if exists else f"missing: {rel}",
    )


def _file_contains(path: Path, keyword: str, label: str) -> dict[str, Any]:
    if not path.is_file():
        return _check(f"{label}: '{keyword}'", False, "file missing")
    content = path.read_text(encoding="utf-8")
    found = keyword in content
    return _check(
        f"{label}: '{keyword}'",
        found,
        "found" if found else "not found in file",
    )


def _file_contains_all(path: Path, keywords: list[str], category: str) -> list[dict[str, Any]]:
    results = []
    if not path.is_file():
        for kw in keywords:
            results.append(_check(f"{category}: '{kw}'", False, "file missing"))
        return results
    content = path.read_text(encoding="utf-8")
    for kw in keywords:
        found = kw in content
        results.append(_check(f"{category}: '{kw}'", found, "found" if found else "not found"))
    return results


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_spec_exists() -> dict[str, Any]:
    """C01: Spec contract file exists."""
    return _file_exists(SPEC, "spec contract")


def check_policy_exists() -> dict[str, Any]:
    """C02: Policy document exists."""
    return _file_exists(POLICY, "policy document")


def check_rust_impl_exists() -> dict[str, Any]:
    """C03: Rust implementation exists."""
    return _file_exists(RUST_IMPL, "rust implementation")


def check_module_registered() -> dict[str, Any]:
    """C04: Module registered in main.rs."""
    return _file_contains(MAIN_RS, "pub mod verifier_economy;", "main_rs")


def check_spec_event_codes() -> dict[str, Any]:
    """C05: Spec defines all event codes VEP-001 through VEP-008."""
    if not SPEC.is_file():
        return _check("spec_event_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = f"all {len(EVENT_CODES)} event codes present" if passed else f"missing: {missing}"
    return _check("spec_event_codes", passed, detail)


def check_spec_invariants() -> dict[str, Any]:
    """C06: Spec defines all four INV-VEP invariants."""
    if not SPEC.is_file():
        return _check("spec_invariants", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = f"all {len(INVARIANTS)} invariants present" if passed else f"missing: {missing}"
    return _check("spec_invariants", passed, detail)


def check_spec_error_codes() -> dict[str, Any]:
    """C07: Spec defines all error codes."""
    if not SPEC.is_file():
        return _check("spec_error_codes", False, "spec file missing")
    content = SPEC.read_text(encoding="utf-8")
    missing = [c for c in ERROR_CODES if c not in content]
    passed = len(missing) == 0
    detail = f"all {len(ERROR_CODES)} error codes present" if passed else f"missing: {missing}"
    return _check("spec_error_codes", passed, detail)


def check_spec_attestation_format() -> dict[str, Any]:
    """C08: Spec documents attestation format (JSON-LD)."""
    return _file_contains(SPEC, "JSON-LD", "spec_keyword")


def check_spec_anti_gaming() -> dict[str, Any]:
    """C09: Spec documents anti-gaming measures."""
    return _file_contains(SPEC, "Anti-Gaming", "spec_section")


def check_spec_replay_capsule() -> dict[str, Any]:
    """C10: Spec documents replay capsule access."""
    return _file_contains(SPEC, "Replay Capsule", "spec_section")


def check_spec_reputation_scoring() -> dict[str, Any]:
    """C11: Spec documents reputation scoring."""
    return _file_contains(SPEC, "Reputation Scoring", "spec_section")


def check_spec_dispute_resolution() -> dict[str, Any]:
    """C12: Spec documents dispute resolution (via acceptance criteria)."""
    return _file_contains(SPEC, "Dispute", "spec_keyword")


def check_policy_publishing_flow() -> dict[str, Any]:
    """C13: Policy documents publishing flow stages."""
    return _file_contains(POLICY, "Publishing Flow", "policy_section")


def check_policy_event_codes() -> dict[str, Any]:
    """C14: Policy references all event codes."""
    if not POLICY.is_file():
        return _check("policy_event_codes", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [c for c in EVENT_CODES if c not in content]
    passed = len(missing) == 0
    detail = f"all {len(EVENT_CODES)} event codes in policy" if passed else f"missing: {missing}"
    return _check("policy_event_codes", passed, detail)


def check_policy_invariants() -> dict[str, Any]:
    """C15: Policy references all invariants."""
    if not POLICY.is_file():
        return _check("policy_invariants", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [inv for inv in INVARIANTS if inv not in content]
    passed = len(missing) == 0
    detail = f"all {len(INVARIANTS)} invariants in policy" if passed else f"missing: {missing}"
    return _check("policy_invariants", passed, detail)


def check_policy_reputation_tiers() -> dict[str, Any]:
    """C16: Policy defines all reputation tiers."""
    if not POLICY.is_file():
        return _check("policy_reputation_tiers", False, "policy file missing")
    content = POLICY.read_text(encoding="utf-8")
    missing = [t for t in REPUTATION_TIERS if t not in content]
    passed = len(missing) == 0
    detail = f"all {len(REPUTATION_TIERS)} reputation tiers in policy" if passed else f"missing: {missing}"
    return _check("policy_reputation_tiers", passed, detail)


def check_policy_governance() -> dict[str, Any]:
    """C17: Policy defines governance section."""
    return _file_contains(POLICY, "Governance", "policy_section")


def check_policy_dispute_resolution() -> dict[str, Any]:
    """C18: Policy defines dispute resolution."""
    return _file_contains(POLICY, "Dispute Resolution", "policy_section")


def check_policy_anti_gaming() -> dict[str, Any]:
    """C19: Policy defines anti-gaming measures."""
    return _file_contains(POLICY, "Anti-Gaming", "policy_section")


def check_policy_appeal_process() -> dict[str, Any]:
    """C20: Policy defines appeal process."""
    return _file_contains(POLICY, "Appeal Process", "policy_section")


def check_policy_upgrade_path() -> dict[str, Any]:
    """C21: Policy documents upgrade path."""
    return _file_contains(POLICY, "Upgrade Path", "policy_section")


def check_policy_downgrade_triggers() -> dict[str, Any]:
    """C22: Policy documents downgrade triggers."""
    return _file_contains(POLICY, "Downgrade Triggers", "policy_section")


def check_rust_types() -> list[dict[str, Any]]:
    """C23: All required Rust types are implemented."""
    return _file_contains_all(RUST_IMPL, REQUIRED_RUST_TYPES, "rust_type")


def check_rust_methods() -> list[dict[str, Any]]:
    """C24: All required Rust methods are implemented."""
    return _file_contains_all(RUST_IMPL, REQUIRED_RUST_METHODS, "rust_method")


def check_rust_event_codes() -> list[dict[str, Any]]:
    """C25: All event codes are defined in Rust."""
    return _file_contains_all(RUST_IMPL, EVENT_CODES, "rust_event_code")


def check_rust_invariant_constants() -> list[dict[str, Any]]:
    """C26: All invariant constants are defined in Rust."""
    return _file_contains_all(RUST_IMPL, INVARIANTS, "rust_invariant")


def check_rust_error_codes() -> list[dict[str, Any]]:
    """C27: All error codes are defined in Rust."""
    return _file_contains_all(RUST_IMPL, ERROR_CODES, "rust_error_code")


def check_rust_test_count() -> dict[str, Any]:
    """C28: Rust implementation has at least 50 tests."""
    if not RUST_IMPL.is_file():
        return _check("rust_test_count", False, "impl file missing")
    content = RUST_IMPL.read_text(encoding="utf-8")
    import re
    count = len(re.findall(r"#\[test\]", content))
    passed = count >= 50
    return _check("rust_test_count", passed, f"{count} tests (minimum 50)")


def check_rust_tests() -> list[dict[str, Any]]:
    """C29: All required test functions exist in Rust impl."""
    return _file_contains_all(RUST_IMPL, REQUIRED_RUST_TESTS, "rust_test")


# ---------------------------------------------------------------------------
# All check functions
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_rust_impl_exists,
    check_module_registered,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_error_codes,
    check_spec_attestation_format,
    check_spec_anti_gaming,
    check_spec_replay_capsule,
    check_spec_reputation_scoring,
    check_spec_dispute_resolution,
    check_policy_publishing_flow,
    check_policy_event_codes,
    check_policy_invariants,
    check_policy_reputation_tiers,
    check_policy_governance,
    check_policy_dispute_resolution,
    check_policy_anti_gaming,
    check_policy_appeal_process,
    check_policy_upgrade_path,
    check_policy_downgrade_triggers,
]

LIST_CHECKS = [
    check_rust_types,
    check_rust_methods,
    check_rust_event_codes,
    check_rust_invariant_constants,
    check_rust_error_codes,
    check_rust_tests,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    """Run all checks and return structured result."""
    global RESULTS
    RESULTS = []

    for fn in ALL_CHECKS:
        fn()

    for fn in LIST_CHECKS:
        fn()

    # Also check test count as a single check
    check_rust_test_count()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-m8p",
        "title": "Verifier economy portal and external attestation publishing flow",
        "section": "10.9",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": "PASS" if failed == 0 else "FAIL",
        "overall_pass": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def write_evidence(evidence: dict[str, Any]) -> None:
    """Write verification evidence to artifact directory."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n")


def write_summary(evidence: dict[str, Any]) -> None:
    """Write human-readable verification summary."""
    lines = [
        f"# Verification Summary: {evidence['title']}",
        "",
        f"**Bead:** {evidence['bead_id']} | **Section:** {evidence['section']}",
        f"**Timestamp:** {evidence['timestamp']}",
        f"**Overall:** {evidence['verdict']}",
        f"**Checks:** {evidence['passed']}/{evidence['total']} passed",
        "",
        "## Check Results",
        "",
    ]

    for c in evidence["checks"]:
        status = "PASS" if c["pass"] else "FAIL"
        lines.append(f"- [{status}] {c['check']}: {c['detail']}")

    lines.extend(["", "## Artifacts", ""])
    lines.append(f"- Spec: `{_safe_rel(SPEC)}`")
    lines.append(f"- Policy: `{_safe_rel(POLICY)}`")
    lines.append(f"- Implementation: `{_safe_rel(RUST_IMPL)}`")
    lines.append(f"- Evidence: `{_safe_rel(EVIDENCE_PATH)}`")
    lines.append("")

    SUMMARY_PATH.write_text("\n".join(lines) + "\n")


def self_test() -> bool:
    """Run self-test: execute all checks and report pass/fail."""
    report = run_all()
    total = report["total"]
    passed = report["passed"]
    failed = report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-m8p: Verifier economy portal and attestation publishing flow"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test mode")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    report = run_all()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{report['passed']}/{report['total']} checks pass (verdict={report['verdict']})")

    write_evidence(report)
    write_summary(report)

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
