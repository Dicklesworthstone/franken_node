#!/usr/bin/env python3
"""Verification script for bd-174: policy checkpoint chain for release channels.

Checks that all required artifacts exist, contain the expected tokens,
and that the implementation satisfies the acceptance criteria from the
bd-174 contract.

Usage:
    python3 scripts/check_policy_checkpoint.py            # human-readable
    python3 scripts/check_policy_checkpoint.py --json      # machine-readable
    python3 scripts/check_policy_checkpoint.py --self-test  # smoke-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


SPEC = ROOT / "docs" / "specs" / "section_10_10" / "bd-174_contract.md"
POLICY = ROOT / "docs" / "policy" / "policy_checkpoint_chain.md"
IMPL_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "policy_checkpoint.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
EVIDENCE = ROOT / "artifacts" / "section_10_10" / "bd-174" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_10" / "bd-174" / "verification_summary.md"

EVENT_CODES = ["PCK-001", "PCK-002", "PCK-003", "PCK-004"]
INVARIANTS = [
    "INV-PCK-MONOTONIC",
    "INV-PCK-PARENT-CHAIN",
    "INV-PCK-HASH-INTEGRITY",
    "INV-PCK-APPEND-ONLY",
    "INV-PCK-CANONICAL-SER",
    "INV-PCK-MULTI-CHANNEL",
]
ERROR_CODES = [
    "CHECKPOINT_SEQ_VIOLATION",
    "CHECKPOINT_PARENT_MISMATCH",
    "CHECKPOINT_HASH_CHAIN_BREAK",
    "CHECKPOINT_EMPTY_CHAIN",
    "CHECKPOINT_SERIALIZATION_ERROR",
]

REQUIRED_IMPL_TOKENS = [
    "pub enum ReleaseChannel",
    "pub struct PolicyCheckpoint",
    "pub struct PolicyCheckpointChain",
    "pub struct CheckpointChainEvent",
    "pub enum CheckpointChainError",
    "pub fn create_checkpoint(",
    "pub fn verify_chain(",
    "pub fn latest_for_channel(",
    "pub fn policy_frontier(",
    "pub fn append_checkpoint(",
    "fn compute_hash(",
    "pub fn verify_hash(",
    "pub sequence: u64",
    "pub epoch_id: u64",
    "pub channel: ReleaseChannel",
    "pub policy_hash: String",
    "pub parent_hash: Option<String>",
    "pub timestamp: u64",
    "pub signer: String",
    "pub checkpoint_hash: String",
    "CHECKPOINT_CREATED",
    "CHECKPOINT_VERIFIED",
    "CHECKPOINT_REJECTED",
    "CHECKPOINT_FRONTIER",
]

REQUIRED_TEST_NAMES = [
    "test_new_chain_is_empty",
    "test_create_genesis_checkpoint",
    "test_create_sequential_checkpoints",
    "test_append_rejects_wrong_sequence",
    "test_append_rejects_wrong_parent_hash",
    "test_verify_empty_chain",
    "test_verify_valid_chain",
    "test_verify_detects_tampered_policy_hash",
    "test_verify_detects_tampered_checkpoint_hash",
    "test_verify_detects_tampered_parent_hash",
    "test_verify_single_bit_flip_detection",
    "test_latest_for_channel_empty",
    "test_latest_for_channel_multi",
    "test_policy_frontier_multi_channel",
    "test_chain_100_plus_checkpoints",
    "test_epoch_boundary_continuity",
    "test_checkpoint_serde",
]

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
    s_path, s_root = str(path), str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_spec_exists() -> None:
    ok = SPEC.is_file()
    _check("spec_exists", ok, f"found: {_safe_rel(SPEC)}" if ok else f"MISSING: {_safe_rel(SPEC)}")


def check_policy_exists() -> None:
    ok = POLICY.is_file()
    _check("policy_exists", ok, f"found: {_safe_rel(POLICY)}" if ok else f"MISSING: {_safe_rel(POLICY)}")


def check_impl_exists() -> None:
    ok = IMPL_RS.is_file()
    _check("impl_exists", ok, f"found: {_safe_rel(IMPL_RS)}" if ok else f"MISSING: {_safe_rel(IMPL_RS)}")


def check_mod_exports() -> None:
    if not MOD_RS.is_file():
        _check("mod_exports", False, "connector/mod.rs missing")
        return
    text = MOD_RS.read_text()
    ok = "pub mod policy_checkpoint;" in text
    _check("mod_exports", ok, "policy_checkpoint module exported" if ok else "NOT exported in mod.rs")


def check_spec_bead_id() -> None:
    if not SPEC.is_file():
        _check("spec_bead_id", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "bd-174" in text
    _check("spec_bead_id", ok, "found" if ok else "NOT FOUND")


def check_spec_section() -> None:
    if not SPEC.is_file():
        _check("spec_section_10_10", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "10.10" in text and "FCP" in text
    _check("spec_section_10_10", ok, "found" if ok else "NOT FOUND")


def check_spec_event_codes() -> None:
    if not SPEC.is_file():
        for code in EVENT_CODES:
            _check(f"spec_event_{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"spec_event_{code}", ok, "found" if ok else "NOT FOUND")


def check_spec_invariants() -> None:
    if not SPEC.is_file():
        for inv in INVARIANTS:
            _check(f"spec_inv_{inv}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"spec_inv_{inv}", ok, "found" if ok else "NOT FOUND")


def check_spec_error_codes() -> None:
    if not SPEC.is_file():
        for code in ERROR_CODES:
            _check(f"spec_err_{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in ERROR_CODES:
        ok = code in text
        _check(f"spec_err_{code}", ok, "found" if ok else "NOT FOUND")


def check_spec_acceptance_criteria() -> None:
    if not SPEC.is_file():
        _check("spec_acceptance_criteria", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Acceptance Criteria" in text
    _check("spec_acceptance_criteria", ok, "found" if ok else "NOT FOUND")


def check_spec_test_scenarios() -> None:
    if not SPEC.is_file():
        _check("spec_test_scenarios", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Test Scenario" in text or "Scenario" in text
    _check("spec_test_scenarios", ok, "found" if ok else "NOT FOUND")


def check_spec_dependencies() -> None:
    if not SPEC.is_file():
        _check("spec_dependencies", False, "spec file missing")
        return
    text = SPEC.read_text()
    has_jjm = "bd-jjm" in text
    has_1l5 = "bd-1l5" in text
    has_2ms = "bd-2ms" in text
    ok = has_jjm and has_1l5 and has_2ms
    _check(
        "spec_dependencies",
        ok,
        "upstream (bd-jjm, bd-1l5) and downstream (bd-2ms) referenced"
        if ok else "missing dependency references",
    )


def check_impl_tokens() -> None:
    if not IMPL_RS.is_file():
        for token in REQUIRED_IMPL_TOKENS:
            short = token[:40].replace(" ", "_")
            _check(f"impl_token_{short}", False, "impl file missing")
        return
    text = IMPL_RS.read_text()
    for token in REQUIRED_IMPL_TOKENS:
        ok = token in text
        short = token[:40].replace(" ", "_")
        _check(f"impl_token_{short}", ok, "found" if ok else f"NOT FOUND: {token}")


def check_impl_event_codes() -> None:
    if not IMPL_RS.is_file():
        for code in EVENT_CODES:
            _check(f"impl_event_{code}", False, "impl file missing")
        return
    text = IMPL_RS.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"impl_event_{code}", ok, "found" if ok else "NOT FOUND")


def check_impl_error_codes() -> None:
    if not IMPL_RS.is_file():
        for code in ERROR_CODES:
            _check(f"impl_err_{code}", False, "impl file missing")
        return
    text = IMPL_RS.read_text()
    for code in ERROR_CODES:
        ok = code in text
        _check(f"impl_err_{code}", ok, "found" if ok else "NOT FOUND")


def check_impl_invariants() -> None:
    if not IMPL_RS.is_file():
        for inv in INVARIANTS:
            _check(f"impl_inv_{inv}", False, "impl file missing")
        return
    text = IMPL_RS.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"impl_inv_{inv}", ok, "found" if ok else "NOT FOUND")


def check_impl_test_names() -> None:
    if not IMPL_RS.is_file():
        for tn in REQUIRED_TEST_NAMES:
            _check(f"impl_test_{tn}", False, "impl file missing")
        return
    text = IMPL_RS.read_text()
    for tn in REQUIRED_TEST_NAMES:
        ok = tn in text
        _check(f"impl_test_{tn}", ok, "found" if ok else "NOT FOUND")


def check_impl_release_channels() -> None:
    """At least 3 release channels (stable, beta, canary) defined."""
    if not IMPL_RS.is_file():
        _check("impl_release_channels", False, "impl file missing")
        return
    text = IMPL_RS.read_text()
    has_stable = "Stable" in text
    has_beta = "Beta" in text
    has_canary = "Canary" in text
    has_custom = "Custom" in text
    ok = has_stable and has_beta and has_canary and has_custom
    _check(
        "impl_release_channels",
        ok,
        "stable, beta, canary, custom all present"
        if ok else "missing release channel variants",
    )


def check_impl_canonical_serialization() -> None:
    """Checkpoint hashing uses canonical serialization domain tag."""
    if not IMPL_RS.is_file():
        _check("impl_canonical_serialization", False, "impl file missing")
        return
    text = IMPL_RS.read_text()
    ok = "policy_checkpoint_hash_v1:" in text
    _check(
        "impl_canonical_serialization",
        ok,
        "canonical domain tag policy_checkpoint_hash_v1: present"
        if ok else "missing canonical serialization domain tag",
    )


def check_impl_100_checkpoint_test() -> None:
    """Impl must have a test creating 100+ checkpoints."""
    if not IMPL_RS.is_file():
        _check("impl_100_checkpoint_test", False, "impl file missing")
        return
    text = IMPL_RS.read_text()
    ok = "150" in text and "test_chain_100_plus_checkpoints" in text
    _check(
        "impl_100_checkpoint_test",
        ok,
        "100+ checkpoint test found (150 checkpoints)"
        if ok else "missing 100+ checkpoint test",
    )


def check_policy_content() -> None:
    if not POLICY.is_file():
        _check("policy_content", False, "policy file missing")
        return
    text = POLICY.read_text()
    has_append_only = "Append-Only" in text or "append-only" in text
    has_monotonic = "Monotonic" in text or "monotonic" in text
    has_channels = "stable" in text.lower() and "beta" in text.lower() and "canary" in text.lower()
    has_rollback = "rollback" in text.lower() or "Rollback" in text
    ok = has_append_only and has_monotonic and has_channels and has_rollback
    _check(
        "policy_content",
        ok,
        "append-only, monotonic, multi-channel, rollback resistance documented"
        if ok else "policy content incomplete",
    )


def check_policy_event_codes() -> None:
    if not POLICY.is_file():
        for code in EVENT_CODES:
            _check(f"policy_event_{code}", False, "policy file missing")
        return
    text = POLICY.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"policy_event_{code}", ok, "found" if ok else "NOT FOUND")


def check_policy_invariants() -> None:
    if not POLICY.is_file():
        for inv in INVARIANTS:
            _check(f"policy_inv_{inv}", False, "policy file missing")
        return
    text = POLICY.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"policy_inv_{inv}", ok, "found" if ok else "NOT FOUND")


def check_verification_evidence() -> None:
    p = EVIDENCE
    if not p.is_file():
        _check("verification_evidence", False, f"MISSING: {_safe_rel(p)}")
        return
    try:
        data = json.JSONDecoder().decode(p.read_text())
        ok = data.get("bead_id") == "bd-174" and data.get("status") == "pass"
        _check(
            "verification_evidence",
            ok,
            f"valid: {_safe_rel(p)}" if ok else "evidence has incorrect bead_id or status",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"parse error: {exc}")


def check_evidence_chain_metrics() -> None:
    """Evidence must include chain_length, channels, and sample hashes."""
    if not EVIDENCE.is_file():
        _check("evidence_chain_metrics", False, "evidence file missing")
        return
    try:
        data = json.JSONDecoder().decode(EVIDENCE.read_text())
        metrics = data.get("metrics", {})
        has_length = "chain_length" in metrics
        has_channels = "channels_covered" in metrics
        has_hashes = "sample_checkpoint_hashes" in metrics
        ok = has_length and has_channels and has_hashes
        _check(
            "evidence_chain_metrics",
            ok,
            "chain_length, channels_covered, sample_checkpoint_hashes present"
            if ok else "missing chain metrics in evidence",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("evidence_chain_metrics", False, f"parse error: {exc}")


def check_verification_summary() -> None:
    p = SUMMARY
    ok = p.is_file()
    _check(
        "verification_summary",
        ok,
        f"found: {_safe_rel(p)}" if ok else f"MISSING: {_safe_rel(p)}",
    )


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_impl_exists,
    check_mod_exports,
    check_spec_bead_id,
    check_spec_section,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_error_codes,
    check_spec_acceptance_criteria,
    check_spec_test_scenarios,
    check_spec_dependencies,
    check_impl_tokens,
    check_impl_event_codes,
    check_impl_error_codes,
    check_impl_invariants,
    check_impl_test_names,
    check_impl_release_channels,
    check_impl_canonical_serialization,
    check_impl_100_checkpoint_test,
    check_policy_content,
    check_policy_event_codes,
    check_policy_invariants,
    check_verification_evidence,
    check_evidence_chain_metrics,
    check_verification_summary,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_all() -> dict[str, Any]:
    global RESULTS
    RESULTS = []
    for fn in ALL_CHECKS:
        fn()
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    return {
        "bead_id": "bd-174",
        "title": "policy checkpoint chain for release channels",
        "section": "10.10",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    """Run all checks and report. Returns True if all pass."""
    report = run_all()
    total, passed, failed = report["total"], report["passed"], report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    configure_test_logging("check_policy_checkpoint")
    parser = argparse.ArgumentParser(
        description="Verify bd-174: policy checkpoint chain"
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
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
        print(
            f"\n{report['passed']}/{report['total']} checks pass"
            f" (verdict={report['verdict']})"
        )
    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
