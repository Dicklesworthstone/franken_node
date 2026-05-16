#!/usr/bin/env python3
"""Verification script for bd-sh3: policy change approval workflows with cryptographic audit trail.

Usage:
    python scripts/check_policy_change_workflow.py          # human-readable
    python scripts/check_policy_change_workflow.py --json    # machine-readable
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "approval_workflow.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_5" / "bd-sh3_contract.md"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "policy" / "mod.rs"

REQUIRED_TYPES = [
    "pub enum RiskAssessment",
    "pub struct PolicyDiffEntry",
    "pub struct PolicyChangeProposal",
    "pub enum ProposalState",
    "pub struct ApprovalSignature",
    "pub struct PolicyChangeAuditEntry",
    "pub struct ProposalRecord",
    "pub struct ChangeEvidencePackage",
    "pub struct PolicyChangeEngine",
    "pub struct PolicyChangeError",
]

REQUIRED_METHODS = [
    "pub fn propose(",
    "pub fn approve(",
    "pub fn reject(",
    "pub fn activate(",
    "pub fn rollback(",
    "pub fn get_proposal(",
    "pub fn audit_ledger(",
    "pub fn verify_audit_chain(",
    "pub fn query_audit_by_proposal(",
    "pub fn total_proposals(",
    "pub fn total_activated(",
    "pub fn total_rollbacks(",
    "pub fn min_quorum(",
]

EVENT_CODES = [
    "POLICY_CHANGE_PROPOSED",
    "POLICY_CHANGE_REVIEWED",
    "POLICY_CHANGE_APPROVED",
    "POLICY_CHANGE_REJECTED",
    "POLICY_CHANGE_ACTIVATED",
    "POLICY_CHANGE_ROLLED_BACK",
    "AUDIT_CHAIN_VERIFIED",
    "AUDIT_CHAIN_BROKEN",
]

ERROR_CODES = [
    "ERR_PROPOSAL_NOT_FOUND",
    "ERR_SOLE_APPROVER",
    "ERR_INVALID_SIGNATURE",
    "ERR_QUORUM_NOT_MET",
    "ERR_INVALID_STATE_TRANSITION",
    "ERR_AUDIT_CHAIN_BROKEN",
    "ERR_JUSTIFICATION_TOO_SHORT",
]

INVARIANTS = [
    "INV-POL-MULTI-PARTY",
    "INV-POL-ROLE-SEP",
    "INV-POL-HASH-CHAIN",
    "INV-POL-ROLLBACK",
    "INV-POL-EVIDENCE",
    "INV-POL-JUSTIFICATION",
    "INV-POL-ENVELOPE",
    "INV-POL-LIFECYCLE",
]

PROPOSAL_STATES = [
    "Proposed",
    "UnderReview",
    "Approved",
    "Rejected",
    "Applied",
    "RolledBack",
]

REQUIRED_TESTS = [
    "test_propose_policy_change",
    "test_justification_minimum_length",
    "test_required_approvers_not_empty",
    "test_approval_transitions_to_under_review",
    "test_quorum_approval",
    "test_sole_approver_rejected",
    "test_activate_approved_proposal",
    "test_activate_without_approval_fails",
    "test_reject_proposal",
    "test_rollback_creates_inverse_proposal",
    "test_rollback_without_applied_fails",
    "test_audit_chain_integrity",
    "test_audit_chain_tamper_detection",
    "test_query_audit_by_proposal",
    "test_rollback_command_stored",
    "test_envelope_guarded_flag",
    "test_risk_assessment_ordering",
    "test_evidence_package_on_activation",
    "test_proposal_state_machine_full_lifecycle",
    "test_large_audit_chain_verification",
]


def safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {safe_rel(path)}" if ok else f"MISSING: {path}",
    }


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def read_rust_source(path: Path) -> str:
    return strip_rust_comments(read_text(path))


def strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = rust_block_comment_end(text, i + 2)
            continue

        raw_end = rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


def check_content(path, patterns, category, *, strip_comments=True):
    results = []
    if not path.exists():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    text = read_rust_source(path) if strip_comments else read_text(path)
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_module_registered():
    if not MOD_RS.exists():
        return {"check": "module registered in mod.rs", "pass": False, "detail": "mod.rs missing"}
    text = read_rust_source(MOD_RS)
    found = "pub mod approval_workflow;" in text
    return {
        "check": "module registered in mod.rs",
        "pass": found,
        "detail": "found" if found else "NOT FOUND",
    }


def check_test_count():
    if not IMPL.exists():
        return {"check": "unit test count", "pass": False, "detail": "impl missing"}
    text = read_rust_source(IMPL)
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 20
    return {
        "check": "unit test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 20)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = read_rust_source(IMPL)
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_hash_chain():
    results = []
    if not IMPL.exists():
        results.append({"check": "hash chain: SHA-256", "pass": False, "detail": "impl missing"})
        return results
    text = read_rust_source(IMPL)

    has_sha256 = "Sha256" in text
    results.append({
        "check": "hash chain: SHA-256",
        "pass": has_sha256,
        "detail": "found" if has_sha256 else "NOT FOUND",
    })

    has_prev_hash = "prev_hash" in text
    results.append({
        "check": "hash chain: prev_hash linkage",
        "pass": has_prev_hash,
        "detail": "found" if has_prev_hash else "NOT FOUND",
    })

    has_compute = "compute_entry_hash" in text
    results.append({
        "check": "hash chain: compute_entry_hash",
        "pass": has_compute,
        "detail": "found" if has_compute else "NOT FOUND",
    })

    has_verify = "verify_audit_chain" in text
    results.append({
        "check": "hash chain: verify_audit_chain",
        "pass": has_verify,
        "detail": "found" if has_verify else "NOT FOUND",
    })
    return results


def check_role_separation():
    results = []
    if not IMPL.exists():
        results.append({"check": "role separation: sole approver check", "pass": False, "detail": "impl missing"})
        return results
    text = read_rust_source(IMPL)

    has_sole = "ERR_SOLE_APPROVER" in text
    results.append({
        "check": "role separation: sole approver check",
        "pass": has_sole,
        "detail": "found" if has_sole else "NOT FOUND",
    })

    has_proposer = "proposed_by" in text
    results.append({
        "check": "role separation: proposer identity tracking",
        "pass": has_proposer,
        "detail": "found" if has_proposer else "NOT FOUND",
    })

    has_non_proposer = "non_proposer_approvals" in text
    results.append({
        "check": "role separation: non-proposer counting",
        "pass": has_non_proposer,
        "detail": "found" if has_non_proposer else "NOT FOUND",
    })
    return results


def check_rollback_mechanism():
    results = []
    if not IMPL.exists():
        results.append({"check": "rollback: function exists", "pass": False, "detail": "impl missing"})
        return results
    text = read_rust_source(IMPL)

    has_rollback_fn = "pub fn rollback(" in text
    results.append({
        "check": "rollback: function exists",
        "pass": has_rollback_fn,
        "detail": "found" if has_rollback_fn else "NOT FOUND",
    })

    has_inverse = "old_value: d.new_value" in text or "inverse_diff" in text or "rollback_of" in text
    results.append({
        "check": "rollback: inverse diff computation",
        "pass": has_inverse,
        "detail": "found" if has_inverse else "NOT FOUND",
    })

    has_rollback_ref = "rollback_of" in text
    results.append({
        "check": "rollback: original proposal reference",
        "pass": has_rollback_ref,
        "detail": "found" if has_rollback_ref else "NOT FOUND",
    })

    has_rollback_cmd = "rollback_command" in text
    results.append({
        "check": "rollback: deterministic rollback command",
        "pass": has_rollback_cmd,
        "detail": "found" if has_rollback_cmd else "NOT FOUND",
    })
    return results


def check_spec_invariants():
    results = []
    if not SPEC.exists():
        for inv in INVARIANTS:
            results.append({"check": f"spec invariant: {inv}", "pass": False, "detail": "spec missing"})
        return results
    text = read_text(SPEC)
    for inv in INVARIANTS:
        found = inv in text
        results.append({
            "check": f"spec invariant: {inv}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "implementation"))
    checks.append(check_file(SPEC, "spec contract"))

    # Module registration
    checks.append(check_module_registered())

    # Test count
    checks.append(check_test_count())

    # Serde
    checks.append(check_serde_derives())

    # Types
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))

    # Methods
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))

    # Event codes
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))

    # Error codes
    checks.extend(check_content(IMPL, ERROR_CODES, "error_code"))

    # Proposal states
    checks.extend(check_content(IMPL, PROPOSAL_STATES, "state"))

    # Required tests
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    # Spec invariants
    checks.extend(check_spec_invariants())

    # Hash chain
    checks.extend(check_hash_chain())

    # Role separation
    checks.extend(check_role_separation())

    # Rollback mechanism
    checks.extend(check_rollback_mechanism())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-sh3",
        "title": "Policy change approval workflows with cryptographic audit trail",
        "section": "10.5",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": check_test_count()["detail"].split()[0] if IMPL.exists() else 0,
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    logger = configure_test_logging("check_policy_change_workflow")
    logger.info("starting %s verification", "check_policy_change_workflow")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-sh3 verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
