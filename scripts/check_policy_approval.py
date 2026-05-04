#!/usr/bin/env python3
"""Verification script for bd-sh3 policy change approval workflows."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

SPEC_PATH = ROOT / "docs/specs/section_10_5/bd-sh3_contract.md"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/policy/approval_workflow.rs"
MOD_PATH = ROOT / "crates/franken-node/src/policy/mod.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_5/bd-sh3"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-POL-MULTI-PARTY",
    "INV-POL-ROLE-SEP",
    "INV-POL-HASH-CHAIN",
    "INV-POL-ROLLBACK",
    "INV-POL-EVIDENCE",
    "INV-POL-JUSTIFICATION",
    "INV-POL-ENVELOPE",
    "INV-POL-LIFECYCLE",
]

REQUIRED_RUST_SYMBOLS = [
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

REQUIRED_EVENT_CODES = [
    "POLICY_CHANGE_PROPOSED",
    "POLICY_CHANGE_REVIEWED",
    "POLICY_CHANGE_APPROVED",
    "POLICY_CHANGE_REJECTED",
    "POLICY_CHANGE_ACTIVATED",
    "POLICY_CHANGE_ROLLED_BACK",
    "AUDIT_CHAIN_VERIFIED",
    "AUDIT_CHAIN_BROKEN",
]

REQUIRED_ERROR_CODES = [
    "ERR_PROPOSAL_NOT_FOUND",
    "ERR_SOLE_APPROVER",
    "ERR_INVALID_SIGNATURE",
    "ERR_QUORUM_NOT_MET",
    "ERR_INVALID_STATE_TRANSITION",
    "ERR_AUDIT_CHAIN_BROKEN",
    "ERR_JUSTIFICATION_TOO_SHORT",
]

REQUIRED_ENGINE_METHODS = [
    "pub fn propose(",
    "pub fn approve(",
    "pub fn reject(",
    "pub fn activate(",
    "pub fn rollback(",
    "pub fn get_proposal(",
    "pub fn audit_ledger(",
    "pub fn verify_audit_chain(",
    "pub fn query_audit_by_proposal(",
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

REQUIRED_STATES = [
    "Proposed",
    "UnderReview",
    "Approved",
    "Rejected",
    "Applied",
    "RolledBack",
]


def check_file_exists(path: Path) -> dict[str, Any]:
    display_path = render_path(path)
    exists = path.exists()
    if exists:
        try:
            size_bytes = path.stat().st_size
        except OSError as exc:
            return {
                "path": display_path,
                "exists": False,
                "size_bytes": 0,
                "reason": f"unable to stat file: {exc}",
            }
    return {
        "path": display_path,
        "exists": exists,
        "size_bytes": size_bytes if exists else 0,
    }


def render_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def read_required_text(path: Path, missing_reason: str) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, missing_reason
    try:
        return path.read_text(encoding="utf-8"), None
    except UnicodeError as exc:
        return None, f"invalid UTF-8 in {render_path(path)}: {exc}"
    except OSError as exc:
        return None, f"unable to read {render_path(path)}: {exc}"


def check_content(name: str, path: Path, required: list[str]) -> dict[str, Any]:
    content, error = read_required_text(path, f"{name} file not found")
    if error is not None:
        return {"pass": False, "reason": error, "found": [], "missing": required}
    found = [item for item in required if item in content]
    missing = [item for item in required if item not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_mod_registration() -> dict[str, Any]:
    content, error = read_required_text(MOD_PATH, "mod.rs not found")
    if error is not None:
        return {"pass": False, "reason": error}
    has_module = "pub mod approval_workflow;" in content
    return {"pass": has_module, "registered": has_module}


def check_hash_chain() -> dict[str, Any]:
    content, error = read_required_text(RUST_IMPL_PATH, "rust impl not found")
    if error is not None:
        return {"pass": False, "reason": error}
    has_prev_hash = "prev_hash" in content
    has_entry_hash = "entry_hash" in content
    has_sha256 = "Sha256" in content
    has_verify = "verify_audit_chain" in content
    return {
        "pass": all([has_prev_hash, has_entry_hash, has_sha256, has_verify]),
        "hash_chain": has_prev_hash and has_entry_hash,
        "sha256": has_sha256,
        "integrity_check": has_verify,
    }


def check_role_separation() -> dict[str, Any]:
    content, error = read_required_text(RUST_IMPL_PATH, "rust impl not found")
    if error is not None:
        return {"pass": False, "reason": error}
    has_sole_check = "ERR_SOLE_APPROVER" in content
    has_proposer_check = "proposed_by" in content
    has_non_proposer = "non_proposer_approvals" in content
    return {
        "pass": all([has_sole_check, has_proposer_check, has_non_proposer]),
        "sole_approver_check": has_sole_check,
        "proposer_identity_check": has_proposer_check,
        "non_proposer_counting": has_non_proposer,
    }


def check_rollback_mechanism() -> dict[str, Any]:
    content, error = read_required_text(RUST_IMPL_PATH, "rust impl not found")
    if error is not None:
        return {"pass": False, "reason": error}
    has_rollback_fn = "pub fn rollback(" in content
    has_inverse_diff = "inverse_diff" in content
    has_rollback_of = "rollback_of" in content
    has_rollback_command = "rollback_command" in content
    return {
        "pass": all([has_rollback_fn, has_inverse_diff, has_rollback_of, has_rollback_command]),
        "rollback_function": has_rollback_fn,
        "inverse_diff": has_inverse_diff,
        "rollback_reference": has_rollback_of,
        "rollback_command": has_rollback_command,
    }


def run_all_checks() -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = {
        "files": {
            "spec": check_file_exists(SPEC_PATH),
            "rust_impl": check_file_exists(RUST_IMPL_PATH),
            "mod_rs": check_file_exists(MOD_PATH),
        },
        "spec_invariants": check_content("spec", SPEC_PATH, REQUIRED_INVARIANTS),
        "rust_symbols": check_content("rust", RUST_IMPL_PATH, REQUIRED_RUST_SYMBOLS),
        "event_codes": check_content("rust", RUST_IMPL_PATH, REQUIRED_EVENT_CODES),
        "error_codes": check_content("rust", RUST_IMPL_PATH, REQUIRED_ERROR_CODES),
        "engine_methods": check_content("rust", RUST_IMPL_PATH, REQUIRED_ENGINE_METHODS),
        "tests": check_content("rust", RUST_IMPL_PATH, REQUIRED_TESTS),
        "states": check_content("rust", RUST_IMPL_PATH, REQUIRED_STATES),
        "mod_registration": check_mod_registration(),
        "hash_chain": check_hash_chain(),
        "role_separation": check_role_separation(),
        "rollback_mechanism": check_rollback_mechanism(),
    }

    check_results = [
        checks["spec_invariants"],
        checks["rust_symbols"],
        checks["event_codes"],
        checks["error_codes"],
        checks["engine_methods"],
        checks["tests"],
        checks["states"],
        checks["mod_registration"],
        checks["hash_chain"],
        checks["role_separation"],
        checks["rollback_mechanism"],
    ]

    all_pass = all(c.get("pass", False) for c in check_results)
    file_pass = all(f["exists"] for f in checks["files"].values())
    passed_count = sum(1 for c in check_results if c.get("pass", False)) + (1 if file_pass else 0)

    return {
        "bead_id": "bd-sh3",
        "section": "10.5",
        "title": "Policy Change Approval Workflows with Cryptographic Audit Trail",
        "timestamp": timestamp,
        "overall_pass": all_pass and file_pass,
        "checks": checks,
        "summary": {
            "total_checks": 12,
            "passed": passed_count,
            "failed": 12 - passed_count,
        },
    }


def write_evidence(evidence: dict[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def write_summary(evidence: dict[str, Any]) -> None:
    s = evidence["summary"]
    lines = [
        f"# Verification Summary: {evidence['title']}",
        "",
        f"**Bead:** {evidence['bead_id']} | **Section:** {evidence['section']}",
        f"**Timestamp:** {evidence['timestamp']}",
        f"**Overall:** {'PASS' if evidence['overall_pass'] else 'FAIL'}",
        f"**Checks:** {s['passed']}/{s['total_checks']} passed",
        "",
        "## Check Results",
        "",
    ]
    for name, result in sorted(evidence["checks"].items()):
        if name == "files":
            for fname, finfo in result.items():
                status = "PASS" if finfo["exists"] else "FAIL"
                lines.append(f"- **File {fname}:** {status} ({finfo['path']}, {finfo['size_bytes']} bytes)")
        else:
            status = "PASS" if result.get("pass", False) else "FAIL"
            lines.append(f"- **{name}:** {status}")
            if "missing" in result and result["missing"]:
                for m in result["missing"]:
                    lines.append(f"  - Missing: `{m}`")

    lines.extend(["", "## Artifacts", ""])
    lines.append(f"- Spec: `{SPEC_PATH.relative_to(ROOT)}`")
    lines.append(f"- Implementation: `{RUST_IMPL_PATH.relative_to(ROOT)}`")
    lines.append(f"- Evidence: `{EVIDENCE_PATH.relative_to(ROOT)}`")
    lines.append("")
    SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def self_test() -> bool:
    evidence = run_all_checks()
    if not isinstance(evidence, dict):
        raise AssertionError("evidence must be a dictionary")
    if evidence.get("bead_id") != "bd-sh3":
        raise AssertionError("evidence bead_id mismatch")
    for key in ("checks", "summary"):
        if key not in evidence:
            raise AssertionError(f"missing evidence key: {key}")
    expected = [
        "files", "spec_invariants", "rust_symbols", "event_codes",
        "error_codes", "engine_methods", "tests", "states",
        "mod_registration", "hash_chain", "role_separation", "rollback_mechanism",
    ]
    missing = []
    for cat in expected:
        if cat not in evidence["checks"]:
            missing.append(cat)
    if missing:
        raise AssertionError(f"missing checks: {', '.join(missing)}")
    return True


def main() -> None:
    configure_test_logging("check_policy_approval")
    parser = argparse.ArgumentParser(description="Verify bd-sh3 policy approval workflows")
    parser.add_argument("--json", action="store_true", help="Output JSON evidence")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    evidence = run_all_checks()

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        s = evidence["summary"]
        status = "PASS" if evidence["overall_pass"] else "FAIL"
        print(f"bd-sh3 verification: {status} ({s['passed']}/{s['total_checks']} checks passed)")
        for name, result in sorted(evidence["checks"].items()):
            if name == "files":
                for fname, finfo in result.items():
                    sym = "+" if finfo["exists"] else "-"
                    print(f"  [{sym}] file:{fname} {finfo['path']}")
            else:
                sym = "+" if result.get("pass", False) else "-"
                print(f"  [{sym}] {name}")
                if "missing" in result and result["missing"]:
                    for m in result["missing"]:
                        print(f"       missing: {m}")

    write_evidence(evidence)
    write_summary(evidence)


if __name__ == "__main__":
    main()
