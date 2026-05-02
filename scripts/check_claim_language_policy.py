#!/usr/bin/env python3
"""Verification script for bd-33kj: claim-language policy for trust/replay claims.

Validates that the claim-language policy document exists, contains required
sections, defines event codes, maps claims to asupersync-backed invariants,
and has no unbacked claims.

Usage:
    python3 scripts/check_claim_language_policy.py           # human-readable
    python3 scripts/check_claim_language_policy.py --json     # machine-readable
    python3 scripts/check_claim_language_policy.py --self-test # internal validation
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


BEAD_ID = "bd-33kj"
SECTION = "10.15"
TITLE = "Claim-language policy tying trust/replay claims to asupersync-backed invariant evidence"

POLICY_PATH = ROOT / "docs" / "policy" / "claim_language_policy.md"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_15" / "bd-33kj_contract.md"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_15" / "bd-33kj" / "verification_evidence.json"

# Event codes that must be defined in the policy document
REQUIRED_EVENT_CODES = ["CLM-001", "CLM-002", "CLM-003", "CLM-004"]

# Required sections in the policy document
REQUIRED_SECTIONS = [
    "Purpose",
    "Rules",
    "Event Codes",
    "Claim-Invariant Mapping Table",
    "Invariant Definitions",
    "Retired Claims",
]

# Required rule phrases (key wording from each rule)
REQUIRED_RULES = [
    "No Claim Without Backing Invariant",
    "Claims Must Cite Evidence Artifact Path",
]

# Asupersync-backed invariants that must be referenced
REQUIRED_INVARIANTS = [
    "INV-EP-MONOTONIC",
    "INV-EP-DRAIN-BARRIER",
    "INV-EP-FAIL-CLOSED",
    "INV-EP-SPLIT-BRAIN-GUARD",
    "INV-EP-IMMUTABLE-CREATION-EPOCH",
    "INV-EP-AUDIT-HISTORY",
]

# Claim categories expected in the mapping table
REQUIRED_CLAIM_CATEGORIES = ["replay", "trust", "security", "integrity", "resilience"]

# Minimum number of claim-invariant mappings expected
MIN_CLAIM_MAPPINGS = 5


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _count_claim_mappings(text: str) -> int:
    """Count CLM-*-NN entries in the mapping table."""
    return len(re.findall(r"\bCLM-[A-Z]+-\d+\b", text))


def _configure_logging() -> None:
    from scripts.lib.test_logger import configure_test_logging

    configure_test_logging("check_claim_language_policy")


def run_checks() -> dict:
    """Run all verification checks and return structured result."""
    policy = _read(POLICY_PATH)
    spec = _read(SPEC_PATH)

    checks: list[dict] = []

    # --- File existence checks ---
    checks.append(_check(
        "policy_doc_exists",
        POLICY_PATH.is_file(),
        str(POLICY_PATH.relative_to(ROOT)) if POLICY_PATH.is_file() else "MISSING",
    ))
    checks.append(_check(
        "spec_contract_exists",
        SPEC_PATH.is_file(),
        str(SPEC_PATH.relative_to(ROOT)) if SPEC_PATH.is_file() else "MISSING",
    ))
    checks.append(_check(
        "evidence_artifact_exists",
        EVIDENCE_PATH.is_file(),
        str(EVIDENCE_PATH.relative_to(ROOT)) if EVIDENCE_PATH.is_file() else "MISSING",
    ))

    # --- Required sections ---
    for section in REQUIRED_SECTIONS:
        found = section in policy
        checks.append(_check(
            f"section:{section}",
            found,
            f"'{section}' present in policy" if found else f"'{section}' NOT FOUND",
        ))

    # --- Required rules ---
    for rule in REQUIRED_RULES:
        found = rule in policy
        checks.append(_check(
            f"rule:{rule}",
            found,
            "rule present" if found else "rule NOT FOUND in policy",
        ))

    # --- Event codes ---
    for code in REQUIRED_EVENT_CODES:
        found = code in policy
        checks.append(_check(
            f"event_code:{code}",
            found,
            f"{code} defined in policy" if found else f"{code} NOT FOUND",
        ))

    # --- Event codes also in spec ---
    for code in REQUIRED_EVENT_CODES:
        found = code in spec
        checks.append(_check(
            f"spec_event_code:{code}",
            found,
            f"{code} present in spec contract" if found else f"{code} NOT FOUND in spec",
        ))

    # --- Asupersync-backed invariants referenced ---
    for inv in REQUIRED_INVARIANTS:
        found = inv in policy
        checks.append(_check(
            f"invariant:{inv}",
            found,
            f"{inv} referenced in policy" if found else f"{inv} NOT FOUND",
        ))

    # --- Claim categories ---
    for cat in REQUIRED_CLAIM_CATEGORIES:
        found = cat in policy
        checks.append(_check(
            f"claim_category:{cat}",
            found,
            f"category '{cat}' present" if found else f"category '{cat}' NOT FOUND",
        ))

    # --- Claim-invariant mapping count ---
    mapping_count = _count_claim_mappings(policy)
    checks.append(_check(
        "claim_mapping_count",
        mapping_count >= MIN_CLAIM_MAPPINGS,
        f"{mapping_count} claim mappings (>= {MIN_CLAIM_MAPPINGS} required)",
    ))

    # --- No unbacked claims: every CLM-* must reference at least one INV-EP- ---
    claim_ids = re.findall(r"\bCLM-[A-Z]+-\d+\b", policy)
    unbacked = []
    if claim_ids:
        # Parse each row from the mapping table
        rows = re.findall(
            r"\|\s*(CLM-[A-Z]+-\d+)\s*\|[^|]*\|[^|]*\|([^|]*)\|",
            policy,
        )
        for claim_id, invariant_cell in rows:
            if "INV-" not in invariant_cell:
                unbacked.append(claim_id)

    checks.append(_check(
        "no_unbacked_claims",
        len(unbacked) == 0,
        "0 unbacked claims" if not unbacked else f"unbacked: {', '.join(unbacked)}",
    ))

    # --- Evidence artifact verdict ---
    evidence_verdict = None
    if EVIDENCE_PATH.is_file():
        try:
            evidence_data = json.JSONDecoder().decode(EVIDENCE_PATH.read_text(encoding="utf-8"))
            evidence_verdict = evidence_data.get("verdict")
        except (json.JSONDecodeError, OSError):
            pass

    checks.append(_check(
        "evidence_verdict_pass",
        evidence_verdict == "PASS",
        f"verdict: {evidence_verdict}" if evidence_verdict else "verdict not found",
    ))

    # --- Asupersync keyword presence ---
    has_asupersync = "asupersync" in policy.lower()
    checks.append(_check(
        "asupersync_referenced",
        has_asupersync,
        "asupersync referenced in policy" if has_asupersync else "asupersync NOT FOUND",
    ))

    # --- Staleness window defined ---
    has_staleness = "staleness" in policy.lower() or "stale" in policy.lower()
    checks.append(_check(
        "staleness_window_defined",
        has_staleness,
        "staleness window defined" if has_staleness else "staleness window NOT FOUND",
    ))

    # --- Retirement protocol ---
    has_retirement = "retire" in policy.lower()
    checks.append(_check(
        "retirement_protocol_defined",
        has_retirement,
        "retirement protocol present" if has_retirement else "retirement protocol NOT FOUND",
    ))

    # --- Compile result ---
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "summary": {"passing": passed, "failing": failed, "total": passed + failed},
        "verdict": "PASS" if failed == 0 else "FAIL",
        "overall_pass": failed == 0,
    }


def self_test() -> tuple[bool, list]:
    """Internal validation: ensure check structure is well-formed."""
    result = run_checks()

    if result["bead_id"] != BEAD_ID:
        raise RuntimeError(f"bead_id mismatch: {result['bead_id']}")
    if result["section"] != SECTION:
        raise RuntimeError(f"section mismatch: {result['section']}")
    if result["summary"]["total"] < 25:
        raise RuntimeError(f"expected >= 25 checks, got {result['summary']['total']}")

    for check in result["checks"]:
        if "name" not in check:
            raise RuntimeError(f"check missing 'name': {check}")
        if "passed" not in check:
            raise RuntimeError(f"check missing 'passed': {check}")
        if "detail" not in check:
            raise RuntimeError(f"check missing 'detail': {check}")

    all_pass = result["summary"]["failing"] == 0
    return all_pass, result["checks"]


def main() -> None:
    _configure_logging()
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        status = "PASS" if ok else "FAIL"
        print(f"self_test: {status} ({len(checks)} checks verified)")
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== {BEAD_ID}: Claim-Language Policy Verification ===")
        print()
        for check in result["checks"]:
            marker = "PASS" if check["passed"] else "FAIL"
            print(f"  [{marker}] {check['name']}: {check['detail']}")
        print()
        s = result["summary"]
        print(f"Checks: {s['passing']}/{s['total']} pass")
        print(f"Verdict: {result['verdict']}")

    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
