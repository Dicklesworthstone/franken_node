#!/usr/bin/env python3
"""
EvidenceEntry schema verification for bd-nupr.

Usage:
    python3 scripts/check_evidence_entry_schema.py [--json]
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "spec" / "evidence_entry_v1.json"
SPEC_PATH = ROOT / "docs" / "specs" / "evidence_entry_schema.md"
VALIDATION_REPORT_PATH = ROOT / "artifacts" / "10.14" / "evidence_schema_validation_report.json"
EVIDENCE_OUT_PATH = ROOT / "artifacts" / "section_10_14" / "bd-nupr" / "verification_evidence.json"

CANONICAL_ROOT_FIELDS = [
    "schema_version",
    "decision_id",
    "decision_kind",
    "decision_time",
    "trace_id",
    "candidates",
    "constraints",
    "chosen_action",
    "witness_refs",
    "canonical_order",
]

CHECK_IDS = {
    "schema": "EE-SCHEMA",
    "spec": "EE-SPEC",
    "report": "EE-REPORT",
    "unit": "EE-UNIT",
    "integration": "EE-INTEGRATION",
    "e2e": "EE-E2E",
    "logs": "EE-LOGS",
}

ERROR_CODES = {
    "missing": "EE_MISSING_REQUIRED_FIELD",
    "order": "EE_INVALID_CANONICAL_ORDER",
    "candidate_order": "EE_INVALID_CANDIDATE_ORDER",
    "chosen": "EE_UNKNOWN_CHOSEN_CANDIDATE",
    "witness": "EE_INVALID_WITNESS_DIGEST",
    "constraints": "EE_INVALID_CONSTRAINT_ORDER",
}

EVENT_CODES = {
    "started": "EVIDENCE_SCHEMA_VALIDATION_STARTED",
    "case": "EVIDENCE_SCHEMA_VALIDATION_CASE",
    "completed": "EVIDENCE_SCHEMA_VALIDATION_COMPLETED",
}


def check_result(check_id: str, description: str, passed: bool, details: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": check_id,
        "description": description,
        "status": "PASS" if passed else "FAIL",
    }
    if details is not None:
        result["details"] = details
    return result


def make_valid_entry() -> dict[str, Any]:
    entry = {
        "schema_version": "1.0",
        "decision_id": "DEC-20260220-example",
        "decision_kind": "admit",
        "decision_time": "2026-02-20T17:13:00Z",
        "trace_id": "trace-bd-nupr-001",
        "candidates": [
            {
                "ordinal": 1,
                "candidate_id": "cand-alpha",
                "action_code": "allow",
                "score": 0.92,
                "feasible": True,
                "rationale_refs": ["R-001"],
            },
            {
                "ordinal": 2,
                "candidate_id": "cand-beta",
                "action_code": "deny",
                "score": 0.17,
                "feasible": True,
                "rationale_refs": ["R-002"],
            },
        ],
        "constraints": [
            {
                "constraint_id": "C-001",
                "severity": "high",
                "status": "pass",
                "details": "Revocation frontier is fresh.",
            },
            {
                "constraint_id": "C-010",
                "severity": "medium",
                "status": "pass",
                "details": "Risk envelope within threshold.",
            },
        ],
        "chosen_action": {
            "candidate_id": "cand-alpha",
            "action_code": "allow",
            "justification": "Lowest expected loss while preserving safety constraints.",
            "expected_loss": 0.03,
        },
        "witness_refs": [
            {
                "witness_id": "W-001",
                "witness_type": "proof",
                "digest_sha256": "a" * 64,
                "uri": "artifact://proofs/decision-W-001.json",
            }
        ],
        "canonical_order": {
            "root_fields": CANONICAL_ROOT_FIELDS,
            "candidate_sort_rule": "ordinal-ascending-then-candidate-id",
            "constraint_sort_rule": "constraint-id-lexicographic",
        },
    }
    return entry


def validate_entry(entry: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    required = set(CANONICAL_ROOT_FIELDS)
    if not required.issubset(entry.keys()):
        errors.append(ERROR_CODES["missing"])

    if list(entry.keys()) != CANONICAL_ROOT_FIELDS:
        errors.append(ERROR_CODES["order"])

    canonical = entry.get("canonical_order", {})
    if canonical.get("root_fields") != CANONICAL_ROOT_FIELDS:
        errors.append(ERROR_CODES["order"])

    candidates = entry.get("candidates", [])
    if not isinstance(candidates, list) or len(candidates) == 0:
        errors.append(ERROR_CODES["missing"])
    else:
        sorted_candidates = sorted(candidates, key=lambda c: (c.get("ordinal", 0), c.get("candidate_id", "")))
        if sorted_candidates != candidates:
            errors.append(ERROR_CODES["candidate_order"])
        ordinals = [c.get("ordinal") for c in candidates]
        if len(set(ordinals)) != len(ordinals):
            errors.append(ERROR_CODES["candidate_order"])

    constraints = entry.get("constraints", [])
    if isinstance(constraints, list) and constraints:
        sorted_constraints = sorted(constraints, key=lambda c: c.get("constraint_id", ""))
        if sorted_constraints != constraints:
            errors.append(ERROR_CODES["constraints"])

    chosen = entry.get("chosen_action", {})
    candidate_ids = {c.get("candidate_id") for c in candidates if isinstance(c, dict)}
    if chosen.get("candidate_id") not in candidate_ids:
        errors.append(ERROR_CODES["chosen"])

    witness_refs = entry.get("witness_refs", [])
    if not witness_refs:
        errors.append(ERROR_CODES["missing"])
    else:
        for witness in witness_refs:
            digest = witness.get("digest_sha256", "")
            if not re.fullmatch(r"[a-f0-9]{64}", digest):
                errors.append(ERROR_CODES["witness"])
                break

    return sorted(set(errors))


def check_schema_contract() -> dict[str, Any]:
    if not SCHEMA_PATH.exists():
        return check_result(CHECK_IDS["schema"], "Schema file exists and encodes canonical fields", False)

    schema = json.loads(SCHEMA_PATH.read_text())
    required = schema.get("required", [])
    props = schema.get("properties", {})
    canonical = props.get("canonical_order", {}).get("properties", {})
    root_const = canonical.get("root_fields", {}).get("const", [])

    passed = (
        set(CANONICAL_ROOT_FIELDS).issubset(set(required))
        and "chosen_action" in props
        and "witness_refs" in props
        and root_const == CANONICAL_ROOT_FIELDS
    )
    return check_result(
        CHECK_IDS["schema"],
        "Schema file exists and encodes canonical fields",
        passed,
        {
            "required_count": len(required),
            "root_const_matches": root_const == CANONICAL_ROOT_FIELDS,
        },
    )


def check_spec_contract() -> dict[str, Any]:
    if not SPEC_PATH.exists():
        return check_result(CHECK_IDS["spec"], "Spec contract documents required invariants", False)

    content = SPEC_PATH.read_text()
    required_terms = [
        "decision kind",
        "candidates",
        "constraints",
        "chosen action",
        "witness references",
        "INV-EE-CANDIDATE-ORDER",
        "EE_INVALID_CANDIDATE_ORDER",
    ]
    missing = [term for term in required_terms if term.lower() not in content.lower()]
    return check_result(
        CHECK_IDS["spec"],
        "Spec contract documents required invariants",
        len(missing) == 0,
        {"missing_terms": missing},
    )


def check_validation_report() -> dict[str, Any]:
    if not VALIDATION_REPORT_PATH.exists():
        return check_result(CHECK_IDS["report"], "Validation report artifact is present and complete", False)

    report = json.loads(VALIDATION_REPORT_PATH.read_text())
    cases = report.get("cases", [])
    summary = report.get("summary", {})
    expected_case_ids = {
        "valid-canonical-entry",
        "missing-witness-refs",
        "candidate-order-violation",
        "chosen-candidate-missing",
    }
    actual_case_ids = {c.get("id") for c in cases}

    passed = (
        report.get("event_code") == EVENT_CODES["completed"]
        and expected_case_ids.issubset(actual_case_ids)
        and summary.get("verdict") == "PASS"
        and summary.get("actual_matches_expectation") == len(cases)
    )

    return check_result(
        CHECK_IDS["report"],
        "Validation report artifact is present and complete",
        passed,
        {
            "case_count": len(cases),
            "expected_cases_present": expected_case_ids.issubset(actual_case_ids),
            "summary_verdict": summary.get("verdict"),
        },
    )


def check_unit_semantics() -> dict[str, Any]:
    valid = make_valid_entry()
    invalid_missing = make_valid_entry()
    invalid_missing.pop("witness_refs")
    invalid_order = make_valid_entry()
    invalid_order["candidates"][0], invalid_order["candidates"][1] = (
        invalid_order["candidates"][1],
        invalid_order["candidates"][0],
    )

    valid_errors = validate_entry(valid)
    missing_errors = validate_entry(invalid_missing)
    order_errors = validate_entry(invalid_order)

    passed = (
        valid_errors == []
        and ERROR_CODES["missing"] in missing_errors
        and ERROR_CODES["candidate_order"] in order_errors
    )

    return check_result(
        CHECK_IDS["unit"],
        "Unit semantics for positive and negative schema cases",
        passed,
        {
            "valid_error_count": len(valid_errors),
            "missing_case_errors": missing_errors,
            "order_case_errors": order_errors,
        },
    )


def check_integration_semantics() -> dict[str, Any]:
    entry = make_valid_entry()
    canonical_json = json.dumps(entry, separators=(",", ":"), ensure_ascii=True)
    round_trip = json.loads(canonical_json)
    passed = validate_entry(round_trip) == [] and list(round_trip.keys()) == CANONICAL_ROOT_FIELDS
    return check_result(
        CHECK_IDS["integration"],
        "Integration check: canonical serialization round-trip",
        passed,
        {"json_length": len(canonical_json)},
    )


def check_e2e_flow() -> dict[str, Any]:
    # E2E proxy: script-level self-validation inputs all present.
    required_paths = [SCHEMA_PATH, SPEC_PATH, VALIDATION_REPORT_PATH]
    missing_paths = [str(p.relative_to(ROOT)) for p in required_paths if not p.exists()]
    passed = len(missing_paths) == 0
    return check_result(
        CHECK_IDS["e2e"],
        "E2E gate inputs exist for full validation flow",
        passed,
        {"missing_paths": missing_paths},
    )


def check_structured_logs() -> dict[str, Any]:
    report = json.loads(VALIDATION_REPORT_PATH.read_text()) if VALIDATION_REPORT_PATH.exists() else {}
    logs = report.get("structured_logs", [])
    found = {log.get("event_code") for log in logs}
    expected = set(EVENT_CODES.values())
    passed = expected.issubset(found)
    return check_result(
        CHECK_IDS["logs"],
        "Structured log event codes are stable and present",
        passed,
        {"found_event_codes": sorted(found)},
    )


def self_test() -> dict[str, Any]:
    checks = [
        check_schema_contract(),
        check_spec_contract(),
        check_validation_report(),
        check_unit_semantics(),
        check_integration_semantics(),
        check_e2e_flow(),
        check_structured_logs(),
    ]
    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "evidence_entry_schema_verification",
        "bead": "bd-nupr",
        "section": "10.14",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main() -> int:
    json_output = "--json" in sys.argv
    result = self_test()

    EVIDENCE_OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_OUT_PATH.write_text(json.dumps(result, indent=2) + "\n")

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for check in result["checks"]:
            icon = "OK" if check["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {check['id']}: {check['description']}")
        print(f"\nVerdict: {result['verdict']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
