#!/usr/bin/env python3
"""Verification script for bd-p73r: canonical VEF ExecutionReceipt contract.

Usage:
    python3 scripts/check_vef_execution_receipt.py
    python3 scripts/check_vef_execution_receipt.py --json
    python3 scripts/check_vef_execution_receipt.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_execution_receipt.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
SPEC_DOC = ROOT / "docs" / "specs" / "vef_execution_receipt.md"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-p73r_contract.md"
SCHEMA = ROOT / "spec" / "vef_execution_receipt_v1.json"
VECTORS = ROOT / "artifacts" / "10.18" / "vef_receipt_schema_vectors.json"
UNIT_TEST = ROOT / "tests" / "test_check_vef_execution_receipt.py"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-p73r" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-p73r" / "verification_summary.md"

ACTION_TYPES = [
    "network_access",
    "filesystem_operation",
    "process_spawn",
    "secret_access",
    "policy_transition",
    "artifact_promotion",
]

REQUIRED_EVENT_CODES = [
    "VEF-RECEIPT-001",
    "VEF-RECEIPT-002",
]

REQUIRED_ERROR_CODES = [
    "VEF-RECEIPT-ERR-001",
    "VEF-RECEIPT-ERR-002",
    "VEF-RECEIPT-ERR-003",
    "VEF-RECEIPT-ERR-004",
    "VEF-RECEIPT-ERR-005",
]

REQUIRED_INVARIANTS = [
    "INV-VEF-RECEIPT-DETERMINISTIC",
    "INV-VEF-RECEIPT-HASH-STABLE",
    "INV-VEF-RECEIPT-VERSIONED",
    "INV-VEF-RECEIPT-TRACEABLE",
]

REQUIRED_IMPL_SYMBOLS = [
    "pub enum ExecutionActionType",
    "pub struct ExecutionReceipt",
    "pub struct ExecutionReceiptError",
    "pub fn validate_receipt",
    "pub fn serialize_canonical",
    "pub fn receipt_hash_sha256",
    "pub fn verify_hash",
    "pub fn round_trip_canonical_bytes",
    "pub fn canonicalized",
]

REQUIRED_RECEIPT_FIELDS = [
    "schema_version",
    "action_type",
    "capability_context",
    "actor_identity",
    "artifact_identity",
    "policy_snapshot_hash",
    "timestamp_millis",
    "sequence_number",
    "witness_references",
    "trace_id",
]

RECEIPT_FIELD_ORDER = [
    "schema_version",
    "action_type",
    "capability_context",
    "actor_identity",
    "artifact_identity",
    "policy_snapshot_hash",
    "timestamp_millis",
    "sequence_number",
    "witness_references",
    "trace_id",
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


def _canonical_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    canonical: dict[str, Any] = {}
    for field in RECEIPT_FIELD_ORDER:
        value = receipt[field]
        if field == "capability_context" and isinstance(value, dict):
            value = dict(sorted(value.items()))
        elif field == "witness_references" and isinstance(value, list):
            value = sorted(set(value))
        canonical[field] = value
    return json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _canonical_receipt_hash(receipt: dict[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(_canonical_receipt_bytes(receipt)).hexdigest()}"


def check_file_presence() -> None:
    files = [
        ("impl_exists", IMPL),
        ("mod_exists", MOD_RS),
        ("spec_doc_exists", SPEC_DOC),
        ("spec_contract_exists", SPEC_CONTRACT),
        ("schema_exists", SCHEMA),
        ("vectors_exists", VECTORS),
        ("unit_test_exists", UNIT_TEST),
        ("evidence_exists", EVIDENCE),
        ("summary_exists", SUMMARY),
    ]
    for name, path in files:
        _check(name, path.is_file(), _safe_rel(path))


def check_impl_symbols() -> None:
    src = _read(IMPL)
    for symbol in REQUIRED_IMPL_SYMBOLS:
        _check(f"impl_symbol_{symbol}", symbol in src, symbol)

    for field in REQUIRED_RECEIPT_FIELDS:
        _check(f"impl_field_{field}", field in src, field)

    for action in ACTION_TYPES:
        _check(f"impl_action_type_{action}", action in src, action)

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_{code}", code in src, code)

    for code in REQUIRED_ERROR_CODES:
        _check(f"impl_error_{code}", code in src, code)

    for invariant in REQUIRED_INVARIANTS:
        _check(f"impl_invariant_{invariant}", invariant in src, invariant)

    _check("impl_uses_sha256", "Sha256" in src, "Sha256")
    _check("impl_has_validation_hash_prefix", "sha256:" in src, "sha256:")
    _check("impl_has_canonicalization", "witness_references.sort()" in src, "witness_references.sort()")

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 15, f"{test_count} tests")


def check_mod_wiring() -> None:
    mod_text = _read(MOD_RS)
    _check(
        "connector_mod_wires_vef_execution_receipt",
        "pub mod vef_execution_receipt;" in mod_text,
        "pub mod vef_execution_receipt;",
    )


def check_schema_structure() -> None:
    schema = _load_json(SCHEMA)
    if schema is None:
        _check("schema_parseable_json", False, "invalid or missing JSON")
        return

    _check("schema_parseable_json", True, "valid JSON")
    _check("schema_draft_2020_12", schema.get("$schema", "").endswith("2020-12/schema"), schema.get("$schema", ""))

    required = set(schema.get("required", []))
    _check("schema_required_top_fields", set(REQUIRED_RECEIPT_FIELDS).issubset(required), f"have={len(required)}")

    props = schema.get("properties", {})
    _check("schema_has_properties_block", isinstance(props, dict), "properties")
    if isinstance(props, dict):
        _check(
            "schema_version_const",
            props.get("schema_version", {}).get("const") == "vef-execution-receipt-v1",
            str(props.get("schema_version", {}).get("const")),
        )
        _check(
            "schema_policy_hash_pattern",
            props.get("policy_snapshot_hash", {}).get("pattern") == "^sha256:[0-9a-f]{64}$",
            str(props.get("policy_snapshot_hash", {}).get("pattern")),
        )
        _check(
            "schema_capability_context_nonempty",
            props.get("capability_context", {}).get("minProperties", 0) >= 1,
            str(props.get("capability_context", {}).get("minProperties")),
        )

    action_enum = schema.get("$defs", {}).get("ExecutionActionType", {}).get("enum", [])
    _check("schema_action_enum_count", len(action_enum) == 6, str(len(action_enum)))
    _check("schema_action_enum_values", set(action_enum) == set(ACTION_TYPES), str(action_enum))


def check_specs_content() -> None:
    doc = _read(SPEC_DOC)
    contract = _read(SPEC_CONTRACT)

    _check("spec_doc_mentions_bead", "bd-p73r" in doc, "bd-p73r")
    _check("spec_doc_mentions_schema", "vef-execution-receipt-v1" in doc, "vef-execution-receipt-v1")
    _check(
        "spec_doc_mentions_deterministic_serialization",
        "Deterministic Serialization Contract" in doc,
        "Deterministic Serialization Contract",
    )
    _check("spec_doc_mentions_hash_contract", "Hashing Contract" in doc, "Hashing Contract")

    _check("contract_mentions_acceptance", "Acceptance Criteria" in contract, "Acceptance Criteria")
    _check("contract_mentions_receipt_contract", "Receipt Contract" in contract, "Receipt Contract")

    for code in REQUIRED_EVENT_CODES:
        _check(f"spec_doc_event_{code}", code in doc, code)
    for code in REQUIRED_ERROR_CODES:
        _check(f"spec_doc_error_{code}", code in doc, code)
    for invariant in REQUIRED_INVARIANTS:
        _check(f"spec_doc_invariant_{invariant}", invariant in doc, invariant)


def check_vectors() -> None:
    vectors = _load_json(VECTORS)
    if vectors is None:
        _check("vectors_parseable_json", False, "invalid or missing JSON")
        return

    _check("vectors_parseable_json", True, "valid JSON")
    _check("vectors_bead_id", vectors.get("bead_id") == "bd-p73r", str(vectors.get("bead_id")))
    _check(
        "vectors_receipt_schema_version",
        vectors.get("receipt_schema_version") == "vef-execution-receipt-v1",
        str(vectors.get("receipt_schema_version")),
    )

    entries = vectors.get("vectors", [])
    _check("vectors_minimum_count", isinstance(entries, list) and len(entries) >= 3, str(len(entries)))
    if not isinstance(entries, list):
        return

    seen_actions = set()
    hash_regex = re.compile(r"^sha256:[0-9a-f]{64}$")

    for idx, entry in enumerate(entries):
        check_prefix = f"vector_{idx}"
        receipt = entry.get("input_receipt", {}) if isinstance(entry, dict) else {}
        expected_hash = entry.get("expected_hash", "") if isinstance(entry, dict) else ""
        canonical_witnesses = entry.get("expected_canonical_witnesses", []) if isinstance(entry, dict) else []

        _check(f"{check_prefix}_receipt_object", isinstance(receipt, dict), "input_receipt object")
        _check(
            f"{check_prefix}_expected_hash_format",
            isinstance(expected_hash, str) and bool(hash_regex.match(expected_hash)),
            str(expected_hash),
        )
        _check(
            f"{check_prefix}_canonical_witnesses_list",
            isinstance(canonical_witnesses, list) and len(canonical_witnesses) >= 1,
            str(canonical_witnesses),
        )

        if isinstance(receipt, dict):
            missing = [field for field in REQUIRED_RECEIPT_FIELDS if field not in receipt]
            _check(
                f"{check_prefix}_required_fields",
                not missing,
                "all fields present" if not missing else f"missing: {', '.join(missing)}",
            )
            action = str(receipt.get("action_type", ""))
            seen_actions.add(action)
            _check(
                f"{check_prefix}_action_type_valid",
                action in ACTION_TYPES,
                action,
            )
            witnesses = receipt.get("witness_references", [])
            if isinstance(witnesses, list) and isinstance(canonical_witnesses, list):
                normalized = sorted(set(witnesses))
                _check(
                    f"{check_prefix}_canonical_witnesses_match",
                    normalized == canonical_witnesses,
                    f"normalized={normalized}",
                )
            if not missing:
                computed_hash = _canonical_receipt_hash(receipt)
                _check(
                    f"{check_prefix}_expected_hash_matches_canonical_bytes",
                    expected_hash == computed_hash,
                    f"computed={computed_hash}",
                )

    _check(
        "vectors_action_type_coverage",
        seen_actions == set(ACTION_TYPES),
        str(sorted(seen_actions)),
    )


def check_evidence_summary() -> None:
    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check("evidence_bead_id", evidence.get("bead_id") == "bd-p73r", str(evidence.get("bead_id")))
        _check("evidence_verdict_pass", evidence.get("verdict") == "PASS", str(evidence.get("verdict")))

    summary = _read(SUMMARY)
    _check("summary_mentions_bead", "bd-p73r" in summary, "bd-p73r")
    _check("summary_mentions_pass", "PASS" in summary, "PASS")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_impl_symbols()
    check_mod_wiring()
    check_schema_structure()
    check_specs_content()
    check_vectors()
    check_evidence_summary()

    total = len(RESULTS)
    passed = sum(1 for entry in RESULTS if entry["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-p73r",
        "title": "VEF canonical ExecutionReceipt schema and deterministic serialization",
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

    push("action_type_count", len(ACTION_TYPES) == 6, str(len(ACTION_TYPES)))
    push("event_code_count", len(REQUIRED_EVENT_CODES) == 2, str(len(REQUIRED_EVENT_CODES)))
    push("error_code_count", len(REQUIRED_ERROR_CODES) == 5, str(len(REQUIRED_ERROR_CODES)))
    push("invariant_count", len(REQUIRED_INVARIANTS) == 4, str(len(REQUIRED_INVARIANTS)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": "bd-p73r",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    logger = configure_test_logging("check_vef_execution_receipt")
    parser = argparse.ArgumentParser(description="Verify bd-p73r artifacts")
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
