#!/usr/bin/env python3
"""Validate the validation proof cache contract artifacts."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD_ID = "bd-jbkiq"
TITLE = "Validation proof cache receipt and freshness contract"
KEY_SCHEMA_VERSION = "franken-node/validation-proof-cache/key/v1"
ENTRY_SCHEMA_VERSION = "franken-node/validation-proof-cache/entry/v1"
DECISION_SCHEMA_VERSION = "franken-node/validation-proof-cache/decision/v1"
GC_REPORT_SCHEMA_VERSION = "franken-node/validation-proof-cache/gc-report/v1"
SCHEMA_CATALOG_VERSION = "franken-node/validation-proof-cache/schema-catalog/v1"
FIXTURE_SCHEMA_VERSION = "franken-node/validation-proof-cache/fixtures/v1"

SPEC_FILE = ROOT / "docs/specs/validation_proof_cache.md"
SCHEMA_FILE = ROOT / "artifacts/validation_broker/proof_cache/validation_proof_cache_contract.schema.json"
FIXTURES_FILE = ROOT / "artifacts/validation_broker/proof_cache/validation_proof_cache_fixtures.v1.json"
SCRIPT_FILE = ROOT / "scripts/check_validation_proof_cache_contract.py"
TEST_FILE = ROOT / "tests/test_check_validation_proof_cache_contract.py"

REQUIRED_SPEC_MARKERS = [
    "ValidationProofCacheKey",
    "ValidationProofCacheEntry",
    "ValidationProofCacheDecision",
    "ValidationProofCacheGcReport",
    "INV-VPC-KEY-DETERMINISTIC",
    "INV-VPC-RECEIPT-DIGEST",
    "INV-VPC-COMMAND-DIGEST",
    "INV-VPC-INPUT-DIGESTS",
    "INV-VPC-FRESHNESS",
    "INV-VPC-DIRTY-STATE",
    "INV-VPC-POLICY-MATCH",
    "INV-VPC-FAIL-CLOSED",
    "INV-VPC-AUDITABLE-DECISION",
    "INV-VPC-BOUNDED-GROWTH",
    "ERR_VPC_RECEIPT_DIGEST_MISMATCH",
    "ERR_VPC_COMMAND_DIGEST_MISMATCH",
    "ERR_VPC_INPUT_DIGEST_MISMATCH",
    "ERR_VPC_DIRTY_STATE_MISMATCH",
    "VPC-001",
    "VPC-010",
]

KEY_REQUIRED_FIELDS = [
    "schema_version",
    "key_id",
    "algorithm",
    "hex",
    "canonical_material",
    "command_digest",
    "input_digests",
    "git_commit",
    "dirty_worktree",
    "dirty_state_policy",
    "feature_flags",
    "cargo_toolchain",
    "package",
    "test_target",
    "environment_policy_id",
    "target_dir_policy_id",
]

ENTRY_REQUIRED_FIELDS = [
    "schema_version",
    "entry_id",
    "cache_key",
    "bead_id",
    "receipt_ref",
    "receipt_digest",
    "producer_agent",
    "created_at",
    "freshness_expires_at",
    "trust",
    "reuse",
    "storage",
    "invalidation",
]

DECISION_REQUIRED_FIELDS = [
    "schema_version",
    "decision_id",
    "cache_key",
    "bead_id",
    "trace_id",
    "decided_at",
    "decision",
    "reason_code",
    "entry_ref",
    "receipt_ref",
    "required_action",
    "diagnostics",
]

GC_REPORT_REQUIRED_FIELDS = [
    "schema_version",
    "report_id",
    "generated_at",
    "policy",
    "kept_entries",
    "removed_entries",
    "rejected_entries",
    "disk_pressure",
]

DECISION_KINDS = {
    "hit",
    "miss",
    "stale",
    "digest_mismatch",
    "policy_mismatch",
    "dirty_state_mismatch",
    "quota_blocked",
    "corrupted_entry",
}

REASON_CODES = {
    "VPC_HIT_FRESH",
    "VPC_MISS_NO_ENTRY",
    "VPC_REJECT_STALE",
    "VPC_REJECT_RECEIPT_DIGEST",
    "VPC_REJECT_COMMAND_DIGEST",
    "VPC_REJECT_INPUT_DIGEST",
    "VPC_REJECT_POLICY",
    "VPC_REJECT_DIRTY_STATE",
    "VPC_REJECT_QUOTA",
    "VPC_REJECT_CORRUPTED",
}

REQUIRED_ACTIONS = {
    "reuse_receipt",
    "run_validation",
    "refresh_validation",
    "repair_cache",
    "free_space",
    "source_only_not_allowed",
}

DIRTY_STATE_POLICIES = {
    "clean_required",
    "dirty_allowed_with_digest",
    "source_only_documented",
}

EVENT_CODES = {
    "VPC-001",
    "VPC-002",
    "VPC-003",
    "VPC-004",
    "VPC-005",
    "VPC-006",
    "VPC-007",
    "VPC-008",
    "VPC-009",
    "VPC-010",
}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _load_json(path: Path) -> Any:
    return json.JSONDecoder().decode(path.read_text(encoding="utf-8"))


def _check(check: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": check,
        "passed": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }


def _is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def _parse_rfc3339(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _get_path(payload: Any, dotted_path: str) -> Any:
    current = payload
    for part in dotted_path.split("."):
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return None
            current = current[index]
            continue
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _set_path(payload: dict[str, Any], dotted_path: str, value: Any) -> None:
    parts = dotted_path.split(".")
    current: Any = payload
    for part in parts[:-1]:
        if isinstance(current, list) and part.isdigit():
            current = current[int(part)]
            continue
        if not isinstance(current, dict):
            raise TypeError(f"cannot set {dotted_path}")
        current = current.setdefault(part, {})
    last = parts[-1]
    if isinstance(current, list) and last.isdigit():
        current[int(last)] = value
    elif isinstance(current, dict):
        current[last] = value
    else:
        raise TypeError(f"cannot set {dotted_path}")


def _remove_path(payload: dict[str, Any], dotted_path: str) -> None:
    parts = dotted_path.split(".")
    current: Any = payload
    for part in parts[:-1]:
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return
            current = current[index]
            continue
        if not isinstance(current, dict) or part not in current:
            return
        current = current[part]
    last = parts[-1]
    if isinstance(current, list) and last.isdigit():
        index = int(last)
        if index < len(current):
            current.pop(index)
    elif isinstance(current, dict):
        current.pop(last, None)


def apply_fixture_patch(base: Any, patch: dict[str, Any] | None) -> Any:
    patched = copy.deepcopy(base)
    if not patch:
        return patched
    for dotted_path in patch.get("remove", []):
        if isinstance(patched, dict):
            _remove_path(patched, dotted_path)
    for dotted_path, value in patch.get("set", {}).items():
        if isinstance(patched, dict):
            _set_path(patched, dotted_path, value)
    return patched


def _digest_verifies(digest: Any) -> bool:
    if not isinstance(digest, dict):
        return False
    algorithm = digest.get("algorithm")
    digest_hex = digest.get("hex")
    material = digest.get("canonical_material")
    if (
        not isinstance(algorithm, str)
        or not hmac.compare_digest(algorithm, "sha256")
        or not _is_sha256_hex(digest_hex)
        or not isinstance(material, str)
    ):
        return False
    computed = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return isinstance(digest_hex, str) and hmac.compare_digest(computed, digest_hex)


def _input_digest_key(input_digest: Any) -> tuple[str, str] | None:
    if not isinstance(input_digest, dict):
        return None
    path = input_digest.get("path")
    digest_hex = input_digest.get("hex")
    if not isinstance(path, str) or not _is_sha256_hex(digest_hex):
        return None
    if not _digest_verifies(input_digest):
        return None
    return path, digest_hex


def _input_digest_set(input_digests: Any) -> set[tuple[str, str]] | None:
    if not isinstance(input_digests, list) or not input_digests:
        return None
    pairs = [_input_digest_key(entry) for entry in input_digests]
    if any(pair is None for pair in pairs):
        return None
    return set(pair for pair in pairs if pair is not None)


def _same_input_digest_set(left: Any, right: Any) -> bool:
    left_pairs = _input_digest_set(left)
    right_pairs = _input_digest_set(right)
    if left_pairs is None or right_pairs is None or len(left_pairs) != len(right_pairs):
        return False
    for path, digest_hex in sorted(left_pairs):
        matched = any(
            hmac.compare_digest(path, right_path) and hmac.compare_digest(digest_hex, right_hex)
            for right_path, right_hex in right_pairs
        )
        if not matched:
            return False
    return True


def validate_cache_key(cache_key: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(cache_key, dict):
        return ["ERR_VPC_MALFORMED_KEY"]

    for field in KEY_REQUIRED_FIELDS:
        if field not in cache_key:
            errors.append("ERR_VPC_MALFORMED_KEY")
            break

    if cache_key.get("schema_version") != KEY_SCHEMA_VERSION:
        errors.append("ERR_VPC_INVALID_SCHEMA_VERSION")

    algorithm = cache_key.get("algorithm")
    if (
        not isinstance(algorithm, str)
        or not hmac.compare_digest(algorithm, "sha256")
        or not _is_sha256_hex(cache_key.get("hex"))
        or not isinstance(cache_key.get("canonical_material"), str)
    ):
        errors.append("ERR_VPC_BAD_CACHE_KEY")
    else:
        computed = hashlib.sha256(cache_key["canonical_material"].encode("utf-8")).hexdigest()
        if not hmac.compare_digest(computed, cache_key["hex"]):
            errors.append("ERR_VPC_BAD_CACHE_KEY")

    if not _digest_verifies(cache_key.get("command_digest")):
        errors.append("ERR_VPC_COMMAND_DIGEST_MISMATCH")

    if _input_digest_set(cache_key.get("input_digests")) is None:
        errors.append("ERR_VPC_INPUT_DIGEST_MISMATCH")

    if not isinstance(cache_key.get("dirty_worktree"), bool):
        errors.append("ERR_VPC_MALFORMED_KEY")
    if cache_key.get("dirty_state_policy") not in DIRTY_STATE_POLICIES:
        errors.append("ERR_VPC_DIRTY_STATE_MISMATCH")
    if not isinstance(cache_key.get("feature_flags"), list) or not all(
        isinstance(item, str) for item in cache_key.get("feature_flags", [])
    ):
        errors.append("ERR_VPC_MALFORMED_KEY")
    for field in ["git_commit", "cargo_toolchain", "package", "test_target", "environment_policy_id", "target_dir_policy_id"]:
        value = cache_key.get(field)
        if not isinstance(value, str) or not value:
            errors.append("ERR_VPC_MALFORMED_KEY")
            break

    return sorted(set(errors))


def validate_cache_entry(
    entry: Any,
    *,
    expected_bead_id: str | None = None,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(entry, dict):
        return ["ERR_VPC_MALFORMED_ENTRY"]

    for field in ENTRY_REQUIRED_FIELDS:
        if field not in entry:
            errors.append("ERR_VPC_MALFORMED_ENTRY")
            break

    if entry.get("schema_version") != ENTRY_SCHEMA_VERSION:
        errors.append("ERR_VPC_INVALID_SCHEMA_VERSION")

    cache_key = entry.get("cache_key")
    errors.extend(validate_cache_key(cache_key))

    bead_id = entry.get("bead_id")
    if not isinstance(bead_id, str) or (expected_bead_id is not None and bead_id != expected_bead_id):
        errors.append("ERR_VPC_MALFORMED_ENTRY")

    created_at = _parse_rfc3339(entry.get("created_at"))
    freshness_expires_at = _parse_rfc3339(entry.get("freshness_expires_at"))
    if created_at is None or freshness_expires_at is None:
        errors.append("ERR_VPC_MALFORMED_ENTRY")
    if now is not None and freshness_expires_at is not None and freshness_expires_at < now:
        errors.append("ERR_VPC_STALE_ENTRY")

    if not _digest_verifies(entry.get("receipt_digest")):
        errors.append("ERR_VPC_RECEIPT_DIGEST_MISMATCH")

    receipt_ref = entry.get("receipt_ref")
    if not isinstance(receipt_ref, dict):
        errors.append("ERR_VPC_MALFORMED_ENTRY")
    elif isinstance(cache_key, dict):
        if receipt_ref.get("bead_id") != bead_id:
            errors.append("ERR_VPC_MALFORMED_ENTRY")
        if not isinstance(receipt_ref.get("path"), str) or not receipt_ref.get("path"):
            errors.append("ERR_VPC_MALFORMED_ENTRY")

        key_command = _get_path(cache_key, "command_digest.hex")
        receipt_command = _get_path(receipt_ref, "command_digest.hex")
        commands_match = (
            isinstance(key_command, str)
            and isinstance(receipt_command, str)
            and hmac.compare_digest(key_command, receipt_command)
        )
        if not _digest_verifies(receipt_ref.get("command_digest")) or not commands_match:
            errors.append("ERR_VPC_COMMAND_DIGEST_MISMATCH")

        if not _same_input_digest_set(
            cache_key.get("input_digests"),
            receipt_ref.get("input_digests")
        ):
            errors.append("ERR_VPC_INPUT_DIGEST_MISMATCH")

        if cache_key.get("dirty_worktree") != receipt_ref.get("dirty_worktree") or cache_key.get(
            "dirty_state_policy"
        ) != receipt_ref.get("dirty_state_policy"):
            errors.append("ERR_VPC_DIRTY_STATE_MISMATCH")

        if cache_key.get("environment_policy_id") != receipt_ref.get(
            "environment_policy_id"
        ) or cache_key.get("target_dir_policy_id") != receipt_ref.get("target_dir_policy_id"):
            errors.append("ERR_VPC_POLICY_MISMATCH")

    trust = entry.get("trust")
    if not isinstance(trust, dict):
        errors.append("ERR_VPC_MALFORMED_ENTRY")
    elif isinstance(cache_key, dict):
        if trust.get("dirty_worktree") != cache_key.get("dirty_worktree") or trust.get(
            "dirty_state_policy"
        ) != cache_key.get("dirty_state_policy"):
            errors.append("ERR_VPC_DIRTY_STATE_MISMATCH")
        if trust.get("environment_policy_id") != cache_key.get(
            "environment_policy_id"
        ) or trust.get("target_dir_policy_id") != cache_key.get("target_dir_policy_id"):
            errors.append("ERR_VPC_POLICY_MISMATCH")

    invalidation = entry.get("invalidation")
    if not isinstance(invalidation, dict):
        errors.append("ERR_VPC_MALFORMED_ENTRY")
    elif bool(invalidation.get("corrupted")):
        errors.append("ERR_VPC_CORRUPTED_ENTRY")

    storage = entry.get("storage")
    reuse = entry.get("reuse")
    if not isinstance(storage, dict) or not isinstance(storage.get("bytes"), int) or storage.get("bytes", 0) < 0:
        errors.append("ERR_VPC_MALFORMED_ENTRY")
    if not isinstance(reuse, dict) or not isinstance(reuse.get("count"), int) or reuse.get("count", -1) < 0:
        errors.append("ERR_VPC_MALFORMED_ENTRY")

    return sorted(set(errors))


def validate_cache_decision(
    decision: Any,
    *,
    expected_bead_id: str | None = None,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(decision, dict):
        return ["ERR_VPC_MALFORMED_DECISION"]

    for field in DECISION_REQUIRED_FIELDS:
        if field not in decision:
            errors.append("ERR_VPC_MALFORMED_DECISION")
            break

    if decision.get("schema_version") != DECISION_SCHEMA_VERSION:
        errors.append("ERR_VPC_INVALID_SCHEMA_VERSION")

    errors.extend(validate_cache_key(decision.get("cache_key")))

    bead_id = decision.get("bead_id")
    if not isinstance(bead_id, str) or (expected_bead_id is not None and bead_id != expected_bead_id):
        errors.append("ERR_VPC_MALFORMED_DECISION")

    decided_at = _parse_rfc3339(decision.get("decided_at"))
    if decided_at is None or (now is not None and decided_at > now):
        errors.append("ERR_VPC_MALFORMED_DECISION")

    decision_kind = decision.get("decision")
    reason_code = decision.get("reason_code")
    required_action = decision.get("required_action")
    if decision_kind not in DECISION_KINDS or reason_code not in REASON_CODES or required_action not in REQUIRED_ACTIONS:
        errors.append("ERR_VPC_MALFORMED_DECISION")

    diagnostics = decision.get("diagnostics")
    event_code = diagnostics.get("event_code") if isinstance(diagnostics, dict) else None
    if not isinstance(diagnostics, dict) or event_code not in EVENT_CODES:
        errors.append("ERR_VPC_MALFORMED_DECISION")

    if decision_kind == "hit":
        if reason_code != "VPC_HIT_FRESH" or required_action != "reuse_receipt":
            errors.append("ERR_VPC_MALFORMED_DECISION")
        if not isinstance(decision.get("entry_ref"), dict) or not isinstance(decision.get("receipt_ref"), dict):
            errors.append("ERR_VPC_MALFORMED_DECISION")
    elif decision_kind == "quota_blocked":
        errors.append("ERR_VPC_QUOTA_BLOCKED")
    elif decision_kind == "corrupted_entry":
        errors.append("ERR_VPC_CORRUPTED_ENTRY")

    return sorted(set(errors))


def _load_contract_files() -> tuple[Any, Any]:
    schema = _load_json(SCHEMA_FILE) if SCHEMA_FILE.exists() else None
    fixtures = _load_json(FIXTURES_FILE) if FIXTURES_FILE.exists() else None
    return schema, fixtures


def _check_files() -> list[dict[str, Any]]:
    return [
        _check("spec_exists", SPEC_FILE.is_file(), str(SPEC_FILE)),
        _check("schema_catalog_exists", SCHEMA_FILE.is_file(), str(SCHEMA_FILE)),
        _check("fixtures_exist", FIXTURES_FILE.is_file(), str(FIXTURES_FILE)),
        _check("script_exists", SCRIPT_FILE.is_file(), str(SCRIPT_FILE)),
        _check("tests_exist", TEST_FILE.is_file(), str(TEST_FILE)),
    ]


def _check_spec() -> list[dict[str, Any]]:
    content = _read_text(SPEC_FILE)
    return [_check(f"spec_marker:{marker}", marker in content, marker) for marker in REQUIRED_SPEC_MARKERS]


def _schema_has_required(schema: Any, name: str, required: list[str]) -> bool:
    if not isinstance(schema, dict):
        return False
    schemas = schema.get("schemas")
    contract_schema = schemas.get(name, {}) if isinstance(schemas, dict) else {}
    declared = contract_schema.get("required", [])
    return isinstance(declared, list) and set(declared) == set(required)


def _check_schema(schema: Any) -> list[dict[str, Any]]:
    if not isinstance(schema, dict):
        return [_check("schema_parseable", False, "schema missing or invalid")]

    return [
        _check("schema_version", schema.get("schema_version") == SCHEMA_CATALOG_VERSION),
        _check("decision_kinds_complete", set(schema.get("decision_kinds", [])) == DECISION_KINDS),
        _check("reason_codes_complete", set(schema.get("reason_codes", [])) == REASON_CODES),
        _check("required_actions_complete", set(schema.get("required_actions", [])) == REQUIRED_ACTIONS),
        _check("dirty_state_policies_complete", set(schema.get("dirty_state_policies", [])) == DIRTY_STATE_POLICIES),
        _check("event_codes_complete", set(schema.get("event_codes", [])) == EVENT_CODES),
        _check("required_key_fields_complete", set(schema.get("required_key_fields", [])) == set(KEY_REQUIRED_FIELDS)),
        _check("required_entry_fields_complete", set(schema.get("required_entry_fields", [])) == set(ENTRY_REQUIRED_FIELDS)),
        _check(
            "required_decision_fields_complete",
            set(schema.get("required_decision_fields", [])) == set(DECISION_REQUIRED_FIELDS),
        ),
        _check(
            "required_gc_report_fields_complete",
            set(schema.get("required_gc_report_fields", [])) == set(GC_REPORT_REQUIRED_FIELDS),
        ),
        _check("key_schema_required_complete", _schema_has_required(schema, "ValidationProofCacheKey", KEY_REQUIRED_FIELDS)),
        _check(
            "entry_schema_required_complete",
            _schema_has_required(schema, "ValidationProofCacheEntry", ENTRY_REQUIRED_FIELDS),
        ),
        _check(
            "decision_schema_required_complete",
            _schema_has_required(schema, "ValidationProofCacheDecision", DECISION_REQUIRED_FIELDS),
        ),
        _check(
            "gc_report_schema_required_complete",
            _schema_has_required(schema, "ValidationProofCacheGcReport", GC_REPORT_REQUIRED_FIELDS),
        ),
    ]


def _check_fixtures(fixtures: Any) -> list[dict[str, Any]]:
    if not isinstance(fixtures, dict):
        return [_check("fixtures_parseable", False, "fixtures missing or invalid")]

    checks: list[dict[str, Any]] = [
        _check("fixtures_schema_version", fixtures.get("schema_version") == FIXTURE_SCHEMA_VERSION),
    ]
    validation_time = _parse_rfc3339(fixtures.get("validation_time"))
    checks.append(_check("fixtures_validation_time_parseable", validation_time is not None))
    now = validation_time or datetime.now(timezone.utc)

    valid_keys = fixtures.get("valid_cache_keys", [])
    checks.append(_check("valid_cache_keys_present", isinstance(valid_keys, list) and len(valid_keys) >= 1))
    for index, cache_key in enumerate(valid_keys if isinstance(valid_keys, list) else []):
        errors = validate_cache_key(cache_key)
        checks.append(_check(f"valid_cache_key:{index}", errors == [], ",".join(errors)))

    valid_entries = fixtures.get("valid_entries", [])
    checks.append(_check("valid_entries_present", isinstance(valid_entries, list) and len(valid_entries) >= 1))
    base_entry = valid_entries[0] if isinstance(valid_entries, list) and valid_entries else None
    for index, entry in enumerate(valid_entries if isinstance(valid_entries, list) else []):
        errors = validate_cache_entry(entry, expected_bead_id=BEAD_ID, now=now)
        checks.append(_check(f"valid_entry:{index}", errors == [], ",".join(errors)))

    valid_decisions = fixtures.get("valid_decisions", [])
    checks.append(_check("valid_decisions_present", isinstance(valid_decisions, list) and len(valid_decisions) >= 1))
    base_decision = valid_decisions[0] if isinstance(valid_decisions, list) and valid_decisions else None
    for index, decision in enumerate(valid_decisions if isinstance(valid_decisions, list) else []):
        errors = validate_cache_decision(decision, expected_bead_id=BEAD_ID, now=now)
        checks.append(_check(f"valid_decision:{index}", errors == [], ",".join(errors)))

    invalid_entries = fixtures.get("invalid_entries", [])
    checks.append(_check("invalid_entries_present", isinstance(invalid_entries, list) and len(invalid_entries) >= 6))
    for case in invalid_entries if isinstance(invalid_entries, list) else []:
        entry = case.get("entry", apply_fixture_patch(base_entry, case.get("patch")))
        expected = set(case.get("expected_errors", []))
        errors = set(validate_cache_entry(entry, expected_bead_id=BEAD_ID, now=now))
        checks.append(
            _check(
                f"invalid_entry:{case.get('name', 'unnamed')}",
                expected.issubset(errors),
                f"expected={sorted(expected)} actual={sorted(errors)}",
            )
        )

    invalid_decisions = fixtures.get("invalid_decisions", [])
    checks.append(_check("invalid_decisions_present", isinstance(invalid_decisions, list) and len(invalid_decisions) >= 2))
    for case in invalid_decisions if isinstance(invalid_decisions, list) else []:
        decision = case.get("decision_payload", apply_fixture_patch(base_decision, case.get("patch")))
        expected = set(case.get("expected_errors", []))
        errors = set(validate_cache_decision(decision, expected_bead_id=BEAD_ID, now=now))
        checks.append(
            _check(
                f"invalid_decision:{case.get('name', 'unnamed')}",
                expected.issubset(errors),
                f"expected={sorted(expected)} actual={sorted(errors)}",
            )
        )

    decision_examples = fixtures.get("decision_examples", [])
    example_decisions = {example.get("decision") for example in decision_examples if isinstance(example, dict)}
    example_reasons = {example.get("reason_code") for example in decision_examples if isinstance(example, dict)}
    example_actions = {example.get("required_action") for example in decision_examples if isinstance(example, dict)}
    example_events = {example.get("event_code") for example in decision_examples if isinstance(example, dict)}
    checks.extend(
        [
            _check("decision_examples_cover_kinds", example_decisions == DECISION_KINDS),
            _check("decision_examples_use_known_reasons", example_reasons.issubset(REASON_CODES)),
            _check("decision_examples_use_known_actions", example_actions.issubset(REQUIRED_ACTIONS)),
            _check("decision_examples_use_known_events", example_events.issubset(EVENT_CODES)),
        ]
    )

    return checks


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(_check_files())
    checks.extend(_check_spec())

    schema, fixtures = _load_contract_files()
    checks.extend(_check_schema(schema))
    checks.extend(_check_fixtures(fixtures))

    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "schema_version": SCHEMA_CATALOG_VERSION,
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def self_test() -> dict[str, Any]:
    result = run_all()
    checks = [
        _check("run_all_returns_dict", isinstance(result, dict)),
        _check("run_all_verdict_passes", result.get("verdict") == "PASS", str(result.get("verdict"))),
        _check("run_all_has_many_checks", result.get("total", 0) >= 40, str(result.get("total"))),
    ]
    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    return {
        "bead_id": BEAD_ID,
        "title": f"{TITLE} self-test",
        "schema_version": SCHEMA_CATALOG_VERSION,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "contract_result": result,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    configure_test_logging("validation-proof-cache-contract")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result['verdict']} {TITLE}: {result['passed']}/{result['total']} checks passed")
        for check in result["checks"]:
            if not check["passed"]:
                print(f"- {check['check']}: {check['detail']}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
