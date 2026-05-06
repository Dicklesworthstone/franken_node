#!/usr/bin/env python3
"""Validate the validation proof coalescer contract artifacts."""

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


BEAD_ID = "bd-ov7ca"
TITLE = "Validation proof coalescer contract"
WORK_KEY_SCHEMA_VERSION = "franken-node/validation-proof-coalescer/work-key/v1"
LEASE_SCHEMA_VERSION = "franken-node/validation-proof-coalescer/lease/v1"
DECISION_SCHEMA_VERSION = "franken-node/validation-proof-coalescer/decision/v1"
ADMISSION_POLICY_SCHEMA_VERSION = "franken-node/validation-proof-coalescer/admission-policy/v1"
SCHEMA_CATALOG_VERSION = "franken-node/validation-proof-coalescer/schema-catalog/v1"
FIXTURE_SCHEMA_VERSION = "franken-node/validation-proof-coalescer/fixtures/v1"

SPEC_FILE = ROOT / "docs/specs/validation_proof_coalescer.md"
SCHEMA_FILE = (
    ROOT
    / "artifacts/validation_broker/proof_coalescer/validation_proof_coalescer_contract.schema.json"
)
FIXTURES_FILE = (
    ROOT
    / "artifacts/validation_broker/proof_coalescer/validation_proof_coalescer_fixtures.v1.json"
)
SCRIPT_FILE = ROOT / "scripts/check_validation_proof_coalescer_contract.py"
TEST_FILE = ROOT / "tests/test_check_validation_proof_coalescer_contract.py"

REQUIRED_SPEC_MARKERS = [
    "ValidationProofWorkKey",
    "ValidationProofCoalescerLease",
    "ValidationProofCoalescerDecision",
    "ValidationProofCoalescerAdmissionPolicy",
    "run_locally_via_rch",
    "join_existing_proof",
    "wait_for_receipt",
    "queued_by_policy",
    "retry_after_stale_lease",
    "reject_dirty_policy",
    "reject_capacity",
    "repair_state",
    "INV-VPCO-WORK-KEY-DETERMINISTIC",
    "INV-VPCO-CACHE-COMPATIBLE",
    "INV-VPCO-EXACT-JOIN",
    "INV-VPCO-FRESHNESS",
    "INV-VPCO-FENCING",
    "INV-VPCO-OWNER-AUDIT",
    "INV-VPCO-DIRTY-STATE",
    "INV-VPCO-CAPACITY-BOUNDED",
    "INV-VPCO-FAIL-CLOSED",
    "INV-VPCO-AUDITABLE-DECISION",
    "ERR_VPCO_STALE_LEASE",
    "ERR_VPCO_FENCED_OWNER",
    "ERR_VPCO_DIRTY_POLICY",
    "ERR_VPCO_CAPACITY_REJECTED",
    "trace_id",
    "proof_work_key",
    "proof_cache_key",
    "fencing_token",
    "VPCO-001",
    "VPCO-010",
    "completed_receipt_handoff",
]

WORK_KEY_REQUIRED_FIELDS = [
    "schema_version",
    "work_key_id",
    "algorithm",
    "hex",
    "canonical_material",
    "proof_cache_key",
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

LEASE_REQUIRED_FIELDS = [
    "schema_version",
    "lease_id",
    "proof_work_key",
    "state",
    "owner_agent",
    "owner_bead_id",
    "fencing_token",
    "created_at",
    "updated_at",
    "expires_at",
    "waiter_agents",
    "admission_policy_id",
    "rch_command",
    "target_dir_policy_id",
    "receipt_ref",
    "proof_cache_key",
    "diagnostics",
]

DECISION_REQUIRED_FIELDS = [
    "schema_version",
    "decision_id",
    "proof_work_key",
    "lease_ref",
    "bead_id",
    "agent_name",
    "trace_id",
    "decided_at",
    "decision",
    "reason_code",
    "required_action",
    "diagnostics",
]

ADMISSION_POLICY_REQUIRED_FIELDS = [
    "schema_version",
    "policy_id",
    "max_running_proofs",
    "max_waiters_per_lease",
    "stale_after_seconds",
    "queue_high_watermark",
    "min_available_worker_slots",
    "dirty_state_policy",
    "capacity_mode",
]

LEASE_STATES = {
    "proposed",
    "running",
    "joined",
    "completed",
    "stale",
    "fenced",
    "rejected",
    "failed_closed",
}

DECISION_KINDS = {
    "run_locally_via_rch",
    "join_existing_proof",
    "wait_for_receipt",
    "queued_by_policy",
    "retry_after_stale_lease",
    "reject_dirty_policy",
    "reject_capacity",
    "repair_state",
}

REASON_CODES = {
    "VPCO_RUN_NO_LEASE",
    "VPCO_JOIN_RUNNING",
    "VPCO_WAIT_COMPLETION",
    "VPCO_QUEUE_CAPACITY",
    "VPCO_RETRY_STALE",
    "VPCO_REJECT_DIRTY_POLICY",
    "VPCO_REJECT_CAPACITY",
    "VPCO_REPAIR_CORRUPTED",
}

REQUIRED_ACTIONS = {
    "start_rch_validation",
    "join_existing_lease",
    "wait_for_receipt",
    "queue_validation",
    "retry_with_new_fence",
    "fail_closed",
    "repair_state",
}

DECISION_RULES = {
    "run_locally_via_rch": ("VPCO_RUN_NO_LEASE", "start_rch_validation"),
    "join_existing_proof": ("VPCO_JOIN_RUNNING", "join_existing_lease"),
    "wait_for_receipt": ("VPCO_WAIT_COMPLETION", "wait_for_receipt"),
    "queued_by_policy": ("VPCO_QUEUE_CAPACITY", "queue_validation"),
    "retry_after_stale_lease": ("VPCO_RETRY_STALE", "retry_with_new_fence"),
    "reject_dirty_policy": ("VPCO_REJECT_DIRTY_POLICY", "fail_closed"),
    "reject_capacity": ("VPCO_REJECT_CAPACITY", "fail_closed"),
    "repair_state": ("VPCO_REPAIR_CORRUPTED", "repair_state"),
}

DIRTY_STATE_POLICIES = {
    "clean_required",
    "dirty_allowed_with_digest",
    "source_only_documented",
}

CAPACITY_MODES = {
    "observe_only",
    "queue_when_busy",
    "reject_when_busy",
}

EVENT_CODES = {
    "VPCO-001",
    "VPCO-002",
    "VPCO-003",
    "VPCO-004",
    "VPCO-005",
    "VPCO-006",
    "VPCO-007",
    "VPCO-008",
    "VPCO-009",
    "VPCO-010",
}

REQUIRED_SCENARIOS = {
    "happy_path_join",
    "divergent_key_miss",
    "stale_lease_recovery",
    "fenced_owner_rejection",
    "dirty_policy_rejection",
    "capacity_rejection",
    "completed_receipt_handoff",
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


def validate_work_key(work_key: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(work_key, dict):
        return ["ERR_VPCO_MALFORMED_WORK_KEY"]

    for field in WORK_KEY_REQUIRED_FIELDS:
        if field not in work_key:
            errors.append("ERR_VPCO_MALFORMED_WORK_KEY")
            break

    if work_key.get("schema_version") != WORK_KEY_SCHEMA_VERSION:
        errors.append("ERR_VPCO_INVALID_SCHEMA_VERSION")

    algorithm = work_key.get("algorithm")
    if (
        not isinstance(algorithm, str)
        or not hmac.compare_digest(algorithm, "sha256")
        or not _is_sha256_hex(work_key.get("hex"))
        or not isinstance(work_key.get("canonical_material"), str)
    ):
        errors.append("ERR_VPCO_BAD_WORK_KEY")
    else:
        computed = hashlib.sha256(work_key["canonical_material"].encode("utf-8")).hexdigest()
        if not hmac.compare_digest(computed, work_key["hex"]):
            errors.append("ERR_VPCO_BAD_WORK_KEY")

    if not _digest_verifies(work_key.get("proof_cache_key")):
        errors.append("ERR_VPCO_BAD_WORK_KEY")
    else:
        proof_cache_hex = _get_path(work_key, "proof_cache_key.hex")
        if isinstance(proof_cache_hex, str) and isinstance(work_key.get("hex"), str):
            if not hmac.compare_digest(proof_cache_hex, work_key["hex"]):
                errors.append("ERR_VPCO_BAD_WORK_KEY")

    if not _digest_verifies(work_key.get("command_digest")):
        errors.append("ERR_VPCO_COMMAND_DIGEST_MISMATCH")

    if _input_digest_set(work_key.get("input_digests")) is None:
        errors.append("ERR_VPCO_INPUT_DIGEST_MISMATCH")

    if not isinstance(work_key.get("dirty_worktree"), bool):
        errors.append("ERR_VPCO_MALFORMED_WORK_KEY")
    if work_key.get("dirty_state_policy") not in DIRTY_STATE_POLICIES:
        errors.append("ERR_VPCO_DIRTY_POLICY")
    if not isinstance(work_key.get("feature_flags"), list) or not all(
        isinstance(item, str) for item in work_key.get("feature_flags", [])
    ):
        errors.append("ERR_VPCO_MALFORMED_WORK_KEY")
    for field in [
        "work_key_id",
        "git_commit",
        "cargo_toolchain",
        "package",
        "test_target",
        "environment_policy_id",
        "target_dir_policy_id",
    ]:
        value = work_key.get(field)
        if not isinstance(value, str) or not value:
            errors.append("ERR_VPCO_MALFORMED_WORK_KEY")
            break

    return sorted(set(errors))


def validate_admission_policy(policy: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["ERR_VPCO_MALFORMED_POLICY"]

    for field in ADMISSION_POLICY_REQUIRED_FIELDS:
        if field not in policy:
            errors.append("ERR_VPCO_MALFORMED_POLICY")
            break

    if policy.get("schema_version") != ADMISSION_POLICY_SCHEMA_VERSION:
        errors.append("ERR_VPCO_INVALID_SCHEMA_VERSION")

    if not isinstance(policy.get("policy_id"), str) or not policy.get("policy_id"):
        errors.append("ERR_VPCO_MALFORMED_POLICY")

    for field in [
        "max_running_proofs",
        "max_waiters_per_lease",
        "stale_after_seconds",
        "queue_high_watermark",
        "min_available_worker_slots",
    ]:
        value = policy.get(field)
        if not isinstance(value, int) or value < 0:
            errors.append("ERR_VPCO_MALFORMED_POLICY")
            break

    if policy.get("max_running_proofs") == 0 or policy.get("stale_after_seconds") == 0:
        errors.append("ERR_VPCO_MALFORMED_POLICY")
    if policy.get("dirty_state_policy") not in DIRTY_STATE_POLICIES:
        errors.append("ERR_VPCO_DIRTY_POLICY")
    if policy.get("capacity_mode") not in CAPACITY_MODES:
        errors.append("ERR_VPCO_MALFORMED_POLICY")

    return sorted(set(errors))


def validate_lease(
    lease: Any,
    *,
    expected_bead_id: str | None = None,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(lease, dict):
        return ["ERR_VPCO_MALFORMED_LEASE"]

    for field in LEASE_REQUIRED_FIELDS:
        if field not in lease:
            errors.append("ERR_VPCO_MALFORMED_LEASE")
            break

    if lease.get("schema_version") != LEASE_SCHEMA_VERSION:
        errors.append("ERR_VPCO_INVALID_SCHEMA_VERSION")

    proof_work_key = lease.get("proof_work_key")
    errors.extend(validate_work_key(proof_work_key))

    state = lease.get("state")
    if state not in LEASE_STATES:
        errors.append("ERR_VPCO_MALFORMED_LEASE")

    for field in ["lease_id", "owner_agent", "owner_bead_id", "fencing_token", "admission_policy_id"]:
        value = lease.get(field)
        if not isinstance(value, str) or not value:
            errors.append("ERR_VPCO_MALFORMED_LEASE")
            break

    if expected_bead_id is not None and lease.get("owner_bead_id") != expected_bead_id:
        errors.append("ERR_VPCO_MALFORMED_LEASE")

    created_at = _parse_rfc3339(lease.get("created_at"))
    updated_at = _parse_rfc3339(lease.get("updated_at"))
    expires_at = _parse_rfc3339(lease.get("expires_at"))
    if created_at is None or updated_at is None or expires_at is None:
        errors.append("ERR_VPCO_MALFORMED_LEASE")
    if now is not None and expires_at is not None and expires_at < now:
        errors.append("ERR_VPCO_STALE_LEASE")

    if not isinstance(lease.get("waiter_agents"), list) or not all(
        isinstance(agent, str) and agent for agent in lease.get("waiter_agents", [])
    ):
        errors.append("ERR_VPCO_MALFORMED_LEASE")

    if not _digest_verifies(lease.get("proof_cache_key")):
        errors.append("ERR_VPCO_BAD_WORK_KEY")
    else:
        lease_cache_hex = _get_path(lease, "proof_cache_key.hex")
        work_cache_hex = _get_path(proof_work_key, "proof_cache_key.hex")
        if isinstance(lease_cache_hex, str) and isinstance(work_cache_hex, str):
            if not hmac.compare_digest(lease_cache_hex, work_cache_hex):
                errors.append("ERR_VPCO_BAD_WORK_KEY")

    if lease.get("target_dir_policy_id") != _get_path(proof_work_key, "target_dir_policy_id"):
        errors.append("ERR_VPCO_MALFORMED_LEASE")

    rch_command = lease.get("rch_command")
    if not isinstance(rch_command, dict) or not _digest_verifies(rch_command.get("command_digest")):
        errors.append("ERR_VPCO_COMMAND_DIGEST_MISMATCH")
    else:
        lease_command_hex = _get_path(rch_command, "command_digest.hex")
        work_command_hex = _get_path(proof_work_key, "command_digest.hex")
        if isinstance(lease_command_hex, str) and isinstance(work_command_hex, str):
            if not hmac.compare_digest(lease_command_hex, work_command_hex):
                errors.append("ERR_VPCO_COMMAND_DIGEST_MISMATCH")

    receipt_ref = lease.get("receipt_ref")
    if state == "completed":
        if not isinstance(receipt_ref, dict):
            errors.append("ERR_VPCO_MALFORMED_LEASE")
        elif not _digest_verifies(receipt_ref.get("receipt_digest")):
            errors.append("ERR_VPCO_CORRUPTED_STATE")
        elif receipt_ref.get("proof_cache_key_hex") != _get_path(lease, "proof_cache_key.hex"):
            errors.append("ERR_VPCO_BAD_WORK_KEY")
    elif receipt_ref is not None and not isinstance(receipt_ref, dict):
        errors.append("ERR_VPCO_MALFORMED_LEASE")

    diagnostics = lease.get("diagnostics")
    event_code = diagnostics.get("event_code") if isinstance(diagnostics, dict) else None
    reason_code = diagnostics.get("reason_code") if isinstance(diagnostics, dict) else None
    if not isinstance(diagnostics, dict) or event_code not in EVENT_CODES or reason_code not in REASON_CODES:
        errors.append("ERR_VPCO_MALFORMED_LEASE")
    elif bool(diagnostics.get("corrupted")):
        errors.append("ERR_VPCO_CORRUPTED_STATE")
    elif state == "fenced" and bool(diagnostics.get("fencing_owner_mismatch")):
        errors.append("ERR_VPCO_FENCED_OWNER")
    elif reason_code == "VPCO_REJECT_DIRTY_POLICY":
        errors.append("ERR_VPCO_DIRTY_POLICY")
    elif reason_code == "VPCO_REJECT_CAPACITY":
        errors.append("ERR_VPCO_CAPACITY_REJECTED")

    if state in {"stale", "fenced", "rejected", "failed_closed"} and not errors:
        errors.append("ERR_VPCO_MALFORMED_LEASE")

    return sorted(set(errors))


def validate_decision(
    decision: Any,
    *,
    expected_bead_id: str | None = None,
    now: datetime | None = None,
    include_fail_closed_errors: bool = True,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(decision, dict):
        return ["ERR_VPCO_MALFORMED_DECISION"]

    for field in DECISION_REQUIRED_FIELDS:
        if field not in decision:
            errors.append("ERR_VPCO_MALFORMED_DECISION")
            break

    if decision.get("schema_version") != DECISION_SCHEMA_VERSION:
        errors.append("ERR_VPCO_INVALID_SCHEMA_VERSION")

    errors.extend(validate_work_key(decision.get("proof_work_key")))

    bead_id = decision.get("bead_id")
    if not isinstance(bead_id, str) or (expected_bead_id is not None and bead_id != expected_bead_id):
        errors.append("ERR_VPCO_MALFORMED_DECISION")

    decided_at = _parse_rfc3339(decision.get("decided_at"))
    if decided_at is None or (now is not None and decided_at > now):
        errors.append("ERR_VPCO_MALFORMED_DECISION")

    for field in ["decision_id", "agent_name", "trace_id"]:
        value = decision.get(field)
        if not isinstance(value, str) or not value:
            errors.append("ERR_VPCO_MALFORMED_DECISION")
            break

    decision_kind = decision.get("decision")
    reason_code = decision.get("reason_code")
    required_action = decision.get("required_action")
    if decision_kind not in DECISION_KINDS or reason_code not in REASON_CODES or required_action not in REQUIRED_ACTIONS:
        errors.append("ERR_VPCO_MALFORMED_DECISION")
    elif DECISION_RULES[decision_kind] != (reason_code, required_action):
        errors.append("ERR_VPCO_MALFORMED_DECISION")

    diagnostics = decision.get("diagnostics")
    event_code = diagnostics.get("event_code") if isinstance(diagnostics, dict) else None
    if not isinstance(diagnostics, dict) or event_code not in EVENT_CODES:
        errors.append("ERR_VPCO_MALFORMED_DECISION")

    if include_fail_closed_errors:
        if decision_kind == "reject_dirty_policy":
            errors.append("ERR_VPCO_DIRTY_POLICY")
        elif decision_kind == "reject_capacity":
            errors.append("ERR_VPCO_CAPACITY_REJECTED")
        elif decision_kind == "repair_state":
            errors.append("ERR_VPCO_CORRUPTED_STATE")

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
        _check("lease_states_complete", set(schema.get("lease_states", [])) == LEASE_STATES),
        _check("decision_kinds_complete", set(schema.get("decision_kinds", [])) == DECISION_KINDS),
        _check("reason_codes_complete", set(schema.get("reason_codes", [])) == REASON_CODES),
        _check("required_actions_complete", set(schema.get("required_actions", [])) == REQUIRED_ACTIONS),
        _check("dirty_state_policies_complete", set(schema.get("dirty_state_policies", [])) == DIRTY_STATE_POLICIES),
        _check("capacity_modes_complete", set(schema.get("capacity_modes", [])) == CAPACITY_MODES),
        _check("event_codes_complete", set(schema.get("event_codes", [])) == EVENT_CODES),
        _check("required_work_key_fields_complete", set(schema.get("required_work_key_fields", [])) == set(WORK_KEY_REQUIRED_FIELDS)),
        _check("required_lease_fields_complete", set(schema.get("required_lease_fields", [])) == set(LEASE_REQUIRED_FIELDS)),
        _check("required_decision_fields_complete", set(schema.get("required_decision_fields", [])) == set(DECISION_REQUIRED_FIELDS)),
        _check(
            "required_admission_policy_fields_complete",
            set(schema.get("required_admission_policy_fields", [])) == set(ADMISSION_POLICY_REQUIRED_FIELDS),
        ),
        _check("work_key_schema_required_complete", _schema_has_required(schema, "ValidationProofWorkKey", WORK_KEY_REQUIRED_FIELDS)),
        _check(
            "lease_schema_required_complete",
            _schema_has_required(schema, "ValidationProofCoalescerLease", LEASE_REQUIRED_FIELDS),
        ),
        _check(
            "decision_schema_required_complete",
            _schema_has_required(schema, "ValidationProofCoalescerDecision", DECISION_REQUIRED_FIELDS),
        ),
        _check(
            "admission_policy_schema_required_complete",
            _schema_has_required(
                schema,
                "ValidationProofCoalescerAdmissionPolicy",
                ADMISSION_POLICY_REQUIRED_FIELDS,
            ),
        ),
    ]


def _check_decision_examples(fixtures: dict[str, Any]) -> list[dict[str, Any]]:
    examples = fixtures.get("decision_examples", [])
    checks = [_check("decision_examples_present", isinstance(examples, list) and len(examples) >= len(DECISION_KINDS))]
    if not isinstance(examples, list):
        return checks

    observed_decisions = {item.get("decision") for item in examples if isinstance(item, dict)}
    observed_reasons = {item.get("reason_code") for item in examples if isinstance(item, dict)}
    observed_actions = {item.get("required_action") for item in examples if isinstance(item, dict)}
    observed_events = {item.get("event_code") for item in examples if isinstance(item, dict)}
    checks.extend(
        [
            _check("decision_examples_cover_decisions", observed_decisions == DECISION_KINDS),
            _check("decision_examples_cover_reasons", observed_reasons == REASON_CODES),
            _check("decision_examples_cover_actions", observed_actions == REQUIRED_ACTIONS),
            _check("decision_examples_events_known", observed_events.issubset(EVENT_CODES) and len(observed_events) >= 8),
        ]
    )
    for item in examples:
        if not isinstance(item, dict):
            checks.append(_check("decision_example_shape", False, "example is not an object"))
            continue
        decision = item.get("decision")
        expected = DECISION_RULES.get(decision)
        checks.append(
            _check(
                f"decision_example_rule:{decision}",
                expected == (item.get("reason_code"), item.get("required_action")),
                json.dumps(item, sort_keys=True),
            )
        )
    return checks


def _check_fixtures(fixtures: Any) -> list[dict[str, Any]]:
    if not isinstance(fixtures, dict):
        return [_check("fixtures_parseable", False, "fixtures missing or invalid")]

    checks: list[dict[str, Any]] = [
        _check("fixtures_schema_version", fixtures.get("schema_version") == FIXTURE_SCHEMA_VERSION),
    ]
    validation_time = _parse_rfc3339(fixtures.get("validation_time"))
    checks.append(_check("fixtures_validation_time_parseable", validation_time is not None))
    now = validation_time or datetime.now(timezone.utc)

    valid_work_keys = fixtures.get("valid_work_keys", [])
    checks.append(_check("valid_work_keys_present", isinstance(valid_work_keys, list) and len(valid_work_keys) >= 1))
    for index, work_key in enumerate(valid_work_keys if isinstance(valid_work_keys, list) else []):
        errors = validate_work_key(work_key)
        checks.append(_check(f"valid_work_key:{index}", errors == [], ",".join(errors)))

    valid_policies = fixtures.get("valid_admission_policies", [])
    checks.append(_check("valid_admission_policies_present", isinstance(valid_policies, list) and len(valid_policies) >= 1))
    for index, policy in enumerate(valid_policies if isinstance(valid_policies, list) else []):
        errors = validate_admission_policy(policy)
        checks.append(_check(f"valid_admission_policy:{index}", errors == [], ",".join(errors)))

    valid_leases = fixtures.get("valid_leases", [])
    checks.append(_check("valid_leases_present", isinstance(valid_leases, list) and len(valid_leases) >= 2))
    base_lease = valid_leases[0] if isinstance(valid_leases, list) and valid_leases else None
    for index, lease in enumerate(valid_leases if isinstance(valid_leases, list) else []):
        errors = validate_lease(lease, expected_bead_id=BEAD_ID, now=now)
        checks.append(_check(f"valid_lease:{index}", errors == [], ",".join(errors)))

    valid_decisions = fixtures.get("valid_decisions", [])
    checks.append(_check("valid_decisions_present", isinstance(valid_decisions, list) and len(valid_decisions) >= 1))
    base_decision = valid_decisions[0] if isinstance(valid_decisions, list) and valid_decisions else None
    for index, decision in enumerate(valid_decisions if isinstance(valid_decisions, list) else []):
        errors = validate_decision(decision, expected_bead_id=BEAD_ID, now=now)
        checks.append(_check(f"valid_decision:{index}", errors == [], ",".join(errors)))

    checks.extend(_check_decision_examples(fixtures))

    invalid_leases = fixtures.get("invalid_leases", [])
    checks.append(_check("invalid_leases_present", isinstance(invalid_leases, list) and len(invalid_leases) >= 6))
    for case in invalid_leases if isinstance(invalid_leases, list) else []:
        lease = case.get("lease", apply_fixture_patch(base_lease, case.get("patch"))) if isinstance(case, dict) else None
        errors = validate_lease(lease, expected_bead_id=BEAD_ID, now=now)
        expected_errors = case.get("expected_errors", []) if isinstance(case, dict) else []
        passed = isinstance(expected_errors, list) and all(error in errors for error in expected_errors)
        checks.append(_check(f"invalid_lease:{case.get('name', 'unnamed')}", passed, ",".join(errors)))

    invalid_decisions = fixtures.get("invalid_decisions", [])
    checks.append(_check("invalid_decisions_present", isinstance(invalid_decisions, list) and len(invalid_decisions) >= 4))
    for case in invalid_decisions if isinstance(invalid_decisions, list) else []:
        decision = (
            case.get("decision_payload", apply_fixture_patch(base_decision, case.get("patch")))
            if isinstance(case, dict)
            else None
        )
        errors = validate_decision(decision, expected_bead_id=BEAD_ID, now=now)
        expected_errors = case.get("expected_errors", []) if isinstance(case, dict) else []
        passed = isinstance(expected_errors, list) and all(error in errors for error in expected_errors)
        checks.append(_check(f"invalid_decision:{case.get('name', 'unnamed')}", passed, ",".join(errors)))

    scenarios = fixtures.get("scenarios", [])
    scenario_names = {item.get("name") for item in scenarios if isinstance(item, dict)}
    checks.append(_check("scenarios_cover_acceptance", REQUIRED_SCENARIOS.issubset(scenario_names)))
    for scenario in scenarios if isinstance(scenarios, list) else []:
        if not isinstance(scenario, dict):
            checks.append(_check("scenario_shape", False, "scenario is not an object"))
            continue
        decision = scenario.get("decision")
        reason = scenario.get("reason_code")
        event_code = scenario.get("expected_event_code")
        checks.append(
            _check(
                f"scenario_known:{scenario.get('name', 'unnamed')}",
                decision in DECISION_KINDS and reason in REASON_CODES and event_code in EVENT_CODES,
                json.dumps(scenario, sort_keys=True),
            )
        )

    return checks


def run_all() -> dict[str, Any]:
    configure_test_logging("validation_proof_coalescer_contract")
    checks = _check_files()
    checks.extend(_check_spec())

    try:
        schema, fixtures = _load_contract_files()
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        checks.append(_check("contract_files_parse", False, str(exc)))
        schema = None
        fixtures = None

    checks.extend(_check_schema(schema))
    checks.extend(_check_fixtures(fixtures))

    passed = sum(1 for check in checks if check["passed"])
    total = len(checks)
    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "schema_version": SCHEMA_CATALOG_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verdict": "PASS" if passed == total else "FAIL",
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "checks": checks,
    }


def run_self_test() -> dict[str, Any]:
    contract_result = run_all()
    fixtures = _load_json(FIXTURES_FILE)
    validation_time = _parse_rfc3339(fixtures["validation_time"])
    valid_key = fixtures["valid_work_keys"][0]
    valid_lease = fixtures["valid_leases"][0]
    valid_decision = fixtures["valid_decisions"][0]

    bad_key = copy.deepcopy(valid_key)
    bad_key["hex"] = "0" * 64
    stale_lease = copy.deepcopy(valid_lease)
    stale_lease["expires_at"] = "2026-05-06T01:00:00Z"
    bad_decision = copy.deepcopy(valid_decision)
    bad_decision["reason_code"] = "VPCO_UNKNOWN"

    checks = [
        _check("contract_run_all_passes", contract_result["verdict"] == "PASS"),
        _check("self_bad_work_key_rejected", "ERR_VPCO_BAD_WORK_KEY" in validate_work_key(bad_key)),
        _check(
            "self_stale_lease_rejected",
            "ERR_VPCO_STALE_LEASE" in validate_lease(stale_lease, expected_bead_id=BEAD_ID, now=validation_time),
        ),
        _check(
            "self_bad_decision_rejected",
            "ERR_VPCO_MALFORMED_DECISION"
            in validate_decision(bad_decision, expected_bead_id=BEAD_ID, now=validation_time),
        ),
    ]
    passed = sum(1 for check in checks if check["passed"])
    return {
        "bead_id": BEAD_ID,
        "title": f"{TITLE} self-test",
        "schema_version": SCHEMA_CATALOG_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verdict": "PASS" if passed == len(checks) else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": len(checks) - passed,
        "checks": checks,
        "contract_result": contract_result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument("--self-test", action="store_true", help="run checker self-tests")
    args = parser.parse_args(argv)

    result = run_self_test() if args.self_test else run_all()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result['verdict']} {result['passed']}/{result['total']} {TITLE}")
        for check in result["checks"]:
            if not check["passed"]:
                print(f"FAIL {check['check']}: {check['detail']}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
