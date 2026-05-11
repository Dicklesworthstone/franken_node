#!/usr/bin/env python3
"""Validate the validation swarm scheduler contract artifacts for bd-4iy4h."""

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


BEAD_ID = "bd-4iy4h"
TITLE = "Validation swarm scheduler contract"
INPUT_SCHEMA_VERSION = "franken-node/validation-swarm-scheduler/input/v1"
POLICY_SCHEMA_VERSION = "franken-node/validation-swarm-scheduler/policy/v1"
DECISION_SCHEMA_VERSION = "franken-node/validation-swarm-scheduler/decision/v1"
SCHEMA_CATALOG_VERSION = "franken-node/validation-swarm-scheduler/schema-catalog/v1"
FIXTURE_SCHEMA_VERSION = "franken-node/validation-swarm-scheduler/fixtures/v1"

SPEC_FILE = ROOT / "docs/specs/validation_swarm_scheduler.md"
SCHEMA_FILE = (
    ROOT
    / "artifacts/validation_broker/swarm_scheduler/validation_swarm_scheduler_contract.schema.json"
)
FIXTURES_FILE = (
    ROOT
    / "artifacts/validation_broker/swarm_scheduler/validation_swarm_scheduler_fixtures.v1.json"
)
STRESS_MATRIX_FILE = (
    ROOT
    / "artifacts/validation_broker/swarm_scheduler/validation_swarm_scheduler_stress_matrix.v1.json"
)
SCRIPT_FILE = ROOT / "scripts/check_validation_swarm_scheduler_contract.py"
TEST_FILE = ROOT / "tests/test_check_validation_swarm_scheduler_contract.py"

REQUIRED_SPEC_MARKERS = [
    "ValidationSwarmSchedulerInput",
    "ValidationSwarmSchedulerPolicy",
    "ValidationSwarmSchedulerDecision",
    "run_now",
    "join_existing",
    "wait_for_capacity",
    "steal_stale_work",
    "reject_low_priority",
    "record_source_only_blocker",
    "fail_closed_product",
    "fail_closed_invalid_artifact",
    "INV-VSS-WORK-KEY-COMPATIBLE",
    "INV-VSS-DETERMINISTIC-DECISION",
    "INV-VSS-BOUNDED-QUEUE",
    "INV-VSS-AGING-NO-STARVATION",
    "INV-VSS-EXACT-JOIN",
    "INV-VSS-FENCED-STEAL",
    "INV-VSS-SOURCE-ONLY-EXPLICIT",
    "INV-VSS-PRODUCT-FAIL-CLOSED",
    "INV-VSS-WORKER-INFRA-NOT-GREEN",
    "INV-VSS-INVALID-ARTIFACT-FAIL-CLOSED",
    "trace_id",
    "proof_work_key",
    "fencing_token_digest",
    "ERR_VSS_WORKER_INFRA_GREEN",
    "ERR_VSS_PRODUCT_RETRIED_AS_INFRA",
    "Degraded-worker stress matrix",
    "degraded-reroute-256",
    "degraded-reroute-1024",
    "optional live cargo or benchmark path is rch-only",
]

INPUT_REQUIRED_FIELDS = [
    "schema_version",
    "input_id",
    "bead_id",
    "agent_name",
    "proof_work_key",
    "command_digest",
    "dirty_state_policy",
    "target_dir_class",
    "capacity_snapshot",
    "coalescer_state",
    "flight_recorder_state",
    "proof_debt_class",
    "queue_age_ms",
    "priority",
    "timeout_budget_ms",
    "source_only_allowed",
    "product_failure",
    "worker_infra_retryable",
    "artifact_valid",
]

POLICY_REQUIRED_FIELDS = [
    "schema_version",
    "policy_id",
    "max_running_proofs",
    "max_waiters_per_work_key",
    "queue_high_watermark",
    "starvation_after_ms",
    "aging_step_ms",
    "min_available_worker_slots",
    "allow_work_stealing",
    "fairness_buckets",
]

DECISION_REQUIRED_FIELDS = [
    "schema_version",
    "decision_id",
    "input_ref",
    "bead_id",
    "agent_name",
    "trace_id",
    "decided_at",
    "freshness_expires_at",
    "decision",
    "reason_code",
    "event_code",
    "required_action",
    "fairness_bucket",
    "starvation_risk",
    "retryable",
    "fail_closed",
    "green_proof_eligible",
    "operator_message",
    "diagnostics",
]

DECISION_KINDS = {
    "run_now",
    "join_existing",
    "wait_for_capacity",
    "steal_stale_work",
    "reject_low_priority",
    "record_source_only_blocker",
    "fail_closed_product",
    "fail_closed_invalid_artifact",
}

DECISION_RULES = {
    "run_now": ("VSS_RUN_READY", "VSS-001", "start_rch_validation", False, False),
    "join_existing": ("VSS_JOIN_IDENTICAL", "VSS-002", "join_existing_proof", False, False),
    "wait_for_capacity": ("VSS_WAIT_CAPACITY", "VSS-003", "wait_for_capacity", True, False),
    "steal_stale_work": ("VSS_STEAL_STALE", "VSS-004", "steal_with_new_fence", True, False),
    "reject_low_priority": ("VSS_REJECT_LOW_PRIORITY", "VSS-005", "defer_low_priority", True, False),
    "record_source_only_blocker": (
        "VSS_SOURCE_ONLY_BLOCKER",
        "VSS-006",
        "record_source_only_blocker",
        False,
        True,
    ),
    "fail_closed_product": ("VSS_FAIL_PRODUCT", "VSS-007", "surface_product_failure", False, True),
    "fail_closed_invalid_artifact": (
        "VSS_FAIL_INVALID_ARTIFACT",
        "VSS-008",
        "reject_artifact",
        False,
        True,
    ),
}

REASON_CODES = {rule[0] for rule in DECISION_RULES.values()}
EVENT_CODES = {rule[1] for rule in DECISION_RULES.values()}
REQUIRED_ACTIONS = {rule[2] for rule in DECISION_RULES.values()}
RETRYABLE_DECISIONS = {decision for decision, rule in DECISION_RULES.items() if rule[3]}
FAIL_CLOSED_DECISIONS = {decision for decision, rule in DECISION_RULES.items() if rule[4]}

FAIRNESS_BUCKETS = {"emergency", "high", "normal", "low", "aging", "blocked"}
STARVATION_RISKS = {"none", "watch", "elevated", "breached"}
COALESCER_STATES = {"none", "running", "joined", "completed", "stale", "fenced", "rejected", "failed_closed"}
FLIGHT_RECORDER_STATES = {
    "none",
    "remote_success",
    "worker_timeout",
    "missing_toolchain",
    "disk_pressure",
    "contention_deferred",
    "local_fallback_refused",
    "source_only_blocker",
    "product_failure",
    "invalid_artifact",
}
PROOF_DEBT_CLASSES = {
    "none",
    "worker_infra",
    "capacity",
    "stale_producer",
    "source_only",
    "product_failure",
    "invalid_artifact",
}
TARGET_DIR_CLASSES = {"off_repo", "repo_local_guarded", "repo_local_writable", "unwritable", "missing", "unknown"}
DIRTY_STATE_POLICIES = {"clean_required", "dirty_allowed_with_digest", "source_only_documented"}
PRIORITIES = {"P0", "P1", "P2", "P3", "P4"}

REQUIRED_SCENARIOS = {
    "healthy_fleet_run",
    "saturated_fleet_wait",
    "degraded_worker_join",
    "stale_queue_aging",
    "stale_producer_steal",
    "proof_cache_hit_join",
    "source_only_blocker",
    "product_failure",
    "invalid_artifact",
}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _load_json(path: Path) -> Any:
    return json.JSONDecoder().decode(path.read_text(encoding="utf-8"))


def _check(check: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {"check": check, "passed": bool(passed), "detail": detail or ("ok" if passed else "FAIL")}


def _is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


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


def apply_fixture_patch(base: Any, patch: dict[str, Any] | None) -> Any:
    patched = copy.deepcopy(base)
    if not patch:
        return patched
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
    if not isinstance(algorithm, str) or not hmac.compare_digest(algorithm, "sha256"):
        return False
    if not _is_sha256_hex(digest_hex) or not isinstance(material, str):
        return False
    computed = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return isinstance(digest_hex, str) and hmac.compare_digest(computed, digest_hex)


def validate_input(payload: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["ERR_VSS_MALFORMED_INPUT"]
    for field in INPUT_REQUIRED_FIELDS:
        if field not in payload:
            errors.append("ERR_VSS_MALFORMED_INPUT")
            break
    if payload.get("schema_version") != INPUT_SCHEMA_VERSION:
        errors.append("ERR_VSS_INVALID_SCHEMA_VERSION")
    for field in ["input_id", "bead_id", "agent_name"]:
        value = payload.get(field)
        if not isinstance(value, str) or not value or "\0" in value:
            errors.append("ERR_VSS_MALFORMED_INPUT")
            break
    if payload.get("bead_id") != BEAD_ID:
        errors.append("ERR_VSS_MALFORMED_INPUT")
    if not _digest_verifies(payload.get("proof_work_key")):
        errors.append("ERR_VSS_BAD_WORK_KEY")
    if not _digest_verifies(payload.get("command_digest")):
        errors.append("ERR_VSS_COMMAND_DIGEST_MISMATCH")
    if payload.get("dirty_state_policy") not in DIRTY_STATE_POLICIES:
        errors.append("ERR_VSS_MALFORMED_INPUT")
    if payload.get("target_dir_class") not in TARGET_DIR_CLASSES:
        errors.append("ERR_VSS_MALFORMED_INPUT")
    if payload.get("coalescer_state") not in COALESCER_STATES:
        errors.append("ERR_VSS_MALFORMED_INPUT")
    if payload.get("flight_recorder_state") not in FLIGHT_RECORDER_STATES:
        errors.append("ERR_VSS_MALFORMED_INPUT")
    if payload.get("proof_debt_class") not in PROOF_DEBT_CLASSES:
        errors.append("ERR_VSS_MALFORMED_INPUT")
    if payload.get("priority") not in PRIORITIES:
        errors.append("ERR_VSS_MALFORMED_INPUT")
    for field in ["queue_age_ms", "timeout_budget_ms"]:
        value = payload.get(field)
        if not isinstance(value, int) or value < 0:
            errors.append("ERR_VSS_MALFORMED_INPUT")
            break
    if payload.get("timeout_budget_ms") == 0:
        errors.append("ERR_VSS_MALFORMED_INPUT")
    for field in ["source_only_allowed", "product_failure", "worker_infra_retryable", "artifact_valid"]:
        if not isinstance(payload.get(field), bool):
            errors.append("ERR_VSS_MALFORMED_INPUT")
            break
    snapshot = payload.get("capacity_snapshot")
    if not isinstance(snapshot, dict):
        errors.append("ERR_VSS_MALFORMED_INPUT")
    else:
        for field in ["workers_total", "workers_healthy", "slots_total", "slots_available", "queue_depth", "stale_active_builds"]:
            value = snapshot.get(field)
            if not isinstance(value, int) or value < 0:
                errors.append("ERR_VSS_MALFORMED_INPUT")
                break
    if payload.get("product_failure") and payload.get("worker_infra_retryable"):
        errors.append("ERR_VSS_PRODUCT_RETRIED_AS_INFRA")
    artifact_valid = payload.get("artifact_valid")
    if isinstance(artifact_valid, bool) and not artifact_valid and payload.get("proof_debt_class") != "invalid_artifact":
        errors.append("ERR_VSS_INVALID_ARTIFACT_ACCEPTED")
    return sorted(set(errors))


def validate_policy(policy: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["ERR_VSS_MALFORMED_POLICY"]
    for field in POLICY_REQUIRED_FIELDS:
        if field not in policy:
            errors.append("ERR_VSS_MALFORMED_POLICY")
            break
    if policy.get("schema_version") != POLICY_SCHEMA_VERSION:
        errors.append("ERR_VSS_INVALID_SCHEMA_VERSION")
    for field in [
        "max_running_proofs",
        "max_waiters_per_work_key",
        "queue_high_watermark",
        "starvation_after_ms",
        "aging_step_ms",
        "min_available_worker_slots",
    ]:
        value = policy.get(field)
        if not isinstance(value, int) or value < 0:
            errors.append("ERR_VSS_MALFORMED_POLICY")
            break
    if policy.get("max_running_proofs") == 0 or policy.get("starvation_after_ms") == 0:
        errors.append("ERR_VSS_MALFORMED_POLICY")
    if not isinstance(policy.get("allow_work_stealing"), bool):
        errors.append("ERR_VSS_MALFORMED_POLICY")
    if set(policy.get("fairness_buckets", [])) != FAIRNESS_BUCKETS:
        errors.append("ERR_VSS_MALFORMED_POLICY")
    return sorted(set(errors))


def validate_decision(decision: Any, *, now: datetime | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(decision, dict):
        return ["ERR_VSS_MALFORMED_DECISION"]
    for field in DECISION_REQUIRED_FIELDS:
        if field not in decision:
            errors.append("ERR_VSS_MALFORMED_DECISION")
            break
    if decision.get("schema_version") != DECISION_SCHEMA_VERSION:
        errors.append("ERR_VSS_INVALID_SCHEMA_VERSION")
    for field in ["decision_id", "input_ref", "bead_id", "agent_name", "trace_id", "operator_message"]:
        value = decision.get(field)
        if not isinstance(value, str) or not value or "\0" in value:
            errors.append("ERR_VSS_MALFORMED_DECISION")
            break
    if decision.get("bead_id") != BEAD_ID:
        errors.append("ERR_VSS_MALFORMED_DECISION")
    decided_at = _parse_rfc3339(decision.get("decided_at"))
    expires_at = _parse_rfc3339(decision.get("freshness_expires_at"))
    if decided_at is None or expires_at is None or expires_at <= decided_at:
        errors.append("ERR_VSS_MALFORMED_DECISION")
    if now is not None and expires_at is not None and expires_at < now:
        errors.append("ERR_VSS_STALE_DECISION")
    kind = decision.get("decision")
    expected = DECISION_RULES.get(kind)
    if expected is None:
        errors.append("ERR_VSS_MALFORMED_DECISION")
    else:
        expected_reason, expected_event, expected_action, retryable, fail_closed = expected
        if (
            decision.get("reason_code") != expected_reason
            or decision.get("event_code") != expected_event
            or decision.get("required_action") != expected_action
            or decision.get("retryable") != retryable
            or decision.get("fail_closed") != fail_closed
        ):
            errors.append("ERR_VSS_MALFORMED_DECISION")
    if decision.get("fairness_bucket") not in FAIRNESS_BUCKETS:
        errors.append("ERR_VSS_MALFORMED_DECISION")
    if decision.get("starvation_risk") not in STARVATION_RISKS:
        errors.append("ERR_VSS_MALFORMED_DECISION")
    if not isinstance(decision.get("green_proof_eligible"), bool):
        errors.append("ERR_VSS_MALFORMED_DECISION")
    diagnostics = decision.get("diagnostics")
    if not isinstance(diagnostics, dict):
        errors.append("ERR_VSS_MALFORMED_DECISION")
    else:
        debt_class = diagnostics.get("proof_debt_class")
        if decision.get("green_proof_eligible") and debt_class == "worker_infra":
            errors.append("ERR_VSS_WORKER_INFRA_GREEN")
        if kind == "fail_closed_invalid_artifact" and decision.get("fail_closed") is not True:
            errors.append("ERR_VSS_INVALID_ARTIFACT_ACCEPTED")
    return sorted(set(errors))


def _schema_has_required(schema: Any, name: str, required: list[str]) -> bool:
    if not isinstance(schema, dict):
        return False
    schemas = schema.get("schemas")
    contract_schema = schemas.get(name, {}) if isinstance(schemas, dict) else {}
    declared = contract_schema.get("required", [])
    return isinstance(declared, list) and set(declared) == set(required)


def _check_files() -> list[dict[str, Any]]:
    return [
        _check("spec_exists", SPEC_FILE.is_file(), str(SPEC_FILE)),
        _check("schema_catalog_exists", SCHEMA_FILE.is_file(), str(SCHEMA_FILE)),
        _check("fixtures_exist", FIXTURES_FILE.is_file(), str(FIXTURES_FILE)),
        _check("stress_matrix_exists", STRESS_MATRIX_FILE.is_file(), str(STRESS_MATRIX_FILE)),
        _check("script_exists", SCRIPT_FILE.is_file(), str(SCRIPT_FILE)),
        _check("tests_exist", TEST_FILE.is_file(), str(TEST_FILE)),
    ]


def _check_spec() -> list[dict[str, Any]]:
    content = _read_text(SPEC_FILE)
    return [_check(f"spec_marker:{marker}", marker in content, marker) for marker in REQUIRED_SPEC_MARKERS]


def _check_schema(schema: Any) -> list[dict[str, Any]]:
    if not isinstance(schema, dict):
        return [_check("schema_parseable", False, "schema missing or invalid")]
    return [
        _check("schema_version", schema.get("schema_version") == SCHEMA_CATALOG_VERSION),
        _check("input_schema_version", schema.get("input_schema_version") == INPUT_SCHEMA_VERSION),
        _check("policy_schema_version", schema.get("policy_schema_version") == POLICY_SCHEMA_VERSION),
        _check("decision_schema_version", schema.get("decision_schema_version") == DECISION_SCHEMA_VERSION),
        _check("decision_kinds_complete", set(schema.get("decision_kinds", [])) == DECISION_KINDS),
        _check("reason_codes_complete", set(schema.get("reason_codes", [])) == REASON_CODES),
        _check("event_codes_complete", set(schema.get("event_codes", [])) == EVENT_CODES),
        _check("required_actions_complete", set(schema.get("required_actions", [])) == REQUIRED_ACTIONS),
        _check("fairness_buckets_complete", set(schema.get("fairness_buckets", [])) == FAIRNESS_BUCKETS),
        _check("starvation_risks_complete", set(schema.get("starvation_risks", [])) == STARVATION_RISKS),
        _check("required_input_fields_complete", set(schema.get("required_input_fields", [])) == set(INPUT_REQUIRED_FIELDS)),
        _check("required_policy_fields_complete", set(schema.get("required_policy_fields", [])) == set(POLICY_REQUIRED_FIELDS)),
        _check("required_decision_fields_complete", set(schema.get("required_decision_fields", [])) == set(DECISION_REQUIRED_FIELDS)),
        _check("input_schema_required_complete", _schema_has_required(schema, "ValidationSwarmSchedulerInput", INPUT_REQUIRED_FIELDS)),
        _check("policy_schema_required_complete", _schema_has_required(schema, "ValidationSwarmSchedulerPolicy", POLICY_REQUIRED_FIELDS)),
        _check("decision_schema_required_complete", _schema_has_required(schema, "ValidationSwarmSchedulerDecision", DECISION_REQUIRED_FIELDS)),
    ]


def _check_decision_examples(fixtures: Any, now: datetime | None) -> list[dict[str, Any]]:
    examples = fixtures.get("decision_examples", []) if isinstance(fixtures, dict) else []
    checks = [_check("decision_examples_present", isinstance(examples, list) and len(examples) >= len(DECISION_KINDS))]
    if not isinstance(examples, list):
        return checks
    observed_decisions = {item.get("decision") for item in examples if isinstance(item, dict)}
    observed_reasons = {item.get("reason_code") for item in examples if isinstance(item, dict)}
    observed_actions = {item.get("required_action") for item in examples if isinstance(item, dict)}
    checks.extend(
        [
            _check("decision_examples_cover_decisions", observed_decisions == DECISION_KINDS),
            _check("decision_examples_cover_reasons", observed_reasons == REASON_CODES),
            _check("decision_examples_cover_actions", observed_actions == REQUIRED_ACTIONS),
        ]
    )
    for item in examples:
        if not isinstance(item, dict):
            checks.append(_check("decision_example_shape", False, "example is not object"))
            continue
        errors = validate_decision(item, now=now)
        checks.append(_check(f"decision_example:{item.get('decision', '<unnamed>')}", errors == [], ",".join(errors)))
    return checks


def _check_fixtures(fixtures: Any) -> list[dict[str, Any]]:
    if not isinstance(fixtures, dict):
        return [_check("fixtures_parseable", False, "fixtures missing or invalid")]
    validation_time = _parse_rfc3339(fixtures.get("validation_time"))
    now = validation_time or datetime.now(timezone.utc)
    checks = [
        _check("fixtures_schema_version", fixtures.get("schema_version") == FIXTURE_SCHEMA_VERSION),
        _check("fixtures_validation_time_parseable", validation_time is not None),
    ]
    checks.append(_check("base_policy_valid", validate_policy(fixtures.get("base_policy")) == []))
    checks.append(_check("base_input_valid", validate_input(fixtures.get("base_input")) == []))
    checks.extend(_check_decision_examples(fixtures, now))

    scenarios = fixtures.get("scenarios", [])
    scenario_names = {item.get("name") for item in scenarios if isinstance(item, dict)}
    checks.append(_check("scenario_matrix_complete", REQUIRED_SCENARIOS.issubset(scenario_names), ",".join(sorted(scenario_names))))

    base_input = fixtures.get("base_input")
    for case in fixtures.get("invalid_inputs", []):
        candidate = apply_fixture_patch(base_input, case.get("patch")) if isinstance(case, dict) else None
        errors = validate_input(candidate)
        expected = case.get("expected_errors", []) if isinstance(case, dict) else []
        checks.append(
            _check(
                f"invalid_input:{case.get('name', '<unnamed>') if isinstance(case, dict) else '<bad>'}",
                isinstance(expected, list) and all(error in errors for error in expected),
                ",".join(errors),
            )
        )

    base_decision = fixtures.get("decision_examples", [{}])[0]
    for case in fixtures.get("invalid_decisions", []):
        candidate = apply_fixture_patch(base_decision, case.get("patch")) if isinstance(case, dict) else None
        errors = validate_decision(candidate, now=now)
        expected = case.get("expected_errors", []) if isinstance(case, dict) else []
        checks.append(
            _check(
                f"invalid_decision:{case.get('name', '<unnamed>') if isinstance(case, dict) else '<bad>'}",
                isinstance(expected, list) and all(error in errors for error in expected),
                ",".join(errors),
            )
        )
    return checks


def degraded_reroute_stress_summary(case: dict[str, Any]) -> dict[str, Any]:
    attempts = case["attempts"]
    unique_work_keys = case["unique_work_keys"]
    product_failure_lanes = case["product_failure_lanes"]
    stale_lease_lanes = case["stale_lease_lanes"]
    proof_cache_reuses = case["proof_cache_reuses"]
    exhausted_budget_lanes = case["exhausted_budget_lanes"]
    aged_low_priority_lanes = case["aged_low_priority_lanes"]
    producer_count = unique_work_keys
    joined_waiters = (
        attempts
        - producer_count
        - product_failure_lanes
        - stale_lease_lanes
        - proof_cache_reuses
        - exhausted_budget_lanes
        - aged_low_priority_lanes
    )
    return {
        "attempts": attempts,
        "unique_work_keys": unique_work_keys,
        "producer_count": producer_count,
        "duplicate_producer_count": case.get("duplicate_producer_count", 0),
        "joined_waiters": joined_waiters,
        "max_waiters_per_work_key": case["max_waiters_per_work_key"],
        "alternate_worker_reroutes": case["alternate_worker_reroutes"],
        "degraded_worker_new_proofs": case.get("degraded_worker_new_proofs", 0),
        "proof_debt_backoffs": exhausted_budget_lanes,
        "stale_lease_fences": stale_lease_lanes,
        "proof_cache_reuses": proof_cache_reuses,
        "aged_low_priority_lanes": aged_low_priority_lanes,
        "stopped_after_budget_exhausted": exhausted_budget_lanes,
        "retry_after_exhausted_count": case.get("retry_after_exhausted_count", 0),
        "worker_infra_green_count": case.get("worker_infra_green_count", 0),
        "product_failure_retry_count": case.get("product_failure_retry_count", 0),
        "event_count": (
            attempts
            + proof_cache_reuses
            + stale_lease_lanes
            + product_failure_lanes
            + exhausted_budget_lanes
            + aged_low_priority_lanes
        ),
        "decision_counts": {
            "run_now": producer_count,
            "join_existing": joined_waiters + proof_cache_reuses,
            "wait_for_capacity": exhausted_budget_lanes + aged_low_priority_lanes,
            "steal_stale_work": stale_lease_lanes,
            "fail_closed_product": product_failure_lanes,
        },
    }


def validate_degraded_reroute_stress_case(case: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(case, dict):
        return ["ERR_VSS_MALFORMED_STRESS_CASE"]
    required = {
        "case_id",
        "attempts",
        "unique_work_keys",
        "healthy_workers",
        "degraded_workers",
        "alternate_worker_reroutes",
        "product_failure_lanes",
        "stale_lease_lanes",
        "proof_cache_reuses",
        "exhausted_budget_lanes",
        "aged_low_priority_lanes",
        "max_waiters_per_work_key",
        "bounded_event_count_max",
        "expected_summary",
    }
    if not required.issubset(case):
        return ["ERR_VSS_MALFORMED_STRESS_CASE"]
    for field in required - {"case_id", "expected_summary"}:
        value = case.get(field)
        if not isinstance(value, int) or value < 0:
            errors.append("ERR_VSS_MALFORMED_STRESS_CASE")
    if case.get("attempts") not in {256, 1024}:
        errors.append("ERR_VSS_MALFORMED_STRESS_CASE")
    if case.get("degraded_worker_new_proofs", 0) > 0:
        errors.append("ERR_VSS_DEGRADED_WORKER_SELECTED")
    if case.get("duplicate_producer_count", 0) > 0:
        errors.append("ERR_VSS_DUPLICATE_PRODUCER")
    if case.get("worker_infra_green_count", 0) > 0:
        errors.append("ERR_VSS_WORKER_INFRA_GREEN")
    if case.get("product_failure_retry_count", 0) > 0:
        errors.append("ERR_VSS_PRODUCT_RETRIED_AS_INFRA")
    if case.get("retry_after_exhausted_count", 0) > 0:
        errors.append("ERR_VSS_RETRY_BUDGET_EXHAUSTED")
    if errors:
        return sorted(set(errors))

    summary = degraded_reroute_stress_summary(case)
    if summary["joined_waiters"] < 0:
        errors.append("ERR_VSS_MALFORMED_STRESS_CASE")
    if summary["producer_count"] != summary["unique_work_keys"]:
        errors.append("ERR_VSS_DUPLICATE_PRODUCER")
    if summary["max_waiters_per_work_key"] > 256:
        errors.append("ERR_VSS_UNBOUNDED_WAITER_SET")
    if summary["event_count"] > case["bounded_event_count_max"]:
        errors.append("ERR_VSS_UNBOUNDED_OUTPUT")
    if case.get("growth_class") != "constant_work_keys_linear_rows":
        errors.append("ERR_VSS_UNBOUNDED_OUTPUT")
    if summary != case.get("expected_summary"):
        errors.append("ERR_VSS_STRESS_GOLDEN_MISMATCH")
    return sorted(set(errors))


def _check_stress_matrix(stress: Any) -> list[dict[str, Any]]:
    if not isinstance(stress, dict):
        return [_check("stress_matrix_parseable", False, "stress matrix missing or invalid")]
    checks = [
        _check(
            "stress_schema_version",
            stress.get("schema_version") == "franken-node/validation-swarm-scheduler/stress-matrix/v1",
        ),
        _check("stress_attempts_64_baseline", stress.get("attempts") == 64),
    ]
    required_scenarios = {
        "equivalent_attempts_single_producer",
        "equivalent_attempts_join_existing",
        "proof_cache_hit_join_existing",
        "worker_infra_waits_for_capacity",
        "stale_producer_requires_fenced_steal",
        "product_failure_fails_closed",
    }
    scenario_names = {item.get("name") for item in stress.get("scenarios", []) if isinstance(item, dict)}
    checks.append(_check("stress_64_scenarios_cover_core", required_scenarios.issubset(scenario_names), ",".join(sorted(scenario_names))))

    degraded_cases = stress.get("degraded_reroute_cases", [])
    checks.append(_check("degraded_reroute_cases_present", isinstance(degraded_cases, list) and len(degraded_cases) >= 2))
    represented = {case.get("case_id") for case in degraded_cases if isinstance(case, dict)}
    for required_case in {"degraded-reroute-256", "degraded-reroute-1024"}:
        checks.append(_check(f"degraded_reroute_matrix:{required_case}", required_case in represented, ",".join(sorted(str(case) for case in represented))))
    for case in degraded_cases if isinstance(degraded_cases, list) else []:
        case_id = case.get("case_id", "<unnamed>") if isinstance(case, dict) else "<bad>"
        errors = validate_degraded_reroute_stress_case(case)
        checks.append(_check(f"degraded_reroute_case:{case_id}", errors == [], ",".join(errors)))
        if not errors:
            summary = degraded_reroute_stress_summary(case)
            checks.extend(
                [
                    _check(f"degraded_reroute_no_duplicate_producer:{case_id}", summary["duplicate_producer_count"] == 0),
                    _check(f"degraded_reroute_no_degraded_worker_selected:{case_id}", summary["degraded_worker_new_proofs"] == 0),
                    _check(f"degraded_reroute_no_worker_infra_green:{case_id}", summary["worker_infra_green_count"] == 0),
                    _check(f"degraded_reroute_no_product_retry:{case_id}", summary["product_failure_retry_count"] == 0),
                    _check(f"degraded_reroute_budget_stop:{case_id}", summary["retry_after_exhausted_count"] == 0),
                    _check(f"degraded_reroute_output_bounded:{case_id}", summary["event_count"] <= case["bounded_event_count_max"]),
                    _check(
                        f"degraded_reroute_byte_stable:{case_id}",
                        json.dumps(summary, sort_keys=True) == json.dumps(degraded_reroute_stress_summary(copy.deepcopy(case)), sort_keys=True),
                    ),
                ]
            )

    invalid_cases = stress.get("invalid_degraded_reroute_cases", [])
    checks.append(_check("invalid_degraded_reroute_cases_present", isinstance(invalid_cases, list) and len(invalid_cases) >= 5))
    for case in invalid_cases if isinstance(invalid_cases, list) else []:
        case_id = case.get("case_id", "<unnamed>") if isinstance(case, dict) else "<bad>"
        expected_errors = case.get("expected_errors", []) if isinstance(case, dict) else []
        errors = validate_degraded_reroute_stress_case(case)
        checks.append(
            _check(
                f"invalid_degraded_reroute_case:{case_id}",
                isinstance(expected_errors, list) and all(error in errors for error in expected_errors),
                ",".join(errors),
            )
        )
    return checks


def run_all() -> dict[str, Any]:
    configure_test_logging("validation_swarm_scheduler_contract")
    checks = _check_files()
    checks.extend(_check_spec())
    try:
        schema = _load_json(SCHEMA_FILE)
        fixtures = _load_json(FIXTURES_FILE)
        stress = _load_json(STRESS_MATRIX_FILE)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        checks.append(_check("contract_files_parse", False, str(exc)))
        schema = None
        fixtures = None
        stress = None
    checks.extend(_check_schema(schema))
    checks.extend(_check_fixtures(fixtures))
    checks.extend(_check_stress_matrix(stress))
    passed = sum(1 for check in checks if check["passed"])
    total = len(checks)
    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "schema_version": SCHEMA_CATALOG_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verdict": "PASS" if passed == total else "FAIL",
        "passed": passed,
        "failed": total - passed,
        "total": total,
        "checks": checks,
    }


def run_self_test() -> dict[str, Any]:
    contract_result = run_all()
    fixtures = _load_json(FIXTURES_FILE)
    validation_time = _parse_rfc3339(fixtures["validation_time"])
    bad_input = copy.deepcopy(fixtures["base_input"])
    bad_input["proof_work_key"]["hex"] = "0" * 64
    bad_decision = copy.deepcopy(fixtures["decision_examples"][0])
    bad_decision["required_action"] = "wait_for_capacity"
    worker_green = copy.deepcopy(fixtures["decision_examples"][0])
    worker_green["green_proof_eligible"] = True
    worker_green["diagnostics"]["proof_debt_class"] = "worker_infra"
    checks = [
        _check("contract_run_all_passes", contract_result["verdict"] == "PASS"),
        _check("self_bad_input_rejected", "ERR_VSS_BAD_WORK_KEY" in validate_input(bad_input)),
        _check("self_bad_decision_rejected", "ERR_VSS_MALFORMED_DECISION" in validate_decision(bad_decision, now=validation_time)),
        _check("self_worker_infra_green_rejected", "ERR_VSS_WORKER_INFRA_GREEN" in validate_decision(worker_green, now=validation_time)),
    ]
    passed = sum(1 for check in checks if check["passed"])
    total = len(checks)
    return {
        "bead_id": BEAD_ID,
        "title": f"{TITLE} self-test",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verdict": "PASS" if passed == total else "FAIL",
        "passed": passed,
        "failed": total - passed,
        "total": total,
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
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
