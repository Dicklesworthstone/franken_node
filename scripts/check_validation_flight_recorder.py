#!/usr/bin/env python3
"""Validation flight recorder contract checker for bd-2zn9k.

Usage:
    python3 scripts/check_validation_flight_recorder.py
    python3 scripts/check_validation_flight_recorder.py --json
    python3 scripts/check_validation_flight_recorder.py --self-test
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

BEAD_ID = "bd-2zn9k"
TITLE = "Validation flight recorder contract checker"
ATTEMPT_SCHEMA_VERSION = "franken-node/validation-flight-recorder/attempt/v1"
OBSERVATION_SCHEMA_VERSION = "franken-node/validation-flight-recorder/observation/v1"
RECOVERY_SCHEMA_VERSION = "franken-node/validation-flight-recorder/recovery/v1"
FIXTURE_SCHEMA_VERSION = "franken-node/validation-flight-recorder/fixtures/v1"
EXPLANATION_BUNDLE_SCHEMA_VERSION = "franken-node/validation-proof-explanation-bundle/v1"
MAX_OBSERVATIONS = 256
MAX_SNIPPET_BYTES = 4096
MAX_EXPLANATION_MARKDOWN_BYTES = 2048
REDACTED_ENV_VALUE = "<redacted>"

SPEC_FILE = ROOT / "docs/specs/validation_flight_recorder.md"
FIXTURES_FILE = (
    ROOT
    / "artifacts/validation_broker/bd-2zn9k/validation_flight_recorder_fixtures.v1.json"
)
SCRIPT_FILE = ROOT / "scripts/check_validation_flight_recorder.py"
TEST_FILE = ROOT / "tests/test_check_validation_flight_recorder.py"

ERR_INVALID_SCHEMA_VERSION = "ERR_VFR_INVALID_SCHEMA_VERSION"
ERR_MALFORMED_ATTEMPT = "ERR_VFR_MALFORMED_ATTEMPT"
ERR_BEAD_MISMATCH = "ERR_VFR_BEAD_MISMATCH"
ERR_MISSING_COMMAND_DIGEST = "ERR_VFR_MISSING_COMMAND_DIGEST"
ERR_STALE_ATTEMPT = "ERR_VFR_STALE_ATTEMPT"
ERR_INVALID_OBSERVATION_ORDER = "ERR_VFR_INVALID_OBSERVATION_ORDER"
ERR_INVALID_ARTIFACT_PATH = "ERR_VFR_INVALID_ARTIFACT_PATH"
ERR_UNBOUNDED_SNIPPET = "ERR_VFR_UNBOUNDED_SNIPPET"
ERR_UNREDACTED_ENVIRONMENT = "ERR_VFR_UNREDACTED_ENVIRONMENT"
ERR_INVALID_RECOVERY_DECISION = "ERR_VFR_INVALID_RECOVERY_DECISION"
ERR_INVALID_TIMEOUT_CLASS = "ERR_VFR_INVALID_TIMEOUT_CLASS"

REQUIRED_SPEC_MARKERS = [
    ATTEMPT_SCHEMA_VERSION,
    OBSERVATION_SCHEMA_VERSION,
    RECOVERY_SCHEMA_VERSION,
    "artifacts/validation_broker/<bead-id>/flight-recorder/",
    "fresh-heartbeat/no-output ambiguity",
    "Worker Reliability Ledger",
    "Proof Debt SLO",
    "Proof Lane Reroute Policy",
    "Validation Proof Explanation Bundle",
    EXPLANATION_BUNDLE_SCHEMA_VERSION,
    "python3 scripts/check_validation_flight_recorder.py --json",
    "tests/test_check_validation_flight_recorder.py",
    "ValidationFlightRecorderAttempt",
    "ValidationFlightRecorderRecovery",
    "command digest is missing",
    "artifact paths are empty",
    "Required Fixture Matrix",
    "Doctor and Closeout",
]

ATTEMPT_REQUIRED_FIELDS = [
    "schema_version",
    "attempt_id",
    "trace_id",
    "bead_id",
    "thread_id",
    "request_id",
    "queue_id",
    "coalescer_lease_id",
    "proof_cache_key_hex",
    "created_at",
    "started_at",
    "finished_at",
    "freshness_expires_at",
    "command",
    "environment",
    "target_dir",
    "input_digests",
    "observations",
    "adapter_outcome",
    "exit",
    "artifacts",
    "recovery_ref",
    "trust",
]

COMMAND_REQUIRED_FIELDS = [
    "program",
    "argv",
    "cwd",
    "command_digest",
    "environment_policy_id",
    "target_dir_policy_id",
]

RECOVERY_REQUIRED_FIELDS = [
    "schema_version",
    "decision_id",
    "attempt_id",
    "bead_id",
    "thread_id",
    "decided_at",
    "input_digest",
    "decision",
    "reason_code",
    "event_code",
    "required_action",
    "fail_closed",
    "retryable",
    "freshness_expires_at",
    "operator_message",
    "diagnostics",
]

TIMEOUT_CLASSES = {
    "none",
    "queue_wait",
    "rch_dispatch",
    "ssh_command",
    "cargo_test_timeout",
    "process_idle",
    "process_wall",
    "worker_unreachable",
    "unknown",
}

ERROR_CLASSES = {
    "none",
    "compile_error",
    "test_failure",
    "clippy_warning",
    "format_failure",
    "transport_timeout",
    "worker_infra",
    "environment_contention",
    "disk_pressure",
    "source_only",
    "unknown",
}

TARGET_DIR_CLASSES = {
    "off_repo",
    "repo_local_guarded",
    "repo_local_writable",
    "unwritable",
    "missing",
    "unknown",
}

OBSERVATION_PHASES = {
    "request_enqueued",
    "lease_acquired",
    "capacity_observed",
    "dispatch_started",
    "worker_selected",
    "progress_observed",
    "progress_stale",
    "attempt_cancelled",
    "adapter_classified",
    "receipt_emitted",
    "recovery_planned",
}

RCH_MODES = {"remote", "local_fallback", "not_used", "unavailable", "unknown"}
QUEUE_STATES = {"queued", "leased", "running", "completed", "failed", "cancelled"}

ADAPTER_OUTCOMES = {
    "passed",
    "command_failed",
    "compile_failed",
    "test_failed",
    "worker_timeout",
    "worker_missing_toolchain",
    "worker_filesystem_error",
    "local_fallback_refused",
    "contention_deferred",
    "broker_internal_error",
}

EXIT_KINDS = {"success", "failure", "timeout", "worker_infra", "deferred"}
SOURCE_ONLY_REASONS = {
    "cargo_contention",
    "rch_unavailable",
    "sibling_dependency_blocker",
    "disk_pressure",
    "reserved_surface",
    "no_cargo_requested",
    "docs_only",
}

EVENT_CODES = {
    "VFR-001",
    "VFR-002",
    "VFR-003",
    "VFR-004",
    "VFR-005",
    "VFR-006",
    "VFR-007",
    "VFR-008",
    "VFR-009",
    "VFR-010",
    "VFR-011",
    "VFR-012",
}

REASON_EVENT_PAIRS = {
    "VFR_SUCCESS_REMOTE": "VFR-001",
    "VFR_RETRY_SSH_TIMEOUT": "VFR-002",
    "VFR_RETRY_MISSING_TOOLCHAIN": "VFR-003",
    "VFR_RETRY_WORKER_FS": "VFR-004",
    "VFR_QUEUE_CONTENTION": "VFR-005",
    "VFR_REJECT_LOCAL_FALLBACK": "VFR-006",
    "VFR_SOURCE_ONLY_ALLOWED": "VFR-007",
    "VFR_PRODUCT_FAILURE": "VFR-008",
    "VFR_STALE_PROGRESS": "VFR-009",
    "VFR_STALE_LEASE_FENCE": "VFR-010",
    "VFR_REUSE_RECEIPT": "VFR-011",
    "VFR_INVALID_ARTIFACT": "VFR-012",
}

DECISION_ACTIONS = {
    "accept_success": {"use_receipt", "none"},
    "retry_remote_same_worker": {"retry_rch", "retry_remote"},
    "retry_remote_different_worker": {"retry_rch_different_worker", "retry_remote"},
    "queue_until_capacity": {"wait_for_capacity"},
    "drain_worker_then_retry": {"drain_worker"},
    "wait_for_existing_proof": {"wait_for_proof", "wait_for_existing_proof"},
    "retry_with_new_fence": {"fence_stale_lease", "refresh_lease_fence"},
    "reuse_receipt": {"reuse_receipt"},
    "use_source_only_blocker": {"record_source_only", "record_source_only_blocker"},
    "fail_closed_product": {"fix_product_failure", "surface_product_failure"},
    "fail_closed_invalid": {"repair_artifact_or_contract", "reject_artifact"},
}

RETRYABLE_DECISIONS = {
    "retry_remote_same_worker",
    "retry_remote_different_worker",
    "queue_until_capacity",
    "drain_worker_then_retry",
    "wait_for_existing_proof",
    "retry_with_new_fence",
}

FAIL_CLOSED_DECISIONS = {
    "use_source_only_blocker",
    "fail_closed_product",
    "fail_closed_invalid",
}

STALE_PROGRESS_STATES = {
    "fresh_heartbeat_no_output",
    "stale_heartbeat_no_output",
    "progress_stale_timeout",
}

AMBIGUITY_NEXT_ACTIONS = {
    "wait_until_budget",
    "reroute_after_budget",
    "record_blocker",
}

WORKER_RELIABILITY_CLASSES = {"healthy", "degraded", "drain", "blocked", "unknown"}
WORKER_RELIABILITY_ACTIONS = {
    "allow_worker",
    "retry_different_worker",
    "drain_worker",
    "reject_worker",
}

PROOF_DEBT_SLO_CLASSES = {
    "fresh_green",
    "stale_proof",
    "worker_infra",
    "product_failure",
    "source_only",
    "waiting_for_capacity",
    "stale_lease",
    "missing_proof",
}

PROOF_DEBT_SLO_ACTIONS = {
    "use_reusable_proof",
    "refresh_stale_proof",
    "retry_different_worker",
    "retry_priority_lane",
    "wait_for_capacity",
    "record_blocker",
    "record_source_only_blocker",
    "fail_closed_product",
    "refresh_lease_fence",
}

PROOF_LANE_REROUTE_ACTIONS = {
    "retry_same_worker",
    "select_alternate_worker",
    "drain_worker_then_retry",
    "wait_for_capacity",
    "join_existing_proof",
    "refresh_lease_fence",
    "record_source_only_blocker",
    "fail_closed_product",
    "reject_local_fallback",
    "reuse_fresh_proof",
    "record_blocker",
}

PROOF_LANE_REROUTE_REASONS = {
    "healthy_worker_retry",
    "degraded_worker_reroute",
    "drain_worker",
    "waiting_for_capacity",
    "cargo_contention",
    "join_existing_proof",
    "stale_lease_fence",
    "source_only_blocker",
    "product_failure",
    "remote_required_local_fallback",
    "fresh_proof_reuse",
    "no_eligible_worker",
    "invalid_reroute_input",
}

PROOF_LANE_REROUTE_COALESCER_STATES = {"none", "open", "fresh_joinable", "stale_lease"}
PROOF_LANE_REROUTE_CACHE_STATES = {"miss", "fresh_hit", "stale_hit"}
EXPLANATION_BUNDLE_STATUSES = {"complete", "blocked", "deferred", "failed", "invalid"}
EXPLANATION_BUNDLE_MAIL_HEALTH = {"green", "yellow", "red", "unavailable"}
EXPLANATION_BUNDLE_FAILURE_CLASSES = {"none", "worker_infra", "product_failure", "source_only", "unknown"}
EXPLANATION_BUNDLE_FIELD_ERRORS = {
    "invalid_input",
    "missing_artifact",
    "unsafe_artifact_path",
    "bead_mismatch",
    "command_digest_mismatch",
    "malformed_command_digest",
    "stale_receipt",
    "product_failure_hidden_as_infra",
    "worker_infra_marked_green",
    "raw_output_snippet_present",
}
EXPLANATION_BUNDLE_TIMELINE_PHASES = {
    "bead",
    "scheduler",
    "coalescer",
    "proof_cache",
    "worker_selection",
    "reroute_policy",
    "proof_debt_slo",
    "final_recommendation",
}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
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
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


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


def _repo_relative_path_valid(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\0" in value:
        return False
    if value.startswith("/") or value.startswith("\\"):
        return False
    parts = value.replace("\\", "/").split("/")
    return ".." not in parts and all(part != "" for part in parts)


def _bounded(value: Any) -> bool:
    return isinstance(value, str) and "\0" not in value and len(value.encode("utf-8")) <= MAX_SNIPPET_BYTES


def _digest_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and hmac.compare_digest(str(value.get("algorithm")), "sha256")
        and _is_sha256_hex(value.get("hex"))
    )


def _get_path(payload: Any, dotted_path: str) -> Any:
    current = payload
    for part in dotted_path.split("."):
        if isinstance(current, list):
            if not part.isdigit():
                return None
            index = int(part)
            if index >= len(current):
                return None
            current = current[index]
        elif isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        else:
            return None
    return current


def _set_path(payload: Any, dotted_path: str, value: Any) -> None:
    current = payload
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current.setdefault(part, {})
    last = parts[-1]
    if isinstance(current, list):
        current[int(last)] = value
    else:
        current[last] = value


def _remove_path(payload: Any, dotted_path: str) -> None:
    current = payload
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        if isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                return
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return
    if isinstance(current, dict):
        current.pop(parts[-1], None)
    elif isinstance(current, list) and parts[-1].isdigit():
        index = int(parts[-1])
        if index < len(current):
            current.pop(index)


def _expand_patch_value(value: Any) -> Any:
    if (
        isinstance(value, dict)
        and set(value) == {"repeat", "count"}
        and isinstance(value.get("repeat"), str)
        and isinstance(value.get("count"), int)
    ):
        return value["repeat"] * value["count"]
    return value


def apply_fixture_patch(base: Any, patch: dict[str, Any] | None) -> Any:
    patched = copy.deepcopy(base)
    if not patch:
        return patched
    for dotted_path in patch.get("remove", []):
        _remove_path(patched, str(dotted_path))
    for dotted_path, value in patch.get("set", {}).items():
        _set_path(patched, str(dotted_path), _expand_patch_value(value))
    return patched


def command_canonical_material(command: dict[str, Any]) -> str:
    argv = command.get("argv")
    argv_material = " ".join(argv) if isinstance(argv, list) else ""
    return (
        f"program={command.get('program', '')}\0"
        f"argv={argv_material}\0"
        f"cwd={command.get('cwd', '')}\0"
        f"env_policy={command.get('environment_policy_id', '')}\0"
        f"target_dir_policy={command.get('target_dir_policy_id', '')}"
    )


def validate_command(command: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(command, dict):
        return [ERR_MISSING_COMMAND_DIGEST]
    if any(field not in command for field in COMMAND_REQUIRED_FIELDS):
        errors.append(ERR_MISSING_COMMAND_DIGEST)
    if not isinstance(command.get("program"), str) or not command.get("program"):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if not isinstance(command.get("argv"), list) or not all(isinstance(arg, str) for arg in command.get("argv", [])):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if not isinstance(command.get("cwd"), str) or not command.get("cwd"):
        errors.append(ERR_MALFORMED_ATTEMPT)

    digest = command.get("command_digest")
    if not isinstance(digest, dict):
        errors.append(ERR_MISSING_COMMAND_DIGEST)
        return sorted(set(errors))
    material = command_canonical_material(command)
    computed = hashlib.sha256(material.encode("utf-8")).hexdigest()
    digest_ok = (
        hmac.compare_digest(str(digest.get("algorithm")), "sha256")
        and isinstance(digest.get("canonical_material"), str)
        and hmac.compare_digest(digest["canonical_material"], material)
        and _is_sha256_hex(digest.get("hex"))
        and hmac.compare_digest(str(digest.get("hex")), computed)
    )
    if not digest_ok:
        errors.append(ERR_MISSING_COMMAND_DIGEST)
    return sorted(set(errors))


def validate_environment(environment: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(environment, dict):
        return [ERR_MALFORMED_ATTEMPT]
    allowed = environment.get("allowed_env")
    redacted = environment.get("redacted_env")
    captured = environment.get("captured_env", {})
    if not isinstance(allowed, list) or not isinstance(redacted, list) or not isinstance(captured, dict):
        return [ERR_MALFORMED_ATTEMPT]
    allowed_set = {value for value in allowed if isinstance(value, str)}
    redacted_set = {value for value in redacted if isinstance(value, str)}
    for key, value in captured.items():
        if not isinstance(key, str) or not isinstance(value, str):
            errors.append(ERR_UNREDACTED_ENVIRONMENT)
        elif key not in allowed_set and key not in redacted_set:
            errors.append(ERR_UNREDACTED_ENVIRONMENT)
        elif key in redacted_set and not hmac.compare_digest(value, REDACTED_ENV_VALUE):
            errors.append(ERR_UNREDACTED_ENVIRONMENT)
    return sorted(set(errors))


def validate_target_dir(target_dir: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(target_dir, dict):
        return [ERR_MALFORMED_ATTEMPT]
    class_name = target_dir.get("class")
    if class_name not in TARGET_DIR_CLASSES:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if class_name in {"off_repo", "repo_local_guarded", "repo_local_writable", "unwritable"}:
        if not isinstance(target_dir.get("path"), str) or not target_dir["path"]:
            errors.append(ERR_MALFORMED_ATTEMPT)
    guarded_placeholder = target_dir.get("guarded_placeholder")
    if isinstance(guarded_placeholder, bool) and guarded_placeholder and class_name != "repo_local_guarded":
        errors.append(ERR_MALFORMED_ATTEMPT)
    for field in ("path_digest", "sync_root_digest"):
        value = target_dir.get(field)
        if value is not None and not _digest_valid(value):
            errors.append(ERR_MALFORMED_ATTEMPT)
    if not _bounded(target_dir.get("diagnostic")):
        errors.append(ERR_UNBOUNDED_SNIPPET)
    return sorted(set(errors))


def validate_observation(observation: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(observation, dict):
        return [ERR_MALFORMED_ATTEMPT]
    if observation.get("schema_version") != OBSERVATION_SCHEMA_VERSION:
        errors.append(ERR_INVALID_SCHEMA_VERSION)
    if not observation.get("observation_id"):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if _parse_rfc3339(observation.get("observed_at")) is None:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if observation.get("phase") not in OBSERVATION_PHASES:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if observation.get("event_code") not in EVENT_CODES:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if observation.get("rch_mode") not in RCH_MODES:
        errors.append(ERR_MALFORMED_ATTEMPT)
    queue_state = observation.get("queue_state")
    if queue_state is not None and queue_state not in QUEUE_STATES:
        errors.append(ERR_MALFORMED_ATTEMPT)
    worker_id = observation.get("worker_id")
    if worker_id is not None and (not isinstance(worker_id, str) or not worker_id):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if not _bounded(observation.get("message")):
        errors.append(ERR_UNBOUNDED_SNIPPET)
    details = observation.get("details")
    if not isinstance(details, dict):
        errors.append(ERR_MALFORMED_ATTEMPT)
    else:
        for key, value in details.items():
            if not isinstance(key, str) or not key or not _bounded(value):
                errors.append(ERR_UNBOUNDED_SNIPPET)
    return sorted(set(errors))


def validate_observations(observations: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(observations, list) or not observations or len(observations) > MAX_OBSERVATIONS:
        return [ERR_INVALID_OBSERVATION_ORDER]
    previous_key: tuple[datetime, str] | None = None
    for observation in observations:
        errors.extend(validate_observation(observation))
        observed_at = _parse_rfc3339(observation.get("observed_at")) if isinstance(observation, dict) else None
        observation_id = observation.get("observation_id") if isinstance(observation, dict) else None
        if observed_at is not None and isinstance(observation_id, str):
            key = (observed_at, observation_id)
            if previous_key is not None and key < previous_key:
                errors.append(ERR_INVALID_OBSERVATION_ORDER)
            previous_key = key
    return sorted(set(errors))


def validate_adapter_outcome(adapter_outcome: Any) -> list[str]:
    errors: list[str] = []
    if adapter_outcome is None:
        return []
    if not isinstance(adapter_outcome, dict):
        return [ERR_MALFORMED_ATTEMPT]
    outcome = adapter_outcome.get("outcome")
    if outcome not in ADAPTER_OUTCOMES:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if adapter_outcome.get("execution_mode") not in RCH_MODES:
        errors.append(ERR_MALFORMED_ATTEMPT)
    timeout_class = adapter_outcome.get("timeout_class")
    if timeout_class not in TIMEOUT_CLASSES:
        errors.append(ERR_INVALID_TIMEOUT_CLASS)
    if not isinstance(adapter_outcome.get("retryable"), bool) or not isinstance(adapter_outcome.get("product_failure"), bool):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if not _bounded(adapter_outcome.get("detail")):
        errors.append(ERR_UNBOUNDED_SNIPPET)

    retryable = adapter_outcome.get("retryable")
    product_failure = adapter_outcome.get("product_failure")
    if outcome == "passed" and (
        adapter_outcome.get("execution_mode") != "remote"
        or timeout_class != "none"
        or retryable
        or product_failure
    ):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if outcome in {"command_failed", "compile_failed", "test_failed"} and (
        retryable or not product_failure
    ):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if outcome == "worker_timeout" and (
        timeout_class == "none" or product_failure or not retryable
    ):
        errors.append(ERR_INVALID_TIMEOUT_CLASS)
    if outcome in {
        "worker_missing_toolchain",
        "worker_filesystem_error",
        "local_fallback_refused",
        "contention_deferred",
    } and (product_failure or not retryable):
        errors.append(ERR_MALFORMED_ATTEMPT)
    return sorted(set(errors))


def validate_exit(exit_info: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(exit_info, dict):
        return [ERR_MALFORMED_ATTEMPT]
    kind = exit_info.get("kind")
    timeout_class = exit_info.get("timeout_class")
    error_class = exit_info.get("error_class")
    retryable = exit_info.get("retryable")
    product_failure = exit_info.get("product_failure")
    if kind not in EXIT_KINDS:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if timeout_class not in TIMEOUT_CLASSES:
        errors.append(ERR_INVALID_TIMEOUT_CLASS)
    if error_class not in ERROR_CLASSES:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if not isinstance(retryable, bool) or not isinstance(product_failure, bool):
        errors.append(ERR_MALFORMED_ATTEMPT)

    if kind == "success" and (
        timeout_class != "none" or error_class != "none" or retryable or product_failure
    ):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if kind == "timeout" and (
        timeout_class == "none" or error_class != "transport_timeout" or not retryable or product_failure
    ):
        errors.append(ERR_INVALID_TIMEOUT_CLASS)
    if kind == "worker_infra" and (
        error_class in {"none", "source_only"} or product_failure or not retryable
    ):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if kind == "deferred" and error_class == "source_only":
        if exit_info.get("source_only_reason") not in SOURCE_ONLY_REASONS:
            errors.append(ERR_INVALID_RECOVERY_DECISION)
    elif kind == "deferred" and (
        error_class != "environment_contention" or product_failure or not retryable
    ):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if kind == "failure" and (retryable or error_class == "none"):
        errors.append(ERR_MALFORMED_ATTEMPT)
    if error_class in {"compile_error", "test_failure", "clippy_warning", "format_failure"} and not product_failure:
        errors.append(ERR_MALFORMED_ATTEMPT)
    return sorted(set(errors))


def stale_progress_observations(attempt: Any) -> list[dict[str, Any]]:
    if not isinstance(attempt, dict):
        return []
    observations = attempt.get("observations")
    if not isinstance(observations, list):
        return []
    return [
        observation
        for observation in observations
        if isinstance(observation, dict)
        and observation.get("phase") == "progress_stale"
        and observation.get("event_code") == "VFR-009"
    ]


def validate_stale_progress_evidence(
    attempt: Any,
    recovery: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    observations = stale_progress_observations(attempt)
    if not observations:
        return errors

    saw_fresh_heartbeat_ambiguity = False
    for observation in observations:
        details = observation.get("details")
        if not isinstance(details, dict):
            errors.append(ERR_MALFORMED_ATTEMPT)
            continue
        state = details.get("stale_progress_state")
        if state not in STALE_PROGRESS_STATES:
            errors.append(ERR_MALFORMED_ATTEMPT)
            continue
        for field in (
            "heartbeat_fresh",
            "progress_age_seconds",
            "last_phase",
            "stale_detector_progress_stale",
            "recommended_action",
        ):
            if not _bounded(details.get(field)) or not details.get(field):
                errors.append(ERR_MALFORMED_ATTEMPT)
        if details.get("stale_detector_progress_stale") != "true":
            errors.append(ERR_MALFORMED_ATTEMPT)
        if details.get("recommended_action") not in AMBIGUITY_NEXT_ACTIONS:
            errors.append(ERR_INVALID_RECOVERY_DECISION)
        if state == "fresh_heartbeat_no_output":
            saw_fresh_heartbeat_ambiguity = True
            if details.get("heartbeat_fresh") != "true":
                errors.append(ERR_MALFORMED_ATTEMPT)
        elif details.get("heartbeat_fresh") != "false":
            errors.append(ERR_MALFORMED_ATTEMPT)

    if not saw_fresh_heartbeat_ambiguity:
        return sorted(set(errors))

    adapter_outcome = attempt.get("adapter_outcome") if isinstance(attempt, dict) else None
    exit_info = attempt.get("exit") if isinstance(attempt, dict) else None
    if not isinstance(adapter_outcome, dict) or (
        adapter_outcome.get("outcome") != "worker_timeout"
        or adapter_outcome.get("timeout_class") != "process_idle"
        or adapter_outcome.get("product_failure")
        or not adapter_outcome.get("retryable")
    ):
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    if not isinstance(exit_info, dict) or (
        exit_info.get("kind") != "timeout"
        or exit_info.get("timeout_class") != "process_idle"
        or exit_info.get("error_class") != "transport_timeout"
        or exit_info.get("product_failure")
        or not exit_info.get("retryable")
    ):
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    if recovery is not None and (
        recovery.get("decision") == "accept_success"
        or recovery.get("required_action") in {"none", "use_receipt"}
        or recovery.get("reason_code") != "VFR_STALE_PROGRESS"
        or recovery.get("event_code") != "VFR-009"
    ):
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    return sorted(set(errors))


def _first_stale_progress_state(attempt: dict[str, Any]) -> str | None:
    for observation in stale_progress_observations(attempt):
        details = observation.get("details")
        if isinstance(details, dict) and isinstance(details.get("stale_progress_state"), str):
            return details["stale_progress_state"]
    return None


def _attempt_worker_id(attempt: dict[str, Any]) -> str | None:
    adapter_outcome = attempt.get("adapter_outcome")
    if isinstance(adapter_outcome, dict) and isinstance(adapter_outcome.get("worker_id"), str):
        return adapter_outcome["worker_id"]
    observations = attempt.get("observations")
    if isinstance(observations, list):
        for observation in observations:
            if isinstance(observation, dict) and isinstance(observation.get("worker_id"), str):
                return observation["worker_id"]
    return None


def _score_to_class(score: int, reasons: set[str]) -> str:
    if not reasons and score == 100:
        return "healthy"
    if "local_fallback_refused" in reasons:
        return "blocked"
    if "worker_filesystem_error" in reasons or "repeated_stale_progress" in reasons or score < 50:
        return "drain"
    if score < 85:
        return "degraded"
    return "healthy"


def _next_action_for_class(worker_class: str, reasons: set[str]) -> str:
    if worker_class == "healthy":
        return "allow_worker"
    if worker_class == "blocked":
        return "reject_worker"
    if worker_class == "drain" or "worker_filesystem_error" in reasons:
        return "drain_worker"
    return "retry_different_worker"


def worker_reliability_ledger(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for attempt in attempts:
        worker_id = _attempt_worker_id(attempt)
        if worker_id:
            grouped.setdefault(worker_id, []).append(attempt)

    rows: list[dict[str, Any]] = []
    for worker_id in sorted(grouped):
        score = 100
        reasons: set[str] = set()
        successes = 0
        infra_failures = 0
        product_failures = 0
        stale_progress_count = 0
        confidence = "high"
        contributing_attempt_ids: list[str] = []

        for attempt in grouped[worker_id]:
            attempt_id = attempt.get("attempt_id")
            if isinstance(attempt_id, str):
                contributing_attempt_ids.append(attempt_id)
            adapter_outcome = attempt.get("adapter_outcome")
            exit_info = attempt.get("exit")
            outcome = adapter_outcome.get("outcome") if isinstance(adapter_outcome, dict) else None
            product_failure = bool(
                isinstance(exit_info, dict)
                and exit_info.get("product_failure")
                or isinstance(adapter_outcome, dict)
                and adapter_outcome.get("product_failure")
            )
            if product_failure:
                product_failures += 1
                reasons.add("product_failure_excluded")
                continue
            if outcome == "passed":
                successes += 1
                continue
            if outcome == "worker_filesystem_error":
                score -= 70
                infra_failures += 1
                reasons.add("worker_filesystem_error")
            elif outcome == "worker_missing_toolchain":
                score -= 45
                infra_failures += 1
                reasons.add("worker_missing_toolchain")
            elif outcome == "local_fallback_refused":
                score = 0
                infra_failures += 1
                reasons.add("local_fallback_refused")
            elif outcome == "worker_timeout":
                infra_failures += 1
                state = _first_stale_progress_state(attempt)
                if state == "fresh_heartbeat_no_output":
                    score -= 45
                    stale_progress_count += 1
                    confidence = "medium"
                    reasons.add("fresh_heartbeat_no_output")
                elif state == "stale_heartbeat_no_output":
                    score -= 65
                    stale_progress_count += 1
                    reasons.add("stale_heartbeat_no_output")
                else:
                    score -= 50
                    reasons.add("worker_timeout")
            elif outcome == "contention_deferred":
                score -= 10
                confidence = "medium"
                reasons.add("contention_deferred")

        if stale_progress_count > 1:
            score -= 20
            reasons.add("repeated_stale_progress")

        score = max(0, min(100, score))
        worker_class = _score_to_class(score, reasons - {"product_failure_excluded"})
        rows.append(
            {
                "worker_id": worker_id,
                "score": score,
                "class": worker_class,
                "sample_count": len(grouped[worker_id]),
                "success_count": successes,
                "infra_failure_count": infra_failures,
                "product_failure_count": product_failures,
                "confidence": confidence,
                "drain_hint": worker_class == "drain",
                "cooldown_hint": "none" if worker_class == "healthy" else "bounded_retry_budget",
                "next_action": _next_action_for_class(worker_class, reasons),
                "reasons": sorted(reasons),
                "contributing_attempt_ids": sorted(contributing_attempt_ids),
            }
        )
    return rows


def _bounded_int(value: Any, *, minimum: int = 0, maximum: int = 1_000_000) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < minimum or value > maximum:
        return None
    return value


def _proof_debt_retry_after_ms(bead_priority: int, command_class: str, aged: bool) -> int:
    if bead_priority <= 1:
        return 10_000
    if aged:
        return 45_000
    if command_class == "broad_validation":
        return 180_000
    if bead_priority >= 4:
        return 240_000
    return 60_000


def proof_debt_slo_decision(input_data: dict[str, Any]) -> dict[str, Any]:
    bead_priority = _bounded_int(input_data.get("bead_priority"), maximum=4)
    retry_count = _bounded_int(input_data.get("retry_count"))
    retry_budget = _bounded_int(input_data.get("retry_budget"), minimum=1, maximum=64)
    worker_diversity_count = _bounded_int(input_data.get("worker_diversity_count"))
    worker_diversity_budget = _bounded_int(
        input_data.get("worker_diversity_budget"),
        minimum=1,
        maximum=64,
    )
    queue_depth = _bounded_int(input_data.get("queue_depth"))
    max_queue_depth = _bounded_int(input_data.get("max_queue_depth"), minimum=1)
    active_cargo_processes = _bounded_int(input_data.get("active_cargo_processes"))
    max_cargo_processes = _bounded_int(input_data.get("max_cargo_processes"), minimum=1)
    healthy_workers = _bounded_int(input_data.get("healthy_workers"))
    oldest_queued_age_seconds = _bounded_int(input_data.get("oldest_queued_age_seconds"))
    stale_lease_age_seconds = _bounded_int(input_data.get("stale_lease_age_seconds"))
    stale_lease_after_seconds = _bounded_int(input_data.get("stale_lease_after_seconds"), minimum=1)
    debt_class = input_data.get("debt_class")
    freshness = input_data.get("proof_freshness")
    command_class = input_data.get("command_class")

    invalid = (
        bead_priority is None
        or retry_count is None
        or retry_budget is None
        or worker_diversity_count is None
        or worker_diversity_budget is None
        or queue_depth is None
        or max_queue_depth is None
        or active_cargo_processes is None
        or max_cargo_processes is None
        or healthy_workers is None
        or oldest_queued_age_seconds is None
        or stale_lease_age_seconds is None
        or stale_lease_after_seconds is None
        or debt_class not in PROOF_DEBT_SLO_CLASSES
        or freshness not in {"fresh", "stale", "missing"}
        or command_class not in {"focused_validation", "broad_validation", "source_only_gate"}
    )
    if invalid:
        return {
            "debt_class": "invalid",
            "budget_remaining": 0,
            "worker_diversity_remaining": 0,
            "next_action": "record_blocker",
            "retry_after_ms": None,
            "cooldown_hint": "none",
            "escalation_reason": "invalid_slo_input",
            "complete": False,
            "br_comment_warranted": True,
            "operator_summary": "record_blocker: invalid proof-debt SLO input",
        }

    budget_remaining = max(0, retry_budget - retry_count)
    worker_diversity_remaining = max(0, worker_diversity_budget - worker_diversity_count)
    aged = oldest_queued_age_seconds >= 3_600
    saturated_queue = queue_depth >= max_queue_depth
    cargo_saturated = active_cargo_processes >= max_cargo_processes
    no_healthy_workers = healthy_workers == 0
    stale_lease = stale_lease_age_seconds >= stale_lease_after_seconds
    retry_after_ms = _proof_debt_retry_after_ms(bead_priority, command_class, aged)
    escalation_reason = "within_budget"
    next_action = "retry_different_worker"
    complete = False
    br_comment_warranted = False

    if debt_class == "fresh_green" and freshness == "fresh":
        next_action = "use_reusable_proof"
        retry_after_ms = None
        complete = True
        escalation_reason = "fresh_green_proof"
    elif debt_class == "product_failure":
        next_action = "fail_closed_product"
        retry_after_ms = None
        escalation_reason = "product_failure"
        br_comment_warranted = True
    elif debt_class == "source_only":
        next_action = "record_source_only_blocker"
        retry_after_ms = None
        escalation_reason = "source_only_not_green"
        br_comment_warranted = True
    elif debt_class == "stale_lease" or stale_lease:
        next_action = "refresh_lease_fence"
        escalation_reason = "stale_lease_fence_required"
        br_comment_warranted = True
    elif freshness == "stale" or debt_class == "stale_proof":
        next_action = "refresh_stale_proof"
        escalation_reason = "proof_freshness_expired"
    elif no_healthy_workers:
        next_action = "record_blocker"
        retry_after_ms = None
        escalation_reason = "no_healthy_workers"
        br_comment_warranted = True
    elif saturated_queue or cargo_saturated or debt_class == "waiting_for_capacity":
        if bead_priority <= 1 and budget_remaining > 0 and not no_healthy_workers:
            next_action = "retry_priority_lane"
            escalation_reason = "priority_preemption"
        else:
            next_action = "wait_for_capacity"
            escalation_reason = "capacity_saturated"
            br_comment_warranted = saturated_queue and cargo_saturated
    elif debt_class in {"worker_infra", "missing_proof"}:
        if budget_remaining == 0 or worker_diversity_remaining == 0:
            next_action = "record_blocker"
            retry_after_ms = None
            escalation_reason = "retry_budget_exhausted"
            br_comment_warranted = True
        else:
            next_action = "retry_different_worker"
            escalation_reason = "retryable_worker_infra"

    if debt_class in {"source_only", "worker_infra", "waiting_for_capacity", "stale_lease"}:
        complete = False
    if next_action not in PROOF_DEBT_SLO_ACTIONS:
        next_action = "record_blocker"
        retry_after_ms = None
        escalation_reason = "invalid_slo_action"
        br_comment_warranted = True

    cooldown_hint = "none" if retry_after_ms is None else f"retry_after_ms={retry_after_ms}"
    operator_summary = (
        f"{next_action}: class={debt_class}; budget_remaining={budget_remaining}; "
        f"worker_diversity_remaining={worker_diversity_remaining}; reason={escalation_reason}"
    )
    return {
        "debt_class": debt_class,
        "budget_remaining": budget_remaining,
        "worker_diversity_remaining": worker_diversity_remaining,
        "next_action": next_action,
        "retry_after_ms": retry_after_ms,
        "cooldown_hint": cooldown_hint,
        "escalation_reason": escalation_reason,
        "complete": complete,
        "br_comment_warranted": br_comment_warranted,
        "operator_summary": operator_summary,
    }


def proof_lane_reroute_decision(input_data: dict[str, Any]) -> dict[str, Any]:
    worker_class = input_data.get("worker_class")
    worker_next_action = input_data.get("worker_next_action")
    proof_debt_next_action = input_data.get("proof_debt_next_action")
    proof_debt_complete = input_data.get("proof_debt_complete")
    proof_freshness = input_data.get("proof_freshness")
    coalescer_state = input_data.get("coalescer_state")
    proof_cache_state = input_data.get("proof_cache_state")
    remote_required = input_data.get("remote_required")
    execution_mode = input_data.get("execution_mode")
    product_failure = input_data.get("product_failure")
    source_only = input_data.get("source_only")
    candidate_worker_id = input_data.get("candidate_worker_id")
    alternate_worker_count = _bounded_int(input_data.get("alternate_worker_count"))
    healthy_workers = _bounded_int(input_data.get("healthy_workers"))
    active_cargo_processes = _bounded_int(input_data.get("active_cargo_processes"))
    max_cargo_processes = _bounded_int(input_data.get("max_cargo_processes"), minimum=1)

    invalid = (
        worker_class not in WORKER_RELIABILITY_CLASSES
        or worker_next_action not in WORKER_RELIABILITY_ACTIONS
        or proof_debt_next_action not in PROOF_DEBT_SLO_ACTIONS
        or not isinstance(proof_debt_complete, bool)
        or proof_freshness not in {"fresh", "stale", "missing"}
        or coalescer_state not in PROOF_LANE_REROUTE_COALESCER_STATES
        or proof_cache_state not in PROOF_LANE_REROUTE_CACHE_STATES
        or not isinstance(remote_required, bool)
        or execution_mode not in RCH_MODES
        or not isinstance(product_failure, bool)
        or not isinstance(source_only, bool)
        or not _bounded(candidate_worker_id)
        or alternate_worker_count is None
        or healthy_workers is None
        or active_cargo_processes is None
        or max_cargo_processes is None
    )
    if invalid:
        return {
            "selected_action": "record_blocker",
            "rejected_actions": sorted(PROOF_LANE_REROUTE_ACTIONS - {"record_blocker"}),
            "reason_codes": ["invalid_reroute_input"],
            "constraints": {"valid": False},
            "cooldown_hint": "none",
            "drain_recommendation": False,
            "freshness_window_seconds": 0,
            "green_proof_eligible": False,
            "operator_summary": "record_blocker: invalid proof-lane reroute input",
        }

    cargo_saturated = active_cargo_processes >= max_cargo_processes
    selected_action = "retry_same_worker"
    rejected_actions: list[str] = []
    reason_codes: list[str] = []
    cooldown_hint = "none"
    drain_recommendation = False
    green_proof_eligible = False
    freshness_window_seconds = 900 if proof_freshness == "fresh" else 0

    def reject(*actions: str) -> None:
        rejected_actions.extend(action for action in actions if action in PROOF_LANE_REROUTE_ACTIONS)

    if product_failure:
        selected_action = "fail_closed_product"
        reason_codes.append("product_failure")
        reject("retry_same_worker", "select_alternate_worker", "join_existing_proof", "reuse_fresh_proof")
    elif remote_required and execution_mode == "local_fallback":
        selected_action = "reject_local_fallback"
        reason_codes.append("remote_required_local_fallback")
        reject("retry_same_worker", "select_alternate_worker", "reuse_fresh_proof")
    elif source_only or proof_debt_next_action == "record_source_only_blocker":
        selected_action = "record_source_only_blocker"
        reason_codes.append("source_only_blocker")
        reject("retry_same_worker", "select_alternate_worker", "reuse_fresh_proof")
    elif coalescer_state == "stale_lease" or proof_debt_next_action == "refresh_lease_fence":
        selected_action = "refresh_lease_fence"
        reason_codes.append("stale_lease_fence")
        cooldown_hint = "refresh_lease_fence"
        reject("retry_same_worker", "join_existing_proof", "reuse_fresh_proof")
    elif proof_cache_state == "fresh_hit" or (proof_debt_complete and proof_freshness == "fresh"):
        selected_action = "reuse_fresh_proof"
        reason_codes.append("fresh_proof_reuse")
        green_proof_eligible = True
        reject("retry_same_worker", "select_alternate_worker")
    elif coalescer_state == "fresh_joinable":
        selected_action = "join_existing_proof"
        reason_codes.append("join_existing_proof")
        cooldown_hint = "wait_for_existing_proof"
        reject("retry_same_worker", "select_alternate_worker", "reuse_fresh_proof")
    elif cargo_saturated:
        selected_action = "wait_for_capacity"
        reason_codes.append("cargo_contention")
        cooldown_hint = "wait_for_capacity"
        reject("retry_same_worker", "select_alternate_worker", "reuse_fresh_proof")
    elif proof_debt_next_action == "wait_for_capacity":
        selected_action = "wait_for_capacity"
        reason_codes.append("waiting_for_capacity")
        cooldown_hint = "wait_for_capacity"
        reject("retry_same_worker", "select_alternate_worker", "reuse_fresh_proof")
    elif worker_class == "drain" or worker_next_action == "drain_worker":
        selected_action = "drain_worker_then_retry"
        reason_codes.append("drain_worker")
        cooldown_hint = "drain_before_retry"
        drain_recommendation = True
        reject("retry_same_worker", "reuse_fresh_proof")
    elif worker_class == "blocked" or worker_next_action == "reject_worker":
        if alternate_worker_count > 0 and healthy_workers > 0:
            selected_action = "select_alternate_worker"
            reason_codes.append("degraded_worker_reroute")
            reject("retry_same_worker", "reuse_fresh_proof")
        else:
            selected_action = "record_blocker"
            reason_codes.append("no_eligible_worker")
            reject("retry_same_worker", "select_alternate_worker", "reuse_fresh_proof")
    elif worker_class in {"degraded", "unknown"} or worker_next_action == "retry_different_worker":
        if alternate_worker_count > 0 and healthy_workers > 0:
            selected_action = "select_alternate_worker"
            reason_codes.append("degraded_worker_reroute")
            reject("retry_same_worker", "reuse_fresh_proof")
        else:
            selected_action = "wait_for_capacity"
            reason_codes.append("waiting_for_capacity")
            cooldown_hint = "wait_for_capacity"
            reject("retry_same_worker", "select_alternate_worker", "reuse_fresh_proof")
    else:
        selected_action = "retry_same_worker"
        reason_codes.append("healthy_worker_retry")
        reject("select_alternate_worker", "record_source_only_blocker", "reject_local_fallback")

    if selected_action not in PROOF_LANE_REROUTE_ACTIONS:
        selected_action = "record_blocker"
        reason_codes = ["invalid_reroute_input"]
        cooldown_hint = "none"
        green_proof_eligible = False
        drain_recommendation = False

    if selected_action not in {"reuse_fresh_proof"}:
        green_proof_eligible = False

    rejected_actions = sorted(set(rejected_actions) - {selected_action})
    reason_codes = sorted(set(reason_codes))
    constraints = {
        "candidate_worker_id": candidate_worker_id,
        "worker_class": worker_class,
        "remote_required": remote_required,
        "cargo_saturated": cargo_saturated,
        "proof_freshness": proof_freshness,
        "coalescer_state": coalescer_state,
        "proof_cache_state": proof_cache_state,
    }
    operator_summary = (
        f"{selected_action}: worker={candidate_worker_id}; class={worker_class}; "
        f"reasons={'+'.join(reason_codes)}"
    )
    return {
        "selected_action": selected_action,
        "rejected_actions": rejected_actions,
        "reason_codes": reason_codes,
        "constraints": constraints,
        "cooldown_hint": cooldown_hint,
        "drain_recommendation": drain_recommendation,
        "freshness_window_seconds": freshness_window_seconds,
        "green_proof_eligible": green_proof_eligible,
        "operator_summary": operator_summary,
    }


def _short_digest(value: Any) -> str:
    return str(value)[:12] if _is_sha256_hex(value) else "<invalid>"


def _explanation_field_errors(input_data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    bead_id = input_data.get("bead_id")
    receipt_bead_id = input_data.get("receipt_bead_id")
    command_digest = input_data.get("command_digest")
    receipt_command_digest = input_data.get("receipt_command_digest")
    artifact_paths = input_data.get("artifact_paths")
    failure_class = input_data.get("failure_class")
    product_failure = input_data.get("product_failure")
    green_proof_eligible = input_data.get("green_proof_eligible")

    if not _bounded(bead_id) or not _bounded(input_data.get("thread_id")):
        errors.append("invalid_input")
    if not _is_sha256_hex(command_digest) or not _is_sha256_hex(receipt_command_digest):
        errors.append("malformed_command_digest")
    elif not hmac.compare_digest(str(command_digest), str(receipt_command_digest)):
        errors.append("command_digest_mismatch")
    if not _bounded(receipt_bead_id) or receipt_bead_id != bead_id:
        errors.append("bead_mismatch")
    if not isinstance(artifact_paths, list) or not artifact_paths:
        errors.append("missing_artifact")
    elif not all(_repo_relative_path_valid(path) for path in artifact_paths):
        errors.append("unsafe_artifact_path")
    if input_data.get("receipt_state") == "stale" or input_data.get("proof_freshness") == "stale":
        errors.append("stale_receipt")
    if isinstance(product_failure, bool) and product_failure and failure_class == "worker_infra":
        errors.append("product_failure_hidden_as_infra")
    if isinstance(green_proof_eligible, bool) and green_proof_eligible and failure_class == "worker_infra":
        errors.append("worker_infra_marked_green")
    if _bounded(input_data.get("stdout_snippet")) or _bounded(input_data.get("stderr_snippet")):
        errors.append("raw_output_snippet_present")
    return sorted(set(errors))


def _render_explanation_markdown(bundle: dict[str, Any]) -> str:
    refs = bundle.get("evidence_refs") if isinstance(bundle.get("evidence_refs"), dict) else {}
    timeline = bundle.get("timeline") if isinstance(bundle.get("timeline"), list) else []
    phases = ", ".join(str(entry.get("phase")) for entry in timeline if isinstance(entry, dict))
    lines = [
        "### Validation Proof Explanation",
        f"- bead: {bundle.get('bead_id')}",
        f"- status: {bundle.get('final_status')}",
        f"- next_action: {bundle.get('next_action')}",
        f"- command: sha256:{_short_digest(bundle.get('command_digest'))}",
        f"- receipt: sha256:{_short_digest(bundle.get('receipt_command_digest'))}",
        f"- mail_fallback: {bundle.get('mail_fallback')}",
        f"- evidence: {', '.join(str(path) for path in refs.get('artifact_paths', []))}",
        f"- timeline: {phases}",
    ]
    if bundle.get("field_errors"):
        lines.append(f"- field_errors: {', '.join(str(error) for error in bundle['field_errors'])}")
    rendered = "\n".join(lines)
    encoded = rendered.encode("utf-8")
    if len(encoded) <= MAX_EXPLANATION_MARKDOWN_BYTES:
        return rendered
    return encoded[:MAX_EXPLANATION_MARKDOWN_BYTES].decode("utf-8", errors="ignore")


def validation_explanation_bundle(input_data: dict[str, Any]) -> dict[str, Any]:
    bead_id = input_data.get("bead_id")
    thread_id = input_data.get("thread_id")
    command_digest = input_data.get("command_digest")
    receipt_command_digest = input_data.get("receipt_command_digest")
    worker_class = input_data.get("worker_class")
    failure_class = input_data.get("failure_class")
    reroute_selected_action = input_data.get("reroute_selected_action")
    proof_debt_next_action = input_data.get("proof_debt_next_action")
    mail_health = input_data.get("mail_health")
    mail_thread_present = input_data.get("mail_thread_present")
    artifact_paths = input_data.get("artifact_paths")
    proof_debt_complete = input_data.get("proof_debt_complete")
    green_proof_eligible = input_data.get("green_proof_eligible")
    product_failure = input_data.get("product_failure")
    source_only = input_data.get("source_only")

    field_errors = _explanation_field_errors(input_data)
    invalid_input = (
        worker_class not in WORKER_RELIABILITY_CLASSES
        or failure_class not in EXPLANATION_BUNDLE_FAILURE_CLASSES
        or reroute_selected_action not in PROOF_LANE_REROUTE_ACTIONS
        or proof_debt_next_action not in PROOF_DEBT_SLO_ACTIONS
        or mail_health not in EXPLANATION_BUNDLE_MAIL_HEALTH
        or not isinstance(mail_thread_present, bool)
        or not isinstance(proof_debt_complete, bool)
        or not isinstance(green_proof_eligible, bool)
        or not isinstance(product_failure, bool)
        or not isinstance(source_only, bool)
    )
    if invalid_input:
        field_errors = sorted(set(field_errors + ["invalid_input"]))

    complete = (
        not field_errors
        and isinstance(proof_debt_complete, bool)
        and proof_debt_complete
        and isinstance(green_proof_eligible, bool)
        and green_proof_eligible
        and input_data.get("proof_freshness") == "fresh"
        and input_data.get("receipt_state") == "fresh"
        and reroute_selected_action == "reuse_fresh_proof"
        and failure_class == "none"
        and isinstance(product_failure, bool)
        and not product_failure
        and isinstance(source_only, bool)
        and not source_only
        and hmac.compare_digest(str(command_digest), str(receipt_command_digest))
        and bead_id == input_data.get("receipt_bead_id")
    )

    if field_errors:
        final_status = "invalid"
        next_action = "repair_explanation_bundle"
    elif complete:
        final_status = "complete"
        next_action = "use_green_proof"
    elif (isinstance(product_failure, bool) and product_failure) or failure_class == "product_failure":
        final_status = "failed"
        next_action = "fail_closed_product"
    elif reroute_selected_action in {"wait_for_capacity", "join_existing_proof"}:
        final_status = "deferred"
        next_action = reroute_selected_action
    else:
        final_status = "blocked"
        next_action = reroute_selected_action

    artifact_list = artifact_paths if isinstance(artifact_paths, list) else []
    mail_fallback = (
        "agent_mail_thread"
        if mail_health in {"green", "yellow"} and mail_thread_present
        else "beads_and_git_artifacts"
    )
    timeline = [
        {"phase": "bead", "status": str(final_status), "detail": str(bead_id)},
        {"phase": "scheduler", "status": str(input_data.get("scheduler_decision")), "detail": str(thread_id)},
        {"phase": "coalescer", "status": str(input_data.get("coalescer_state")), "detail": "bounded snapshot"},
        {"phase": "proof_cache", "status": str(input_data.get("proof_cache_state")), "detail": str(input_data.get("receipt_state"))},
        {"phase": "worker_selection", "status": str(worker_class), "detail": str(input_data.get("worker_id"))},
        {"phase": "reroute_policy", "status": str(reroute_selected_action), "detail": str(input_data.get("reroute_reason"))},
        {"phase": "proof_debt_slo", "status": str(proof_debt_next_action), "detail": str(input_data.get("proof_debt_complete"))},
        {"phase": "final_recommendation", "status": str(final_status), "detail": str(next_action)},
    ]
    bundle = {
        "schema_version": EXPLANATION_BUNDLE_SCHEMA_VERSION,
        "bead_id": bead_id,
        "thread_id": thread_id,
        "command_digest": command_digest,
        "receipt_command_digest": receipt_command_digest,
        "final_status": final_status,
        "complete": complete,
        "next_action": next_action,
        "field_errors": field_errors,
        "timeline": timeline,
        "evidence_refs": {
            "artifact_paths": artifact_list,
            "stdout_digest": input_data.get("stdout_digest"),
            "stderr_digest": input_data.get("stderr_digest"),
            "stdout_path": input_data.get("stdout_path"),
            "stderr_path": input_data.get("stderr_path"),
        },
        "mail_fallback": mail_fallback,
        "green_proof_eligible": bool(input_data.get("green_proof_eligible")),
        "operator_summary": (
            f"{final_status}: bead={bead_id}; next={next_action}; "
            f"fallback={mail_fallback}; errors={','.join(field_errors) or 'none'}"
        ),
    }
    bundle["operator_markdown"] = _render_explanation_markdown(bundle)
    return bundle


def validate_artifacts(artifacts: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(artifacts, dict):
        return [ERR_INVALID_ARTIFACT_PATH]
    for field in ("attempt_path", "stdout_path", "stderr_path", "summary_path"):
        if not _repo_relative_path_valid(artifacts.get(field)):
            errors.append(ERR_INVALID_ARTIFACT_PATH)
    recovery_path = artifacts.get("recovery_path")
    if recovery_path is not None and not _repo_relative_path_valid(recovery_path):
        errors.append(ERR_INVALID_ARTIFACT_PATH)
    for field in ("stdout_digest", "stderr_digest"):
        if not _digest_valid(artifacts.get(field)):
            errors.append(ERR_MALFORMED_ATTEMPT)
    for field in ("stdout_snippet", "stderr_snippet"):
        value = artifacts.get(field)
        if value is not None and not _bounded(value):
            errors.append(ERR_UNBOUNDED_SNIPPET)
    return sorted(set(errors))


def validate_attempt(
    attempt: Any,
    *,
    expected_bead_id: str | None = None,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(attempt, dict):
        return [ERR_MALFORMED_ATTEMPT]
    for field in ATTEMPT_REQUIRED_FIELDS:
        if field not in attempt:
            errors.append(ERR_MALFORMED_ATTEMPT)
            break
    if attempt.get("schema_version") != ATTEMPT_SCHEMA_VERSION:
        errors.append(ERR_INVALID_SCHEMA_VERSION)
    if expected_bead_id is not None and attempt.get("bead_id") != expected_bead_id:
        errors.append(ERR_BEAD_MISMATCH)
    if attempt.get("thread_id") != attempt.get("bead_id"):
        errors.append(ERR_BEAD_MISMATCH)
    for field in ("attempt_id", "trace_id", "bead_id", "thread_id"):
        value = attempt.get(field)
        if not isinstance(value, str) or not value or "\0" in value:
            errors.append(ERR_MALFORMED_ATTEMPT)
    cache_key = attempt.get("proof_cache_key_hex")
    if cache_key is not None and not _is_sha256_hex(cache_key):
        errors.append(ERR_MALFORMED_ATTEMPT)

    created_at = _parse_rfc3339(attempt.get("created_at"))
    started_at = _parse_rfc3339(attempt.get("started_at"))
    finished_at = _parse_rfc3339(attempt.get("finished_at"))
    expires_at = _parse_rfc3339(attempt.get("freshness_expires_at"))
    if created_at is None or expires_at is None:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if started_at is not None and created_at is not None and started_at < created_at:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if finished_at is not None and started_at is not None and finished_at < started_at:
        errors.append(ERR_MALFORMED_ATTEMPT)
    if now is not None and expires_at is not None and expires_at < now:
        errors.append(ERR_STALE_ATTEMPT)

    errors.extend(validate_command(attempt.get("command")))
    errors.extend(validate_environment(attempt.get("environment")))
    errors.extend(validate_target_dir(attempt.get("target_dir")))
    errors.extend(validate_observations(attempt.get("observations")))
    errors.extend(validate_adapter_outcome(attempt.get("adapter_outcome")))
    errors.extend(validate_exit(attempt.get("exit")))
    errors.extend(validate_stale_progress_evidence(attempt))
    errors.extend(validate_artifacts(attempt.get("artifacts")))

    input_digests = attempt.get("input_digests")
    if not isinstance(input_digests, list) or not input_digests:
        errors.append(ERR_MALFORMED_ATTEMPT)
    else:
        for entry in input_digests:
            if not isinstance(entry, dict) or not entry.get("path") or not _digest_valid(entry):
                errors.append(ERR_MALFORMED_ATTEMPT)
                break

    recovery_ref = attempt.get("recovery_ref")
    if recovery_ref is not None:
        if not isinstance(recovery_ref, dict):
            errors.append(ERR_MALFORMED_ATTEMPT)
        elif not _repo_relative_path_valid(recovery_ref.get("path")) or not _digest_valid(recovery_ref.get("digest")):
            errors.append(ERR_INVALID_ARTIFACT_PATH)

    trust = attempt.get("trust")
    if not isinstance(trust, dict):
        errors.append(ERR_MALFORMED_ATTEMPT)
    else:
        for field in ("generated_by", "agent_name", "git_commit", "freshness", "signature_status"):
            if not isinstance(trust.get(field), str) or not trust[field]:
                errors.append(ERR_MALFORMED_ATTEMPT)

    return sorted(set(errors))


def validate_recovery(
    recovery: Any,
    *,
    attempt: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(recovery, dict):
        return [ERR_INVALID_RECOVERY_DECISION]
    for field in RECOVERY_REQUIRED_FIELDS:
        if field not in recovery:
            errors.append(ERR_INVALID_RECOVERY_DECISION)
            break
    if recovery.get("schema_version") != RECOVERY_SCHEMA_VERSION:
        errors.append(ERR_INVALID_SCHEMA_VERSION)
    if not _digest_valid(recovery.get("input_digest")):
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    reason_code = recovery.get("reason_code")
    event_code = recovery.get("event_code")
    if reason_code not in REASON_EVENT_PAIRS or REASON_EVENT_PAIRS.get(reason_code) != event_code:
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    decision = recovery.get("decision")
    required_action = recovery.get("required_action")
    allowed_actions = DECISION_ACTIONS.get(decision, set())
    if required_action not in allowed_actions:
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    if recovery.get("retryable") != (decision in RETRYABLE_DECISIONS):
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    if recovery.get("fail_closed") != (decision in FAIL_CLOSED_DECISIONS):
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    if not _bounded(recovery.get("operator_message")):
        errors.append(ERR_UNBOUNDED_SNIPPET)
    diagnostics = recovery.get("diagnostics")
    if not isinstance(diagnostics, dict):
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    elif any(not isinstance(key, str) or not _bounded(value) for key, value in diagnostics.items()):
        errors.append(ERR_UNBOUNDED_SNIPPET)

    decided_at = _parse_rfc3339(recovery.get("decided_at"))
    expires_at = _parse_rfc3339(recovery.get("freshness_expires_at"))
    if decided_at is None or expires_at is None:
        errors.append(ERR_INVALID_RECOVERY_DECISION)
    if now is not None and expires_at is not None and expires_at < now:
        errors.append(ERR_STALE_ATTEMPT)
    if attempt is not None:
        created_at = _parse_rfc3339(attempt.get("created_at"))
        if created_at is not None and decided_at is not None and decided_at < created_at:
            errors.append(ERR_INVALID_RECOVERY_DECISION)
        for field in ("attempt_id", "bead_id", "thread_id"):
            if recovery.get(field) != attempt.get(field):
                errors.append(ERR_BEAD_MISMATCH)
        errors.extend(validate_stale_progress_evidence(attempt, recovery))
    return sorted(set(errors))


def _load_fixtures() -> dict[str, Any] | None:
    if not FIXTURES_FILE.exists():
        return None
    loaded = _load_json(FIXTURES_FILE)
    return loaded if isinstance(loaded, dict) else None


def _fixture_attempt_and_recovery(
    fixtures: dict[str, Any],
    case: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    attempt = apply_fixture_patch(fixtures["base_attempt"], case.get("patch_attempt"))
    recovery = apply_fixture_patch(fixtures["base_recovery"], case.get("patch_recovery"))
    return attempt, recovery


def _check_files() -> list[dict[str, Any]]:
    return [
        _check("spec_exists", SPEC_FILE.is_file(), str(SPEC_FILE)),
        _check("fixtures_exist", FIXTURES_FILE.is_file(), str(FIXTURES_FILE)),
        _check("script_exists", SCRIPT_FILE.is_file(), str(SCRIPT_FILE)),
        _check("test_exists", TEST_FILE.is_file(), str(TEST_FILE)),
    ]


def _check_spec() -> list[dict[str, Any]]:
    content = _read_text(SPEC_FILE)
    return [_check(f"spec_marker:{marker}", marker in content, marker) for marker in REQUIRED_SPEC_MARKERS]


def _check_fixture_catalog(fixtures: dict[str, Any] | None) -> list[dict[str, Any]]:
    if fixtures is None:
        return [_check("fixtures_parseable", False, "fixture file missing or invalid")]
    checks = [
        _check(
            "fixtures_schema_version",
            fixtures.get("schema_version") == FIXTURE_SCHEMA_VERSION,
            str(fixtures.get("schema_version")),
        ),
        _check("base_attempt_present", isinstance(fixtures.get("base_attempt"), dict)),
        _check("base_recovery_present", isinstance(fixtures.get("base_recovery"), dict)),
    ]
    return checks


def _check_valid_cases(fixtures: dict[str, Any] | None) -> list[dict[str, Any]]:
    if fixtures is None or not isinstance(fixtures.get("valid_cases"), list):
        return [_check("valid_cases_present", False, "missing valid_cases")]
    now = _parse_rfc3339(fixtures.get("validation_time")) or datetime.now(timezone.utc)
    checks: list[dict[str, Any]] = []
    represented = set()
    for case in fixtures["valid_cases"]:
        if not isinstance(case, dict):
            checks.append(_check("valid_case_malformed", False, "case is not object"))
            continue
        attempt, recovery = _fixture_attempt_and_recovery(fixtures, case)
        attempt_errors = validate_attempt(attempt, expected_bead_id=BEAD_ID, now=now)
        recovery_errors = validate_recovery(recovery, attempt=attempt, now=now)
        represented.add(case.get("matrix_case"))
        checks.append(
            _check(
                f"valid_case:{case.get('case', '<unnamed>')}",
                not attempt_errors and not recovery_errors,
                ",".join(attempt_errors + recovery_errors) or "ok",
            )
        )
        expected_decision = case.get("expected_decision")
        checks.append(
            _check(
                f"valid_decision:{case.get('case', '<unnamed>')}",
                expected_decision == recovery.get("decision"),
                str(recovery.get("decision")),
            )
        )

    required_matrix = {
        "remote_success",
        "ssh_timeout",
        "missing_toolchain",
        "disk_pressure",
        "local_fallback_refused",
        "contention_deferred",
        "stale_progress",
        "fresh_heartbeat_progress_ambiguous",
        "stale_heartbeat_progress_stale",
        "clean_cancellation_after_ambiguity",
        "compile_error",
        "test_failure",
        "source_only_allowed",
        "reuse_receipt",
    }
    for matrix_case in sorted(required_matrix):
        checks.append(
            _check(
                f"fixture_matrix:{matrix_case}",
                matrix_case in represented,
                ",".join(sorted(represented)),
            )
        )
    return checks


def _check_invalid_cases(fixtures: dict[str, Any] | None) -> list[dict[str, Any]]:
    if fixtures is None or not isinstance(fixtures.get("invalid_cases"), list):
        return [_check("invalid_cases_present", False, "missing invalid_cases")]
    now = _parse_rfc3339(fixtures.get("validation_time")) or datetime.now(timezone.utc)
    checks: list[dict[str, Any]] = []
    represented = set()
    for case in fixtures["invalid_cases"]:
        if not isinstance(case, dict):
            checks.append(_check("invalid_case_malformed", False, "case is not object"))
            continue
        attempt, recovery = _fixture_attempt_and_recovery(fixtures, case)
        errors = validate_attempt(attempt, expected_bead_id=BEAD_ID, now=now)
        errors.extend(validate_recovery(recovery, attempt=attempt, now=now))
        errors = sorted(set(errors))
        expected = case.get("expected_error")
        represented.add(case.get("case"))
        checks.append(
            _check(
                f"invalid_case:{case.get('case', '<unnamed>')}",
                isinstance(expected, str) and expected in errors,
                ",".join(errors) or "no error",
            )
        )

    required_failure_cases = {
        "missing_command_digest",
        "unsupported_timeout_class",
        "unbounded_output_snippet",
        "absolute_artifact_path",
        "missing_next_action",
        "mismatched_bead_thread",
        "fresh_heartbeat_ambiguity_marked_green",
        "fresh_heartbeat_ambiguity_missing_state",
    }
    for failure_case in sorted(required_failure_cases):
        checks.append(
            _check(
                f"invalid_matrix:{failure_case}",
                failure_case in represented,
                ",".join(sorted(str(case) for case in represented)),
            )
        )
    return checks


def _valid_case_attempts_by_name(fixtures: dict[str, Any]) -> dict[str, dict[str, Any]]:
    attempts: dict[str, dict[str, Any]] = {}
    for case in fixtures.get("valid_cases", []):
        if isinstance(case, dict) and isinstance(case.get("case"), str):
            attempt, _ = _fixture_attempt_and_recovery(fixtures, case)
            attempts[case["case"]] = attempt
    return attempts


def _check_worker_reliability_cases(fixtures: dict[str, Any] | None) -> list[dict[str, Any]]:
    if fixtures is None or not isinstance(fixtures.get("worker_reliability_cases"), list):
        return [_check("worker_reliability_cases_present", False, "missing worker_reliability_cases")]
    attempts_by_name = _valid_case_attempts_by_name(fixtures)
    checks: list[dict[str, Any]] = []
    represented = set()
    for case in fixtures["worker_reliability_cases"]:
        if not isinstance(case, dict):
            checks.append(_check("worker_reliability_case_malformed", False, "case is not object"))
            continue
        represented.add(case.get("case"))
        attempt_names = case.get("attempt_cases")
        if not isinstance(attempt_names, list) or not all(isinstance(name, str) for name in attempt_names):
            checks.append(_check(f"worker_reliability_case:{case.get('case', '<unnamed>')}", False, "bad attempt_cases"))
            continue
        attempts = [attempts_by_name[name] for name in attempt_names if name in attempts_by_name]
        ledger = worker_reliability_ledger(attempts)
        worker_id = case.get("worker_id")
        row = next((entry for entry in ledger if entry.get("worker_id") == worker_id), None)
        checks.append(
            _check(
                f"worker_reliability_present:{case.get('case', '<unnamed>')}",
                row is not None,
                str(worker_id),
            )
        )
        if row is None:
            continue
        expected_class = case.get("expected_class")
        expected_action = case.get("expected_next_action")
        expected_reasons = set(case.get("expected_reasons", []))
        checks.append(
            _check(
                f"worker_reliability_class:{case.get('case', '<unnamed>')}",
                expected_class in WORKER_RELIABILITY_CLASSES and row.get("class") == expected_class,
                str(row.get("class")),
            )
        )
        checks.append(
            _check(
                f"worker_reliability_action:{case.get('case', '<unnamed>')}",
                row.get("next_action") == expected_action,
                str(row.get("next_action")),
            )
        )
        checks.append(
            _check(
                f"worker_reliability_reasons:{case.get('case', '<unnamed>')}",
                expected_reasons.issubset(set(row.get("reasons", []))),
                ",".join(row.get("reasons", [])),
            )
        )

    required_cases = {
        "remote_success_healthy",
        "repeated_stale_progress_drain",
        "product_failures_excluded",
        "fresh_heartbeat_ambiguity_degraded",
        "filesystem_pressure_drain",
        "missing_toolchain_degraded",
        "local_fallback_blocked",
    }
    for required_case in sorted(required_cases):
        checks.append(
            _check(
                f"worker_reliability_matrix:{required_case}",
                required_case in represented,
                ",".join(sorted(str(case) for case in represented)),
            )
        )
    if fixtures.get("worker_reliability_cases"):
        all_attempts = [
            attempts_by_name[name]
            for case in fixtures["worker_reliability_cases"]
            if isinstance(case, dict)
            for name in case.get("attempt_cases", [])
            if isinstance(name, str) and name in attempts_by_name
        ]
        ledger = worker_reliability_ledger(all_attempts)
        checks.append(
            _check(
                "worker_reliability_sorted",
                [row["worker_id"] for row in ledger] == sorted(row["worker_id"] for row in ledger),
                ",".join(row["worker_id"] for row in ledger),
            )
        )
    return checks


def _check_proof_debt_slo_cases(fixtures: dict[str, Any] | None) -> list[dict[str, Any]]:
    if fixtures is None or not isinstance(fixtures.get("proof_debt_slo_cases"), list):
        return [_check("proof_debt_slo_cases_present", False, "missing proof_debt_slo_cases")]
    checks: list[dict[str, Any]] = []
    represented = set()
    for case in fixtures["proof_debt_slo_cases"]:
        if not isinstance(case, dict):
            checks.append(_check("proof_debt_slo_case_malformed", False, "case is not object"))
            continue
        name = case.get("case", "<unnamed>")
        represented.add(name)
        input_data = case.get("input")
        if not isinstance(input_data, dict):
            checks.append(_check(f"proof_debt_slo_case:{name}", False, "missing input"))
            continue
        decision = proof_debt_slo_decision(input_data)
        checks.append(
            _check(
                f"proof_debt_slo_action:{name}",
                decision.get("next_action") == case.get("expected_next_action"),
                str(decision.get("next_action")),
            )
        )
        checks.append(
            _check(
                f"proof_debt_slo_complete:{name}",
                decision.get("complete") == case.get("expected_complete"),
                str(decision.get("complete")),
            )
        )
        checks.append(
            _check(
                f"proof_debt_slo_reason:{name}",
                decision.get("escalation_reason") == case.get("expected_escalation_reason"),
                str(decision.get("escalation_reason")),
            )
        )
        if "expected_budget_remaining" in case:
            checks.append(
                _check(
                    f"proof_debt_slo_budget:{name}",
                    decision.get("budget_remaining") == case.get("expected_budget_remaining"),
                    str(decision.get("budget_remaining")),
                )
            )
        checks.append(
            _check(
                f"proof_debt_slo_summary:{name}",
                _bounded(decision.get("operator_summary"))
                and str(decision.get("next_action")) in str(decision.get("operator_summary")),
                str(decision.get("operator_summary")),
            )
        )
        if input_data.get("debt_class") in {"source_only", "worker_infra"}:
            complete_value = decision.get("complete")
            checks.append(
                _check(
                    f"proof_debt_slo_not_green:{name}",
                    isinstance(complete_value, bool) and not complete_value,
                    str(complete_value),
                )
            )

    required_cases = {
        "fresh_green_proof",
        "stale_proof_refresh",
        "repeated_worker_infra_budget_exhausted",
        "product_failure_fail_closed",
        "p1_urgent_retry_budget",
        "p4_fairness_aging",
        "saturated_rch_queue",
        "no_healthy_workers",
        "stale_coalescer_lease",
        "source_only_not_green",
    }
    for required_case in sorted(required_cases):
        checks.append(
            _check(
                f"proof_debt_slo_matrix:{required_case}",
                required_case in represented,
                ",".join(sorted(str(case) for case in represented)),
            )
        )

    stress_inputs = [
        {
            "debt_class": "worker_infra" if index % 3 else "waiting_for_capacity",
            "bead_priority": index % 5,
            "command_class": "focused_validation",
            "proof_freshness": "missing",
            "retry_count": index % 3,
            "retry_budget": 3,
            "worker_diversity_count": index % 2,
            "worker_diversity_budget": 2,
            "queue_depth": index % 17,
            "max_queue_depth": 32,
            "active_cargo_processes": index % 3,
            "max_cargo_processes": 3,
            "healthy_workers": 1 + (index % 4),
            "oldest_queued_age_seconds": 4_000 if index % 7 == 0 else 100,
            "stale_lease_age_seconds": 0,
            "stale_lease_after_seconds": 600,
        }
        for index in range(1024)
    ]
    stress_decisions = [proof_debt_slo_decision(input_data) for input_data in stress_inputs]
    stress_bytes = len(json.dumps(stress_decisions, sort_keys=True).encode("utf-8"))
    checks.append(
        _check(
            "proof_debt_slo_stress_1024",
            len(stress_decisions) == 1024 and stress_bytes <= 512 * 1024,
            f"decisions={len(stress_decisions)} bytes={stress_bytes}",
        )
    )
    checks.append(
        _check(
            "proof_debt_slo_stress_deterministic",
            stress_decisions == [proof_debt_slo_decision(input_data) for input_data in stress_inputs],
            "stable",
        )
    )
    return checks


def _check_proof_lane_reroute_cases(fixtures: dict[str, Any] | None) -> list[dict[str, Any]]:
    if fixtures is None or not isinstance(fixtures.get("proof_lane_reroute_cases"), list):
        return [_check("proof_lane_reroute_cases_present", False, "missing proof_lane_reroute_cases")]
    checks: list[dict[str, Any]] = []
    represented = set()
    for case in fixtures["proof_lane_reroute_cases"]:
        if not isinstance(case, dict):
            checks.append(_check("proof_lane_reroute_case_malformed", False, "case is not object"))
            continue
        name = case.get("case", "<unnamed>")
        represented.add(name)
        input_data = case.get("input")
        if not isinstance(input_data, dict):
            checks.append(_check(f"proof_lane_reroute_case:{name}", False, "missing input"))
            continue
        decision = proof_lane_reroute_decision(input_data)
        checks.append(
            _check(
                f"proof_lane_reroute_action:{name}",
                decision.get("selected_action") == case.get("expected_selected_action"),
                str(decision.get("selected_action")),
            )
        )
        checks.append(
            _check(
                f"proof_lane_reroute_green:{name}",
                decision.get("green_proof_eligible") == case.get("expected_green_proof_eligible"),
                str(decision.get("green_proof_eligible")),
            )
        )
        expected_reason = case.get("expected_reason")
        checks.append(
            _check(
                f"proof_lane_reroute_reason:{name}",
                expected_reason in PROOF_LANE_REROUTE_REASONS
                and expected_reason in set(decision.get("reason_codes", [])),
                ",".join(decision.get("reason_codes", [])),
            )
        )
        expected_rejected = set(case.get("expected_rejected_actions", []))
        checks.append(
            _check(
                f"proof_lane_reroute_rejected:{name}",
                expected_rejected.issubset(set(decision.get("rejected_actions", [])))
                and len(decision.get("rejected_actions", [])) > 0,
                ",".join(decision.get("rejected_actions", [])),
            )
        )
        checks.append(
            _check(
                f"proof_lane_reroute_summary:{name}",
                _bounded(decision.get("operator_summary"))
                and str(decision.get("selected_action")) in str(decision.get("operator_summary")),
                str(decision.get("operator_summary")),
            )
        )
        checks.append(
            _check(
                f"proof_lane_reroute_degraded_not_selected:{name}",
                not (
                    input_data.get("worker_class") in {"degraded", "drain", "blocked"}
                    and decision.get("selected_action") == "retry_same_worker"
                ),
                str(decision.get("selected_action")),
            )
        )

    required_cases = {
        "healthy_same_worker_retry",
        "alternate_worker_reroute",
        "drain_before_retry",
        "wait_for_capacity",
        "join_existing_proof",
        "fence_stale_lease",
        "source_only_blocker",
        "product_failure_fail_closed",
        "remote_required_local_fallback_refusal",
        "active_cargo_contention_above_threshold",
    }
    for required_case in sorted(required_cases):
        checks.append(
            _check(
                f"proof_lane_reroute_matrix:{required_case}",
                required_case in represented,
                ",".join(sorted(str(case) for case in represented)),
            )
        )

    stress_inputs = [
        {
            "worker_class": ("healthy", "degraded", "drain", "blocked")[index % 4],
            "worker_next_action": (
                "allow_worker",
                "retry_different_worker",
                "drain_worker",
                "reject_worker",
            )[index % 4],
            "proof_debt_next_action": "wait_for_capacity" if index % 11 == 0 else "retry_different_worker",
            "proof_debt_complete": index % 17 == 0,
            "proof_freshness": "fresh" if index % 17 == 0 else "missing",
            "coalescer_state": "fresh_joinable" if index % 13 == 0 else "none",
            "proof_cache_state": "fresh_hit" if index % 17 == 0 else "miss",
            "remote_required": True,
            "execution_mode": "remote",
            "product_failure": index % 19 == 0,
            "source_only": index % 23 == 0,
            "candidate_worker_id": f"worker-{index % 7}",
            "alternate_worker_count": index % 3,
            "healthy_workers": 1 + (index % 5),
            "active_cargo_processes": index % 5,
            "max_cargo_processes": 4,
        }
        for index in range(1024)
    ]
    stress_decisions = [proof_lane_reroute_decision(input_data) for input_data in stress_inputs]
    stress_bytes = len(json.dumps(stress_decisions, sort_keys=True).encode("utf-8"))
    checks.append(
        _check(
            "proof_lane_reroute_stress_1024",
            len(stress_decisions) == 1024 and stress_bytes <= 768 * 1024,
            f"decisions={len(stress_decisions)} bytes={stress_bytes}",
        )
    )
    checks.append(
        _check(
            "proof_lane_reroute_stress_deterministic",
            stress_decisions == [proof_lane_reroute_decision(input_data) for input_data in stress_inputs],
            "stable",
        )
    )
    return checks


def _check_explanation_bundle_cases(fixtures: dict[str, Any] | None) -> list[dict[str, Any]]:
    if fixtures is None or not isinstance(fixtures.get("explanation_bundle_cases"), list):
        return [_check("explanation_bundle_cases_present", False, "missing explanation_bundle_cases")]
    checks: list[dict[str, Any]] = []
    represented = set()
    for case in fixtures["explanation_bundle_cases"]:
        if not isinstance(case, dict):
            checks.append(_check("explanation_bundle_case_malformed", False, "case is not object"))
            continue
        name = case.get("case", "<unnamed>")
        represented.add(name)
        input_data = case.get("input")
        if not isinstance(input_data, dict):
            checks.append(_check(f"explanation_bundle_case:{name}", False, "missing input"))
            continue
        bundle = validation_explanation_bundle(input_data)
        expected_status = case.get("expected_final_status")
        expected_next_action = case.get("expected_next_action")
        expected_complete = case.get("expected_complete")
        expected_error = case.get("expected_field_error")
        expected_mail_fallback = case.get("expected_mail_fallback")
        markdown = str(bundle.get("operator_markdown", ""))
        repeated = validation_explanation_bundle(copy.deepcopy(input_data))
        raw_fragments = [
            value
            for value in (input_data.get("stdout_snippet"), input_data.get("stderr_snippet"))
            if isinstance(value, str) and value
        ]

        checks.append(
            _check(
                f"explanation_bundle_schema:{name}",
                bundle.get("schema_version") == EXPLANATION_BUNDLE_SCHEMA_VERSION,
                str(bundle.get("schema_version")),
            )
        )
        checks.append(
            _check(
                f"explanation_bundle_status:{name}",
                expected_status in EXPLANATION_BUNDLE_STATUSES and bundle.get("final_status") == expected_status,
                str(bundle.get("final_status")),
            )
        )
        checks.append(
            _check(
                f"explanation_bundle_next:{name}",
                bundle.get("next_action") == expected_next_action,
                str(bundle.get("next_action")),
            )
        )
        checks.append(
            _check(
                f"explanation_bundle_complete:{name}",
                isinstance(expected_complete, bool) and bundle.get("complete") == expected_complete,
                str(bundle.get("complete")),
            )
        )
        checks.append(
            _check(
                f"explanation_bundle_markdown_bounded:{name}",
                len(markdown.encode("utf-8")) <= MAX_EXPLANATION_MARKDOWN_BYTES
                and all(fragment not in markdown for fragment in raw_fragments),
                str(len(markdown.encode("utf-8"))),
            )
        )
        checks.append(
            _check(
                f"explanation_bundle_deterministic:{name}",
                bundle == repeated,
                "stable",
            )
        )
        checks.append(
            _check(
                f"explanation_bundle_timeline:{name}",
                {entry.get("phase") for entry in bundle.get("timeline", []) if isinstance(entry, dict)}
                == EXPLANATION_BUNDLE_TIMELINE_PHASES,
                ",".join(
                    str(entry.get("phase")) for entry in bundle.get("timeline", []) if isinstance(entry, dict)
                ),
            )
        )
        if expected_error is not None:
            checks.append(
                _check(
                    f"explanation_bundle_error:{name}",
                    expected_error in EXPLANATION_BUNDLE_FIELD_ERRORS
                    and expected_error in set(bundle.get("field_errors", [])),
                    ",".join(bundle.get("field_errors", [])),
                )
            )
        else:
            checks.append(
                _check(
                    f"explanation_bundle_no_error:{name}",
                    not bundle.get("field_errors"),
                    ",".join(bundle.get("field_errors", [])),
                )
            )
        if expected_mail_fallback is not None:
            checks.append(
                _check(
                    f"explanation_bundle_mail_fallback:{name}",
                    bundle.get("mail_fallback") == expected_mail_fallback,
                    str(bundle.get("mail_fallback")),
                )
            )

    required_cases = {
        "green_proof_reuse",
        "worker_degraded_reroute",
        "exhausted_proof_debt_budget",
        "stale_lease_fence",
        "source_only_blocker",
        "product_failure",
        "missing_agent_mail_thread",
        "corrupt_missing_artifact",
        "mismatched_bead_id",
        "malformed_command_digest",
        "stale_receipt",
        "worker_infra_marked_green",
        "product_failure_hidden_as_infra",
    }
    for required_case in sorted(required_cases):
        checks.append(
            _check(
                f"explanation_bundle_matrix:{required_case}",
                required_case in represented,
                ",".join(sorted(str(case) for case in represented)),
            )
        )

    stress_inputs = [
        {
            "bead_id": f"bd-wc27p.{13 + (index % 3)}",
            "thread_id": f"bd-wc27p.{13 + (index % 3)}",
            "scheduler_decision": "validation_lane",
            "command_digest": "a" * 64,
            "receipt_bead_id": f"bd-wc27p.{13 + (index % 3)}",
            "receipt_command_digest": "a" * 64,
            "receipt_state": "fresh" if index % 5 == 0 else "missing",
            "proof_freshness": "fresh" if index % 5 == 0 else "missing",
            "proof_debt_complete": index % 5 == 0,
            "proof_debt_next_action": "use_reusable_proof" if index % 5 == 0 else "retry_different_worker",
            "green_proof_eligible": index % 5 == 0,
            "coalescer_state": "fresh_joinable" if index % 7 == 0 else "none",
            "proof_cache_state": "fresh_hit" if index % 5 == 0 else "miss",
            "reroute_selected_action": "reuse_fresh_proof" if index % 5 == 0 else "select_alternate_worker",
            "reroute_reason": "fresh_proof_reuse" if index % 5 == 0 else "degraded_worker_reroute",
            "worker_id": f"worker-{index % 11}",
            "worker_class": "healthy" if index % 5 == 0 else "degraded",
            "failure_class": "none",
            "product_failure": False,
            "source_only": False,
            "mail_health": "red" if index % 13 == 0 else "green",
            "mail_thread_present": index % 13 != 0,
            "artifact_paths": [f"artifacts/validation_broker/bd-wc27p.13/explanation-{index}.json"],
            "stdout_digest": "b" * 64,
            "stderr_digest": "c" * 64,
            "stdout_path": f"artifacts/validation_broker/bd-wc27p.13/stdout-{index}.txt",
            "stderr_path": f"artifacts/validation_broker/bd-wc27p.13/stderr-{index}.txt",
        }
        for index in range(384)
    ]
    stress_bundles = [validation_explanation_bundle(input_data) for input_data in stress_inputs]
    stress_bytes = len(json.dumps(stress_bundles, sort_keys=True).encode("utf-8"))
    checks.append(
        _check(
            "explanation_bundle_stress_384",
            len(stress_bundles) == 384 and stress_bytes <= 1024 * 1024,
            f"bundles={len(stress_bundles)} bytes={stress_bytes}",
        )
    )
    checks.append(
        _check(
            "explanation_bundle_stress_deterministic",
            stress_bundles == [validation_explanation_bundle(input_data) for input_data in stress_inputs],
            "stable",
        )
    )
    return checks


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(_check_files())
    checks.extend(_check_spec())
    fixtures = _load_fixtures()
    checks.extend(_check_fixture_catalog(fixtures))
    checks.extend(_check_valid_cases(fixtures))
    checks.extend(_check_invalid_cases(fixtures))
    checks.extend(_check_worker_reliability_cases(fixtures))
    checks.extend(_check_proof_debt_slo_cases(fixtures))
    checks.extend(_check_proof_lane_reroute_cases(fixtures))
    checks.extend(_check_explanation_bundle_cases(fixtures))
    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    fixtures = _load_fixtures()
    result = run_all()
    checks = [
        _check("run_all_returns_dict", isinstance(result, dict)),
        _check("bead_id_matches", result.get("bead_id") == BEAD_ID),
        _check("has_substantial_checks", isinstance(result.get("checks"), list) and len(result["checks"]) >= 40),
        _check("contract_passes", result.get("verdict") == "PASS", f"{result.get('passed')}/{result.get('total')}"),
    ]
    if fixtures is not None:
        base_attempt = fixtures.get("base_attempt")
        base_recovery = fixtures.get("base_recovery")
        checks.append(_check("base_attempt_validates", validate_attempt(base_attempt, expected_bead_id=BEAD_ID) == []))
        checks.append(_check("base_recovery_validates", validate_recovery(base_recovery, attempt=base_attempt) == []))
    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    return {
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    configure_test_logging("check_validation_flight_recorder")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"# {BEAD_ID}: {TITLE}")
        print(f"Verdict: {result['verdict']} ({result['passed']}/{result['total']})")
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")
    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
