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
MAX_OBSERVATIONS = 256
MAX_SNIPPET_BYTES = 4096
REDACTED_ENV_VALUE = "<redacted>"

SPEC_FILE = ROOT / "docs/specs/validation_flight_recorder.md"
FIXTURES_FILE = (
    ROOT
    / "artifacts/validation_broker/bd-2zn9k/validation_flight_recorder_fixtures.v1.json"
)
SCRIPT_FILE = ROOT / "scripts/check_validation_flight_recorder.py"

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
    "accept_success": "use_receipt",
    "retry_remote_same_worker": "retry_rch",
    "retry_remote_different_worker": "retry_rch_different_worker",
    "queue_until_capacity": "wait_for_capacity",
    "drain_worker_then_retry": "drain_worker",
    "wait_for_existing_proof": "wait_for_proof",
    "retry_with_new_fence": "fence_stale_lease",
    "reuse_receipt": "reuse_receipt",
    "use_source_only_blocker": "record_source_only",
    "fail_closed_product": "fix_product_failure",
    "fail_closed_invalid": "repair_artifact_or_contract",
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
    if decision not in DECISION_ACTIONS or DECISION_ACTIONS.get(decision) != required_action:
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


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(_check_files())
    checks.extend(_check_spec())
    fixtures = _load_fixtures()
    checks.extend(_check_fixture_catalog(fixtures))
    checks.extend(_check_valid_cases(fixtures))
    checks.extend(_check_invalid_cases(fixtures))
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
