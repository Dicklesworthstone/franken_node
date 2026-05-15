#!/usr/bin/env python3
"""Validate cross-repo validation drift snapshot fixtures.

Usage:
    python3 scripts/check_cross_repo_validation_drift.py
    python3 scripts/check_cross_repo_validation_drift.py --json
    python3 scripts/check_cross_repo_validation_drift.py --self-test
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


BEAD_ID = "bd-7vk3p.1"
TITLE = "Cross-repo validation dependency drift snapshots"
SNAPSHOT_SCHEMA_VERSION = "franken-node/cross-repo-validation-drift/snapshot/v1"
SCHEMA_CATALOG_VERSION = "franken-node/cross-repo-validation-drift/schema-catalog/v1"
FIXTURE_SCHEMA_VERSION = "franken-node/cross-repo-validation-drift/fixtures/v1"
HANDOFF_SCHEMA_VERSION = "franken-node/cross-repo-validation-drift/handoff/v1"

SCHEMA_FILE = (
    ROOT
    / "artifacts/validation_broker/cross_repo_drift/"
    "cross_repo_validation_drift_contract.schema.json"
)
FIXTURES_FILE = (
    ROOT
    / "artifacts/validation_broker/cross_repo_drift/"
    "cross_repo_validation_drift_fixtures.v1.json"
)
SCRIPT_FILE = ROOT / "scripts/check_cross_repo_validation_drift.py"
TEST_FILE = ROOT / "tests/test_check_cross_repo_validation_drift.py"

REQUIRED_FIELDS = [
    "schema_version",
    "snapshot_id",
    "bead_id",
    "thread_id",
    "generated_at",
    "producer",
    "validation_command",
    "command_digest",
    "cargo_pressure",
    "sibling_repo",
    "symbol_probes",
    "agent_mail",
    "classification",
    "recommended_action",
]

DIRTY_STATES = {
    "clean",
    "dirty_relevant",
    "dirty_unrelated",
    "unavailable",
}

SYMBOL_STATUSES = {
    "present",
    "missing_referenced",
    "absent_from_call_sites",
    "not_checked",
}

BEADS_LOCK_STATUSES = {
    "ok",
    "timeout",
    "stale_file",
    "unavailable",
}

AGENT_MAIL_STATUSES = {
    "green",
    "red_corrupt",
    "unavailable",
}

CLASSIFICATION_CODES = {
    "CRVD_SAFE_TO_RUN",
    "CRVD_BLOCKED_CARGO_PRESSURE",
    "CRVD_BLOCKED_SIBLING_DIRTY_RELEVANT",
    "CRVD_BLOCKED_SIBLING_API_DRIFT",
    "CRVD_BLOCKED_SIBLING_BEADS_LOCK",
    "CRVD_BLOCKED_AGENT_MAIL_CORRUPT",
    "CRVD_NEEDS_RCH_REPROOF",
}

RECOMMENDED_ACTIONS = {
    "run_rch_validation",
    "wait_for_cargo_pressure",
    "coordinate_sibling_owner",
    "inspect_sibling_api_drift",
    "record_beads_blocker",
    "source_only_handoff",
}

MAX_DIRTY_FILES = 64
MAX_SYMBOL_PROBES = 32
MAX_LIST_ITEMS = 128
MAX_STRING_BYTES = 1024
MAX_PATH_BYTES = 240
MAX_HANDOFF_JSON_BYTES = 8192
MAX_HANDOFF_MARKDOWN_BYTES = 4096
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BEAD_RE = re.compile(r"^bd-[A-Za-z0-9.]+$")
SNAPSHOT_ID_RE = re.compile(r"^crvd-[a-z0-9-]+$")


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


def _path_parts(dotted_path: str) -> list[str]:
    return [part for part in dotted_path.split(".") if part != ""]


def _get_path(payload: Any, dotted_path: str) -> Any:
    current = payload
    for part in _path_parts(dotted_path):
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


def _set_path(payload: Any, dotted_path: str, value: Any) -> None:
    current = payload
    parts = _path_parts(dotted_path)
    for next_index, part in enumerate(parts[:-1]):
        next_part = parts[next_index + 1]
        if isinstance(current, dict):
            if part not in current or not isinstance(current[part], (dict, list)):
                current[part] = [] if next_part.isdigit() else {}
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            while len(current) <= index:
                current.append({} if not next_part.isdigit() else [])
            if not isinstance(current[index], (dict, list)):
                current[index] = [] if next_part.isdigit() else {}
            current = current[index]
        else:
            return

    last = parts[-1]
    if isinstance(current, dict):
        current[last] = value
    elif isinstance(current, list) and last.isdigit():
        index = int(last)
        while len(current) <= index:
            current.append(None)
        current[index] = value


def _remove_path(payload: Any, dotted_path: str) -> None:
    current = payload
    parts = _path_parts(dotted_path)
    for part in parts[:-1]:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else None
        else:
            return
    if current is None:
        return
    last = parts[-1]
    if isinstance(current, dict):
        current.pop(last, None)
    elif isinstance(current, list) and last.isdigit():
        index = int(last)
        if index < len(current):
            current.pop(index)


def apply_fixture_patch(base: Any, patch: dict[str, Any] | None) -> Any:
    patched = copy.deepcopy(base)
    if not patch:
        return patched
    for dotted_path in patch.get("remove", []):
        _remove_path(patched, str(dotted_path))
    for dotted_path, value in patch.get("set", {}).items():
        _set_path(patched, str(dotted_path), value)
    return patched


def _is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.fullmatch(value))


def _bounded_string(value: Any, max_bytes: int = MAX_STRING_BYTES) -> bool:
    return isinstance(value, str) and 0 < len(value.encode("utf-8")) <= max_bytes and "\0" not in value


def _bounded_path(value: Any) -> bool:
    if not _bounded_string(value, MAX_PATH_BYTES):
        return False
    return not str(value).startswith("../") and "/../" not in str(value)


def _collect_bound_errors(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES or "\0" in value:
            errors.append("ERR_CRVD_UNBOUNDED_STRING")
    elif isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            errors.append("ERR_CRVD_UNBOUNDED_LIST")
        for index, item in enumerate(value):
            errors.extend(_collect_bound_errors(item, f"{path}.{index}"))
    elif isinstance(value, dict):
        for key, item in value.items():
            if len(str(key).encode("utf-8")) > MAX_STRING_BYTES:
                errors.append("ERR_CRVD_UNBOUNDED_STRING")
            errors.extend(_collect_bound_errors(item, f"{path}.{key}"))
    return errors


def _list_of_bounded_paths(value: Any, max_items: int = MAX_LIST_ITEMS) -> bool:
    return isinstance(value, list) and len(value) <= max_items and all(_bounded_path(item) for item in value)


def _sorted_unique_strings(value: Any) -> bool:
    return isinstance(value, list) and value == sorted(value) and len(value) == len(set(value))


def _expected_command_material(command: Any) -> str | None:
    if not isinstance(command, dict):
        return None
    program = command.get("program")
    argv = command.get("argv")
    cwd = command.get("cwd")
    if not isinstance(program, str) or not isinstance(argv, list) or not isinstance(cwd, str):
        return None
    if not all(isinstance(part, str) for part in argv):
        return None
    return f"program={program} argv={' '.join(argv)} cwd={cwd}"


def _canonical_command(snapshot: dict[str, Any]) -> str:
    existing = _get_path(snapshot, "recommended_action.exact_command")
    if isinstance(existing, str) and existing.strip():
        return existing
    command = snapshot.get("validation_command")
    if not isinstance(command, dict):
        return "rch exec -- <validation-command>"
    argv = command.get("argv")
    if not isinstance(argv, list) or not all(isinstance(part, str) for part in argv):
        return "rch exec -- <validation-command>"
    return " ".join(argv)


def _validation_command_string(snapshot: dict[str, Any]) -> str:
    command = snapshot.get("validation_command")
    if not isinstance(command, dict):
        return "rch exec -- <validation-command>"
    program = command.get("program")
    argv = command.get("argv")
    if not isinstance(program, str) or not isinstance(argv, list):
        return "rch exec -- <validation-command>"
    if not all(isinstance(part, str) for part in argv):
        return "rch exec -- <validation-command>"
    return " ".join([program, *argv])


def _sorted_path_values(value: Any, max_items: int = MAX_LIST_ITEMS) -> list[str]:
    if not isinstance(value, list):
        return []
    paths = [str(item) for item in value if isinstance(item, str)]
    return sorted(paths)[:max_items]


def derive_classification(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Derive the fail-closed cross-repo validation decision for a snapshot."""
    command = _canonical_command(snapshot)
    cargo_count = _get_path(snapshot, "cargo_pressure.process_count")
    cargo_threshold = _get_path(snapshot, "cargo_pressure.threshold")
    dirty_state = _get_path(snapshot, "sibling_repo.dirty_state")
    lock_status = _get_path(snapshot, "sibling_repo.beads_lock.status")
    mail_status = _get_path(snapshot, "agent_mail.status")
    symbol_probes = snapshot.get("symbol_probes", [])

    if any(
        isinstance(probe, dict) and probe.get("status") == "missing_referenced"
        for probe in (symbol_probes if isinstance(symbol_probes, list) else [])
    ):
        return {
            "code": "CRVD_BLOCKED_SIBLING_API_DRIFT",
            "action": "inspect_sibling_api_drift",
            "exact_command": "rg -n '<missing-symbol>' <sibling-repo>",
            "operator_message": "Repair or coordinate sibling API drift before rerunning validation.",
        }

    if dirty_state == "dirty_relevant":
        return {
            "code": "CRVD_BLOCKED_SIBLING_DIRTY_RELEVANT",
            "action": "record_beads_blocker",
            "exact_command": "br comments add <bead-id> --message <bounded cross-repo drift summary>",
            "operator_message": "Relevant sibling files are dirty; record a Beads handoff before rerunning validation.",
        }

    if lock_status in {"timeout", "stale_file", "unavailable"}:
        return {
            "code": "CRVD_BLOCKED_SIBLING_BEADS_LOCK",
            "action": "coordinate_sibling_owner",
            "exact_command": "br list --status=in_progress --json",
            "operator_message": "Sibling Beads ownership is unavailable; coordinate before editing or validating.",
        }

    if isinstance(cargo_count, int) and isinstance(cargo_threshold, int) and cargo_count > cargo_threshold:
        return {
            "code": "CRVD_BLOCKED_CARGO_PRESSURE",
            "action": "wait_for_cargo_pressure",
            "exact_command": "pgrep -af 'cargo|rustc' | wc -l",
            "operator_message": "Cargo pressure is above threshold; wait before launching RCH validation.",
        }

    if mail_status in {"red_corrupt", "unavailable"}:
        return {
            "code": "CRVD_BLOCKED_AGENT_MAIL_CORRUPT",
            "action": "source_only_handoff",
            "exact_command": "br comments add <id> --message <handoff>",
            "operator_message": "Agent Mail is corrupt; use Beads-visible ownership and durable comments.",
        }

    if any(
        isinstance(probe, dict) and probe.get("status") == "absent_from_call_sites"
        for probe in (symbol_probes if isinstance(symbol_probes, list) else [])
    ):
        return {
            "code": "CRVD_NEEDS_RCH_REPROOF",
            "action": "run_rch_validation",
            "exact_command": command,
            "operator_message": "Sibling symbols are absent from call sites; rerun the deferred RCH proof.",
        }

    return {
        "code": "CRVD_SAFE_TO_RUN",
        "action": "run_rch_validation",
        "exact_command": command,
        "operator_message": "Cross-repo validation preflight is safe to run through rch.",
    }


def render_handoff_markdown(payload: dict[str, Any]) -> str:
    dirty_files = payload.get("active_dirty_file_summary", {}).get("files", [])
    dirty_lines = [f"- {path}" for path in dirty_files] if dirty_files else ["- none"]
    lines = [
        "# Cross-Repo Validation Handoff",
        f"- bead_id: {payload.get('bead_id')}",
        f"- thread_id: {payload.get('thread_id')}",
        f"- snapshot_id: {payload.get('snapshot_id')}",
        f"- classification: {payload.get('classification_code')}",
        f"- next_safest_action: {payload.get('next_safest_action')}",
        f"- exact_deferred_rch_command: {payload.get('exact_deferred_rch_command')}",
        f"- recommended_command: {payload.get('recommended_command')}",
        f"- command_digest: sha256:{payload.get('command_digest')}",
        "",
        "## Sibling Repo",
        f"- name: {payload.get('sibling_repo', {}).get('name')}",
        f"- path: {payload.get('sibling_repo', {}).get('path')}",
        f"- branch: {payload.get('sibling_repo', {}).get('branch')}",
        f"- head: {payload.get('sibling_repo', {}).get('head')}",
        f"- dirty_state: {payload.get('sibling_repo', {}).get('dirty_state')}",
        f"- Sibling Beads lock: {payload.get('ownership_uncertainty', {}).get('sibling_beads_lock_status')}",
        f"- Agent Mail: {payload.get('ownership_uncertainty', {}).get('agent_mail_status')}",
        "",
        "## Active Dirty Files",
        *dirty_lines,
        "",
        "## Operator Message",
        str(payload.get("operator_message")),
    ]
    return "\n".join(lines)


def build_handoff_payload(snapshot: dict[str, Any]) -> dict[str, Any]:
    classification = snapshot.get("classification") if isinstance(snapshot.get("classification"), dict) else {}
    recommended_action = (
        snapshot.get("recommended_action") if isinstance(snapshot.get("recommended_action"), dict) else {}
    )
    sibling_repo = snapshot.get("sibling_repo") if isinstance(snapshot.get("sibling_repo"), dict) else {}
    agent_mail = snapshot.get("agent_mail") if isinstance(snapshot.get("agent_mail"), dict) else {}
    beads_lock = sibling_repo.get("beads_lock") if isinstance(sibling_repo.get("beads_lock"), dict) else {}
    cargo_pressure = snapshot.get("cargo_pressure") if isinstance(snapshot.get("cargo_pressure"), dict) else {}
    command_digest = snapshot.get("command_digest") if isinstance(snapshot.get("command_digest"), dict) else {}
    dirty_files = _sorted_path_values(sibling_repo.get("dirty_files"), MAX_DIRTY_FILES)
    relevant_paths = _sorted_path_values(sibling_repo.get("relevant_paths"), MAX_LIST_ITEMS)
    lock_status = beads_lock.get("status")
    mail_status = agent_mail.get("status")
    requires_soft_lock = mail_status in {"red_corrupt", "unavailable"} or lock_status != "ok"

    payload: dict[str, Any] = {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "snapshot_id": snapshot.get("snapshot_id"),
        "bead_id": snapshot.get("bead_id"),
        "thread_id": snapshot.get("thread_id"),
        "classification_code": classification.get("code"),
        "next_safest_action": recommended_action.get("action"),
        "exact_deferred_rch_command": _validation_command_string(snapshot),
        "recommended_command": _canonical_command(snapshot),
        "operator_message": classification.get("operator_message"),
        "command_digest": command_digest.get("hex"),
        "cargo_pressure": {
            "process_count": cargo_pressure.get("process_count"),
            "threshold": cargo_pressure.get("threshold"),
            "sampled_at": cargo_pressure.get("sampled_at"),
        },
        "sibling_repo": {
            "name": sibling_repo.get("name"),
            "path": sibling_repo.get("path"),
            "branch": sibling_repo.get("branch"),
            "head": sibling_repo.get("head"),
            "dirty_state": sibling_repo.get("dirty_state"),
            "relevant_paths": relevant_paths,
        },
        "ownership_uncertainty": {
            "requires_beads_soft_lock": requires_soft_lock,
            "sibling_beads_lock_status": lock_status,
            "sibling_beads_lock_detail": beads_lock.get("detail"),
            "agent_mail_status": mail_status,
            "agent_mail_detail": agent_mail.get("detail"),
        },
        "active_dirty_file_summary": {
            "dirty_state": sibling_repo.get("dirty_state"),
            "count": len(dirty_files),
            "files": dirty_files,
        },
        "mail_targeting": {
            "broadcast": False,
            "recipient_scope": "relevant_bead_owner_or_sibling_repo_owner",
        },
    }
    payload["markdown"] = render_handoff_markdown(payload)
    return payload


def validate_handoff_payload(payload: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["ERR_CRVD_BAD_HANDOFF"]
    if payload.get("schema_version") != HANDOFF_SCHEMA_VERSION:
        errors.append("ERR_CRVD_BAD_HANDOFF")
    if payload.get("classification_code") not in CLASSIFICATION_CODES:
        errors.append("ERR_CRVD_BAD_HANDOFF")
    if payload.get("next_safest_action") not in RECOMMENDED_ACTIONS:
        errors.append("ERR_CRVD_BAD_HANDOFF")
    for field in [
        "snapshot_id",
        "bead_id",
        "thread_id",
        "exact_deferred_rch_command",
        "recommended_command",
        "operator_message",
        "command_digest",
    ]:
        if not _bounded_string(payload.get(field)):
            errors.append("ERR_CRVD_BAD_HANDOFF")
    if not _is_sha256_hex(payload.get("command_digest")):
        errors.append("ERR_CRVD_BAD_HANDOFF")
    dirty_files = _get_path(payload, "active_dirty_file_summary.files")
    relevant_paths = _get_path(payload, "sibling_repo.relevant_paths")
    if not _list_of_bounded_paths(dirty_files, MAX_DIRTY_FILES) or not _sorted_unique_strings(dirty_files):
        errors.append("ERR_CRVD_BAD_HANDOFF")
    if not _list_of_bounded_paths(relevant_paths, MAX_LIST_ITEMS) or not _sorted_unique_strings(relevant_paths):
        errors.append("ERR_CRVD_BAD_HANDOFF")
    broadcast = _get_path(payload, "mail_targeting.broadcast")
    if not isinstance(broadcast, bool) or broadcast:
        errors.append("ERR_CRVD_BAD_HANDOFF")

    markdown = payload.get("markdown")
    if not _bounded_string(markdown, MAX_HANDOFF_MARKDOWN_BYTES):
        errors.append("ERR_CRVD_BAD_HANDOFF")
    elif not all(
        str(payload.get(field)) in markdown
        for field in ["bead_id", "classification_code", "exact_deferred_rch_command", "next_safest_action"]
    ):
        errors.append("ERR_CRVD_BAD_HANDOFF")

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_HANDOFF_JSON_BYTES:
        errors.append("ERR_CRVD_BAD_HANDOFF")
    return list(dict.fromkeys(errors))


def validate_snapshot(snapshot: Any, *, expected_bead_id: str | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(snapshot, dict):
        return ["ERR_CRVD_MALFORMED_SNAPSHOT"]

    for field in REQUIRED_FIELDS:
        if field not in snapshot:
            errors.append("ERR_CRVD_MISSING_FIELD")

    errors.extend(_collect_bound_errors(snapshot))

    if snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        errors.append("ERR_CRVD_UNSUPPORTED_SCHEMA")

    snapshot_id = snapshot.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        errors.append("ERR_CRVD_BAD_ID")

    bead_id = snapshot.get("bead_id")
    thread_id = snapshot.get("thread_id")
    if not isinstance(bead_id, str) or not BEAD_RE.fullmatch(bead_id):
        errors.append("ERR_CRVD_BAD_ID")
    if not isinstance(thread_id, str) or not BEAD_RE.fullmatch(thread_id):
        errors.append("ERR_CRVD_BAD_ID")
    if expected_bead_id is not None and bead_id != expected_bead_id:
        errors.append("ERR_CRVD_BEAD_MISMATCH")
    if isinstance(bead_id, str) and isinstance(thread_id, str) and bead_id != thread_id:
        errors.append("ERR_CRVD_BEAD_MISMATCH")

    if _parse_rfc3339(snapshot.get("generated_at")) is None:
        errors.append("ERR_CRVD_BAD_TIMESTAMP")

    producer = snapshot.get("producer")
    if not isinstance(producer, dict) or producer.get("source_only") is not True:
        errors.append("ERR_CRVD_PRODUCER_NOT_SOURCE_ONLY")

    command = snapshot.get("validation_command")
    if not isinstance(command, dict):
        errors.append("ERR_CRVD_BAD_COMMAND")
    else:
        argv = command.get("argv")
        if not _bounded_string(command.get("program"), 64):
            errors.append("ERR_CRVD_BAD_COMMAND")
        if not isinstance(argv, list) or not argv or len(argv) > 64:
            errors.append("ERR_CRVD_BAD_COMMAND")
        elif not all(_bounded_string(item, 240) for item in argv):
            errors.append("ERR_CRVD_BAD_COMMAND")
        if not _bounded_path(command.get("cwd")):
            errors.append("ERR_CRVD_BAD_COMMAND")
        if not isinstance(command.get("remote_required"), bool):
            errors.append("ERR_CRVD_BAD_COMMAND")
        if command.get("remote_required"):
            if command.get("program") != "rch" or not isinstance(argv, list) or not argv or argv[0] != "exec":
                errors.append("ERR_CRVD_REMOTE_REQUIRED_LOCAL_FALLBACK")

    digest = snapshot.get("command_digest")
    if not isinstance(digest, dict):
        errors.append("ERR_CRVD_BAD_COMMAND_DIGEST")
    else:
        algorithm = digest.get("algorithm")
        canonical_material = digest.get("canonical_material")
        if (
            not isinstance(algorithm, str)
            or not hmac.compare_digest(algorithm, "sha256")
            or not _is_sha256_hex(digest.get("hex"))
        ):
            errors.append("ERR_CRVD_BAD_COMMAND_DIGEST")
        if not _bounded_string(canonical_material):
            errors.append("ERR_CRVD_BAD_COMMAND_DIGEST")
        expected_material = _expected_command_material(command)
        if isinstance(canonical_material, str) and isinstance(expected_material, str):
            if not hmac.compare_digest(canonical_material, expected_material):
                errors.append("ERR_CRVD_COMMAND_DIGEST_MISMATCH")
        digest_hex = digest.get("hex")
        if _is_sha256_hex(digest_hex) and isinstance(canonical_material, str):
            computed = hashlib.sha256(canonical_material.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(computed, digest_hex):
                errors.append("ERR_CRVD_COMMAND_DIGEST_MISMATCH")

    cargo_pressure = snapshot.get("cargo_pressure")
    cargo_count = None
    cargo_threshold = None
    if not isinstance(cargo_pressure, dict):
        errors.append("ERR_CRVD_BAD_CARGO_PRESSURE")
    else:
        cargo_count = cargo_pressure.get("process_count")
        cargo_threshold = cargo_pressure.get("threshold")
        if not isinstance(cargo_count, int) or cargo_count < 0:
            errors.append("ERR_CRVD_BAD_CARGO_PRESSURE")
        if not isinstance(cargo_threshold, int) or cargo_threshold < 0:
            errors.append("ERR_CRVD_BAD_CARGO_PRESSURE")
        if _parse_rfc3339(cargo_pressure.get("sampled_at")) is None:
            errors.append("ERR_CRVD_BAD_TIMESTAMP")

    sibling_repo = snapshot.get("sibling_repo")
    dirty_state = None
    beads_lock_status = None
    if not isinstance(sibling_repo, dict):
        errors.append("ERR_CRVD_BAD_SIBLING_REPO")
    else:
        if not _bounded_string(sibling_repo.get("name"), 128):
            errors.append("ERR_CRVD_BAD_SIBLING_REPO")
        if not _bounded_path(sibling_repo.get("path")):
            errors.append("ERR_CRVD_BAD_SIBLING_REPO")
        if not _bounded_string(sibling_repo.get("branch"), 128):
            errors.append("ERR_CRVD_BAD_SIBLING_REPO")
        if not _bounded_string(sibling_repo.get("head"), 128):
            errors.append("ERR_CRVD_BAD_SIBLING_REPO")
        dirty_state = sibling_repo.get("dirty_state")
        if dirty_state not in DIRTY_STATES:
            errors.append("ERR_CRVD_BAD_DIRTY_STATE")
        dirty_files = sibling_repo.get("dirty_files")
        if not _list_of_bounded_paths(dirty_files, MAX_DIRTY_FILES):
            errors.append("ERR_CRVD_UNBOUNDED_LIST")
        elif not _sorted_unique_strings(dirty_files):
            errors.append("ERR_CRVD_UNSORTED_LIST")
        relevant_paths = sibling_repo.get("relevant_paths")
        if not _list_of_bounded_paths(relevant_paths, MAX_LIST_ITEMS):
            errors.append("ERR_CRVD_BAD_SIBLING_REPO")
        elif not _sorted_unique_strings(relevant_paths):
            errors.append("ERR_CRVD_UNSORTED_LIST")
        lock = sibling_repo.get("beads_lock")
        if not isinstance(lock, dict):
            errors.append("ERR_CRVD_BAD_BEADS_LOCK")
        else:
            beads_lock_status = lock.get("status")
            if beads_lock_status not in BEADS_LOCK_STATUSES:
                errors.append("ERR_CRVD_BAD_BEADS_LOCK")
            if not _bounded_string(lock.get("detail")):
                errors.append("ERR_CRVD_BAD_BEADS_LOCK")

    symbol_probes = snapshot.get("symbol_probes")
    if not isinstance(symbol_probes, list) or not symbol_probes or len(symbol_probes) > MAX_SYMBOL_PROBES:
        errors.append("ERR_CRVD_BAD_SYMBOL_PROBES")
    else:
        for probe in symbol_probes:
            if not isinstance(probe, dict):
                errors.append("ERR_CRVD_BAD_SYMBOL_PROBES")
                continue
            status = probe.get("status")
            referenced_paths = probe.get("referenced_paths")
            if not _bounded_string(probe.get("symbol"), 256):
                errors.append("ERR_CRVD_BAD_SYMBOL_PROBES")
            if status not in SYMBOL_STATUSES:
                errors.append("ERR_CRVD_BAD_SYMBOL_PROBES")
            if not _list_of_bounded_paths(probe.get("searched_paths"), MAX_LIST_ITEMS):
                errors.append("ERR_CRVD_BAD_SYMBOL_PROBES")
            elif not _sorted_unique_strings(probe.get("searched_paths")):
                errors.append("ERR_CRVD_UNSORTED_LIST")
            if not _list_of_bounded_paths(referenced_paths, MAX_LIST_ITEMS):
                errors.append("ERR_CRVD_BAD_SYMBOL_PROBES")
            elif not _sorted_unique_strings(referenced_paths):
                errors.append("ERR_CRVD_UNSORTED_LIST")
            if status == "absent_from_call_sites" and referenced_paths:
                errors.append("ERR_CRVD_SYMBOL_STATE_MISMATCH")
            if status == "missing_referenced" and not referenced_paths:
                errors.append("ERR_CRVD_SYMBOL_STATE_MISMATCH")

    agent_mail = snapshot.get("agent_mail")
    if not isinstance(agent_mail, dict):
        errors.append("ERR_CRVD_BAD_AGENT_MAIL")
    else:
        if agent_mail.get("status") not in AGENT_MAIL_STATUSES:
            errors.append("ERR_CRVD_BAD_AGENT_MAIL")
        if not _bounded_string(agent_mail.get("detail")):
            errors.append("ERR_CRVD_BAD_AGENT_MAIL")

    classification = snapshot.get("classification")
    classification_code = None
    if not isinstance(classification, dict):
        errors.append("ERR_CRVD_BAD_CLASSIFICATION")
    else:
        classification_code = classification.get("code")
        if classification_code not in CLASSIFICATION_CODES:
            errors.append("ERR_CRVD_BAD_CLASSIFICATION")
        reasons = classification.get("reasons")
        if not isinstance(reasons, list) or not reasons or len(reasons) > 16:
            errors.append("ERR_CRVD_BAD_CLASSIFICATION")
        elif not all(_bounded_string(reason, 240) for reason in reasons):
            errors.append("ERR_CRVD_BAD_CLASSIFICATION")
        if not _bounded_string(classification.get("operator_message")):
            errors.append("ERR_CRVD_BAD_CLASSIFICATION")

    recommended_action = snapshot.get("recommended_action")
    action = None
    if not isinstance(recommended_action, dict):
        errors.append("ERR_CRVD_BAD_ACTION")
    else:
        action = recommended_action.get("action")
        if action not in RECOMMENDED_ACTIONS:
            errors.append("ERR_CRVD_BAD_ACTION")
        if not _bounded_string(recommended_action.get("exact_command")):
            errors.append("ERR_CRVD_BAD_ACTION")

    if action == "run_rch_validation":
        if isinstance(cargo_count, int) and isinstance(cargo_threshold, int) and cargo_count > cargo_threshold:
            errors.append("ERR_CRVD_CARGO_PRESSURE_RUN")
        if dirty_state == "dirty_relevant":
            errors.append("ERR_CRVD_DIRTY_RELEVANT_RUN")
        if beads_lock_status in {"timeout", "stale_file", "unavailable"}:
            errors.append("ERR_CRVD_BEADS_LOCK_RUN")
        if any(
            isinstance(probe, dict) and probe.get("status") == "missing_referenced"
            for probe in (symbol_probes if isinstance(symbol_probes, list) else [])
        ):
            errors.append("ERR_CRVD_API_DRIFT_RUN")

    if classification_code == "CRVD_SAFE_TO_RUN" and action != "run_rch_validation":
        errors.append("ERR_CRVD_SAFE_WITHOUT_RUN_ACTION")

    if not errors:
        derived = derive_classification(snapshot)
        if classification_code != derived["code"] or action != derived["action"]:
            errors.append("ERR_CRVD_CLASSIFICATION_DERIVATION_MISMATCH")

    return list(dict.fromkeys(errors))


def _fixture_cases(fixtures: dict[str, Any]) -> list[dict[str, Any]]:
    valid = fixtures.get("valid_snapshots", [])
    return valid if isinstance(valid, list) else []


def run_self_test() -> list[dict[str, Any]]:
    fixtures = _load_json(FIXTURES_FILE)
    valid = _fixture_cases(fixtures)
    if not valid:
        return [_check("self_test.fixtures_present", False, "no valid snapshots")]

    checks: list[dict[str, Any]] = []
    base = valid[0]
    mutated = apply_fixture_patch(base, {"set": {"cargo_pressure.process_count": 99}})
    checks.append(_check(
        "self_test.cargo_pressure_blocks_run",
        "ERR_CRVD_CARGO_PRESSURE_RUN" in validate_snapshot(mutated),
    ))
    mutated = apply_fixture_patch(base, {"set": {"symbol_probes.0.status": "absent_from_call_sites"}})
    checks.append(_check(
        "self_test.absent_symbol_rejects_references",
        "ERR_CRVD_SYMBOL_STATE_MISMATCH" in validate_snapshot(mutated),
    ))
    mutated = apply_fixture_patch(base, {"remove": ["producer.source_only"]})
    checks.append(_check(
        "self_test.source_only_required",
        "ERR_CRVD_PRODUCER_NOT_SOURCE_ONLY" in validate_snapshot(mutated),
    ))
    return checks


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    schema = _load_json(SCHEMA_FILE)
    fixtures = _load_json(FIXTURES_FILE)

    checks.append(_check("files.schema_exists", SCHEMA_FILE.is_file(), str(SCHEMA_FILE)))
    checks.append(_check("files.fixtures_exists", FIXTURES_FILE.is_file(), str(FIXTURES_FILE)))
    checks.append(_check("files.script_exists", SCRIPT_FILE.is_file(), str(SCRIPT_FILE)))
    checks.append(_check("files.tests_exists", TEST_FILE.is_file(), str(TEST_FILE)))
    checks.append(_check(
        "schema.catalog_version",
        schema.get("schema_version") == SCHEMA_CATALOG_VERSION,
        str(schema.get("schema_version")),
    ))
    checks.append(_check(
        "schema.snapshot_version",
        schema.get("snapshot_schema_version") == SNAPSHOT_SCHEMA_VERSION,
        str(schema.get("snapshot_schema_version")),
    ))
    checks.append(_check(
        "fixtures.schema_version",
        fixtures.get("schema_version") == FIXTURE_SCHEMA_VERSION,
        str(fixtures.get("schema_version")),
    ))

    valid_snapshots = _fixture_cases(fixtures)
    checks.append(_check("fixtures.valid_snapshot_count", len(valid_snapshots) >= 5, str(len(valid_snapshots))))

    coverage = {
        "CRVD_SAFE_TO_RUN": False,
        "CRVD_BLOCKED_CARGO_PRESSURE": False,
        "CRVD_BLOCKED_SIBLING_DIRTY_RELEVANT": False,
        "CRVD_BLOCKED_SIBLING_API_DRIFT": False,
        "CRVD_BLOCKED_SIBLING_BEADS_LOCK": False,
        "CRVD_BLOCKED_AGENT_MAIL_CORRUPT": False,
        "CRVD_NEEDS_RCH_REPROOF": False,
    }
    absent_symbol_seen = False
    dirty_relevant_seen = False
    dirty_unrelated_seen = False
    missing_referenced_seen = False
    beads_lock_timeout_seen = False
    agent_mail_corrupt_seen = False
    cargo_pressure_seen = False
    for index, snapshot in enumerate(valid_snapshots):
        errors = validate_snapshot(snapshot)
        checks.append(_check(
            f"valid_snapshot.{index}.passes",
            errors == [],
            ",".join(errors),
        ))
        handoff = build_handoff_payload(snapshot)
        handoff_errors = validate_handoff_payload(handoff)
        checks.append(_check(
            f"handoff.{snapshot.get('snapshot_id', index)}.passes",
            handoff_errors == [],
            ",".join(handoff_errors),
        ))
        checks.append(_check(
            f"handoff.{snapshot.get('snapshot_id', index)}.deterministic",
            handoff == build_handoff_payload(snapshot),
        ))
        code = _get_path(snapshot, "classification.code")
        if code in coverage:
            coverage[code] = True
        dirty_state = _get_path(snapshot, "sibling_repo.dirty_state")
        if dirty_state == "dirty_relevant":
            dirty_relevant_seen = True
        if dirty_state == "dirty_unrelated":
            dirty_unrelated_seen = True
        if _get_path(snapshot, "sibling_repo.beads_lock.status") in {"timeout", "stale_file"}:
            beads_lock_timeout_seen = True
        if _get_path(snapshot, "agent_mail.status") == "red_corrupt":
            agent_mail_corrupt_seen = True
        cargo_count = _get_path(snapshot, "cargo_pressure.process_count")
        cargo_threshold = _get_path(snapshot, "cargo_pressure.threshold")
        if isinstance(cargo_count, int) and isinstance(cargo_threshold, int) and cargo_count > cargo_threshold:
            cargo_pressure_seen = True
        for probe in snapshot.get("symbol_probes", []) if isinstance(snapshot, dict) else []:
            if isinstance(probe, dict) and probe.get("status") == "absent_from_call_sites":
                absent_symbol_seen = True
            if isinstance(probe, dict) and probe.get("status") == "missing_referenced":
                missing_referenced_seen = True

    for code, seen in coverage.items():
        checks.append(_check(f"coverage.{code}", seen))
    checks.append(_check("coverage.dirty_relevant_fixture", dirty_relevant_seen))
    checks.append(_check("coverage.dirty_unrelated_fixture", dirty_unrelated_seen))
    checks.append(_check("coverage.absent_symbol_fixture", absent_symbol_seen))
    checks.append(_check("coverage.missing_referenced_symbol_fixture", missing_referenced_seen))
    checks.append(_check("coverage.beads_lock_timeout_fixture", beads_lock_timeout_seen))
    checks.append(_check("coverage.agent_mail_corrupt_fixture", agent_mail_corrupt_seen))
    checks.append(_check("coverage.cargo_pressure_fixture", cargo_pressure_seen))

    invalid_snapshots = fixtures.get("invalid_snapshots", [])
    checks.append(_check(
        "fixtures.invalid_snapshot_count",
        isinstance(invalid_snapshots, list) and len(invalid_snapshots) >= 6,
        str(len(invalid_snapshots)) if isinstance(invalid_snapshots, list) else "not-list",
    ))
    base = valid_snapshots[0] if valid_snapshots else {}
    for case in invalid_snapshots if isinstance(invalid_snapshots, list) else []:
        snapshot = case.get("snapshot", apply_fixture_patch(base, case.get("patch")))
        errors = validate_snapshot(snapshot)
        expected_error = case.get("expected_error")
        checks.append(_check(
            f"invalid_snapshot.{case.get('case', 'unknown')}",
            expected_error in errors,
            ",".join(errors),
        ))

    self_test_checks = run_self_test()
    checks.extend(self_test_checks)

    passed = sum(1 for check in checks if check["passed"])
    total = len(checks)
    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "verdict": "PASS" if passed == total else "FAIL",
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="run self-test checks")
    parser.add_argument("--handoff", metavar="SNAPSHOT_ID", help="emit a fixture handoff payload")
    parser.add_argument(
        "--handoff-format",
        choices=["json", "markdown"],
        default="json",
        help="handoff output format",
    )
    args = parser.parse_args()

    configure_test_logging("check_cross_repo_validation_drift")

    if args.handoff:
        fixtures = _load_json(FIXTURES_FILE)
        snapshot = next(
            (
                item
                for item in _fixture_cases(fixtures)
                if isinstance(item, dict) and item.get("snapshot_id") == args.handoff
            ),
            None,
        )
        if snapshot is None:
            result = {
                "bead_id": BEAD_ID,
                "title": TITLE,
                "schema_version": HANDOFF_SCHEMA_VERSION,
                "verdict": "FAIL",
                "error": "ERR_CRVD_HANDOFF_SNAPSHOT_NOT_FOUND",
            }
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print("FAIL ERR_CRVD_HANDOFF_SNAPSHOT_NOT_FOUND")
            return 1
        snapshot_errors = validate_snapshot(snapshot)
        payload = build_handoff_payload(snapshot)
        handoff_errors = validate_handoff_payload(payload)
        if snapshot_errors or handoff_errors:
            result = {
                "bead_id": snapshot.get("bead_id"),
                "title": TITLE,
                "schema_version": HANDOFF_SCHEMA_VERSION,
                "verdict": "FAIL",
                "errors": snapshot_errors + handoff_errors,
            }
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"FAIL {','.join(result['errors'])}")
            return 1
        if args.handoff_format == "markdown" and not args.json:
            print(payload["markdown"])
        else:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.self_test:
        checks = run_self_test()
        result = {
            "bead_id": BEAD_ID,
            "title": TITLE,
            "schema_version": FIXTURE_SCHEMA_VERSION,
            "verdict": "PASS" if all(check["passed"] for check in checks) else "FAIL",
            "total": len(checks),
            "passed": sum(1 for check in checks if check["passed"]),
            "failed": sum(1 for check in checks if not check["passed"]),
            "checks": checks,
        }
    else:
        result = run_all()

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result['verdict']} {result['title']}: {result['passed']}/{result['total']} checks")
        for check in result["checks"]:
            if not check["passed"]:
                print(f"FAIL {check['check']}: {check['detail']}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
