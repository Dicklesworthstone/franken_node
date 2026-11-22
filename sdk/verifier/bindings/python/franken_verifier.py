"""Offline verifier API. Requires a trusted, separately installed franken-verifier.

Artifact bytes are sent unchanged to the independent Rust SDK. This module
does not load the product/engine, discover trust anchors from evidence, or
execute a captured guest. Only Python's standard library is required.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import subprocess
from typing import Any, Literal, TypedDict

PROTOCOL = "franken-verifier-cli/v1"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_NATIVE_SESSION_INPUT_BYTES = 96 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 + 1
EvidenceFormat = Literal[
    "incident-bundle", "native-session-forensics", "capsule", "signed-bundle", "signed-session", "resolution-receipt",
    "publisher-source", "publisher-source-trust", "counterfactual-receipt", "ltv-evidence",
]
_SCOPES = {
    "incident-bundle": "authenticated_recorded_incident",
    "native-session-forensics": "authenticated_supervisor_observations",
    "capsule": "authenticated_capsule_content",
    "signed-bundle": "authenticated_sdk_replay_bundle",
    "signed-session": "authenticated_verification_session",
    "resolution-receipt": "authenticated_resolution_decision",
    "publisher-source": "authenticated_publisher_source_content",
    "publisher-source-trust": "authenticated_publisher_source_trust",
    "counterfactual-receipt": "authenticated_counterfactual_receipt",
    "ltv-evidence": "authenticated_ltv_anteriority",
}


class Verification(TypedDict):
    schema_version: str
    verdict: Literal["verified"]
    format: EvidenceFormat
    scope: Literal["authenticated_recorded_incident", "authenticated_run_incident",
                   "authenticated_runtime_incident", "authenticated_supervisor_observations",
                   "authenticated_capsule_content", "authenticated_sdk_replay_bundle",
                   "authenticated_verification_session",
                   "authenticated_resolution_decision", "authenticated_publisher_source_content",
                   "authenticated_publisher_source_trust",
                   "authenticated_counterfactual_receipt", "authenticated_ltv_anteriority"]
    artifact_sha256: str
    facts: dict[str, Any]


class SignedSessionFacts(TypedDict):
    """Authentic recorded decisions; a verified signature does not imply pass."""

    session_id: str
    verifier_identity: str
    created_at: str
    final_verdict: Literal["pass", "fail", "inconclusive"]
    step_count: int
    transcript_hash: str
    signer_public_key_hex: str


class RunOriginMetadata(TypedDict):
    """Original receipt-authority statement; not an engine execution verdict."""

    receipt_id: str
    receipt_hash: str
    signer_public_key_hex: str
    record_sha256: str


class RuntimeOriginMetadata(TypedDict):
    """Product-root and session authenticated ledger; not execution or cleanup."""

    session_nonce: str
    product_root_key_id: str
    producer_id: str
    evidence_key_id: str
    signed_epoch: str


class NativeSessionEffectJournalFacts(TypedDict):
    """Authenticated retained prefix, with no historical-completeness claim."""

    schema_version: Literal["franken-node/native-effect-journal-record/v1"]
    scope: Literal["host_io_provider_calls"]
    session_nonce: str
    product_root_key_id: str
    admission_sha256: str
    record_count: int
    event_count: int
    admitted_provider_calls: int
    returned_provider_calls: int
    indeterminate_provider_calls: int
    head_record_sha256: str
    trailing_partial_record: bool
    replay_certified: Literal[False]
    quiescence_certified: Literal[False]
    historical_completeness: Literal[False]


class SourceCapsuleSummary(TypedDict):
    """Authenticated captured content; no module-graph reconstruction claim."""

    schema_version: Literal["franken-node/module-source-capsule/v1"]
    graph_input_hash: str
    graph_hash_recomputed: Literal[False]
    capsule_bytes: int
    payload_bytes: int
    input_count: int
    file_count: int
    metadata_file_count: int
    directory_count: int
    missing_count: int
    symlink_count: int
    symlink_policy: Literal["reject", "contained"]
    condition_count: int | None
    additional_condition_count: int


class _NativeSessionSourceFacts(TypedDict, total=False):
    # Required by v3 and absent from v1/v2; checked before returning a result.
    source_capsule: SourceCapsuleSummary


class NativeSessionForensicsFacts(_NativeSessionSourceFacts):
    """Supervisor observations; unknown outcome fields remain None."""

    schema_version: Literal["franken-node/native-session-forensics/v1",
                            "franken-node/native-session-forensics/v2",
                            "franken-node/native-session-forensics/v3"]
    scope: Literal["authenticated_supervisor_observations"]
    session_nonce: str
    product_root_key_id: str
    admission_sha256: str
    project_root: str
    entrypoint: str
    security_epoch: str
    admitted_at: str
    observed_at: str | None
    outcome_kind: Literal["pending", "completed", "execution_failed", "control_stopped",
                          "interrupted", "telemetry_failed", "panicked", "supervision_incomplete"]
    process_observation: Literal["not_spawned", "worker_reaped", "unproven"] | None
    effect_observation: Literal["not_started", "no_admitted_host_effects",
                                "final_ledger_observed", "interrupted", "unknown"] | None
    containment_empty_observed: bool | None
    completed_provider_calls: int | None
    indeterminate_provider_calls: int | None
    final_ledger_effect_count: int | None
    failed_effect_count: int | None
    journal_complete: bool | None
    durable_journal: NativeSessionEffectJournalFacts | None
    replay_certified: Literal[False]
    quiescence_certified: Literal[False]
    historical_completeness: Literal[False]


class VerifierError(Exception):
    """Typed verification, input, process or protocol rejection; never success."""

    def __init__(self, code: str, message: str, *, exit_code: int | None = None,
                 stderr: bytes = b"") -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        self.stderr = stderr


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response member")
        result[key] = value
    return result


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and re.fullmatch(f"[0-9a-fA-F]{{{length}}}", value) is not None


def _bounded_text(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return len(value.encode("utf-8")) <= 4096
    except UnicodeEncodeError:
        return False


def _run_origin_valid(origin: Any, anchor: str) -> bool:
    return (
        isinstance(origin, dict)
        and set(origin) == {"receipt_id", "receipt_hash", "signer_public_key_hex", "record_sha256"}
        and isinstance(origin["receipt_id"], str)
        and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", origin["receipt_id"]) is not None
        and isinstance(origin["receipt_hash"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", origin["receipt_hash"]) is not None
        and origin["signer_public_key_hex"] == anchor
        and isinstance(origin["record_sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", origin["record_sha256"]) is not None
    )


def _runtime_origin_valid(origin: Any, anchor: str) -> bool:
    return (
        isinstance(origin, dict)
        and set(origin) == {"session_nonce", "product_root_key_id", "producer_id", "evidence_key_id", "signed_epoch"}
        and isinstance(origin["session_nonce"], str)
        and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", origin["session_nonce"]) is not None
        and origin["product_root_key_id"] == f"ed25519:{anchor}"
        and isinstance(origin["producer_id"], str) and 0 < len(origin["producer_id"]) <= 512
        and isinstance(origin["evidence_key_id"], str)
        and re.fullmatch(r"ed25519:[0-9a-f]{64}", origin["evidence_key_id"]) is not None
        and isinstance(origin["signed_epoch"], str)
        and re.fullmatch(r"0|[1-9][0-9]{0,19}", origin["signed_epoch"]) is not None
        and int(origin["signed_epoch"]) <= 2**64 - 1
    )


_PUBLISHER_CAPABILITIES = {
    "builtin", "console", "env_read", "fs_read", "fs_write", "heap_allocate",
    "module_load", "network_egress", "process_spawn", "random_read", "timer", "vm_dispatch",
}
_PUBLISHER_LIMITS = {
    "max_instructions": 2**64 - 1, "max_registers": 65536, "max_call_depth": 10000,
    "max_heap_objects": 2**32 - 1, "max_total_memory_bytes": 2**64 - 1,
    "max_console_entries": 2**32 - 1, "max_parse_source_bytes": 2097152,
    "max_parse_tokens": 131072, "max_parse_recursion_depth": 384,
}


def _publisher_text(value: Any, limit: int) -> bool:
    return (_bounded_text(value) and value == value.strip()
            and len(value.encode("utf-8")) <= limit
            and re.search(r"[\x00-\x1f\x7f-\x9f]", value) is None)


def _digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _decimal_limit(value: Any, limit: int) -> bool:
    return (isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None
            and int(value) <= limit)


def _instant_ns(value: Any) -> int | None:
    """Parse four-digit RFC3339 years and non-leap seconds without rounding."""
    if not isinstance(value, str) or len(value) > 35:
        return None
    match = re.fullmatch(
        r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
        r"(?:\.([0-9]{1,9}))?([Zz]|[+-][0-9]{2}:[0-9]{2})", value,
    )
    if match is None:
        return None
    year, month, day, hour, minute, second = map(int, match.group(1, 2, 3, 4, 5, 6))
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    months = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if not (1 <= month <= 12 and 1 <= day <= months[month - 1]
            and hour < 24 and minute < 60 and second < 60):
        return None
    zone = match.group(8)
    offset = 0
    if zone not in ("Z", "z"):
        offset_hour, offset_minute = int(zone[1:3]), int(zone[4:6])
        if offset_hour >= 24 or offset_minute >= 60:
            return None
        offset = (offset_hour * 60 + offset_minute) * 60
        if zone[0] == "-":
            offset = -offset
    # Count Gregorian leap years from year zero; supports the whole RFC range.
    def days_before_year(y: int) -> int:
        return 365 * y + (y + 3) // 4 - (y + 99) // 100 + (y + 399) // 400
    days = days_before_year(year) - days_before_year(1970) + sum(months[:month - 1]) + day - 1
    seconds = days * 86400 + hour * 3600 + minute * 60 + second - offset
    return seconds * 1_000_000_000 + int((match.group(7) or "").ljust(9, "0"))


def _publisher_source_trust_valid(
    facts: Any, anchor: str, revocation_anchor: str | None, provenance_anchor: str | None,
    evaluation_time: str | None, max_age: str | None,
) -> bool:
    if not isinstance(facts, dict) or set(facts) != {
        "source", "revocation_list_sha256", "revocation_authority_public_key_hex",
        "revocation_issued_at", "revocation_evaluated_at", "max_revocation_age_secs",
        "provenance_chain_sha256", "provenance_authority_public_key_hex", "provenance_link_count",
    }:
        return False
    evaluated = _instant_ns(facts["revocation_evaluated_at"])
    issued = _instant_ns(facts["revocation_issued_at"])
    if (revocation_anchor is None or evaluated is None or issued is None
            or evaluated != _instant_ns(evaluation_time)
            or not _decimal_limit(max_age, 2**64 - 1)
            or facts["max_revocation_age_secs"] != max_age
            or not 0 <= evaluated - issued < int(max_age) * 1_000_000_000
            or not _digest(facts["revocation_list_sha256"])
            or facts["revocation_authority_public_key_hex"] != revocation_anchor
            or not _facts_valid(facts["source"], "publisher-source", anchor, None, None)):
        return False
    if provenance_anchor is None:
        return all(facts[name] is None for name in (
            "provenance_chain_sha256", "provenance_authority_public_key_hex", "provenance_link_count",
        ))
    return (
        _digest(facts["provenance_chain_sha256"])
        and facts["provenance_authority_public_key_hex"] == provenance_anchor
        and type(facts["provenance_link_count"]) is int
        and 1 <= facts["provenance_link_count"] <= 256
    )


def _publisher_endpoint_valid(value: Any) -> bool:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or not value.isascii() or any(ord(char) < 33 or ord(char) == 127 or char in "*?#@/" for char in value)):
        return False
    if value.startswith("["):
        address, separator, rest = value[1:].partition("]")
        if not separator or not rest.startswith(":") or "%" in address:
            return False
        try:
            ipaddress.IPv6Address(address)
        except ValueError:
            return False
        host, port = f"[{address.lower()}]", rest[1:]
    else:
        host, separator, port = value.rpartition(":")
        if not separator or not host or ":" in host:
            return False
        host = host.lower()
    return (re.fullmatch(r"[1-9][0-9]{0,4}", port) is not None
            and int(port) <= 65535 and value == f"{host}:{port}")


def _publisher_host_authority_valid(host: Any, capabilities: list[str], max_instructions: str) -> bool:
    if (not isinstance(host, dict) or "max_calls_per_epoch" not in host
            or set(host) - {"host_ports", "env_keys", "max_calls_per_epoch"}):
        return False
    for name, capability, valid in (
        ("host_ports", "network_egress", _publisher_endpoint_valid),
        ("env_keys", "env_read", lambda value: isinstance(value, str)
         and re.fullmatch(r"[A-Za-z0-9_]{1,128}", value) is not None),
    ):
        if name in host:
            values = host[name]
            if (capability not in capabilities or not isinstance(values, list) or len(values) > 128
                    or not all(valid(value) for value in values)
                    or any(left >= right for left, right in zip(values, values[1:]))):
                return False
    quotas = host["max_calls_per_epoch"]
    return (isinstance(quotas, dict) and len(quotas) <= 6
            and all(capability in {"fs_read", "fs_write", "network_egress", "random_read", "env_read", "process_spawn"}
                    and capability in capabilities and isinstance(limit, str)
                    and re.fullmatch(r"0|[1-9][0-9]{0,19}", limit) is not None
                    and int(limit) <= int(max_instructions)
                    for capability, limit in quotas.items()))


def _publisher_authority_valid(authority: Any) -> bool:
    if not isinstance(authority, dict) or set(authority) - {"host_io"} != {
        "schema_version", "policy_revision", "allowed_capabilities", "allow_process_shape",
        *_PUBLISHER_LIMITS,
    }:
        return False
    capabilities = authority["allowed_capabilities"]
    return (
        authority["schema_version"] == "franken-node/artifact-runtime-authority/v1"
        and _publisher_text(authority["policy_revision"], 128)
        and type(authority["allow_process_shape"]) is bool
        and isinstance(capabilities, list) and len(capabilities) <= len(_PUBLISHER_CAPABILITIES)
        and all(isinstance(value, str) and value in _PUBLISHER_CAPABILITIES for value in capabilities)
        and len(set(capabilities)) == len(capabilities)
        and {"console", "heap_allocate", "vm_dispatch"}.issubset(capabilities)
        and all(_decimal_limit(authority[name], limit) for name, limit in _PUBLISHER_LIMITS.items())
        and ("host_io" not in authority or _publisher_host_authority_valid(
            authority["host_io"], capabilities, authority["max_instructions"]))
    )


def _source_capsule_valid(summary: Any, capsule_limit: int, payload_limit: int) -> bool:
    counts = ("file_count", "metadata_file_count", "directory_count", "missing_count", "symlink_count")
    if not isinstance(summary, dict) or set(summary) != {
        "schema_version", "graph_input_hash", "graph_hash_recomputed", "capsule_bytes", "payload_bytes",
        "input_count", *counts, "symlink_policy", "condition_count", "additional_condition_count",
    }:
        return False
    if not all(type(summary[name]) is int and 0 <= summary[name] <= 1024
               for name in ("input_count", *counts)):
        return False
    condition_count = summary["condition_count"]
    additional_count = summary["additional_condition_count"]
    return (
        summary["schema_version"] == "franken-node/module-source-capsule/v1"
        and _digest(summary["graph_input_hash"]) and summary["graph_hash_recomputed"] is False
        and type(summary["capsule_bytes"]) is int and 12 <= summary["capsule_bytes"] <= capsule_limit
        and type(summary["payload_bytes"]) is int
        and 0 <= summary["payload_bytes"] <= min(payload_limit, summary["capsule_bytes"] - 12)
        and summary["input_count"] > 0 and sum(summary[name] for name in counts) == summary["input_count"]
        and summary["symlink_policy"] in ("reject", "contained")
        and (summary["symlink_policy"] == "contained" or summary["symlink_count"] == 0)
        and (condition_count is None or type(condition_count) is int and 0 <= condition_count <= 64)
        and type(additional_count) is int and 0 <= additional_count <= 62
        and (condition_count is None or condition_count + additional_count <= 64)
    )


def _publisher_source_valid(facts: dict[str, Any], anchor: str) -> bool:
    return (
        _publisher_text(facts["package_name"], 256) and _publisher_text(facts["publisher_id"], 256)
        and _publisher_text(facts["version"], 128)
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", facts["version"]) is not None
        and all(_digest(facts[name]) for name in ("manifest_sha256", "artifact_sha256", "capsule_digest"))
        and facts["signer_key_id"] == hashlib.sha256(
            b"artifact_signing_keyid_v1:" + (32).to_bytes(8, "little") + bytes.fromhex(anchor)
        ).hexdigest()[:16]
        and (facts["registration_schema"] == "franken-node/extension-registration-manifest/v1"
             and facts["runtime_authority"] is None
             or facts["registration_schema"] == "franken-node/extension-registration-manifest/v2"
             and _publisher_authority_valid(facts["runtime_authority"]))
        and _source_capsule_valid(facts["capsule"], 5 * 1024 * 1024, 5 * 1024 * 1024 - 12)
    )


# Validate the typed CLI protocol, not guest execution or the original source.
def _native_path_parts(value: Any) -> list[str] | None:
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    windows = re.match(r"^[a-zA-Z]:[/\\]", value) is not None
    unc = value.startswith("\\\\")
    if not value.startswith("/") and not windows and not unc:
        return None
    parts = re.split(r"[/\\]", value) if windows or unc else value.split("/")
    while len(parts) > 1 and parts[-1] == "":
        parts.pop()
    return None if any(part in (".", "..") for part in parts) else parts


def _native_count(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**53 - 1


def _native_journal_valid(journal: Any, facts: dict[str, Any]) -> bool:
    if (not isinstance(journal, dict) or set(journal) != {
            "schema_version", "scope", "session_nonce", "product_root_key_id", "admission_sha256",
            "record_count", "event_count", "admitted_provider_calls", "returned_provider_calls",
            "indeterminate_provider_calls", "head_record_sha256", "trailing_partial_record",
            "replay_certified", "quiescence_certified", "historical_completeness",
        }
            or journal["schema_version"] != "franken-node/native-effect-journal-record/v1"
            or journal["scope"] != "host_io_provider_calls"
            or any(journal[key] != facts[key] for key in ("session_nonce", "product_root_key_id", "admission_sha256"))
            or any(journal[key] is not False for key in ("replay_certified", "quiescence_certified", "historical_completeness"))
            or type(journal["trailing_partial_record"]) is not bool
            or not isinstance(journal["head_record_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", journal["head_record_sha256"]) is None
            or any(not _native_count(journal[key]) for key in (
                "record_count", "event_count", "admitted_provider_calls",
                "returned_provider_calls", "indeterminate_provider_calls",
            ))):
        return False
    return (
        1 <= journal["record_count"] <= 2049
        and journal["event_count"] == journal["record_count"] - 1
        and journal["event_count"] == journal["admitted_provider_calls"] + journal["returned_provider_calls"]
        and journal["admitted_provider_calls"] <= 1024
        and journal["returned_provider_calls"] <= journal["admitted_provider_calls"]
        and journal["indeterminate_provider_calls"] == journal["admitted_provider_calls"] - journal["returned_provider_calls"]
        and journal["indeterminate_provider_calls"] <= 1
    )


def _native_session_valid(facts: Any, anchor: str) -> bool:
    source_backed = isinstance(facts, dict) and facts.get("schema_version") == "franken-node/native-session-forensics/v3"
    if (not isinstance(facts, dict) or set(facts) != {
            "schema_version", "scope", "session_nonce", "product_root_key_id", "admission_sha256",
            "project_root", "entrypoint", "security_epoch", "admitted_at", "observed_at", "outcome_kind",
            "process_observation", "effect_observation", "containment_empty_observed", "completed_provider_calls",
            "indeterminate_provider_calls", "final_ledger_effect_count", "failed_effect_count", "journal_complete",
            "durable_journal", "replay_certified", "quiescence_certified", "historical_completeness",
            *({"source_capsule"} if source_backed else set()),
        }
            or facts["schema_version"] not in ("franken-node/native-session-forensics/v1",
                                               "franken-node/native-session-forensics/v2",
                                               "franken-node/native-session-forensics/v3")
            or facts["scope"] != "authenticated_supervisor_observations"
            or facts["product_root_key_id"] != "ed25519:" + anchor
            or not isinstance(facts["session_nonce"], str)
            or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", facts["session_nonce"]) is None
            or facts["session_nonce"] == "00000000-0000-0000-0000-000000000000"
            or not isinstance(facts["admission_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", facts["admission_sha256"]) is None
            or not isinstance(facts["security_epoch"], str)
            or re.fullmatch(r"0|[1-9][0-9]{0,19}", facts["security_epoch"]) is None
            or int(facts["security_epoch"]) > 2**64 - 1
            or _instant_ns(facts["admitted_at"]) is None
            or any(facts[key] is not False for key in ("replay_certified", "quiescence_certified", "historical_completeness"))):
        return False
    project, entry = _native_path_parts(facts["project_root"]), _native_path_parts(facts["entrypoint"])
    if project is None or entry is None or len(entry) <= len(project) or entry[:len(project)] != project:
        return False
    if source_backed and not _source_capsule_valid(facts["source_capsule"], 40 * 1024 * 1024 + 12, 32 * 1024 * 1024):
        return False
    journal = facts["durable_journal"]
    if facts["schema_version"] == "franken-node/native-session-forensics/v1":
        if journal is not None:
            return False
    elif (journal is not None or not source_backed) and not _native_journal_valid(journal, facts):
        return False
    outcome_fields = (
        "observed_at", "process_observation", "effect_observation", "containment_empty_observed",
        "completed_provider_calls", "indeterminate_provider_calls", "final_ledger_effect_count",
        "failed_effect_count", "journal_complete",
    )
    if facts["outcome_kind"] == "pending":
        return all(facts[key] is None for key in outcome_fields)
    if (facts["outcome_kind"] not in ("completed", "execution_failed", "control_stopped", "interrupted",
                                     "telemetry_failed", "panicked", "supervision_incomplete")
            or _instant_ns(facts["observed_at"]) is None
            or facts["process_observation"] not in ("not_spawned", "worker_reaped", "unproven")
            or facts["effect_observation"] not in ("not_started", "no_admitted_host_effects",
                                                  "final_ledger_observed", "interrupted", "unknown")
            or type(facts["containment_empty_observed"]) is not bool):
        return False
    if facts["process_observation"] == "not_spawned":
        if (facts["outcome_kind"] != "supervision_incomplete" or facts["effect_observation"] != "not_started"
                or facts["containment_empty_observed"] is not False):
            return False
    elif facts["effect_observation"] == "not_started":
        return False
    if (facts["outcome_kind"] in ("completed", "execution_failed", "control_stopped", "telemetry_failed", "panicked")
            and facts["process_observation"] != "worker_reaped"):
        return False
    if facts["outcome_kind"] == "control_stopped" and facts["effect_observation"] != "final_ledger_observed":
        return False
    if (facts["outcome_kind"] == "interrupted") != (facts["effect_observation"] == "interrupted"):
        return False
    completed, indeterminate = facts["completed_provider_calls"], facts["indeterminate_provider_calls"]
    final_count, failed_count = facts["final_ledger_effect_count"], facts["failed_effect_count"]
    if facts["effect_observation"] == "final_ledger_observed":
        if (facts["outcome_kind"] not in ("completed", "execution_failed", "control_stopped")
                or not _native_count(final_count) or not _native_count(failed_count) or failed_count > final_count
                or completed is not None or indeterminate is not None or facts["journal_complete"] is not None):
            return False
    else:
        if final_count is not None or failed_count is not None:
            return False
        if facts["effect_observation"] == "interrupted":
            if (not _native_count(completed) or not _native_count(indeterminate) or indeterminate > 1
                    or completed * 2 + indeterminate > 2048 or type(facts["journal_complete"]) is not bool):
                return False
        elif facts["effect_observation"] == "no_admitted_host_effects":
            if (facts["outcome_kind"] != "panicked" or type(completed) is not int or completed != 0
                    or type(indeterminate) is not int or indeterminate != 0
                    or (facts["journal_complete"] is not None and facts["journal_complete"] is not True)):
                return False
        elif facts["outcome_kind"] == "panicked" and completed is not None:
            if (not _native_count(completed) or completed > 1024 or type(indeterminate) is not int
                    or indeterminate != 0 or facts["journal_complete"] is not True):
                return False
        elif completed is not None or indeterminate is not None or facts["journal_complete"] is not None:
            return False
    if journal is not None:
        if (facts["effect_observation"] in ("not_started", "no_admitted_host_effects")
                and journal["admitted_provider_calls"] != 0):
            return False
        # A later durable append does not repair an incomplete signed outcome.
        if (facts["journal_complete"] is True and completed is not None
                and (journal["admitted_provider_calls"] > completed + indeterminate
                     or journal["returned_provider_calls"] > completed)):
            return False
    return True


def _facts_valid(facts: Any, format: str, anchor: str, run_anchor: str | None,
                 runtime_anchor: str | None, revocation_anchor: str | None = None,
                 provenance_anchor: str | None = None, evaluation_time: str | None = None,
                 max_age: str | None = None) -> bool:
    if format == "native-session-forensics":
        return _native_session_valid(facts, anchor)
    if format == "publisher-source-trust":
        return _publisher_source_trust_valid(
            facts, anchor, revocation_anchor, provenance_anchor, evaluation_time, max_age,
        )
    if not isinstance(facts, dict) or facts.get("signer_public_key_hex") != anchor:
        return False
    expected = {
        "incident-bundle": {"bundle_id", "incident_id", "created_at", "policy_version", "event_count",
                            "integrity_hash", "decision_sequence_hash", "signer_public_key_hex",
                            "signing_identity", "native_capture"},
        "capsule": {"capsule_id", "expected_hash", "actual_hash", "signer_public_key_hex"},
        "signed-bundle": {"bundle_id", "incident_id", "event_count", "integrity_hash", "signer_public_key_hex"},
        "signed-session": {"session_id", "verifier_identity", "created_at", "final_verdict",
                           "step_count", "transcript_hash", "signer_public_key_hex"},
        "resolution-receipt": {"receipt_id", "crypto_suite", "module_graph_hash", "package_name",
                               "requested_range", "policy_profile", "capability_budget_mode", "decision",
                               "selected_version", "rejected_alternative_count", "canonical_hash",
                               "signer_key_id", "signer_public_key_hex"},
        "publisher-source": {"registration_schema", "package_name", "publisher_id", "version",
                             "manifest_sha256", "artifact_sha256", "capsule_digest", "signer_key_id",
                             "signer_public_key_hex", "runtime_authority", "capsule"},
        "counterfactual-receipt": {"baseline_integrity_hash", "mode", "result_count", "signer_public_key_hex"},
        "ltv-evidence": {"artifact_id", "artifact_hash", "crypto_suite", "as_of_unix_seconds",
                         "claimed_at_unix_seconds", "witness_group_id", "witness_policy_id",
                         "reattestation_count", "hybrid_survived_algo_death", "signer_public_key_hex"},
    }[format]
    if run_anchor is not None:
        expected.add("run_origin")
    if runtime_anchor is not None:
        expected.add("runtime_origin")
    if set(facts) != expected:
        return False
    if format == "publisher-source":
        return _publisher_source_valid(facts, anchor)
    if format == "signed-session":
        return (
            isinstance(facts["session_id"], str)
            and re.fullmatch(r"[A-Za-z0-9._-]{1,255}", facts["session_id"]) is not None
            and isinstance(facts["verifier_identity"], str)
            and re.fullmatch(r"verifier://[A-Za-z0-9._-]{1,255}", facts["verifier_identity"]) is not None
            and _instant_ns(facts["created_at"]) is not None
            and facts["final_verdict"] in ("pass", "fail", "inconclusive")
            and type(facts["step_count"]) is int and 0 <= facts["step_count"] <= 1024
            and (facts["step_count"] == 0) == (facts["final_verdict"] == "inconclusive")
            and isinstance(facts["transcript_hash"], str)
            and re.fullmatch(r"[0-9a-f]{64}", facts["transcript_hash"]) is not None
        )
    if format == "counterfactual-receipt":
        return (
            isinstance(facts["baseline_integrity_hash"], str)
            and re.fullmatch(r"[0-9a-f]{64}", facts["baseline_integrity_hash"]) is not None
            and facts["mode"] in ("single", "sweep")
            and type(facts["result_count"]) is int and 1 <= facts["result_count"] <= 1024
            and (facts["mode"] == "sweep" or facts["result_count"] == 1)
        )
    if format == "ltv-evidence":
        artifact_hash = facts["artifact_hash"]
        hex_body = artifact_hash[7:] if isinstance(artifact_hash, str) and artifact_hash.startswith("sha256:") else artifact_hash
        return (
            _publisher_text(facts["artifact_id"], 256)
            and isinstance(hex_body, str) and re.fullmatch(r"[0-9a-f]{64}", hex_body) is not None
            and _publisher_text(facts["crypto_suite"], 128)
            and all(isinstance(facts[k], str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", facts[k]) is not None
                    and int(facts[k]) <= 2**64 - 1 for k in ("as_of_unix_seconds", "claimed_at_unix_seconds"))
            and _publisher_text(facts["witness_group_id"], 256)
            and _publisher_text(facts["witness_policy_id"], 256)
            and type(facts["reattestation_count"]) is int and 0 <= facts["reattestation_count"] <= 64
            and type(facts["hybrid_survived_algo_death"]) is bool
        )
    if format == "resolution-receipt":
        selected = facts["selected_version"]
        return (
            all(_bounded_text(facts[key])
                for key in ("receipt_id", "package_name", "requested_range"))
            and all(isinstance(facts[key], str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", facts[key]) is not None
                    for key in ("module_graph_hash", "canonical_hash", "signer_key_id"))
            and facts["signer_key_id"] == "sha256:" + hashlib.sha256(
                b"franken-node/resolution-receipt/signer-key-id/v1:" + bytes.fromhex(anchor)
            ).hexdigest()
            and facts["crypto_suite"] == "ed25519-v1"
            and facts["policy_profile"] in ("strict", "balanced", "legacy_risky")
            and facts["capability_budget_mode"] in ("advisory", "enforced")
            and type(facts["rejected_alternative_count"]) is int
            and 0 <= facts["rejected_alternative_count"] <= 1024
            and (facts["decision"] == "reject" and selected is None
                 or facts["decision"] == "admit" and _bounded_text(selected))
        )
    for key, value in facts.items():
        if key == "event_count":
            if type(value) is not int or not 0 <= value <= 2**53 - 1:
                return False
        elif key == "run_origin":
            if run_anchor is None or not _run_origin_valid(value, run_anchor):
                return False
        elif key == "runtime_origin":
            if runtime_anchor is None or not _runtime_origin_valid(value, runtime_anchor):
                return False
        elif key == "native_capture":
            if value is not None:
                if not isinstance(value, dict) or set(value) != {
                    "payload_sha256", "payload_bytes", "captured_terminal_state", "host_io_exchange_count"
                }:
                    return False
                if (not _hex(value["payload_sha256"], 64)
                        or not isinstance(value["captured_terminal_state"], str)
                        or value["captured_terminal_state"] not in {
                    "completed", "uncaught_exception", "engine_failure"
                }):
                    return False
                if any(type(value[k]) is not int or not 0 <= value[k] <= MAX_INPUT_BYTES
                       for k in ("payload_bytes", "host_io_exchange_count")):
                    return False
        elif not isinstance(value, str) or not value:
            return False
    return True


def verify_artifact(
    data: bytes,
    trusted_public_key_hex: str,
    *,
    verifier: str | os.PathLike[str],
    format: EvidenceFormat = "incident-bundle",
    trusted_run_public_key_hex: str | None = None,
    trusted_runtime_public_key_hex: str | None = None,
    trusted_revocation_public_key_hex: str | None = None,
    trusted_provenance_public_key_hex: str | None = None,
    evaluation_time: str | None = None,
    max_revocation_age_secs: str | None = None,
    expected_manifest_sha256: str | None = None,
    expected_source_artifact_sha256: str | None = None,
    expected_graph_input_hash: str | None = None,
    signature_hex: str | None = None,
    timeout: float = 10.0,
) -> Verification:
    """Authenticate raw artifact bytes using an explicit trusted executable/key.

    Supported formats and proof scopes are in ``_SCOPES``. Capsule verification
    re-derives signed content hashes; incident verification checks recorded
    evidence. Neither constitutes guest execution or original-policy replay.
    For incident bundles, supplying ``trusted_run_public_key_hex`` additionally
    requires the original receipt authority's signature and matching run data.
    Missing proof, a different run signer or a narrower response is refused;
    the bundle exporter never supplies this separate authority implicitly.
    Adding ``trusted_runtime_public_key_hex`` requires that run authority plus
    the portable product-root/session signatures over the original effect ledger.
    It does not establish guest replay, external effect completion or quiescence.
    Native-session forensics authenticates retained supervisor observations.
    A pending outcome and a retained journal prefix never certify complete history.
    Version 3 authenticates retained source capsule content without replaying it.
    Its security_epoch is an exact decimal u64 string, including zero.
    Publisher-source trust requires an independent revocation authority, an
    explicit RFC3339 evaluation time, and a positive decimal u64 freshness window.
    An optional independent provenance authority requires matching chain evidence.
    Times use four-digit years, non-leap seconds, and at most nine fractional
    digits; comparison preserves nanoseconds and the exact freshness boundary.
    Publisher identity pins come from caller policy. An exact manifest SHA-256
    pin is required when optional raw source-artifact or graph pins are supplied.
    Pins use ``sha256:`` plus 64 lowercase hex digits. The source-artifact pin
    names raw capsule bytes, not input transport bytes or the capsule domain
    digest. A graph pin matches an authenticated claim without reconstructing it.
    The supplied executable is part of the caller's trusted verifier
    distribution. It is never inferred from an artifact or run through a shell.
    """
    if not isinstance(data, bytes):
        raise VerifierError("INPUT_INVALID", "data must be the original bytes")
    if not isinstance(format, str) or format not in _SCOPES:
        raise VerifierError("UNSUPPORTED_FORMAT", "unsupported evidence format")
    input_limit = MAX_NATIVE_SESSION_INPUT_BYTES if format == "native-session-forensics" else MAX_INPUT_BYTES
    if len(data) > input_limit:
        raise VerifierError("INPUT_TOO_LARGE", f"evidence exceeds {input_limit // (1024 * 1024)} MiB")
    if not _hex(trusted_public_key_hex, 64):
        raise VerifierError("ANCHOR_INVALID", "expected a 32-byte hexadecimal public key")
    if trusted_run_public_key_hex is not None:
        if format != "incident-bundle":
            raise VerifierError("INPUT_INVALID", "original-run trust applies only to incident-bundle")
        if not _hex(trusted_run_public_key_hex, 64):
            raise VerifierError("RUN_ANCHOR_INVALID", "expected a 32-byte hexadecimal run public key")
    if trusted_runtime_public_key_hex is not None:
        if format != "incident-bundle" or trusted_run_public_key_hex is None:
            raise VerifierError("INPUT_INVALID", "runtime trust requires incident-bundle and original-run trust")
        if not _hex(trusted_runtime_public_key_hex, 64):
            raise VerifierError("RUNTIME_ANCHOR_INVALID", "expected a 32-byte hexadecimal product-root public key")
    publisher_trust_options = (
        trusted_revocation_public_key_hex, trusted_provenance_public_key_hex,
        evaluation_time, max_revocation_age_secs,
    )
    if format == "publisher-source-trust":
        if not _hex(trusted_revocation_public_key_hex, 64):
            raise VerifierError("REVOCATION_ANCHOR_INVALID", "an independent revocation public key is required")
        if trusted_provenance_public_key_hex is not None and not _hex(trusted_provenance_public_key_hex, 64):
            raise VerifierError("PROVENANCE_ANCHOR_INVALID", "expected a 32-byte hexadecimal provenance public key")
        if _instant_ns(evaluation_time) is None:
            raise VerifierError("EVALUATION_TIME_INVALID", "a precise RFC3339 evaluation time is required")
        if not _decimal_limit(max_revocation_age_secs, 2**64 - 1):
            raise VerifierError("REVOCATION_FRESHNESS_POLICY_INVALID", "freshness must be a positive decimal u64 string")
    elif any(value is not None for value in publisher_trust_options):
        raise VerifierError("INPUT_INVALID", "publisher trust options require publisher-source-trust")
    expected_identity = (expected_manifest_sha256, expected_source_artifact_sha256, expected_graph_input_hash)
    if any(value is not None for value in expected_identity) and (
        format not in ("publisher-source", "publisher-source-trust")
        or not _digest(expected_manifest_sha256)
        or any(value is not None and not _digest(value) for value in expected_identity)
    ):
        raise VerifierError("EXPECTED_IDENTITY_INVALID", "publisher identity pins require an exact manifest SHA-256 and canonical optional source commitments")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 120 or not math.isfinite(timeout):
        raise VerifierError("TIMEOUT_INVALID", "timeout must be finite and in (0, 120] seconds")
    try:
        executable = os.fspath(verifier)
    except TypeError as error:
        raise VerifierError("EXECUTABLE_INVALID", "verifier must be a trusted executable path") from error
    if not isinstance(executable, str) or not executable or "\0" in executable:
        raise VerifierError("EXECUTABLE_INVALID", "verifier must be a trusted executable path")
    anchor = trusted_public_key_hex.lower()
    run_anchor = trusted_run_public_key_hex.lower() if trusted_run_public_key_hex is not None else None
    runtime_anchor = trusted_runtime_public_key_hex.lower() if trusted_runtime_public_key_hex is not None else None
    revocation_anchor = trusted_revocation_public_key_hex.lower() if trusted_revocation_public_key_hex is not None else None
    provenance_anchor = trusted_provenance_public_key_hex.lower() if trusted_provenance_public_key_hex is not None else None
    scope = ("authenticated_runtime_incident" if runtime_anchor is not None else
             "authenticated_run_incident" if run_anchor is not None else _SCOPES[format])
    args = [executable, "verify", "--format", format, "--trusted-key-hex", anchor]
    if run_anchor is not None:
        args.extend(["--trusted-run-key-hex", run_anchor])
    if runtime_anchor is not None:
        args.extend(["--trusted-runtime-key-hex", runtime_anchor])
    if revocation_anchor is not None:
        args.extend(["--trusted-revocation-key-hex", revocation_anchor,
                     "--evaluation-time", evaluation_time, "--max-revocation-age-secs", max_revocation_age_secs])
    if provenance_anchor is not None:
        args.extend(["--trusted-provenance-key-hex", provenance_anchor])
    if expected_manifest_sha256 is not None:
        args.extend(["--expected-manifest-sha256", expected_manifest_sha256])
    if expected_source_artifact_sha256 is not None:
        args.extend(["--expected-source-artifact-sha256", expected_source_artifact_sha256])
    if expected_graph_input_hash is not None:
        args.extend(["--expected-graph-input-hash", expected_graph_input_hash])
    if format in ("signed-bundle", "publisher-source", "publisher-source-trust", "counterfactual-receipt"):
        if not _hex(signature_hex, 128):
            raise VerifierError("SIGNATURE_MALFORMED", "a detached 64-byte signature is required")
        args.extend(["--signature-hex", signature_hex])
    elif signature_hex is not None:
        raise VerifierError("INPUT_INVALID", "detached signatures require a signed-bundle, publisher-source format, or counterfactual-receipt")
    try:
        process = subprocess.run(args, input=data, capture_output=True, timeout=timeout,
                                 check=False, shell=False)
    except subprocess.TimeoutExpired as error:
        raise VerifierError("PROCESS_TIMEOUT", "verifier exceeded its execution timeout") from error
    except OSError as error:
        raise VerifierError("PROCESS_UNAVAILABLE", "cannot execute the trusted verifier") from error
    if len(process.stdout) > MAX_RESPONSE_BYTES or len(process.stderr) > MAX_RESPONSE_BYTES:
        raise VerifierError("PROTOCOL_INVALID", "verifier response exceeds its size bound")
    try:
        result = json.loads(process.stdout.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise VerifierError("PROTOCOL_INVALID", "verifier returned invalid JSON") from error
    if not isinstance(result, dict) or result.get("schema_version") != PROTOCOL:
        raise VerifierError("PROTOCOL_INVALID", "unsupported verifier response schema")
    if result.get("verdict") == "rejected":
        error = result.get("error")
        if (process.returncode not in (1, 2) or set(result) != {"schema_version", "verdict", "error"}
                or not isinstance(error, dict) or set(error) != {"code", "message"}
                or not isinstance(error.get("code"), str) or not error["code"]
                or not isinstance(error.get("message"), str)):
            raise VerifierError("PROTOCOL_INVALID", "inconsistent rejection response")
        raise VerifierError(error["code"], error["message"], exit_code=process.returncode,
                            stderr=process.stderr)
    if (process.returncode != 0 or result.get("verdict") != "verified"
            or set(result) != {"schema_version", "verdict", "format", "scope", "artifact_sha256", "facts"}
            or result.get("format") != format or result.get("scope") != scope
            or result.get("artifact_sha256") != hashlib.sha256(data).hexdigest()
            or not _facts_valid(result.get("facts"), format, anchor, run_anchor, runtime_anchor,
                                revocation_anchor, provenance_anchor, evaluation_time, max_revocation_age_secs)):
        raise VerifierError("PROTOCOL_INVALID", "verification response does not match the request")
    if expected_manifest_sha256 is not None:
        source = result["facts"]["source"] if format == "publisher-source-trust" else result["facts"]
        if (source["manifest_sha256"] != expected_manifest_sha256
                or (expected_source_artifact_sha256 is not None and source["artifact_sha256"] != expected_source_artifact_sha256)
                or (expected_graph_input_hash is not None and source["capsule"]["graph_input_hash"] != expected_graph_input_hash)):
            raise VerifierError("EXPECTED_IDENTITY_MISMATCH", "authenticated publisher source does not match the expected identity")
    return result
