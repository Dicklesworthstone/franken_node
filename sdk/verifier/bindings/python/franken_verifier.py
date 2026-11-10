"""Offline verifier API. Requires a trusted, separately installed franken-verifier.

Artifact bytes are sent unchanged to the independent Rust SDK. This module
does not load the product/engine, discover trust anchors from evidence, or
execute a captured guest. Only Python's standard library is required.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
from typing import Any, Literal, TypedDict

PROTOCOL = "franken-verifier-cli/v1"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 + 1
EvidenceFormat = Literal["incident-bundle", "capsule", "signed-bundle", "resolution-receipt"]
_SCOPES = {
    "incident-bundle": "authenticated_recorded_incident",
    "capsule": "authenticated_capsule_content",
    "signed-bundle": "authenticated_sdk_replay_bundle",
    "resolution-receipt": "authenticated_resolution_decision",
}


class Verification(TypedDict):
    schema_version: str
    verdict: Literal["verified"]
    format: EvidenceFormat
    scope: Literal["authenticated_recorded_incident", "authenticated_run_incident",
                   "authenticated_runtime_incident",
                   "authenticated_capsule_content", "authenticated_sdk_replay_bundle",
                   "authenticated_resolution_decision"]
    artifact_sha256: str
    facts: dict[str, Any]


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


def _facts_valid(facts: Any, format: str, anchor: str, run_anchor: str | None,
                 runtime_anchor: str | None) -> bool:
    if not isinstance(facts, dict) or facts.get("signer_public_key_hex") != anchor:
        return False
    expected = {
        "incident-bundle": {"bundle_id", "incident_id", "created_at", "policy_version", "event_count",
                            "integrity_hash", "decision_sequence_hash", "signer_public_key_hex",
                            "signing_identity", "native_capture"},
        "capsule": {"capsule_id", "expected_hash", "actual_hash", "signer_public_key_hex"},
        "signed-bundle": {"bundle_id", "incident_id", "event_count", "integrity_hash", "signer_public_key_hex"},
        "resolution-receipt": {"receipt_id", "crypto_suite", "module_graph_hash", "package_name",
                               "requested_range", "policy_profile", "capability_budget_mode", "decision",
                               "selected_version", "rejected_alternative_count", "canonical_hash",
                               "signer_key_id", "signer_public_key_hex"},
    }[format]
    if run_anchor is not None:
        expected.add("run_origin")
    if runtime_anchor is not None:
        expected.add("runtime_origin")
    if set(facts) != expected:
        return False
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
    The supplied executable is part of the caller's trusted verifier
    distribution. It is never inferred from an artifact or run through a shell.
    """
    if not isinstance(data, bytes):
        raise VerifierError("INPUT_INVALID", "data must be the original bytes")
    if len(data) > MAX_INPUT_BYTES:
        raise VerifierError("INPUT_TOO_LARGE", "evidence exceeds 64 MiB")
    if not isinstance(format, str) or format not in _SCOPES:
        raise VerifierError("UNSUPPORTED_FORMAT", "unsupported evidence format")
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
    scope = ("authenticated_runtime_incident" if runtime_anchor is not None else
             "authenticated_run_incident" if run_anchor is not None else _SCOPES[format])
    args = [executable, "verify", "--format", format, "--trusted-key-hex", anchor]
    if run_anchor is not None:
        args.extend(["--trusted-run-key-hex", run_anchor])
    if runtime_anchor is not None:
        args.extend(["--trusted-runtime-key-hex", runtime_anchor])
    if format == "signed-bundle":
        if not _hex(signature_hex, 128):
            raise VerifierError("SIGNATURE_MALFORMED", "a detached 64-byte signature is required")
        args.extend(["--signature-hex", signature_hex])
    elif signature_hex is not None:
        raise VerifierError("INPUT_INVALID", "detached signatures apply only to signed-bundle")
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
            or not _facts_valid(result.get("facts"), format, anchor, run_anchor, runtime_anchor)):
        raise VerifierError("PROTOCOL_INVALID", "verification response does not match the request")
    return result
