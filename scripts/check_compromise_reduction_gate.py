#!/usr/bin/env python3
"""Authenticate a current bd-3cpa campaign statement and recompute its census.

The v2 fixture uses a public test signing seed. Signature integrity is checked
under an independent fixture pin, but cannot authenticate a fresh experiment.
Historical inspection is explicit and cannot qualify a current release. Real
current-source measurement and its independent acceptance remain in .20/.21.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-3cpa_contract.md"
REPORT = ROOT / "artifacts" / "13" / "compromise_reduction_report.json"
BENCHMARK_TEST_RELATIVE_PATH = "crates/franken-node/tests/compromise_reduction_baseline_bench.rs"
BENCHMARK_ARTIFACT_RELATIVE_PATH = "artifacts/adversarial/compromise_reduction_v2.json"
BENCHMARK_TEST_NAME = "compromise_reduction_v2_measures_raw_runtime_baseline_against_strict_policy"
EXPECTED_RAW_BASELINE_RUNTIMES = ["bun", "node"]
# This is public conformance material, NOT release/measurement authority. The
# verifier pins it independently instead of trusting an artifact-selected key.
HISTORICAL_FIXTURE_KEY = "22fc297792f0b6ffc0bfcfdb7edb0c0aa14e025a365ec0e342e86e3829cb74b6"
MAX_CAMPAIGN_BYTES = 64 * 1024 * 1024
MAX_CAMPAIGN_DEPTH = 128
CURRENT_CAMPAIGN_SCHEMA = "franken-node/compromise-campaign/v3"
CURRENT_SIGNATURE_DOMAIN = b"franken-node:compromise-campaign-signature:v3:"
CURRENT_CORPUS_DOMAIN = b"franken-node:compromise-campaign-corpus:v3:"
SOURCE_ROOTS = {"franken_node", "franken_engine", "fastapi_rust", "frankentui", "sqlmodel_rust"}
CAMPAIGN_RUNTIMES = {"node", "bun", "native"}
CONTEXT_FIELDS = {"source_revisions", "binary_sha256", "runtime_versions", "corpus_sha256",
                  "policy_sha256", "policy_profile", "source_selection"}
REQUIRED_BENCHMARK_ASSERTIONS = {
    "status != baseline_unavailable": "baseline_unavailable",
    "baseline_compromised == Some(20)": "baseline_compromised, Some(20)",
    "franken_compromised == Some(0)": "franken_compromised, Some(0)",
    "ratio == Some(20.0)": "ratio, Some(20.0)",
    "pass_criterion.passed": "pass_criterion.passed",  # nosec B105 - artifact field name
}

REQUIRED_ATTACK_CLASSES = {
    "rce_dependency",
    "prototype_pollution",
    "path_traversal",
    "ssrf",
    "deserialization",
    "supply_chain_injection",
    "privilege_escalation",
    "sandbox_escape",
    "memory_corruption",
    "command_injection",
}

REQUIRED_EVENT_CODES = {
    "CRG-001",
    "CRG-002",
    "CRG-003",
    "CRG-004",
    "CRG-005",
    "CRG-006",
    "CRG-007",
}

ALLOWED_BASELINE_OUTCOMES = {"compromised", "blocked"}
ALLOWED_HARDENED_OUTCOMES = {"compromised", "blocked", "contained"}

# Typed franken outcomes the measured v2 artifact (schema >= 2.1.0) may carry.
# `invalid` is the OLD tautological signature (exit non-zero for a harness
# reason, no security denial, no fired control) and must never appear.
VALID_FRANKEN_OUTCOMES = {
    "blocked_at_lowering",
    "capability_denied",
    "ssrf_denied",
    "ifc_denied",
    "contained",
    "executed_uncompromised",
    "compromised",
}


def franken_case_honesty_errors(artifact: dict[str, Any]) -> list[str]:
    """Reject the tautological measured artifact (bd-...26n9r.3).

    The pre-2.1.0 artifact recorded every franken case as an immediate exit-1
    with no typed outcome, no evidence, and no executed control -- a run that
    never executed the payload scored `franken_compromised == 0` for free. A
    HONEST artifact must show, per case: the baseline runtimes really executed
    (control fired) and were compromised, and the franken leg is a TYPED
    containment outcome with evidence -- either a runtime denial with the
    control fired, or a lowering refusal naming the refused construct. Any case
    that is a bare non-zero exit with neither is `invalid` and fails the gate.
    """
    errors: list[str] = []
    cases = artifact.get("cases")
    if not isinstance(cases, list) or not cases:
        return ["measured artifact has no cases[] to audit for honesty"]

    all_franken_exit_codes: set[Any] = set()
    typed_evidence_seen = False
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"cases[{idx}] must be an object")
            continue
        case_id = case.get("case_id", f"index-{idx}")

        raw = case.get("raw_runtimes")
        if not isinstance(raw, list) or not raw:
            errors.append(f"{case_id}: raw_runtimes[] missing")
        else:
            for runtime in raw:
                if not isinstance(runtime, dict):
                    continue
                if not runtime.get("control_executed"):
                    errors.append(
                        f"{case_id}: raw runtime {runtime.get('runtime')!r} did not execute the "
                        "positive control (baseline never ran the payload)"
                    )
                if not runtime.get("compromised"):
                    errors.append(
                        f"{case_id}: raw runtime {runtime.get('runtime')!r} was not compromised "
                        "(baseline oracle did not fire)"
                    )

        franken = case.get("franken")
        if not isinstance(franken, dict):
            errors.append(f"{case_id}: franken outcome object missing")
            continue
        outcome = franken.get("outcome")
        evidence = franken.get("evidence")
        all_franken_exit_codes.add(franken.get("exit_code"))
        if outcome == "invalid":
            errors.append(
                f"{case_id}: franken outcome is `invalid` -- a non-security exit with no typed "
                f"denial and no fired control (the pre-2.1.0 tautological signature): {evidence!r}"
            )
            continue
        if outcome not in VALID_FRANKEN_OUTCOMES:
            errors.append(
                f"{case_id}: franken outcome {outcome!r} is not a typed containment outcome "
                f"(expected one of {sorted(VALID_FRANKEN_OUTCOMES)})"
            )
            continue
        if not isinstance(evidence, str) or not evidence.strip():
            errors.append(f"{case_id}: franken outcome {outcome!r} carries no evidence string")
        else:
            typed_evidence_seen = True
        if franken.get("compromised"):
            errors.append(f"{case_id}: franken leg tripped the host-compromise oracle")
        # `executed_uncompromised` means the guest ran to a clean exit (exit 0,
        # captured_output present) yet the oracle did not fire -- there the
        # positive control MUST have fired, or the run never executed. Every
        # other outcome is a refusal (lowering / capability / ssrf / ifc) whose
        # run exits non-zero, and `run --json` currently drops the guest console
        # on the failure path (bd-uqz71), so the control legitimately cannot be
        # observed there; the typed denial reason in `evidence` is the proof.
        if outcome == "executed_uncompromised" and not franken.get("control_executed"):
            errors.append(
                f"{case_id}: franken outcome {outcome!r} exited cleanly without the positive "
                "control -- the guest never executed"
            )

    # The old artifact's franken cases were ALL an identical non-zero exit with
    # no typed evidence anywhere -- reject that shape explicitly.
    if not typed_evidence_seen and len(all_franken_exit_codes) == 1:
        only = next(iter(all_franken_exit_codes))
        if only not in (0, None):
            errors.append(
                "every franken case is the same non-zero exit code with no typed evidence "
                f"(exit_code={only}); this is the tautological pre-2.1.0 signature"
            )

    if artifact.get("all_franken_cases_accounted") is not True:
        errors.append("measured artifact must set all_franken_cases_accounted=true")

    return errors

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return entry


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _number_close(value: Any, expected: float) -> bool:
    return _is_number(value) and abs(float(value) - expected) <= 0.01


def _as_float(value: Any) -> float | None:
    if not _is_number(value):
        return None
    return float(value)


def _attack_required_fields() -> tuple[str, ...]:
    return (
        "attack_id",
        "attack_class",
        "attack_description",
        "baseline_outcome",
        "franken_node_outcome",
        "mitigation",
        "script_command",
        "containment_demonstrated",
    )


def _validate_attack_entry(entry: dict[str, Any], idx: int, errors: list[str]) -> None:
    for field in _attack_required_fields():
        if field not in entry:
            errors.append(f"attack_vectors[{idx}] missing field: {field}")

    for field in (
        "attack_id",
        "attack_class",
        "attack_description",
        "mitigation",
        "script_command",
    ):
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"attack_vectors[{idx}].{field} must be non-empty string")

    baseline = entry.get("baseline_outcome")
    if baseline not in ALLOWED_BASELINE_OUTCOMES:
        errors.append(
            f"attack_vectors[{idx}].baseline_outcome invalid: {baseline}"
        )

    hardened = entry.get("franken_node_outcome")
    if hardened not in ALLOWED_HARDENED_OUTCOMES:
        errors.append(
            f"attack_vectors[{idx}].franken_node_outcome invalid: {hardened}"
        )

    containment = entry.get("containment_demonstrated")
    if not isinstance(containment, bool):
        errors.append(f"attack_vectors[{idx}].containment_demonstrated must be boolean")
    elif containment and hardened != "contained":
        errors.append(
            f"attack_vectors[{idx}] containment_demonstrated=true requires franken_node_outcome=contained"
        )

    command = entry.get("script_command")
    if isinstance(command, str) and not command.startswith("python3 "):
        errors.append(
            f"attack_vectors[{idx}].script_command must start with 'python3 '"
        )


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _count_compromised(vectors: list[dict[str, Any]]) -> tuple[int, int, int]:
    baseline = sum(1 for vector in vectors if vector.get("baseline_outcome") == "compromised")
    hardened = sum(1 for vector in vectors if vector.get("franken_node_outcome") == "compromised")
    contained = sum(1 for vector in vectors if vector.get("franken_node_outcome") == "contained")
    return baseline, hardened, contained


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _read_campaign_json(path: Path) -> dict[str, Any]:
    # Bound the actual read, not only a potentially stale stat result.
    with path.open("rb") as stream:
        data = stream.read(MAX_CAMPAIGN_BYTES + 1)
    if len(data) > MAX_CAMPAIGN_BYTES:
        raise ValueError("campaign exceeds 64 MiB")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                       parse_constant=_reject_nonfinite, parse_float=_finite_float)
    if not isinstance(value, dict):
        raise ValueError("campaign root must be an object")
    pending = [(value, 1)]
    while pending:
        node, depth = pending.pop()
        if depth > MAX_CAMPAIGN_DEPTH:
            raise ValueError("campaign nesting exceeds 128 levels")
        if isinstance(node, dict):
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)
    return value


def historical_fixture_signature_errors(artifact: dict[str, Any]) -> list[str]:
    """Verify the retained v2 fixture signature, without granting release credit.

    v2 signs compact serde struct-field order, not sorted-key JSON. The frozen
    wire preserves that order; decoding/re-encoding a reordered artifact is
    therefore deliberately not accepted as the same signed representation.
    The public test seed makes this reproducible conformance only. Even a
    valid signature here cannot authenticate a fresh production experiment.
    """
    signature = artifact.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "key_id", "public_key", "payload_sha256", "value"
    }:
        return ["historical fixture signature is missing or malformed"]
    if (artifact.get("schema_version") != "2.1.0"
            or artifact.get("artifact_id") != "compromise_reduction_v2"
            or signature.get("algorithm") != "ed25519-fixture-v1"
            or signature.get("key_id") != "adversarial-extension-runtime-bench-v2"):
        return ["unsupported historical fixture signature scope"]
    key = signature.get("public_key")
    if (not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None
            or not hmac.compare_digest(key, HISTORICAL_FIXTURE_KEY)):
        return ["historical fixture signer is not the independently pinned key"]
    encoded_signature = signature.get("value")
    if (not isinstance(encoded_signature, str)
            or re.fullmatch(r"ed25519:[0-9a-f]{128}", encoded_signature) is None):
        return ["historical fixture Ed25519 signature must contain 64 bytes"]
    unsigned = {key: value for key, value in artifact.items() if key != "signature"}
    try:
        payload = json.dumps(unsigned, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return ["historical fixture payload cannot be encoded unambiguously"]
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if signature.get("payload_sha256") != digest:
        return ["historical fixture signed payload digest mismatch"]
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return ["Ed25519 verification requires the cryptography runtime; not verified"]
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(HISTORICAL_FIXTURE_KEY)).verify(
            bytes.fromhex(encoded_signature.removeprefix("ed25519:")), payload
        )
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        return ["historical fixture Ed25519 signature does not verify"]
    return []


def _sha256_text(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _canonical_current(value: Any) -> bytes:
    """The v3 statement is integer-only sorted-key UTF-8 JSON."""
    pending = [(value, 1)]
    while pending:
        node, depth = pending.pop()
        if depth > MAX_CAMPAIGN_DEPTH or isinstance(node, float):
            raise ValueError("unsupported canonical campaign value")
        if isinstance(node, dict):
            if any(not isinstance(key, str) for key in node):
                raise ValueError("non-string campaign key")
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)
        elif node is not None and not isinstance(node, (str, int, bool)):
            raise ValueError("unsupported canonical campaign value")
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _context_valid(context: Any) -> bool:
    if not isinstance(context, dict) or set(context) != CONTEXT_FIELDS:
        return False
    revisions, binaries, versions = (context[key] for key in
                                    ("source_revisions", "binary_sha256", "runtime_versions"))
    return (
        isinstance(revisions, dict) and set(revisions) == SOURCE_ROOTS
        and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value)
                for value in revisions.values())
        and isinstance(binaries, dict) and set(binaries) == CAMPAIGN_RUNTIMES
        and all(_sha256_text(value) for value in binaries.values())
        and len(set(binaries.values())) == 3
        and isinstance(versions, dict) and set(versions) == CAMPAIGN_RUNTIMES
        and all(isinstance(value, str) and 0 < len(value) <= 128 for value in versions.values())
        and _sha256_text(context["corpus_sha256"]) and _sha256_text(context["policy_sha256"])
        and context["policy_profile"] == "strict"
        and isinstance(context["source_selection"], str)
        and re.fullmatch(r"[0-9a-f]{40}-overlay-[0-9a-f]{64}", context["source_selection"]) is not None
        and context["source_selection"].startswith(revisions["franken_node"] + "-overlay-")
    )


def _current_result(error: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": "franken-node/compromise-campaign-verification/v1",
        "verdict": "FAIL", "evidence_class": "unverified_campaign_statement",
        "release_qualified": False, "independently_reproduced": False,
        "errors": [error] if error is not None else [], "computed": {},
    }


def _wilson_interval_bp(successes: int, trials: int) -> list[int]:
    z = 1.96
    rate = successes / trials
    denominator = 1 + z * z / trials
    center = (rate + z * z / (2 * trials)) / denominator
    margin = z / denominator * math.sqrt(rate * (1 - rate) / trials + z * z / (4 * trials * trials))
    return [math.floor(max(0, min(1, value)) * 10000 + 0.5) for value in (center - margin, center + margin)]


def verify_current_campaign(
    artifact: dict[str, Any], trusted_public_key_hex: str, expected_context: dict[str, Any],
    *, now: datetime | None = None, max_age_seconds: int = 86400,
) -> dict[str, Any]:
    """Authenticate an externally pinned v3 statement and recompute its census.

    The caller must obtain its key/context independently of the statement.
    This checks signed measurement assertions, not independent occurrence of
    the experiment or external replication. Synthetic validator positives
    cannot supply the real campaign acceptance required by .20/.21.
    """
    result = _current_result()
    errors: list[str] = result["errors"]
    if (not isinstance(artifact, dict) or set(artifact) != {
            "schema_version", "campaign_id", "generated_at_utc", "context", "cases", "summary", "signature"
    } or artifact.get("schema_version") != CURRENT_CAMPAIGN_SCHEMA):
        errors.append("CURRENT_SCHEMA_INVALID")
        return result
    if (not _context_valid(expected_context) or artifact["context"] != expected_context):
        errors.append("CURRENT_CONTEXT_MISMATCH")
        return result
    if (not isinstance(trusted_public_key_hex, str)
            or re.fullmatch(r"[0-9a-f]{64}", trusted_public_key_hex) is None
            or trusted_public_key_hex in {HISTORICAL_FIXTURE_KEY,
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"}):
        errors.append("CURRENT_MEASUREMENT_ANCHOR_REQUIRED")
        return result
    if (not isinstance(artifact["campaign_id"], str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact["campaign_id"]) is None):
        errors.append("CURRENT_CAMPAIGN_ID_INVALID")
        return result
    try:
        generated = _parse_iso8601(artifact["generated_at_utc"])
        clock = now if now is not None else datetime.now(timezone.utc)
        if (type(max_age_seconds) is not int or not 0 < max_age_seconds <= 86400
                or generated.utcoffset() is None or clock.utcoffset() is None
                or not 0 <= (clock - generated).total_seconds() <= max_age_seconds):
            raise ValueError("campaign outside freshness policy")
    except (TypeError, ValueError, AttributeError, OverflowError):
        errors.append("CURRENT_CAMPAIGN_NOT_FRESH")
        return result
    signature = artifact["signature"]
    if (not isinstance(signature, dict) or set(signature) != {
            "algorithm", "public_key_hex", "statement_sha256", "signature_hex"
    } or signature.get("algorithm") != "ed25519"
            or signature.get("public_key_hex") != trusted_public_key_hex
            or not isinstance(signature.get("signature_hex"), str)
            or re.fullmatch(r"[0-9a-f]{128}", signature["signature_hex"]) is None):
        errors.append("CURRENT_SIGNATURE_INVALID")
        return result
    try:
        unsigned = {key: value for key, value in artifact.items() if key != "signature"}
        statement = _canonical_current(unsigned)
        if len(statement) > MAX_CAMPAIGN_BYTES:
            raise ValueError("statement too large")
        digest = "sha256:" + hashlib.sha256(statement).hexdigest()
        if signature["statement_sha256"] != digest:
            raise ValueError("statement digest mismatch")
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        errors.append("CURRENT_CRYPTO_UNAVAILABLE")
        return result
    except (TypeError, ValueError, UnicodeError, RecursionError):
        errors.append("CURRENT_STATEMENT_INVALID")
        return result
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key_hex)).verify(
            bytes.fromhex(signature["signature_hex"]),
            CURRENT_SIGNATURE_DOMAIN + len(statement).to_bytes(8, "little") + statement,
        )
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        errors.append("CURRENT_SIGNATURE_INVALID")
        return result
    result["evidence_class"] = "authenticated_campaign_statement"
    cases = artifact["cases"]
    if not isinstance(cases, list) or not 20 <= len(cases) <= 10000:
        errors.append("CURRENT_CENSUS_SIZE_INVALID")
        return result
    ids: set[str] = set()
    classes: set[str] = set()
    inventory: list[dict[str, Any]] = []
    baseline = compromised = contained = prevented = 0
    common = {"available", "binary_sha256", "input_sha256", "stdout", "stderr", "exit_code",
              "timed_out", "control_executed", "compromised"}
    native_extra = {"outcome", "evidence", "security_control", "contained"}
    for case in cases:
        if (not isinstance(case, dict) or set(case) != {
                "case_id", "attack_class", "template_sha256", "observations"
        } or not isinstance(case.get("case_id"), str)
                or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", case["case_id"]) is None
                or case["case_id"] in ids or not isinstance(case.get("attack_class"), str)
                or case["attack_class"] not in REQUIRED_ATTACK_CLASSES
                or not _sha256_text(case.get("template_sha256"))):
            errors.append("CURRENT_CASE_INVALID")
            return result
        ids.add(case["case_id"])
        classes.add(case["attack_class"])
        inventory.append({key: case[key] for key in ("case_id", "attack_class", "template_sha256")})
        observations = case["observations"]
        if not isinstance(observations, dict) or set(observations) != CAMPAIGN_RUNTIMES:
            errors.append("CURRENT_ATTEMPTS_NOT_PAIRED")
            return result
        for runtime in ("node", "bun", "native"):
            record = observations[runtime]
            fields = common | native_extra if runtime == "native" else common
            if (not isinstance(record, dict) or set(record) != fields
                    or record["available"] is not True or type(record["timed_out"]) is not bool
                    or record["binary_sha256"] != expected_context["binary_sha256"][runtime]
                    or not _sha256_text(record["input_sha256"])
                    or not isinstance(record["stdout"], str) or not isinstance(record["stderr"], str)
                    or type(record["control_executed"]) is not bool or type(record["compromised"]) is not bool
                    or record["control_executed"] != ("FN_CONTROL:" + case["case_id"] in record["stdout"].splitlines())):
                errors.append("CURRENT_OBSERVATION_INVALID")
                return result
            completed = (record["timed_out"] is False and type(record["exit_code"]) is int
                         and -(2**31) <= record["exit_code"] < 2**31)
            stopped_after_compromise = (runtime != "native" and record["timed_out"] is True
                                        and record["exit_code"] is None
                                        and record["control_executed"] is True
                                        and record["compromised"] is True)
            # Raw network attacks can leave their event loop alive after the
            # host oracle fires. Retain that termination as a proved baseline
            # compromise, never as a successful defense. A native timeout is
            # always unqualified, even when its positive control appeared.
            if not (completed or stopped_after_compromise):
                errors.append("CURRENT_OBSERVATION_INVALID")
                return result
            if runtime != "native" and (record["control_executed"] is not True
                                         or record["compromised"] is not True):
                errors.append("CURRENT_RAW_CONTROL_NOT_COMPROMISED")
                return result
        baseline += 1  # Both real incumbent legs above executed their positive controls.
        native = observations["native"]
        outcome = native["outcome"]
        if (not isinstance(outcome, str) or outcome not in VALID_FRANKEN_OUTCOMES
                or type(native["contained"]) is not bool
                or not isinstance(native["evidence"], str) or not 0 < len(native["evidence"]) <= 4096
                or not isinstance(native["security_control"], str)
                or native["compromised"] != (outcome == "compromised")
                or (native["compromised"] and native["contained"])):
            errors.append("CURRENT_NATIVE_CLASSIFICATION_INVALID")
            return result
        denial_controls = {"blocked_at_lowering": "ambient_authority_denied",
                           "capability_denied": "capability_gate", "ssrf_denied": "ssrf_gate",
                           "ifc_denied": "ifc_gate"}
        if outcome in denial_controls:
            if native["security_control"] != denial_controls[outcome] or native["exit_code"] == 0:
                errors.append("CURRENT_SECURITY_DENIAL_INVALID")
                return result
            if outcome == "blocked_at_lowering" and native["control_executed"]:
                errors.append("CURRENT_SECURITY_DENIAL_INVALID")
                return result
        elif not native["control_executed"]:
            errors.append("CURRENT_NATIVE_CONTROL_NOT_EXECUTED")
            return result
        if outcome == "executed_uncompromised" and (native["exit_code"] != 0 or native["contained"]):
            errors.append("CURRENT_NATIVE_CLASSIFICATION_INVALID")
            return result
        if outcome == "contained" and (not native["contained"] or native["security_control"] != "runtime_containment"):
            errors.append("CURRENT_NATIVE_CLASSIFICATION_INVALID")
            return result
        compromised += int(native["compromised"])
        contained += int(native["contained"] and native["control_executed"])
        prevented += int(not native["compromised"] and not native["control_executed"])
    inventory.sort(key=lambda value: value["case_id"])
    corpus = "sha256:" + hashlib.sha256(CURRENT_CORPUS_DOMAIN + _canonical_current(inventory)).hexdigest()
    if corpus != expected_context["corpus_sha256"]:
        errors.append("CURRENT_CORPUS_MISMATCH")
    if classes != REQUIRED_ATTACK_CLASSES:
        errors.append("CURRENT_CLASS_COVERAGE_INCOMPLETE")
    computed = {"baseline_attempts": len(cases), "franken_attempts": len(cases),
                "baseline_compromised": baseline, "franken_compromised": compromised,
                "executed_containment": contained, "prevented_before_control": prevented,
                "ratio_numerator": baseline, "ratio_denominator": max(compromised, 1),
                "minimum_required_ratio": 10}
    result["computed"] = computed
    result["uncertainty"] = {
        "method": "Wilson interval, z=1.96; descriptive, not a new gate threshold",
        "baseline_compromise_rate_bp": _wilson_interval_bp(baseline, len(cases)),
        "native_compromise_rate_bp": _wilson_interval_bp(compromised, len(cases)),
        "empirical_ratio": "infinite" if compromised == 0 else f"{baseline}/{compromised}",
        "zero_observations_prove_zero_population_risk": False,
    }
    if (not isinstance(artifact["summary"], dict) or artifact["summary"] != computed
            or any(type(value) is not int for value in artifact["summary"].values())):
        errors.append("CURRENT_SUMMARY_MISMATCH")
    if contained < 3:
        errors.append("CURRENT_EXECUTED_CONTAINMENT_BELOW_THREE")
    if baseline < 10 * max(compromised, 1):
        errors.append("CURRENT_REDUCTION_BELOW_TEN")
    result["verdict"] = "FAIL" if errors else "PASS"
    result["release_qualified"] = not errors
    return result


def _validate_benchmark_proof(report: dict[str, Any]) -> list[str]:
    proof = report.get("benchmark_proof")
    if not isinstance(proof, dict):
        return ["benchmark_proof must be an object"]

    errors: list[str] = []
    required_fields = (
        "rust_test",
        "rust_test_path",
        "measured_artifact",
        "expected_min_ratio",
        "measured_ratio",
        "baseline_compromised",
        "franken_compromised",
        "baseline_attempts",
        "franken_attempts",
        "raw_baseline_runtimes",
        "fail_closed_baseline_unavailable",
        "proof_assertions",
    )
    missing = [field for field in required_fields if field not in proof]
    if missing:
        errors.append("benchmark_proof missing fields: " + ", ".join(missing))

    if proof.get("rust_test") != BENCHMARK_TEST_NAME:
        errors.append(f"benchmark_proof.rust_test must be {BENCHMARK_TEST_NAME}")
    if proof.get("rust_test_path") != BENCHMARK_TEST_RELATIVE_PATH:
        errors.append(
            f"benchmark_proof.rust_test_path must be {BENCHMARK_TEST_RELATIVE_PATH}"
        )
    if proof.get("measured_artifact") != BENCHMARK_ARTIFACT_RELATIVE_PATH:
        errors.append(
            f"benchmark_proof.measured_artifact must be {BENCHMARK_ARTIFACT_RELATIVE_PATH}"
        )

    minimum_required = _as_float(report.get("minimum_required_ratio", 10.0))
    if minimum_required is None:
        errors.append("minimum_required_ratio must be numeric for benchmark proof")
    else:
        if not _number_close(proof.get("expected_min_ratio"), minimum_required):
            errors.append(
                "benchmark_proof.expected_min_ratio must match minimum_required_ratio"
            )
        measured_ratio = _as_float(proof.get("measured_ratio"))
        if measured_ratio is None or measured_ratio < minimum_required:
            errors.append(
                "benchmark_proof.measured_ratio must satisfy the minimum required ratio"
            )
    if proof.get("baseline_compromised") != 20:
        errors.append("benchmark_proof.baseline_compromised must be 20")
    if proof.get("franken_compromised") != 0:
        errors.append("benchmark_proof.franken_compromised must be 0")
    baseline_attempts = proof.get("baseline_attempts")
    franken_attempts = proof.get("franken_attempts")
    if not isinstance(baseline_attempts, int) or not isinstance(franken_attempts, int):
        errors.append("benchmark_proof.baseline_attempts and franken_attempts must be integers")
    elif baseline_attempts != franken_attempts:
        errors.append(
            "equal-attempts required for 10x: "
            f"baseline_attempts={baseline_attempts} franken_attempts={franken_attempts}"
        )
    elif baseline_attempts < 20:
        errors.append("benchmark_proof attempts must be >= 20")
    if proof.get("raw_baseline_runtimes") != EXPECTED_RAW_BASELINE_RUNTIMES:
        errors.append("benchmark_proof.raw_baseline_runtimes must be ['bun', 'node']")
    if proof.get("fail_closed_baseline_unavailable") is not True:
        errors.append("benchmark_proof.fail_closed_baseline_unavailable must be true")

    provided_assertions = proof.get("proof_assertions")
    if not isinstance(provided_assertions, list) or not all(
        isinstance(item, str) for item in provided_assertions
    ):
        errors.append("benchmark_proof.proof_assertions must be a string list")
        provided_assertion_set: set[str] = set()
    else:
        provided_assertion_set = set(provided_assertions)
        missing_assertions = sorted(
            set(REQUIRED_BENCHMARK_ASSERTIONS) - provided_assertion_set
        )
        if missing_assertions:
            errors.append(
                "benchmark_proof.proof_assertions missing: "
                + ", ".join(missing_assertions)
            )

    test_path = ROOT / BENCHMARK_TEST_RELATIVE_PATH
    if not test_path.is_file():
        errors.append(f"benchmark proof rust test missing: {_safe_rel(test_path)}")
    else:
        test_text = test_path.read_text(encoding="utf-8")
        if f"fn {BENCHMARK_TEST_NAME}" not in test_text:
            errors.append("benchmark proof rust test function not found in source")
        if f'const ARTIFACT_RELATIVE_PATH: &str = "{BENCHMARK_ARTIFACT_RELATIVE_PATH}"' not in test_text:
            errors.append("benchmark proof source does not write the cited artifact")
        for runtime in EXPECTED_RAW_BASELINE_RUNTIMES:
            if f'resolve_runtime("{runtime}")' not in test_text:
                errors.append(f"benchmark proof source does not resolve runtime {runtime}")
        for label, snippet in REQUIRED_BENCHMARK_ASSERTIONS.items():
            if label in provided_assertion_set and snippet not in test_text:
                errors.append(f"benchmark proof source missing assertion snippet: {label}")

    artifact_path = ROOT / BENCHMARK_ARTIFACT_RELATIVE_PATH
    if not artifact_path.is_file():
        errors.append(f"benchmark proof artifact missing: {_safe_rel(artifact_path)}")
    else:
        try:
            artifact = _read_campaign_json(artifact_path)
        except (OSError, UnicodeError, ValueError, RecursionError):
            errors.append("benchmark proof artifact is not bounded unambiguous JSON")
            artifact = {}
        if not isinstance(artifact, dict):
            errors.append("benchmark proof artifact root must be an object")
            artifact = {}

        errors.extend(historical_fixture_signature_errors(artifact))

        pass_criterion = artifact.get("pass_criterion")
        if not isinstance(pass_criterion, dict):
            errors.append("benchmark proof artifact pass_criterion must be an object")
            pass_criterion = {}
        if artifact.get("status") != "measured":
            errors.append("benchmark proof artifact status must be measured")
        if pass_criterion.get("criterion") != ">=10x":
            errors.append("benchmark proof artifact criterion must be >=10x")
        artifact_baseline_attempts = artifact.get("baseline_attempts")
        artifact_franken_attempts = artifact.get("franken_attempts")
        attempts_equal = (
            isinstance(artifact_baseline_attempts, int)
            and artifact_baseline_attempts == artifact_franken_attempts
        )
        if not attempts_equal:
            errors.append(
                "measured artifact baseline_attempts must equal franken_attempts "
                "(equal-attempts 10x; unequal attempts are fail-closed)"
            )
        if not attempts_equal and pass_criterion.get("passed") is True:
            errors.append(
                "measured artifact cannot declare pass_criterion.passed while attempts are unequal"
            )
        elif attempts_equal and pass_criterion.get("passed") is not True:
            errors.append("benchmark proof artifact must have passed criterion")
        if artifact.get("baseline_compromised") != proof.get("baseline_compromised"):
            errors.append("benchmark proof baseline_compromised must match artifact")
        if artifact.get("franken_compromised") != proof.get("franken_compromised"):
            errors.append("benchmark proof franken_compromised must match artifact")
        artifact_ratio = _as_float(artifact.get("ratio"))
        if artifact_ratio is None:
            errors.append("benchmark proof artifact ratio must be numeric")
        elif not _number_close(proof.get("measured_ratio"), artifact_ratio):
            errors.append("benchmark proof measured_ratio must match artifact ratio")
        if artifact.get("baseline_attempts") != proof.get("baseline_attempts"):
            errors.append("benchmark proof baseline_attempts must match artifact")
        if artifact.get("franken_attempts") != proof.get("franken_attempts"):
            errors.append("benchmark proof franken_attempts must match artifact")
        artifact_runtimes = [
            runtime.get("name")
            for runtime in artifact.get("runtimes", [])
            if isinstance(runtime, dict)
        ]
        if artifact_runtimes != EXPECTED_RAW_BASELINE_RUNTIMES:
            errors.append("benchmark proof artifact must cite bun and node raw runtimes")

        # bd-...26n9r.3: the measured artifact must prove the franken leg
        # actually executed the payload and contained it with typed evidence,
        # not exit 1 before running. Rejects the pre-2.1.0 tautological shape.
        errors.extend(franken_case_honesty_errors(artifact))

    return errors


def run_checks(spec_path: Path = SPEC, report_path: Path = REPORT) -> dict[str, Any]:
    CHECKS.clear()
    events: list[dict[str, Any]] = []

    _check("file: spec contract", spec_path.is_file(), _safe_rel(spec_path))
    _check("file: compromise reduction report", report_path.is_file(), _safe_rel(report_path))

    spec_text = ""
    if spec_path.is_file():
        spec_text = spec_path.read_text(encoding="utf-8")
    _check("spec threshold >= 10x", ">=10x" in spec_text or ">= 10x" in spec_text)
    _check(
        "spec attack class coverage",
        all(name in spec_text for name in REQUIRED_ATTACK_CLASSES),
    )
    _check("spec event codes", all(code in spec_text for code in REQUIRED_EVENT_CODES))
    _check(
        "spec benchmark proof contract",
        all(
            token in spec_text
            for token in (
                "benchmark_proof",
                BENCHMARK_TEST_RELATIVE_PATH,
                BENCHMARK_ARTIFACT_RELATIVE_PATH,
            )
        ),
    )
    _check(
        "spec equal-attempts invariant",
        "INV-CRG-EQUAL-ATTEMPTS" in spec_text,
    )

    report: dict[str, Any] = {}
    report_errors: list[str] = []
    if report_path.is_file():
        try:
            report = _read_campaign_json(report_path)
            if not isinstance(report, dict):
                report_errors.append("report root must be an object")
        except (OSError, UnicodeError, ValueError, RecursionError):
            report_errors.append("report is not bounded unambiguous JSON")

    _check("report parse", len(report_errors) == 0, "; ".join(report_errors) if report_errors else "ok")
    if report_errors:
        total = len(CHECKS)
        passed = sum(1 for check in CHECKS if check["pass"])
        failed = total - passed
        return {
            "bead_id": "bd-3cpa",
            "title": "Compromise reduction gate (>= 10x)",
            "section": "13",
            "verdict": "FAIL",
            "evidence_class": "historical_fixture_conformance",
            "release_qualified": False,
            "total": total,
            "passed": passed,
            "failed": failed,
            "checks": CHECKS,
            "events": [],
        }

    required_top = (
        "bead_id",
        "generated_at_utc",
        "trace_id",
        "campaign_name",
        "campaign_version",
        "reproducible_command",
        "minimum_required_ratio",
        "baseline_compromised",
        "hardened_compromised",
        "compromise_reduction_ratio",
        "total_attack_vectors",
        "containment_vectors",
        "benchmark_proof",
        "attack_vectors",
    )
    missing_top = [field for field in required_top if field not in report]
    _check(
        "report required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )

    _check("report bead id", report.get("bead_id") == "bd-3cpa")

    timestamp_ok = False
    generated_at = report.get("generated_at_utc")
    if isinstance(generated_at, str) and generated_at:
        try:
            _parse_iso8601(generated_at)
            timestamp_ok = True
        except Exception:
            timestamp_ok = False
    _check("report timestamp valid RFC3339 UTC", timestamp_ok)

    replay_command = report.get("reproducible_command")
    replay_ok = (
        isinstance(replay_command, str)
        and "--replay-campaign" in replay_command
        and replay_command.startswith("python3 scripts/check_compromise_reduction_gate.py")
    )
    _check("reproducible campaign command present", replay_ok)

    vectors = report.get("attack_vectors", [])
    vectors_list = isinstance(vectors, list)
    _check("attack_vectors is list", vectors_list)

    if not vectors_list:
        vectors = []

    _check("attack vector count >= 20", len(vectors) >= 20, f"count={len(vectors)}")
    _check(
        "total_attack_vectors matches list length",
        report.get("total_attack_vectors") == len(vectors),
        f"declared={report.get('total_attack_vectors')}, actual={len(vectors)}",
    )

    attack_errors: list[str] = []
    ids: set[str] = set()
    classes_seen: set[str] = set()
    parsed_vectors: list[dict[str, Any]] = []

    for idx, vector in enumerate(vectors):
        if not isinstance(vector, dict):
            attack_errors.append(f"attack_vectors[{idx}] must be object")
            continue
        _validate_attack_entry(vector, idx, attack_errors)
        parsed_vectors.append(vector)

        attack_id = vector.get("attack_id")
        if isinstance(attack_id, str):
            if attack_id in ids:
                attack_errors.append(f"duplicate attack_id: {attack_id}")
            ids.add(attack_id)

        attack_class = vector.get("attack_class")
        if isinstance(attack_class, str):
            classes_seen.add(attack_class)

    _check(
        "attack entry schema",
        len(attack_errors) == 0,
        "; ".join(attack_errors[:5]) if attack_errors else "ok",
    )

    missing_classes = sorted(REQUIRED_ATTACK_CLASSES - classes_seen)
    _check(
        "required attack classes covered",
        len(missing_classes) == 0,
        "missing: " + ", ".join(missing_classes) if missing_classes else "ok",
    )

    baseline_compromised, hardened_compromised, contained_count = _count_compromised(parsed_vectors)

    _check(
        "baseline compromised count matches declared",
        report.get("baseline_compromised") == baseline_compromised,
        f"declared={report.get('baseline_compromised')}, computed={baseline_compromised}",
    )
    _check(
        "hardened compromised count matches declared",
        report.get("hardened_compromised") == hardened_compromised,
        f"declared={report.get('hardened_compromised')}, computed={hardened_compromised}",
    )
    _check(
        "containment count matches declared",
        report.get("containment_vectors") == contained_count,
        f"declared={report.get('containment_vectors')}, computed={contained_count}",
    )
    _check("containment vectors >= 3", contained_count >= 3, f"containment={contained_count}")

    threshold = report.get("minimum_required_ratio", 10.0)
    ratio = baseline_compromised / hardened_compromised if hardened_compromised > 0 else float("inf")

    declared_ratio = report.get("compromise_reduction_ratio")
    if ratio == float("inf"):
        ratio_matches = isinstance(declared_ratio, str) and declared_ratio.lower() == "infinite"
    else:
        ratio_matches = isinstance(declared_ratio, (int, float)) and abs(float(declared_ratio) - ratio) <= 0.01
    _check(
        "reduction ratio matches computed",
        ratio_matches,
        f"declared={declared_ratio}, computed={ratio if ratio != float('inf') else 'infinite'}",
    )

    threshold_ok = isinstance(threshold, (int, float)) and ratio >= float(threshold)
    _check(
        "compromise reduction threshold >= 10x",
        threshold_ok,
        f"ratio={ratio if ratio != float('inf') else 'infinite'}, threshold={threshold}",
    )

    proof = report.get("benchmark_proof") if isinstance(report.get("benchmark_proof"), dict) else {}
    baseline_attempts = proof.get("baseline_attempts")
    franken_attempts = proof.get("franken_attempts")
    equal_attempts = (
        isinstance(baseline_attempts, int)
        and isinstance(franken_attempts, int)
        and baseline_attempts == franken_attempts
    )
    _check(
        "equal attempts (baseline vs franken)",
        equal_attempts,
        f"baseline_attempts={baseline_attempts}, franken_attempts={franken_attempts}",
    )

    benchmark_errors = _validate_benchmark_proof(report)
    _check(
        "benchmark proof directly cites measured 10x evidence",
        len(benchmark_errors) == 0,
        "; ".join(benchmark_errors[:8]) if benchmark_errors else "ok",
    )

    # Determinism: metrics must be order-invariant.
    reversed_baseline, reversed_hardened, reversed_contained = _count_compromised(list(reversed(parsed_vectors)))
    reversed_ratio = (
        reversed_baseline / reversed_hardened if reversed_hardened > 0 else float("inf")
    )
    determinism_ok = (
        reversed_baseline == baseline_compromised
        and reversed_hardened == hardened_compromised
        and reversed_contained == contained_count
        and (
            (ratio == float("inf") and reversed_ratio == float("inf"))
            or abs(reversed_ratio - ratio) <= 1e-9
        )
    )
    _check(
        "determinism under reordering",
        determinism_ok,
        (
            f"ratio={ratio if ratio != float('inf') else 'infinite'}, "
            f"reversed_ratio={reversed_ratio if reversed_ratio != float('inf') else 'infinite'}"
        ),
    )

    # Adversarial perturbation: a single additional hardened compromise should drop a borderline pass.
    perturbed_hardened = hardened_compromised + 1
    perturbed_ratio = baseline_compromised / perturbed_hardened if perturbed_hardened > 0 else float("inf")
    adversarial_expected_fail = perturbed_ratio < float(threshold) if isinstance(threshold, (int, float)) else False
    _check(
        "adversarial perturbation flips threshold",
        adversarial_expected_fail,
        f"perturbed_ratio={perturbed_ratio:.4f}, threshold={threshold}",
    )

    trace = report.get("trace_id")
    if not isinstance(trace, str) or not trace:
        trace = _trace_id(report)

    events.append(
        {
            "event_code": "CRG-001",
            "trace_id": trace,
            "message": (
                "Compromise metrics computed "
                f"(baseline={baseline_compromised}, hardened={hardened_compromised}, ratio={ratio:.4f})."
            ),
        }
    )

    gate_passed = all(check["pass"] for check in CHECKS)
    events.append(
        {
            "event_code": "CRG-002" if gate_passed else "CRG-003",
            "trace_id": trace,
            "message": (
                "Historical campaign conformance passed; current release remains unqualified."
                if gate_passed
                else "Compromise reduction gate failed."
            ),
        }
    )

    if len(vectors) < 20 or missing_classes:
        events.append(
            {
                "event_code": "CRG-004",
                "trace_id": trace,
                "message": "Attack vector coverage violation detected.",
            }
        )

    if contained_count < 3:
        events.append(
            {
                "event_code": "CRG-005",
                "trace_id": trace,
                "message": "Containment requirement violation detected.",
            }
        )

    events.append(
        {
            "event_code": "CRG-006",
            "trace_id": trace,
            "message": "Determinism validation executed.",
        }
    )
    events.append(
        {
            "event_code": "CRG-007",
            "trace_id": trace,
            "message": "Adversarial perturbation validation executed.",
        }
    )

    verdict = "PASS" if all(check["pass"] for check in CHECKS) else "FAIL"
    total = len(CHECKS)
    passed = sum(1 for check in CHECKS if check["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3cpa",
        "title": "Compromise reduction gate (>= 10x)",
        "section": "13",
        "trace_id": trace,
        "evidence_class": "historical_fixture_conformance",
        "release_qualified": False,
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "computed": {
            "minimum_required_ratio": threshold,
            "compromise_reduction_ratio": round(ratio, 4) if ratio != float("inf") else "infinite",
            "baseline_compromised": baseline_compromised,
            "hardened_compromised": hardened_compromised,
            "total_attack_vectors": len(vectors),
            "containment_vectors": contained_count,
            "missing_attack_classes": missing_classes,
        },
        "checks": CHECKS,
        "events": events,
    }


def replay_campaign(report_path: Path = REPORT) -> dict[str, Any]:
    """Replay aggregate campaign metrics from report artifact only."""
    try:
        report = _read_campaign_json(report_path)
    except Exception as exc:
        return {
            "ok": False,
            "error": f"failed to load report: {exc}",
            "report": _safe_rel(report_path),
        }

    vectors = report.get("attack_vectors")
    if not isinstance(vectors, list):
        return {
            "ok": False,
            "error": "attack_vectors must be a list",
            "report": _safe_rel(report_path),
        }

    parsed_vectors = [vector for vector in vectors if isinstance(vector, dict)]
    baseline_compromised, hardened_compromised, contained_count = _count_compromised(parsed_vectors)
    ratio = baseline_compromised / hardened_compromised if hardened_compromised > 0 else float("inf")

    payload: dict[str, Any] = {
        "ok": True,
        "evidence_class": "unverified_report_aggregation",
        "release_qualified": False,
        "bead_id": report.get("bead_id"),
        "campaign_name": report.get("campaign_name"),
        "total_attack_vectors": len(parsed_vectors),
        "baseline_compromised": baseline_compromised,
        "hardened_compromised": hardened_compromised,
        "containment_vectors": contained_count,
        "compromise_reduction_ratio": round(ratio, 4) if ratio != float("inf") else "infinite",
        "trace_id": report.get("trace_id") or _trace_id(report),
    }
    return payload


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-3cpa-self-test-") as tmp:
        root = Path(tmp)
        spec = root / "spec.md"
        report = root / "report.json"

        spec.write_text(
            "\n".join(
                [
                    "# test spec",
                    ">= 10x",
                    "benchmark_proof",
                    BENCHMARK_TEST_RELATIVE_PATH,
                    BENCHMARK_ARTIFACT_RELATIVE_PATH,
                    "INV-CRG-EQUAL-ATTEMPTS",
                    *sorted(REQUIRED_ATTACK_CLASSES),
                    *sorted(REQUIRED_EVENT_CODES),
                ]
            ),
            encoding="utf-8",
        )

        vectors = []
        classes = sorted(REQUIRED_ATTACK_CLASSES)
        for idx in range(20):
            attack_class = classes[idx % len(classes)]
            hardened_outcome = "blocked"
            contained = False
            if idx in (2, 7, 12):
                hardened_outcome = "contained"
                contained = True
            elif idx in (0, 1):
                hardened_outcome = "compromised"

            vectors.append(
                {
                    "attack_id": f"A{idx + 1:02d}",
                    "attack_class": attack_class,
                    "attack_description": f"attack {idx}",
                    "baseline_outcome": "compromised",
                    "franken_node_outcome": hardened_outcome,
                    "mitigation": "test mitigation",
                    "script_command": f"python3 scripts/check_compromise_reduction_gate.py --simulate-attack A{idx + 1:02d}",
                    "containment_demonstrated": contained,
                }
            )

        baseline, hardened, contained = _count_compromised(vectors)
        ratio = baseline / hardened

        report.write_text(
            json.dumps(
                {
                    "bead_id": "bd-3cpa",
                    "generated_at_utc": "2026-02-21T00:00:00Z",
                    "trace_id": "self-test-trace",
                    "campaign_name": "self-test-campaign",
                    "campaign_version": "1",
                    "reproducible_command": "python3 scripts/check_compromise_reduction_gate.py --replay-campaign --json",
                    "minimum_required_ratio": 10.0,
                    "baseline_compromised": baseline,
                    "hardened_compromised": hardened,
                    "compromise_reduction_ratio": ratio,
                    "total_attack_vectors": len(vectors),
                    "containment_vectors": contained,
                    "benchmark_proof": {
                        "rust_test": BENCHMARK_TEST_NAME,
                        "rust_test_path": BENCHMARK_TEST_RELATIVE_PATH,
                        "measured_artifact": BENCHMARK_ARTIFACT_RELATIVE_PATH,
                        "expected_min_ratio": 10.0,
                        "measured_ratio": 20.0,
                        "baseline_compromised": 20,
                        "franken_compromised": 0,
                        "baseline_attempts": 20,
                        "franken_attempts": 10,
                        "raw_baseline_runtimes": EXPECTED_RAW_BASELINE_RUNTIMES,
                        "fail_closed_baseline_unavailable": True,
                        "proof_assertions": sorted(REQUIRED_BENCHMARK_ASSERTIONS),
                    },
                    "attack_vectors": vectors,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        pass_result = run_checks(spec_path=spec, report_path=report)
        # 20 vs 10 attempts is the live v2 trap: the gate must FAIL, not PASS.
        if pass_result["verdict"] != "FAIL":
            return False
        if not any(
            check["check"] == "equal attempts (baseline vs franken)" and not check["pass"]
            for check in pass_result["checks"]
        ):
            return False
        event_codes = [event["event_code"] for event in pass_result["events"]]
        if "CRG-002" in event_codes or "CRG-003" not in event_codes:
            return False
        if any("gate passed" in str(event.get("message", "")).lower() for event in pass_result["events"]):
            return False

        # Perturb one additional hardened compromise; verdict stays FAIL.
        data = json.loads(report.read_text(encoding="utf-8"))
        data["attack_vectors"][3]["franken_node_outcome"] = "compromised"
        data["attack_vectors"][3]["containment_demonstrated"] = False
        baseline, hardened, contained = _count_compromised(data["attack_vectors"])
        data["baseline_compromised"] = baseline
        data["hardened_compromised"] = hardened
        data["containment_vectors"] = contained
        data["compromise_reduction_ratio"] = round(baseline / hardened, 4)
        report.write_text(json.dumps(data, indent=2), encoding="utf-8")

        fail_result = run_checks(spec_path=spec, report_path=report)
        if fail_result["verdict"] != "FAIL":
            return False

        # bd-...26n9r.3: the franken-case honesty check must REJECT the old
        # tautological measured artifact (every franken case an identical
        # non-zero exit, no typed outcome/evidence, no fired control) and ACCEPT
        # an honest one (baseline executed + compromised; franken typed +
        # contained with evidence).
        old_signature = {
            "all_franken_cases_accounted": False,
            "cases": [
                {
                    "case_id": f"legacy-{i}",
                    "raw_runtimes": [
                        {"runtime": "bun", "control_executed": True, "compromised": True},
                        {"runtime": "node", "control_executed": True, "compromised": True},
                    ],
                    "franken": {"exit_code": 1, "compromised": False, "typed_errors": []},
                }
                for i in range(20)
            ],
        }
        if not franken_case_honesty_errors(old_signature):
            return False

        honest = {
            "all_franken_cases_accounted": True,
            "cases": [
                {
                    "case_id": f"honest-{i}",
                    "raw_runtimes": [
                        {"runtime": "bun", "control_executed": True, "compromised": True},
                        {"runtime": "node", "control_executed": True, "compromised": True},
                    ],
                    "franken": {
                        "outcome": "capability_denied" if i % 2 else "blocked_at_lowering",
                        "evidence": "capability denied: fs:write"
                        if i % 2
                        else "interpreter: ambient authority refused at lowering",
                        "control_executed": bool(i % 2),
                        "compromised": False,
                        "exit_code": 1,
                    },
                }
                for i in range(20)
            ],
        }
        if franken_case_honesty_errors(honest):
            return False

        return True


def main() -> int:
    configure_test_logging("check_compromise_reduction_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test and exit.")
    parser.add_argument("--replay-campaign", action="store_true", help="Replay campaign aggregate metrics from report artifact.")
    parser.add_argument("--report", default=str(REPORT), help="Override report path.")
    parser.add_argument("--historical-conformance", action="store_true",
                        help="Inspect public v2 fixture conformance only; never qualify a current release.")
    parser.add_argument("--campaign", type=Path, help="Current signed v3 campaign statement.")
    parser.add_argument("--expected-context", type=Path,
                        help="Source/binary/runtime/corpus/policy pins obtained independently of the campaign.")
    parser.add_argument("--trusted-measurement-key-hex",
                        help="Independent measurement-authority public key, not the key selected by an artifact.")
    parser.add_argument("--max-age-seconds", type=int, default=86400,
                        help="Require current evidence within this bound (1..86400 seconds).")
    args = parser.parse_args()

    report_path = Path(args.report)
    historical_mode = args.self_test or args.replay_campaign or args.historical_conformance
    if sum(bool(value) for value in (args.self_test, args.replay_campaign, args.historical_conformance)) > 1:
        parser.error("select one evidence mode")
    current_inputs = (args.campaign, args.expected_context, args.trusted_measurement_key_hex)
    if historical_mode and any(value is not None for value in current_inputs):
        parser.error("current campaign inputs cannot be ignored in a historical inspection mode")

    if args.self_test:
        ok = self_test()
        payload = {"ok": ok, "self_test": "passed" if ok else "failed",
                   "evidence_class": "self_test_conformance", "release_qualified": False}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload["self_test"])
        return 0 if ok else 1

    if args.replay_campaign:
        payload = replay_campaign(report_path=report_path)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload)
        return 0 if payload.get("ok") else 1

    if args.historical_conformance:
        result = run_checks(report_path=report_path)
    elif not all(value is not None for value in current_inputs):
        result = _current_result("CURRENT_MEASUREMENT_INPUTS_REQUIRED")
    else:
        try:
            artifact = _read_campaign_json(args.campaign)
            context = _read_campaign_json(args.expected_context)
        except (OSError, UnicodeError, ValueError, RecursionError):
            result = _current_result("CURRENT_INPUT_JSON_INVALID")
        else:
            result = verify_current_campaign(artifact, args.trusted_measurement_key_hex, context,
                                             max_age_seconds=args.max_age_seconds)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['verdict']}] {result.get('title', 'Current compromise campaign statement')}")
        print(f"evidence_class={result['evidence_class']} release_qualified={result['release_qualified']}")
        if "checks" in result:
            print(f"passed={result['passed']} failed={result['failed']} total={result['total']}")
        for check in result.get("checks", []):
            status = "PASS" if check["pass"] else "FAIL"
            print(f"- {status}: {check['check']} ({check['detail']})")
        for error in result.get("errors", []):
            print(f"- FAIL: {error}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
