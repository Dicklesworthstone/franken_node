#!/usr/bin/env python3
"""
Dual-Oracle Completion Close-Condition Gate.

Enforces that L1 product oracle (10.2), L2 engine-boundary oracle (10.17),
and release-policy linkage are all GREEN before program completion is accepted.

Usage:
    python3 scripts/check_oracle_close_condition.py [--json] [--artifacts-dir DIR]

Exit codes:
    0 = PASS (all dimensions GREEN)
    1 = FAIL (one or more dimensions missing or not GREEN)
    2 = ERROR (malformed artifacts, parse error)
"""

import argparse
import hashlib
import hmac
import json
import re
import subprocess
import sys
import tempfile
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

DEFAULT_ARTIFACTS_DIR = ROOT / "artifacts" / "oracle"
# Mirrors the canonical Rust constants in
# crates/franken-node/src/schema_versions.rs (L1_PROOF_CARRYING_EFFECTS{,_V2}
# and L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS, acceptance invariant
# bd-f5b04.2.4). Update both sides together; the Rust conformance tests bind
# the subject list to the compat-gate contract layer.
L1_PROOF_EVIDENCE_SCHEMA = "franken-node/l1-proof-carrying-effects/v1"
L1_PROOF_EVIDENCE_SCHEMA_V2 = "franken-node/l1-proof-carrying-effects/v2"
REQUIRED_L1_PROOF_SUBJECTS = ("fs.read", "fs.write", "http.request")
# bd-ry7d1: the L1 lockstep-oracle verdict evidence block. Mirrors
# schema_versions::L1_LOCKSTEP_VERDICT_V1 and the re-derivation rules in
# ops/close_condition.rs::validate_l1_lockstep_verdict — update both sides
# together.
L1_LOCKSTEP_VERDICT_SCHEMA = "franken-node/l1-lockstep-verdict/v1"
# Mirrors runtime::nversion_oracle::SCHEMA_VERSION.
NVERSION_ORACLE_REPORT_SCHEMA = "nvo-v1.0"
DEFAULT_CLOSE_RECEIPT = DEFAULT_ARTIFACTS_DIR / "close_condition_receipt.json"
SOURCE_REVISION_SCHEMA = "franken-node/source-revision/v1"
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_GITHUB_ACTIONS_RUN_URL_RE = re.compile(
    r"^https://github\.com/[^/\s]+/[^/\s]+/actions/runs/[0-9]+/attempts/[0-9]+$"
)
_CLOSE_RECEIPT_PREIMAGE_DOMAIN = b"close_condition_receipt_v1:"
_ED25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ARTIFACT_SIGNING_KEY_ID_DOMAIN = b"artifact_signing_keyid_v1:"

# ---------------------------------------------------------------------------
# v2 re-derivation (bd-qr5i2.3): the gate does not trust the declared summary.
# Everything below mirrors crates/franken-node/src/runtime/effect_receipt.rs
# byte for byte — canonical hash preimages (domain-separated, length-prefixed
# SHA-256), enum tags, chain genesis, per-receipt validation — so the Python
# CI gate independently re-derives chain integrity, receipt validity,
# subjects, and counts from the embedded receipt_chain_entries and fails
# closed on any declared↔derived mismatch, exactly like the Rust doctor gate
# (ops/close_condition.rs::validate_l1_proof_carrying_effects_v2). A
# cross-language parity pin lives in tests/test_check_oracle_close_condition.py
# and crates/franken-node/tests/doctor_close_condition_e2e.rs: both assert the
# same deterministic hash constants, so preimage drift breaks exactly one
# suite immediately.
# ---------------------------------------------------------------------------

_RECEIPT_HASH_DOMAIN = b"runtime_effect_receipt_canonical_v1:"
_CHAIN_HASH_DOMAIN = b"runtime_effect_receipt_chain_v1:"
_CHAIN_GENESIS = "sha256:" + "0" * 64
_EFFECT_RECEIPT_SCHEMA = "effect-receipt-v1.1"
_U64_MAX = (1 << 64) - 1

_EFFECT_KIND_TAGS = {
    "fs_read": 1,
    "fs_write": 2,
    "net_connect": 3,
    "http_request": 4,
    "spawn": 5,
    "module_resolve": 6,
}
# EffectKind::l1_acceptance_subject() — kinds outside the acceptance list map
# to no subject and never count as executed-subject evidence.
_EFFECT_KIND_SUBJECTS = {
    "fs_read": "fs.read",
    "fs_write": "fs.write",
    "http_request": "http.request",
}
_POLICY_OUTCOME_TAGS = {"allowed": 1, "denied": 2}
_FLOW_VERDICT_TAGS = {"label_clean": 1, "declassified": 2, "blocked": 3}


def _is_u64(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _U64_MAX


def _parse_str(receipt: dict, field: str) -> str:
    value = receipt.get(field)
    if not isinstance(value, str):
        raise ValueError(f"receipt field {field} must be a string")
    return value


def _parse_opt_str(receipt: dict, field: str):
    value = receipt.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"receipt field {field} must be a string or null")
    return value


def _parse_content_hash(receipt: dict, field: str, optional: bool = False):
    """Mirror storage::cas::ContentHash::parse (serde boundary): sha256: +
    64 hex digits, normalized to lowercase."""
    value = receipt.get(field)
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"receipt field {field} must be a canonical sha256:<hex> hash")
    digest = value[len("sha256:"):]
    if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
        raise ValueError(f"receipt field {field} must be a canonical sha256:<hex> hash")
    return "sha256:" + digest.lower()


def _parse_chain_entries(entries_value) -> list[dict]:
    """Mirror serde_json::from_value::<Vec<EffectReceiptChainEntry>>: any
    missing/ill-typed field, unknown enum value, or malformed ContentHash
    makes the whole entry list unparseable (single fail-closed finding)."""
    if not isinstance(entries_value, list):
        raise ValueError("receipt_chain_entries must be an array")
    entries = []
    for position, raw in enumerate(entries_value):
        if not isinstance(raw, dict):
            raise ValueError(f"entry {position} must be an object")
        entry = {}
        for field in ("index",):
            if not _is_u64(raw.get(field)):
                raise ValueError(f"entry {position} field {field} must be a u64")
        entry["index"] = raw["index"]
        for field in ("prev_chain_hash", "receipt_hash", "chain_hash"):
            value = raw.get(field)
            if not isinstance(value, str):
                raise ValueError(f"entry {position} field {field} must be a string")
            entry[field] = value
        raw_receipt = raw.get("receipt")
        if not isinstance(raw_receipt, dict):
            raise ValueError(f"entry {position} receipt must be an object")
        receipt = {
            "schema_version": _parse_str(raw_receipt, "schema_version"),
            "trace_id": _parse_str(raw_receipt, "trace_id"),
            "input_lineage_hash": _parse_str(raw_receipt, "input_lineage_hash"),
            "output_lineage_hash": _parse_opt_str(raw_receipt, "output_lineage_hash"),
            "label_set_commitment": _parse_str(raw_receipt, "label_set_commitment"),
            "declassification_ref": _parse_opt_str(raw_receipt, "declassification_ref"),
            "pre_state_hash": _parse_content_hash(raw_receipt, "pre_state_hash"),
            "args_hash": _parse_content_hash(raw_receipt, "args_hash"),
            "result_hash": _parse_content_hash(raw_receipt, "result_hash", optional=True),
            "post_state_hash": _parse_content_hash(raw_receipt, "post_state_hash", optional=True),
        }
        if not _is_u64(raw_receipt.get("seq")):
            raise ValueError(f"entry {position} receipt seq must be a u64")
        receipt["seq"] = raw_receipt["seq"]
        if not _is_u64(raw_receipt.get("recorded_at_millis")):
            raise ValueError(f"entry {position} receipt recorded_at_millis must be a u64")
        receipt["recorded_at_millis"] = raw_receipt["recorded_at_millis"]
        effect_kind = raw_receipt.get("effect_kind")
        if effect_kind not in _EFFECT_KIND_TAGS:
            raise ValueError(f"entry {position} receipt effect_kind {effect_kind!r} is unknown")
        receipt["effect_kind"] = effect_kind
        flow_verdict = raw_receipt.get("flow_policy_verdict")
        if flow_verdict not in _FLOW_VERDICT_TAGS:
            raise ValueError(
                f"entry {position} receipt flow_policy_verdict {flow_verdict!r} is unknown"
            )
        receipt["flow_policy_verdict"] = flow_verdict
        outcome = raw_receipt.get("policy_outcome")
        if not isinstance(outcome, dict) or outcome.get("outcome") not in _POLICY_OUTCOME_TAGS:
            raise ValueError(f"entry {position} receipt policy_outcome is unknown")
        if outcome["outcome"] == "allowed":
            if not isinstance(outcome.get("capability_ref"), str):
                raise ValueError(f"entry {position} allowed outcome needs capability_ref")
            receipt["policy_outcome"] = {
                "outcome": "allowed",
                "capability_ref": outcome["capability_ref"],
            }
        else:
            if not isinstance(outcome.get("reason"), str):
                raise ValueError(f"entry {position} denied outcome needs reason")
            receipt["policy_outcome"] = {"outcome": "denied", "reason": outcome["reason"]}
        entry["receipt"] = receipt
        entries.append(entry)
    return entries


def _update_str(h, value: str) -> None:
    raw = value.encode("utf-8")
    h.update(len(raw).to_bytes(8, "little"))
    h.update(raw)


def _update_opt_str(h, value) -> None:
    if value is None:
        h.update(b"\x00")
    else:
        h.update(b"\x01")
        _update_str(h, value)


def receipt_hash(receipt: dict) -> str:
    """Canonical, domain-separated, length-prefixed receipt hash —
    byte-identical to EffectReceipt::receipt_hash."""
    h = hashlib.sha256()
    h.update(_RECEIPT_HASH_DOMAIN)
    _update_str(h, receipt["schema_version"])
    h.update(receipt["seq"].to_bytes(8, "little"))
    _update_str(h, receipt["trace_id"])
    h.update(bytes([_EFFECT_KIND_TAGS[receipt["effect_kind"]]]))
    outcome = receipt["policy_outcome"]
    h.update(bytes([_POLICY_OUTCOME_TAGS[outcome["outcome"]]]))
    if outcome["outcome"] == "allowed":
        _update_str(h, outcome["capability_ref"])
    else:
        _update_str(h, outcome["reason"])
    _update_str(h, receipt["pre_state_hash"])
    _update_str(h, receipt["args_hash"])
    _update_opt_str(h, receipt.get("result_hash"))
    _update_opt_str(h, receipt.get("post_state_hash"))
    _update_str(h, receipt["input_lineage_hash"])
    _update_opt_str(h, receipt.get("output_lineage_hash"))
    _update_str(h, receipt["label_set_commitment"])
    _update_opt_str(h, receipt.get("declassification_ref"))
    h.update(bytes([_FLOW_VERDICT_TAGS[receipt["flow_policy_verdict"]]]))
    h.update(receipt["recorded_at_millis"].to_bytes(8, "little"))
    return "sha256:" + h.hexdigest()


def chain_hash(index: int, prev_chain_hash: str, receipt_hash_value: str) -> str:
    """Byte-identical to effect_receipt::compute_chain_hash."""
    h = hashlib.sha256()
    h.update(_CHAIN_HASH_DOMAIN)
    h.update(index.to_bytes(8, "little"))
    _update_str(h, prev_chain_hash)
    _update_str(h, receipt_hash_value)
    return "sha256:" + h.hexdigest()


def _is_lineage_hash(value) -> bool:
    """Mirror effect_receipt::validate_lineage_hash: sha256: + exactly 64
    lowercase hex digits (no case normalization at this layer)."""
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value[len("sha256:"):]
    return len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


def _receipt_validation_error(receipt: dict):
    """Mirror EffectReceipt::validate — returns a reason string or None."""
    if receipt["schema_version"] != _EFFECT_RECEIPT_SCHEMA:
        return "schema version mismatch"
    if not receipt["trace_id"].strip():
        return "empty trace_id"
    if not _is_lineage_hash(receipt["input_lineage_hash"]):
        return "malformed input_lineage_hash"
    if not _is_lineage_hash(receipt["label_set_commitment"]):
        return "malformed label_set_commitment"
    output_lineage = receipt.get("output_lineage_hash")
    if output_lineage is not None and not _is_lineage_hash(output_lineage):
        return "malformed output_lineage_hash"
    declass = receipt.get("declassification_ref")
    if declass is not None and not declass.strip():
        return "empty declassification_ref"
    outcome = receipt["policy_outcome"]
    is_allowed = outcome["outcome"] == "allowed"
    if is_allowed:
        if not outcome["capability_ref"].strip():
            return "empty capability_ref"
        if receipt.get("result_hash") is None:
            return "allowed receipt missing result_hash"
        if receipt.get("post_state_hash") is None:
            return "allowed receipt missing post_state_hash"
        if output_lineage is None:
            return "allowed receipt missing output_lineage_hash"
    else:
        if not outcome["reason"].strip():
            return "empty denial reason"
        if receipt.get("result_hash") is not None:
            return "denied receipt carries result_hash"
        if receipt.get("post_state_hash") is not None:
            return "denied receipt carries post_state_hash"
        if output_lineage is not None:
            return "denied receipt carries output_lineage_hash"
    flow_verdict = receipt["flow_policy_verdict"]
    if flow_verdict == "label_clean" and declass is not None:
        return "label-clean effect carries declassification_ref"
    if flow_verdict == "declassified":
        if not is_allowed:
            return "declassified flow verdict requires an allowed effect"
        if declass is None:
            return "declassified flow verdict requires declassification_ref"
    if flow_verdict == "blocked":
        if is_allowed:
            return "blocked flow verdict requires a denied effect"
        if declass is not None:
            return "blocked flow verdict must not carry declassification_ref"
    return None


def _verify_entries_integrity(entries: list[dict]):
    """Mirror EffectReceiptChain::verify_entries_integrity — returns a
    detail string on the first violation or None when the chain re-derives."""
    expected_prev = _CHAIN_GENESIS
    for position, entry in enumerate(entries):
        if entry["index"] != position:
            return f"index field {entry['index']} != position {position}"
        if entry["prev_chain_hash"] != expected_prev:
            return "prev_chain_hash does not match prior entry"
        recomputed_receipt = receipt_hash(entry["receipt"])
        if recomputed_receipt != entry["receipt_hash"]:
            return "receipt_hash does not match receipt contents"
        recomputed_chain = chain_hash(
            entry["index"], entry["prev_chain_hash"], entry["receipt_hash"]
        )
        if recomputed_chain != entry["chain_hash"]:
            return "chain_hash does not match (index, prev, receipt)"
        expected_prev = entry["chain_hash"]
    return None


def _validate_proof_carrying_v2(proof: dict) -> list[str]:
    """Mirror ops/close_condition.rs::validate_l1_proof_carrying_effects_v2:
    re-derive everything from receipt_chain_entries, cross-check the declared
    summary, and evaluate the acceptance requirements over DERIVED values."""
    if "receipt_chain_entries" not in proof:
        return [
            "L1 proof_carrying_effects v2 missing receipt_chain_entries; "
            "v2 requires the embedded receipt chain"
        ]
    try:
        entries = _parse_chain_entries(proof["receipt_chain_entries"])
    except ValueError as err:
        return [f"L1 proof_carrying_effects v2 receipt_chain_entries failed to parse: {err}"]

    errors = []
    chain_error = _verify_entries_integrity(entries)
    derived_chain_verified = chain_error is None
    if chain_error is not None:
        errors.append(f"L1 proof-carrying receipt chain failed re-derivation: {chain_error}")

    derived_invalid = 0
    derived_verified = 0
    derived_subjects = set()
    for entry in entries:
        receipt = entry["receipt"]
        if _receipt_validation_error(receipt) is not None:
            derived_invalid += 1
            continue
        # Denied receipts are legitimate ledger content (fail-closed proof
        # that nothing ran) but never evidence an executed subject.
        if receipt["policy_outcome"]["outcome"] != "allowed":
            continue
        subject = _EFFECT_KIND_SUBJECTS.get(receipt["effect_kind"])
        if subject in REQUIRED_L1_PROOF_SUBJECTS:
            derived_subjects.add(subject)
            derived_verified += 1

    declared_subjects_raw = proof.get("verified_subjects")
    declared_subjects = (
        {subject for subject in declared_subjects_raw if isinstance(subject, str)}
        if isinstance(declared_subjects_raw, list)
        else set()
    )
    if declared_subjects != derived_subjects:
        errors.append(
            f"L1 declared verified_subjects {sorted(declared_subjects)} do not match "
            f"re-derived {sorted(derived_subjects)}"
        )
    declared_verified = proof.get("effect_receipts_verified")
    if not _is_u64(declared_verified) or declared_verified != derived_verified:
        errors.append(
            f"L1 declared effect_receipts_verified {declared_verified!r} does not match "
            f"re-derived {derived_verified}"
        )
    declared_invalid = proof.get("invalid_receipts")
    if not _is_u64(declared_invalid) or declared_invalid != derived_invalid:
        errors.append(
            f"L1 declared invalid_receipts {declared_invalid!r} does not match "
            f"re-derived {derived_invalid}"
        )
    declared_chain = proof.get("receipt_chain_verified")
    if not isinstance(declared_chain, bool) or declared_chain != derived_chain_verified:
        errors.append(
            f"L1 declared receipt_chain_verified {declared_chain!r} does not match "
            f"re-derived {derived_chain_verified}"
        )

    for subject in REQUIRED_L1_PROOF_SUBJECTS:
        if subject not in derived_subjects:
            errors.append(f"L1 proof_carrying_effects missing subject {subject}")
    if derived_verified < len(REQUIRED_L1_PROOF_SUBJECTS):
        errors.append(
            "L1 proof_carrying_effects effect_receipts_verified below required "
            f"{len(REQUIRED_L1_PROOF_SUBJECTS)}"
        )
    if derived_invalid != 0:
        errors.append(
            f"L1 proof_carrying_effects contains {derived_invalid} invalid receipt(s)"
        )

    return errors

# ---------------------------------------------------------------------------
# bd-ry7d1: lockstep verdict re-derivation. Mirrors
# ops/close_condition.rs::validate_l1_lockstep_verdict — the gate re-derives
# the verdict from the embedded nversion-oracle DivergenceReport (runtimes,
# checks, divergences) instead of trusting the declared "pass", and fails
# closed on any declared↔derived mismatch.
# ---------------------------------------------------------------------------


def _parse_lockstep_report(report) -> dict:
    """Structurally parse the embedded DivergenceReport, mirroring the strict
    serde parse on the Rust side: a missing/ill-typed field consumed by the
    acceptance bar makes the whole report unparseable (single finding)."""
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    parsed = {}
    schema_version = report.get("schema_version")
    if not isinstance(schema_version, str):
        raise ValueError("report schema_version must be a string")
    parsed["schema_version"] = schema_version
    trace_id = report.get("trace_id")
    if not isinstance(trace_id, str):
        raise ValueError("report trace_id must be a string")
    parsed["trace_id"] = trace_id
    runtimes = report.get("runtimes")
    if not isinstance(runtimes, dict):
        raise ValueError("report runtimes must be an object")
    parsed_runtimes = {}
    for runtime_id, entry in runtimes.items():
        if not isinstance(entry, dict):
            raise ValueError(f"runtime {runtime_id!r} entry must be an object")
        runtime_name = entry.get("runtime_name")
        is_reference = entry.get("is_reference")
        if not isinstance(runtime_name, str):
            raise ValueError(f"runtime {runtime_id!r} runtime_name must be a string")
        if not isinstance(is_reference, bool):
            raise ValueError(f"runtime {runtime_id!r} is_reference must be a bool")
        parsed_runtimes[runtime_id] = {
            "runtime_name": runtime_name,
            "is_reference": is_reference,
        }
    parsed["runtimes"] = parsed_runtimes
    checks = report.get("checks")
    if not isinstance(checks, list):
        raise ValueError("report checks must be an array")
    parsed_checks = []
    for position, check in enumerate(checks):
        if not isinstance(check, dict):
            raise ValueError(f"check {position} must be an object")
        check_id = check.get("check_id")
        if not isinstance(check_id, str):
            raise ValueError(f"check {position} check_id must be a string")
        outcome = check.get("outcome")
        if outcome is not None:
            if not isinstance(outcome, dict) or len(outcome) != 1:
                raise ValueError(f"check {check_id!r} outcome is malformed")
            (outcome_kind,) = outcome.keys()
            if outcome_kind not in ("Agree", "Diverge"):
                raise ValueError(f"check {check_id!r} outcome {outcome_kind!r} is unknown")
        parsed_checks.append({"check_id": check_id, "outcome": outcome})
    parsed["checks"] = parsed_checks
    divergences = report.get("divergences")
    if not isinstance(divergences, list):
        raise ValueError("report divergences must be an array")
    parsed["divergences"] = divergences
    verdict = report.get("verdict")
    if verdict == "Pass":
        parsed["verdict_label"] = "pass"
    elif isinstance(verdict, dict) and len(verdict) == 1 and "BlockRelease" in verdict:
        parsed["verdict_label"] = "block_release"
    elif isinstance(verdict, dict) and len(verdict) == 1 and "RequiresReceipt" in verdict:
        parsed["verdict_label"] = "requires_receipt"
    else:
        raise ValueError(f"report verdict {verdict!r} is unknown")
    return parsed


def validate_l1_lockstep_verdict(data: dict) -> list[str]:
    """Mirror ops/close_condition.rs::validate_l1_lockstep_verdict."""
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        # The missing-evidence finding is already emitted by the
        # proof-carrying validator; do not double-report here.
        return []
    block = evidence.get("lockstep_verdict")
    if block is None:
        return [
            "L1 evidence.lockstep_verdict missing; the L1 lockstep leg requires a real "
            "lockstep-oracle verdict (regenerate via `franken-node ops "
            "proof-carrying-evidence --merge-l1-verdict`)"
        ]
    if not isinstance(block, dict):
        return ["L1 lockstep_verdict evidence must be an object"]
    schema_version = block.get("schema_version")
    if schema_version != L1_LOCKSTEP_VERDICT_SCHEMA:
        return [
            f"L1 lockstep_verdict schema_version {schema_version!r} is unsupported: only "
            f"{L1_LOCKSTEP_VERDICT_SCHEMA} is accepted"
        ]
    if "report" not in block:
        return [
            "L1 lockstep_verdict missing embedded report; v1 requires the full divergence "
            "report for re-derivation"
        ]
    try:
        report = _parse_lockstep_report(block.get("report"))
    except ValueError as err:
        return [f"L1 lockstep_verdict embedded report failed to parse: {err}"]

    errors = []
    if report["schema_version"] != NVERSION_ORACLE_REPORT_SCHEMA:
        errors.append(
            f"L1 lockstep report schema_version {report['schema_version']} is not the "
            f"supported {NVERSION_ORACLE_REPORT_SCHEMA}"
        )

    runtimes = report["runtimes"]
    if len(runtimes) < 2:
        errors.append(
            f"L1 lockstep report registered only {len(runtimes)} runtime(s); a lockstep "
            "verdict requires at least 2"
        )
    distinct_names = {entry["runtime_name"] for entry in runtimes.values()}
    if len(runtimes) >= 2 and len(distinct_names) < 2:
        errors.append(
            "L1 lockstep report runtimes share one executor name; self-agreement is not a "
            "cross-check"
        )
    if not any(entry["is_reference"] for entry in runtimes.values()):
        errors.append("L1 lockstep report has no reference runtime leg (is_reference=true)")
    if not any(not entry["is_reference"] for entry in runtimes.values()):
        errors.append("L1 lockstep report has no franken runtime leg (is_reference=false)")

    if not report["checks"]:
        errors.append("L1 lockstep report contains no cross-runtime checks")
    for check in report["checks"]:
        if check["outcome"] is None:
            errors.append(f"L1 lockstep check {check['check_id']} has no recorded outcome")
        elif "Diverge" in check["outcome"]:
            errors.append(f"L1 lockstep check {check['check_id']} diverged across runtimes")

    if report["divergences"]:
        errors.append(
            f"L1 lockstep report carries {len(report['divergences'])} divergence(s); the L1 "
            "bar requires zero"
        )
    if report["verdict_label"] != "pass":
        errors.append(f"L1 lockstep report verdict is {report['verdict_label']} (not pass)")

    declared_verdict = block.get("oracle_verdict")
    if declared_verdict != report["verdict_label"]:
        errors.append(
            f"L1 lockstep declared oracle_verdict {declared_verdict!r} does not match "
            f"re-derived {report['verdict_label']}"
        )
    declared_trace = block.get("trace_id")
    if declared_trace != report["trace_id"]:
        errors.append(
            f"L1 lockstep declared trace_id {declared_trace!r} does not match report "
            f"trace_id {report['trace_id']}"
        )
    declared_runtimes_raw = block.get("runtimes")
    declared_runtimes = (
        {runtime for runtime in declared_runtimes_raw if isinstance(runtime, str)}
        if isinstance(declared_runtimes_raw, list)
        else set()
    )
    if declared_runtimes != set(runtimes.keys()):
        errors.append(
            f"L1 lockstep declared runtimes {sorted(declared_runtimes)} do not match "
            f"re-derived {sorted(runtimes.keys())}"
        )
    declared_checks = block.get("checks_total")
    if not _is_u64(declared_checks) or declared_checks != len(report["checks"]):
        errors.append(
            f"L1 lockstep declared checks_total {declared_checks!r} does not match "
            f"re-derived {len(report['checks'])}"
        )
    declared_divergences = block.get("divergence_count")
    if not _is_u64(declared_divergences) or declared_divergences != len(report["divergences"]):
        errors.append(
            f"L1 lockstep declared divergence_count {declared_divergences!r} does not match "
            f"re-derived {len(report['divergences'])}"
        )

    return errors


def validate_l1_corpus_binding(
    data: dict,
    corpus_results_path: Path,
    *,
    require_runtime_triad: bool = False,
) -> list[str]:
    """bd-ry7d1 cross-file binding: the verdict artifact's
    proof_carrying_effects copy must be value-identical to the
    compatibility-corpus results copy the Rust gate's pass-rate leg reads.

    bd-kfseq gate parity: the SAME corpus copy is then held to the SAME L1
    bar the Rust close-condition leg enforces — genuine
    `lockstep-oracle-run` provenance, a `result_digest` that recomputes from
    `per_test_results`, totals that re-derive, zero errored cases, and a
    measured pass rate at or above the threshold. Before this, the Python
    close-condition gate could report GREEN over a corpus the Rust gate
    refused, which is exactly the two-gates-drift bd-ry7d1 exists to prevent.
    """
    try:
        with open(corpus_results_path) as corpus_file:
            corpus = json.load(corpus_file)
    except (OSError, json.JSONDecodeError) as err:
        return [f"L1 corpus-results binding input unreadable: {err}"]
    if not isinstance(corpus, dict):
        return ["L1 corpus-results binding input must be a JSON object"]
    errors = []
    corpus_proof = corpus.get("proof_carrying_effects")
    evidence = data.get("evidence")
    artifact_proof = evidence.get("proof_carrying_effects") if isinstance(evidence, dict) else None
    if artifact_proof is None:
        return [
            "L1 verdict artifact evidence.proof_carrying_effects missing (binding to the "
            "corpus-results copy is required)"
        ]
    if corpus_proof is None:
        return [
            "L1 verdict artifact proof_carrying_effects binding unverifiable: corpus results "
            "carry no proof_carrying_effects block"
        ]
    if corpus_proof != artifact_proof:
        return [
            "L1 verdict artifact proof_carrying_effects does not match the corpus-results "
            "copy (the two gate inputs have drifted; regenerate both via `franken-node ops "
            "proof-carrying-evidence --merge-corpus --merge-l1-verdict`)"
        ]
    errors.extend(_validate_l1_corpus_pass_rate(corpus))
    if require_runtime_triad:
        errors.extend(_validate_release_runtime_triad(corpus))
    return errors


def _validate_release_runtime_triad(corpus: dict) -> list[str]:
    """Release certification requires two genuine references plus product.

    The producer identity-probes Node and rejects same-executable Node/Bun
    aliases. This consumer pins the resulting machine-readable topology so a
    future workflow cannot silently fall back to the developer dyad.
    """
    metadata = corpus.get("corpus")
    if not isinstance(metadata, dict):
        return ["release compatibility corpus metadata must be an object"]

    errors = []
    if metadata.get("lockstep_topology") != "triad":
        errors.append(
            "release compatibility corpus lockstep_topology must be 'triad' "
            "(Node.js, Bun, and franken-engine-native)"
        )

    references = metadata.get("reference_runtimes")
    parsed_references = {}
    if not isinstance(references, list):
        errors.append("release compatibility corpus reference_runtimes must be an array")
    else:
        for position, runtime in enumerate(references):
            if not isinstance(runtime, dict):
                errors.append(
                    f"release reference runtime {position} must be an object"
                )
                continue
            runtime_id = runtime.get("runtime_id")
            if not isinstance(runtime_id, str) or not runtime_id:
                errors.append(
                    f"release reference runtime {position} has no runtime_id"
                )
                continue
            if runtime_id in parsed_references:
                errors.append(f"release reference runtime {runtime_id!r} is duplicated")
            parsed_references[runtime_id] = runtime

        if set(parsed_references) != {"node", "bun"}:
            errors.append(
                "release compatibility corpus reference runtime ids must be exactly "
                f"['bun', 'node']; got {sorted(parsed_references)}"
            )
        for runtime_id, runtime in parsed_references.items():
            if runtime.get("runtime_name") != runtime_id:
                errors.append(
                    f"release reference runtime {runtime_id!r} has mismatched runtime_name"
                )
            version = runtime.get("version")
            if not isinstance(version, str) or not version.strip():
                errors.append(
                    f"release reference runtime {runtime_id!r} has no pinned version"
                )
            if runtime.get("is_reference") is not True:
                errors.append(
                    f"release reference runtime {runtime_id!r} is not marked as a reference"
                )

    product = metadata.get("product_runtime")
    if not isinstance(product, dict):
        errors.append("release compatibility corpus product_runtime must be an object")
    else:
        if product.get("runtime_id") != "franken-engine-native":
            errors.append(
                "release compatibility corpus product runtime id must be "
                "'franken-engine-native'"
            )
        version = product.get("version")
        if not isinstance(version, str) or not version.strip():
            errors.append("release compatibility corpus product runtime has no version")
        if product.get("is_reference") is not False:
            errors.append(
                "release compatibility corpus product runtime must not be marked as a reference"
            )
    return errors


def _validate_l1_corpus_pass_rate(corpus: dict) -> list[str]:
    """Re-derive the L1 corpus pass-rate leg from the bound corpus copy,
    mirroring `ops/close_condition.rs::validate_l1_corpus_provenance` plus the
    threshold/errored checks of `evaluate_l1_product_oracle` — update both
    sides together (bd-ihusm / bd-kfseq)."""
    from scripts.check_compatibility_corpus_pass_gate import (
        ONLINE_PROVENANCE,
        compute_result_digest,
        compute_runtime_observations_digest,
    )

    errors = []
    corpus_meta = corpus.get("corpus", {})
    provenance = corpus_meta.get("provenance") if isinstance(corpus_meta, dict) else None
    if provenance != ONLINE_PROVENANCE:
        errors.append(
            f"L1 compatibility corpus provenance {provenance!r} is not a genuine oracle run "
            f"(expected {ONLINE_PROVENANCE!r}); the pass rate cannot be consumed as real"
        )

    per_tests = corpus.get("per_test_results")
    if not isinstance(per_tests, list) or not per_tests:
        errors.append(
            "L1 compatibility corpus has no per_test_results; the pass rate cannot be "
            "re-derived or digest-verified"
        )
        return errors

    declared_digest = corpus_meta.get("result_digest") if isinstance(corpus_meta, dict) else None
    recomputed_digest = compute_result_digest(per_tests)
    # Constant-time comparison per the hardening watchlist (content-hash
    # compares mirror the Rust gate's ct_eq even over public operands).
    if not hmac.compare_digest(str(declared_digest or ""), recomputed_digest):
        errors.append(
            f"L1 compatibility corpus result_digest {declared_digest!r} does not match the "
            f"digest recomputed from per_test_results {recomputed_digest!r}"
        )

    declared_observations_digest = (
        corpus_meta.get("runtime_observations_digest")
        if isinstance(corpus_meta, dict)
        else None
    )
    try:
        recomputed_observations_digest = compute_runtime_observations_digest(corpus)
    except (TypeError, ValueError) as error:
        errors.append(f"L1 compatibility corpus runtime observations are invalid: {error}")
    else:
        if not hmac.compare_digest(
            str(declared_observations_digest or ""),
            recomputed_observations_digest,
        ):
            errors.append(
                "L1 compatibility corpus runtime observations digest "
                f"{declared_observations_digest!r} does not match recomputed "
                f"{recomputed_observations_digest!r}"
            )

    totals = corpus.get("totals", {})
    declared_total = int(totals.get("total_test_cases", 0)) if isinstance(totals, dict) else 0
    declared_passed = int(totals.get("passed_test_cases", 0)) if isinstance(totals, dict) else 0
    errored = int(totals.get("errored_test_cases", 0)) if isinstance(totals, dict) else 0
    recomputed_passed = sum(1 for row in per_tests if row.get("status") == "pass")
    if len(per_tests) != declared_total:
        errors.append(
            f"L1 compatibility corpus per_test_results count {len(per_tests)} does not match "
            f"declared total_test_cases {declared_total}"
        )
    if recomputed_passed != declared_passed:
        errors.append(
            f"L1 compatibility corpus declared passed_test_cases {declared_passed} does not "
            f"match the {recomputed_passed} passes in per_test_results"
        )
    if errored > 0:
        errors.append(f"L1 compatibility corpus has {errored} errored test cases")

    thresholds = corpus.get("thresholds", {})
    required_pct = (
        float(thresholds.get("overall_pass_rate_min_pct", 95.0))
        if isinstance(thresholds, dict)
        else 95.0
    )
    measured_pct = (
        round((recomputed_passed / len(per_tests)) * 100.0, 2) if per_tests else 0.0
    )
    if measured_pct < required_pct:
        errors.append(
            f"L1 compatibility corpus pass rate {measured_pct:.2f}% is below required "
            f"{required_pct:.2f}%"
        )
    return errors


def _parse_rfc3339(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty RFC3339 timestamp")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as err:
        raise ValueError(f"{label} is not a valid RFC3339 timestamp: {value!r}") from err
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def validate_evidence_freshness(
    timestamp: object,
    *,
    label: str,
    max_age: timedelta,
    now: datetime | None = None,
) -> list[str]:
    """Fail closed when release evidence is stale or implausibly future-dated."""
    try:
        observed = _parse_rfc3339(timestamp, label)
    except ValueError as err:
        return [str(err)]

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if observed > current + timedelta(minutes=5):
        return [
            f"{label} {observed.isoformat()} is more than five minutes in the future"
        ]
    age = current - observed
    if age > max_age:
        return [
            f"{label} is stale: age {age.total_seconds() / 3600:.2f}h exceeds "
            f"the release maximum {max_age.total_seconds() / 3600:.2f}h"
        ]
    return []


def validate_source_revision(
    data: dict,
    *,
    label: str,
    expected_franken_node: str,
    expected_franken_engine: str,
) -> list[str]:
    """Require evidence to name the exact source pair being released."""
    errors = []
    revision = data.get("source_revision")
    if not isinstance(revision, dict):
        return [f"{label} source_revision object is missing"]
    if revision.get("schema_version") != SOURCE_REVISION_SCHEMA:
        errors.append(
            f"{label} source_revision schema_version {revision.get('schema_version')!r} "
            f"does not match {SOURCE_REVISION_SCHEMA!r}"
        )

    declared_node = revision.get("franken_node_commit")
    declared_engine = revision.get("franken_engine_commit")
    for name, declared, expected in (
        ("franken_node_commit", declared_node, expected_franken_node),
        ("franken_engine_commit", declared_engine, expected_franken_engine),
    ):
        if not isinstance(declared, str) or _GIT_SHA_RE.fullmatch(declared) is None:
            errors.append(f"{label} source_revision.{name} must be a lowercase 40-hex Git SHA")
        elif not hmac.compare_digest(declared, expected):
            errors.append(
                f"{label} source_revision.{name} {declared} does not match release source {expected}"
            )
    return errors


def validate_release_corpus_binding(
    corpus_results_path: Path,
    *,
    expected_franken_node: str,
    expected_franken_engine: str,
    max_age: timedelta,
    now: datetime | None = None,
) -> list[str]:
    try:
        corpus = json.loads(corpus_results_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        return [f"release corpus evidence is unreadable: {err}"]
    if not isinstance(corpus, dict):
        return ["release corpus evidence must be a JSON object"]
    corpus_meta = corpus.get("corpus")
    if not isinstance(corpus_meta, dict):
        return ["release corpus evidence corpus object is missing"]
    errors = validate_source_revision(
        corpus_meta,
        label="release corpus",
        expected_franken_node=expected_franken_node,
        expected_franken_engine=expected_franken_engine,
    )
    errors.extend(
        validate_evidence_freshness(
            corpus_meta.get("generated_at_utc"),
            label="release corpus generated_at_utc",
            max_age=max_age,
            now=now,
        )
    )
    return errors


def _verify_close_receipt_ed25519_signature(
    public_key: bytes, signed_preimage: bytes, signature: bytes
) -> str | None:
    """Verify the Rust receipt signature with the OpenSSL already required by dist."""
    with tempfile.TemporaryDirectory(prefix="franken-node-close-receipt-") as directory:
        directory_path = Path(directory)
        public_key_path = directory_path / "public-key.der"
        payload_path = directory_path / "signed-preimage.bin"
        signature_path = directory_path / "signature.bin"
        public_key_path.write_bytes(_ED25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX + public_key)
        payload_path.write_bytes(signed_preimage)
        signature_path.write_bytes(signature)
        try:
            completed = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key_path),
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            return f"close-condition receipt signature verifier unavailable: {err}"
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "verification failed"
        return f"close-condition receipt Ed25519 signature verification failed: {detail}"
    return None


def _close_receipt_tamper_errors(receipt: dict) -> list[str]:
    tamper = receipt.get("tamper_evidence")
    if not isinstance(tamper, dict):
        return ["close-condition receipt tamper_evidence object is missing"]
    signature = tamper.get("signature")
    if not isinstance(signature, dict):
        return ["close-condition receipt signature object is missing"]

    core = deepcopy(receipt)
    core.pop("tamper_evidence", None)
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    canonical_bytes = canonical.encode("utf-8")
    signed_preimage = (
        _CLOSE_RECEIPT_PREIMAGE_DOMAIN
        + len(canonical_bytes).to_bytes(8, "little")
        + canonical_bytes
    )
    derived = hashlib.sha256(signed_preimage).hexdigest()
    errors = []
    if not hmac.compare_digest(str(tamper.get("sha256") or ""), f"sha256:{derived}"):
        errors.append("close-condition receipt tamper hash does not match its canonical core")
    if not hmac.compare_digest(
        str(signature.get("signed_payload_sha256") or ""), derived
    ):
        errors.append("close-condition receipt signed payload hash does not match its canonical core")
    if not hmac.compare_digest(str(signature.get("algorithm") or ""), "ed25519"):
        errors.append("close-condition receipt signature algorithm must be ed25519")
    public_key = signature.get("public_key_hex")
    signature_hex = signature.get("signature_hex")
    public_key_valid = (
        isinstance(public_key, str) and re.fullmatch(r"[0-9a-f]{64}", public_key) is not None
    )
    signature_valid = (
        isinstance(signature_hex, str)
        and re.fullmatch(r"[0-9a-f]{128}", signature_hex) is not None
    )
    if not public_key_valid:
        errors.append("close-condition receipt public key must be 32 lowercase-hex bytes")
    if not signature_valid:
        errors.append("close-condition receipt signature must be 64 lowercase-hex bytes")
    if public_key_valid:
        public_key_bytes = bytes.fromhex(public_key)
        key_id_hash = hashlib.sha256(
            _ARTIFACT_SIGNING_KEY_ID_DOMAIN
            + len(public_key_bytes).to_bytes(8, "little")
            + public_key_bytes
        ).digest()
        derived_key_id = key_id_hash[:8].hex()
        if not hmac.compare_digest(str(signature.get("key_id") or ""), derived_key_id):
            errors.append("close-condition receipt key_id does not match its public key")
    if public_key_valid and signature_valid:
        signature_error = _verify_close_receipt_ed25519_signature(
            bytes.fromhex(public_key), signed_preimage, bytes.fromhex(signature_hex)
        )
        if signature_error is not None:
            errors.append(signature_error)
    return errors


def check_release_receipt(
    receipt_path: Path,
    *,
    expected_franken_node: str,
    expected_franken_engine: str,
    expected_release_run_url: str,
    max_age: timedelta,
    now: datetime | None = None,
) -> dict:
    """Validate the live, signed composite receipt consumed by tag publication."""
    result = {
        "present": False,
        "composite_verdict": None,
        "dimensions": {},
        "error": None,
    }
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        result["error"] = f"close-condition receipt not found: {receipt_path}"
        return result
    except (OSError, json.JSONDecodeError) as err:
        result["error"] = f"close-condition receipt is malformed: {err}"
        return result
    if not isinstance(receipt, dict):
        result["error"] = "close-condition receipt must be a JSON object"
        return result

    result["present"] = True
    result["composite_verdict"] = receipt.get("composite_verdict")
    errors = validate_source_revision(
        receipt,
        label="close-condition receipt",
        expected_franken_node=expected_franken_node,
        expected_franken_engine=expected_franken_engine,
    )
    errors.extend(
        validate_evidence_freshness(
            receipt.get("generated_at_utc"),
            label="close-condition receipt generated_at_utc",
            max_age=max_age,
            now=now,
        )
    )
    errors.extend(_close_receipt_tamper_errors(receipt))

    release_linkage = receipt.get("release_policy_linkage")
    if not isinstance(release_linkage, dict):
        errors.append("close-condition release_policy_linkage object is missing")
    else:
        if release_linkage.get("source") != "github_actions_release_certification_context":
            errors.append(
                "close-condition release_policy_linkage source is not the live "
                "GitHub Actions certification context"
            )
        if release_linkage.get("ci_outputs_accessible") is not True:
            errors.append("close-condition release_policy_linkage is not CI-accessible")
        ci_output_ref = str(release_linkage.get("ci_output_ref") or "")
        if not hmac.compare_digest(ci_output_ref, expected_release_run_url):
            errors.append(
                "close-condition release_policy_linkage run URL does not match the "
                "current release run attempt"
            )
        if release_linkage.get("consumed_oracles") != [
            "L1_product_oracle",
            "L2_engine_boundary_oracle",
        ]:
            errors.append(
                "close-condition release_policy_linkage must consume both release oracles"
            )

    if receipt.get("composite_verdict") != "GREEN":
        errors.append(
            f"close-condition composite_verdict is {receipt.get('composite_verdict')!r}, expected 'GREEN'"
        )
    failing = receipt.get("failing_dimensions")
    if failing != []:
        errors.append(f"close-condition failing_dimensions must be empty, got {failing!r}")

    for field, dimension_id in (
        ("L1_product_oracle", "l1_product"),
        ("L2_engine_boundary_oracle", "l2_engine_boundary"),
        ("release_policy_linkage", "release_policy_linkage"),
    ):
        dimension = receipt.get(field)
        verdict = dimension.get("verdict") if isinstance(dimension, dict) else None
        result["dimensions"][dimension_id] = verdict
        if verdict != "GREEN":
            errors.append(f"close-condition {field} verdict is {verdict!r}, expected 'GREEN'")

    if errors:
        result["error"] = "; ".join(errors)
    return result


REQUIRED_DIMENSIONS = [
    {
        "id": "l1_product",
        "label": "L1 Product Oracle",
        "owner_track": "10.2",
        "artifact": "l1_product_verdict.json",
    },
    {
        "id": "l2_engine_boundary",
        "label": "L2 Engine-Boundary Oracle",
        "owner_track": "10.17",
        "artifact": "l2_engine_boundary_verdict.json",
    },
    {
        "id": "release_policy_linkage",
        "label": "Release Policy Linkage",
        "owner_track": "10.2",
        "artifact": "release_policy_verdict.json",
    },
]


def validate_l1_proof_carrying_evidence(data: dict) -> list[str]:
    """L1 is GREEN only when parity evidence is also proof-carrying."""
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        return ["L1 evidence object missing"]

    proof = evidence.get("proof_carrying_effects")
    if not isinstance(proof, dict):
        return ["L1 proof_carrying_effects evidence missing"]

    # v2 embeds the receipt chain and is re-derived rather than trusted
    # (bd-qr5i2.3, mirroring the Rust doctor gate's v2 path). v1 acceptance
    # is RETIRED (bd-qr5i2.4): a declared-only summary can no longer pass —
    # regenerate the artifact from a real run with
    # `franken-node ops proof-carrying-evidence`. The v1 schema id stays
    # registered in schema_versions.rs (the registry is append-only); only
    # its acceptance here is withdrawn.
    if proof.get("schema_version") == L1_PROOF_EVIDENCE_SCHEMA_V2:
        return _validate_proof_carrying_v2(proof)

    return [
        f"L1 proof_carrying_effects schema_version {proof.get('schema_version')!r} is "
        f"unsupported: only {L1_PROOF_EVIDENCE_SCHEMA_V2} is accepted (v1 declared-summary "
        "acceptance retired; regenerate via `franken-node ops proof-carrying-evidence`)"
    ]


def check_dimension(
    artifacts_dir: Path,
    dim: dict,
    corpus_results_path=None,
    *,
    expected_franken_node: str | None = None,
    expected_franken_engine: str | None = None,
    max_age: timedelta | None = None,
    now: datetime | None = None,
    require_runtime_triad: bool = False,
    require_green: bool = True,
) -> dict:
    """Check a single oracle dimension."""
    artifact_path = artifacts_dir / dim["artifact"]
    result = {
        "dimension": dim["id"],
        "label": dim["label"],
        "owner_track": dim["owner_track"],
        "present": False,
        "verdict": None,
        "error": None,
    }

    if not artifact_path.exists():
        result["error"] = f"Artifact not found: {artifact_path.name}"
        return result

    result["present"] = True

    try:
        with open(artifact_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        result["error"] = f"Malformed artifact: {e}"
        return result

    verdict = data.get("verdict")
    if verdict not in ("GREEN", "YELLOW", "RED"):
        result["error"] = f"Invalid verdict value: {verdict}"
        return result

    result["verdict"] = verdict
    errors = []
    if require_green and verdict != "GREEN":
        errors.append(f"Verdict is {verdict}, expected GREEN")
    if expected_franken_node is not None and expected_franken_engine is not None:
        errors.extend(
            validate_source_revision(
                data,
                label=f"{dim['label']} artifact",
                expected_franken_node=expected_franken_node,
                expected_franken_engine=expected_franken_engine,
            )
        )
    if max_age is not None:
        errors.extend(
            validate_evidence_freshness(
                data.get("timestamp"),
                label=f"{dim['label']} timestamp",
                max_age=max_age,
                now=now,
            )
        )
    if dim["id"] == "l1_product":
        errors.extend(validate_l1_proof_carrying_evidence(data))
        errors.extend(validate_l1_lockstep_verdict(data))
        if corpus_results_path is not None:
            errors.extend(
                validate_l1_corpus_binding(
                    data,
                    corpus_results_path,
                    require_runtime_triad=require_runtime_triad,
                )
            )
            if (
                expected_franken_node is not None
                and expected_franken_engine is not None
                and max_age is not None
            ):
                errors.extend(
                    validate_release_corpus_binding(
                        corpus_results_path,
                        expected_franken_node=expected_franken_node,
                        expected_franken_engine=expected_franken_engine,
                        max_age=max_age,
                        now=now,
                    )
                )
    if errors:
        result["error"] = "; ".join(errors)

    return result


def _git_sha(value: str) -> str:
    normalized = value.strip().lower()
    if _GIT_SHA_RE.fullmatch(normalized) is None:
        raise argparse.ArgumentTypeError("expected a full 40-hex Git commit SHA")
    return normalized


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--consistency-mode",
        action="store_true",
        help=(
            "CI consistency gate (bd-reality-20260820-w0fc6.1): fail on malformed "
            "artifacts and on L1 GREEN declared while the corpus is below 95%%; "
            "do not require all dimensions GREEN. Release/ship still uses default "
            "or --release-mode."
        ),
    )
    parser.add_argument("--artifacts-dir", type=Path, default=DEFAULT_ARTIFACTS_DIR)
    parser.add_argument("--corpus-results", type=Path)
    parser.add_argument(
        "--release-mode",
        action="store_true",
        help=(
            "validate the live L1 artifact plus signed composite receipt consumed by "
            "tag publication instead of trusting standalone historical L2/linkage verdict files"
        ),
    )
    parser.add_argument("--close-receipt", type=Path, default=DEFAULT_CLOSE_RECEIPT)
    parser.add_argument("--expected-franken-node-revision", type=_git_sha)
    parser.add_argument("--expected-franken-engine-revision", type=_git_sha)
    parser.add_argument("--expected-release-run-url")
    parser.add_argument("--max-age-hours", type=float)
    args = parser.parse_args(argv)

    revision_args = (
        args.expected_franken_node_revision,
        args.expected_franken_engine_revision,
    )
    if any(revision_args) and not all(revision_args):
        parser.error("both expected source revisions must be provided together")
    if args.max_age_hours is not None and args.max_age_hours <= 0:
        parser.error("--max-age-hours must be greater than zero")
    if args.release_mode:
        if not all(revision_args):
            parser.error("--release-mode requires both expected source revisions")
        if args.max_age_hours is None:
            parser.error("--release-mode requires --max-age-hours")
        if (
            args.expected_release_run_url is None
            or _GITHUB_ACTIONS_RUN_URL_RE.fullmatch(args.expected_release_run_url) is None
        ):
            parser.error(
                "--release-mode requires --expected-release-run-url for an exact "
                "https://github.com/.../actions/runs/.../attempts/... URL"
            )
    return args


def main(argv: list[str] | None = None):
    logger = configure_test_logging("check_oracle_close_condition")
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    json_output = args.json
    artifacts_dir = args.artifacts_dir
    corpus_results_path = args.corpus_results

    # bd-ry7d1: on the live repo (default artifacts dir), the corpus binding
    # is enforced by default so the Rust and Python gate inputs cannot drift;
    # explicit --corpus-results opts in for custom layouts.
    if corpus_results_path is None and artifacts_dir == DEFAULT_ARTIFACTS_DIR:
        corpus_results_path = ROOT / "artifacts" / "13" / "compatibility_corpus_results.json"

    timestamp = datetime.now(timezone.utc).isoformat()
    expected_node = args.expected_franken_node_revision
    expected_engine = args.expected_franken_engine_revision
    max_age = (
        timedelta(hours=args.max_age_hours) if args.max_age_hours is not None else None
    )
    dimensions = {}
    failing = []

    dimensions_to_check = (
        [REQUIRED_DIMENSIONS[0]] if args.release_mode else REQUIRED_DIMENSIONS
    )
    for dim in dimensions_to_check:
        result = check_dimension(
            artifacts_dir,
            dim,
            corpus_results_path,
            expected_franken_node=expected_node,
            expected_franken_engine=expected_engine,
            max_age=max_age,
            require_runtime_triad=args.release_mode,
            require_green=not args.consistency_mode,
        )
        dimensions[dim["id"]] = result

        if args.consistency_mode:
            error = result.get("error") or ""
            if (
                dim["id"] == "l1_product"
                and result.get("verdict") == "RED"
            ):
                kept = [
                    part.strip()
                    for part in error.split(";")
                    if part.strip()
                    and "pass rate" not in part
                    and "below required" not in part
                ]
                error = "; ".join(kept)
                result["error"] = error or None
            if result.get("error"):
                failing.append({
                    "dimension": dim["id"],
                    "label": dim["label"],
                    "reason": result["error"],
                })
            elif (
                dim["id"] == "l1_product"
                and result.get("verdict") == "GREEN"
                and "pass rate" in (result.get("error") or "")
            ):
                failing.append({
                    "dimension": dim["id"],
                    "label": dim["label"],
                    "reason": result.get("error", "GREEN while corpus below floor"),
                })
        elif result.get("error") or result["verdict"] != "GREEN":
            failing.append({
                "dimension": dim["id"],
                "label": dim["label"],
                "reason": result.get("error", f"Verdict: {result['verdict']}"),
            })

    release_receipt = None
    if args.release_mode:
        release_receipt = check_release_receipt(
            args.close_receipt,
            expected_franken_node=expected_node,
            expected_franken_engine=expected_engine,
            expected_release_run_url=args.expected_release_run_url,
            max_age=max_age,
        )
        for dim in REQUIRED_DIMENSIONS[1:]:
            verdict = release_receipt["dimensions"].get(dim["id"])
            dimensions[dim["id"]] = {
                "dimension": dim["id"],
                "label": dim["label"],
                "owner_track": dim["owner_track"],
                "present": release_receipt["present"],
                "verdict": verdict,
                "error": release_receipt.get("error"),
            }
        if release_receipt.get("error") or release_receipt["composite_verdict"] != "GREEN":
            failing.append(
                {
                    "dimension": "composite_release_receipt",
                    "label": "Commit-bound Composite Release Receipt",
                    "reason": release_receipt.get("error")
                    or f"Verdict: {release_receipt['composite_verdict']}",
                }
            )

    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "dual_oracle_close_condition",
        "verdict": verdict,
        "timestamp": timestamp,
        "artifacts_dir": str(artifacts_dir),
        "corpus_results": str(corpus_results_path) if corpus_results_path else None,
        "consistency_mode": args.consistency_mode,
        "release_mode": args.release_mode,
        "expected_source_revision": (
            {
                "franken_node_commit": expected_node,
                "franken_engine_commit": expected_engine,
            }
            if expected_node is not None
            else None
        ),
        "max_age_hours": args.max_age_hours,
        "close_receipt": str(args.close_receipt) if args.release_mode else None,
        "expected_release_run_url": (
            args.expected_release_run_url if args.release_mode else None
        ),
        "dimensions": {
            k: {
                "present": v["present"],
                "verdict": v["verdict"],
                "error": v.get("error"),
            }
            for k, v in dimensions.items()
        },
        "failing_dimensions": failing,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Dual-Oracle Close-Condition Gate ===")
        print(f"Artifacts: {artifacts_dir}")
        print(f"Timestamp: {timestamp}")
        print()
        for dim_id, dim_data in dimensions.items():
            status = (
                "OK"
                if dim_data["verdict"] == "GREEN" and not dim_data.get("error")
                else "FAIL"
            )
            label = [d for d in REQUIRED_DIMENSIONS if d["id"] == dim_id][0]["label"]
            if dim_data["present"]:
                print(f"  [{status}] {label}: {dim_data['verdict']}")
            else:
                print(f"  [MISSING] {label}: artifact not found")
            if dim_data.get("error"):
                print(f"         Error: {dim_data['error']}")
        print()
        print(f"Verdict: {verdict}")
        if failing:
            print(f"Failing dimensions: {len(failing)}")
            for f in failing:
                print(f"  - {f['label']}: {f['reason']}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
