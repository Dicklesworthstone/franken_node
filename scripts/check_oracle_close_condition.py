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

import hashlib
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ARTIFACTS_DIR = ROOT / "artifacts" / "oracle"
# Mirrors the canonical Rust constants in
# crates/franken-node/src/schema_versions.rs (L1_PROOF_CARRYING_EFFECTS{,_V2}
# and L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS, acceptance invariant
# bd-f5b04.2.4). Update both sides together; the Rust conformance tests bind
# the subject list to the compat-gate contract layer.
L1_PROOF_EVIDENCE_SCHEMA = "franken-node/l1-proof-carrying-effects/v1"
L1_PROOF_EVIDENCE_SCHEMA_V2 = "franken-node/l1-proof-carrying-effects/v2"
REQUIRED_L1_PROOF_SUBJECTS = ("fs.read", "fs.write", "http.request")

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
    # (bd-qr5i2.3, mirroring the Rust doctor gate's v2 path). v1 remains the
    # legacy declared-summary path until bd-qr5i2.4 retires it.
    if proof.get("schema_version") == L1_PROOF_EVIDENCE_SCHEMA_V2:
        return _validate_proof_carrying_v2(proof)

    errors = []
    if proof.get("schema_version") != L1_PROOF_EVIDENCE_SCHEMA:
        errors.append("L1 proof_carrying_effects schema_version missing or unsupported")

    verified_subjects = proof.get("verified_subjects")
    if not isinstance(verified_subjects, list):
        verified_subjects = []
    verified_subjects = {subject for subject in verified_subjects if isinstance(subject, str)}
    for subject in REQUIRED_L1_PROOF_SUBJECTS:
        if subject not in verified_subjects:
            errors.append(f"L1 proof_carrying_effects missing subject {subject}")

    receipts_verified = proof.get("effect_receipts_verified")
    if not isinstance(receipts_verified, int) or receipts_verified < len(REQUIRED_L1_PROOF_SUBJECTS):
        errors.append(
            "L1 proof_carrying_effects effect_receipts_verified below required "
            f"{len(REQUIRED_L1_PROOF_SUBJECTS)}"
        )

    invalid_receipts = proof.get("invalid_receipts")
    if not isinstance(invalid_receipts, int):
        errors.append("L1 proof_carrying_effects invalid_receipts missing or invalid")
    elif invalid_receipts != 0:
        errors.append(f"L1 proof_carrying_effects reports {invalid_receipts} invalid receipt(s)")

    if proof.get("receipt_chain_verified") is not True:
        errors.append("L1 proof_carrying_effects receipt_chain_verified is not true")

    return errors


def check_dimension(artifacts_dir: Path, dim: dict) -> dict:
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
    if verdict != "GREEN":
        errors.append(f"Verdict is {verdict}, expected GREEN")
    if dim["id"] == "l1_product":
        errors.extend(validate_l1_proof_carrying_evidence(data))
    if errors:
        result["error"] = "; ".join(errors)

    return result


def main():
    logger = configure_test_logging("check_oracle_close_condition")
    json_output = "--json" in sys.argv
    artifacts_dir = DEFAULT_ARTIFACTS_DIR

    for i, arg in enumerate(sys.argv):
        if arg == "--artifacts-dir" and i + 1 < len(sys.argv):
            artifacts_dir = Path(sys.argv[i + 1])

    timestamp = datetime.now(timezone.utc).isoformat()
    dimensions = {}
    failing = []

    for dim in REQUIRED_DIMENSIONS:
        result = check_dimension(artifacts_dir, dim)
        dimensions[dim["id"]] = result

        if result.get("error") or result["verdict"] != "GREEN":
            failing.append({
                "dimension": dim["id"],
                "label": dim["label"],
                "reason": result.get("error", f"Verdict: {result['verdict']}"),
            })

    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "dual_oracle_close_condition",
        "verdict": verdict,
        "timestamp": timestamp,
        "artifacts_dir": str(artifacts_dir),
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
            status = "OK" if dim_data["verdict"] == "GREEN" else "FAIL"
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
