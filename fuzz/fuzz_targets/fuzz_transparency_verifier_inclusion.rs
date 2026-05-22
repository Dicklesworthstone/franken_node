#![no_main]

//! Fuzz harness for
//! `frankenengine_node::supply_chain::transparency_verifier::verify_inclusion`
//! at `crates/franken-node/src/supply_chain/transparency_verifier.rs:268`.
//!
//! Background. The transparency verifier ingests an `Option<InclusionProof>`
//! from a transparency-log-attested supply-chain artifact and returns a
//! `ProofReceipt` carrying `(verified, log_root_matched, proof_valid)` plus
//! an optional `ProofFailure`. Production paths (release-manifest gates,
//! extension-registry admission, replay-bundle audit attestation) depend
//! on this verdict — a panic or a wrongly-true verdict on adversarial
//! input would break the supply-chain trust anchor.
//!
//! Existing fuzz coverage: **zero** before this harness. The supply_chain
//! fuzz fleet (`fuzz_extension_registration_manifest_parse`,
//! `fuzz_parse_signed_registration_manifest`, `fuzz_release_manifest_parse`,
//! `fuzz_checksum_manifest_parse_canonical`) covers manifest *parsing* but
//! never exercises the Merkle inclusion verifier itself. This harness
//! drives the function with arbitrary policy + proof + ID fixtures and
//! pins four production invariants per call:
//!
//!   (A) **Panic-freedom**: arbitrary bytes shaped into the input slots
//!       must NEVER panic. The transparency verifier is on the hot path
//!       for every signed artifact; a panic on attacker-controlled input
//!       would let an artifact author DoS the admission pipeline.
//!
//!   (B) **Required-policy contract**: when `policy.required == true` AND
//!       `proof == None`, the receipt MUST carry `verified == false` with
//!       `ProofFailure::ProofMissing` — otherwise an attacker can land an
//!       un-attested artifact through a required gate by simply omitting
//!       the inclusion proof.
//!
//!   (C) **Invalid-ID rejection happens BEFORE proof recomputation**: bad
//!       `artifact_id` or `connector_id` MUST short-circuit to a
//!       `ProofFailure::Invalid{Artifact,Connector}Id` verdict regardless
//!       of proof shape — this pins the early-return contract at
//!       `transparency_verifier.rs:277-301` so a future refactor cannot
//!       silently let an invalid-ID artifact reach the Merkle recomputation
//!       (which would leak CPU on adversarial audit_path inputs).
//!
//!   (D) **Verified ⇒ log_root_matched ∧ proof_valid**: the three booleans
//!       on `ProofReceipt` must satisfy `verified == log_root_matched AND
//!       proof_valid`. A regression that decouples them (verified=true
//!       with proof_valid=false) would let a malformed proof slip through
//!       any downstream gate that only checks the `verified` field.

use arbitrary::Arbitrary;
use frankenengine_node::supply_chain::transparency_verifier::{
    verify_inclusion, InclusionProof, LogRoot, ProofFailure, TransparencyPolicy,
};
use libfuzzer_sys::fuzz_target;

const MAX_AUDIT_PATH_ENTRIES: usize = 64;
const MAX_PINNED_ROOTS: usize = 16;
const MAX_HEX_STRING_BYTES: usize = 128;
const MAX_ID_BYTES: usize = 256;

#[derive(Debug, Arbitrary)]
struct TransparencyVerifierFuzzCase {
    required: bool,
    pinned_roots: Vec<(u64, String)>,
    proof_present: bool,
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: String,
    audit_path: Vec<String>,
    artifact_hash: String,
    connector_id: String,
    artifact_id: String,
    trace_id: String,
    timestamp: String,
}

fuzz_target!(|case: TransparencyVerifierFuzzCase| {
    let policy = build_bounded_policy(case.required, &case.pinned_roots);
    let proof_owned = if case.proof_present {
        Some(InclusionProof {
            leaf_index: case.leaf_index,
            tree_size: case.tree_size,
            leaf_hash: bounded_string(&case.leaf_hash, MAX_HEX_STRING_BYTES),
            audit_path: case
                .audit_path
                .iter()
                .take(MAX_AUDIT_PATH_ENTRIES)
                .map(|node| bounded_string(node, MAX_HEX_STRING_BYTES))
                .collect(),
        })
    } else {
        None
    };
    let proof = proof_owned.as_ref();

    let artifact_hash = bounded_string(&case.artifact_hash, MAX_HEX_STRING_BYTES);
    let connector_id = bounded_string(&case.connector_id, MAX_ID_BYTES);
    let artifact_id = bounded_string(&case.artifact_id, MAX_ID_BYTES);
    let trace_id = bounded_string(&case.trace_id, MAX_ID_BYTES);
    let timestamp = bounded_string(&case.timestamp, MAX_ID_BYTES);

    // ── (A) Panic-freedom: the call itself is the assertion ─────────────
    let receipt = verify_inclusion(
        &policy,
        proof,
        &artifact_hash,
        &connector_id,
        &artifact_id,
        &trace_id,
        &timestamp,
    );

    // ── (B) Required-policy contract ────────────────────────────────────
    // When proof is None AND policy demands it, the verdict must be false
    // with the specific ProofMissing failure. We only assert this when the
    // IDs are well-formed (otherwise the early-return at L277-301 fires
    // FIRST, which is invariant (C) below).
    if proof.is_none() && policy.required && artifact_id_is_well_formed(&artifact_id)
        && connector_id_is_well_formed(&connector_id)
    {
        assert!(
            !receipt.verified,
            "INV-TLOG-REQUIRED violated: policy.required + missing proof + valid IDs \
             must yield verified=false"
        );
        assert!(
            matches!(receipt.failure_reason, Some(ProofFailure::ProofMissing)),
            "INV-TLOG-REQUIRED violated: missing-proof failure reason must be \
             ProofFailure::ProofMissing, got {:?}",
            receipt.failure_reason
        );
    }

    // ── (C) Invalid-ID short-circuit ────────────────────────────────────
    // A malformed artifact_id or connector_id must surface as
    // ProofFailure::InvalidArtifactId / InvalidConnectorId before any
    // Merkle work happens.
    if !artifact_id_is_well_formed(&artifact_id) {
        assert!(
            !receipt.verified,
            "INV-TLOG-ID-EARLY violated: malformed artifact_id must yield verified=false"
        );
        // The verifier short-circuits on artifact_id BEFORE checking
        // connector_id, so we cannot assert which specific failure code
        // fired when both are malformed. But we can assert it is *one of*
        // the two ID-rejection codes.
        assert!(
            matches!(
                receipt.failure_reason,
                Some(ProofFailure::InvalidArtifactId { .. })
                    | Some(ProofFailure::InvalidConnectorId { .. })
            ),
            "INV-TLOG-ID-EARLY violated: malformed artifact_id must yield \
             InvalidArtifactId or InvalidConnectorId failure, got {:?}",
            receipt.failure_reason
        );
    } else if !connector_id_is_well_formed(&connector_id) {
        assert!(
            !receipt.verified,
            "INV-TLOG-ID-EARLY violated: malformed connector_id must yield verified=false"
        );
        assert!(
            matches!(
                receipt.failure_reason,
                Some(ProofFailure::InvalidConnectorId { .. })
            ),
            "INV-TLOG-ID-EARLY violated: malformed connector_id must yield \
             InvalidConnectorId failure (artifact_id was valid), got {:?}",
            receipt.failure_reason
        );
    }

    // ── (D) verified ⇒ (log_root_matched ∧ proof_valid) ──────────────────
    if receipt.verified {
        assert!(
            receipt.log_root_matched,
            "INV-TLOG-VERDICT-COMPOSITION violated: verified=true with \
             log_root_matched=false would let an unpinned root pass downstream gates"
        );
        assert!(
            receipt.proof_valid,
            "INV-TLOG-VERDICT-COMPOSITION violated: verified=true with \
             proof_valid=false would let a malformed proof pass downstream gates"
        );
        assert!(
            receipt.failure_reason.is_none(),
            "INV-TLOG-VERDICT-COMPOSITION violated: verified=true must carry \
             failure_reason=None, got {:?}",
            receipt.failure_reason
        );
    }
});

fn build_bounded_policy(required: bool, pinned_roots: &[(u64, String)]) -> TransparencyPolicy {
    TransparencyPolicy {
        required,
        pinned_roots: pinned_roots
            .iter()
            .take(MAX_PINNED_ROOTS)
            .map(|(tree_size, root_hash)| LogRoot {
                tree_size: *tree_size,
                root_hash: bounded_string(root_hash, MAX_HEX_STRING_BYTES),
            })
            .collect(),
    }
}

fn bounded_string(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut truncated = String::with_capacity(max_bytes);
    for ch in s.chars() {
        if truncated.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        truncated.push(ch);
    }
    truncated
}

// Mirrors the well-formedness checks the verifier itself uses (per
// `invalid_artifact_id_reason` / `invalid_connector_id_reason` in
// transparency_verifier.rs). A drift between these helpers and the
// verifier would only cause our invariant assertions to be too STRICT
// (we'd assert ID-rejection on inputs the verifier accepts) or too LAX
// (we'd skip ID-rejection assertions on inputs the verifier rejects);
// either way the panic-freedom invariant (A) still holds.
fn artifact_id_is_well_formed(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && !id.chars().any(char::is_control)
}

fn connector_id_is_well_formed(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && !id.chars().any(char::is_control)
}
