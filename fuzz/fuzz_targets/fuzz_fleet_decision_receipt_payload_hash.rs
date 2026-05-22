#![no_main]

//! Fuzz harness for
//! `frankenengine_node::api::fleet_quarantine::canonical_decision_receipt_payload_hash`
//! at `crates/franken-node/src/api/fleet_quarantine.rs:657`.
//!
//! Background. The hash builder is the SHA-256 preimage source for every
//! fleet decision receipt — quarantine, revoke, release, reconcile.
//! Downstream consumers store the resulting 64-char hex as the receipt's
//! `payload_hash` field; any change to the byte layout invalidates every
//! receipt already issued. Existing fuzz coverage of this function:
//! **zero** before this commit (`rg canonical_decision_receipt_payload_hash
//! fuzz/fuzz_targets/` returned no hits).
//!
//! The function is length-prefix-framed:
//!
//!   ```text
//!   "fleet_receipt_v1:" ++
//!     len(op_id) ++ op_id ++
//!     len(principal) ++ principal ++
//!     len(zone_id) ++ zone_id ++
//!     len(timestamp) ++ timestamp ++
//!     <DecisionReceiptPayload::append_framed bytes>
//!   ```
//!
//! where every `len()` is `u64::try_from(field.len()).unwrap_or(u64::MAX)`
//! little-endian-encoded. The framing prevents prefix-collision attacks
//! (e.g., `("ab", "c") != ("a", "bc")` because their length prefixes
//! differ). This harness pins four invariants:
//!
//!   (A) **Determinism**: invoking the function twice on the same
//!       inputs MUST produce byte-identical 64-char hex output. A
//!       regression that introduces a clock-dependent or RNG-dependent
//!       field into the preimage would break receipt verification
//!       across the fleet.
//!
//!   (B) **Output shape**: the returned hex MUST be exactly 64 lowercase
//!       hex characters (SHA-256 hex). Catches a regression that
//!       returns truncated or uppercase output.
//!
//!   (C) **Field sensitivity**: changing any single field MUST change
//!       the hash. SHA-256 structurally guarantees this via avalanche,
//!       but the assertion catches a wiring bug where a field is
//!       dropped from the preimage (e.g., a refactor that forgets to
//!       call `extend_len_prefixed` for one of the four scalar fields).
//!
//!   (D) **Length-prefix safety**: the canonical ((a, bc)) preimage
//!       MUST hash differently than (("ab", c)) when their concatenated
//!       contents are identical. This is the load-bearing property of
//!       length-prefixed framing; the assertion catches a regression
//!       that drops the length prefixes.

use arbitrary::Arbitrary;
use frankenengine_node::api::fleet_quarantine::{
    canonical_decision_receipt_payload_hash, DecisionReceiptPayload, DecisionReceiptScope,
    RevocationSeverity,
};
use libfuzzer_sys::fuzz_target;

const MAX_FIELD_BYTES: usize = 256;

#[derive(Debug, Arbitrary)]
struct FleetReceiptHashFuzzCase {
    operation_id: String,
    principal: String,
    zone_id: String,
    timestamp: String,
    action_type: String,
    extension_id: Option<String>,
    incident_id: Option<String>,
    payload_zone_id: String,
    tenant_id: Option<String>,
    affected_nodes: Option<u32>,
    revocation_severity_selector: Option<u8>,
    reason: String,
    event_code: String,
    flip_selector: u8,
}

fuzz_target!(|case: FleetReceiptHashFuzzCase| {
    let payload = build_payload(&case);
    let op_id = bounded(&case.operation_id, MAX_FIELD_BYTES);
    let principal = bounded(&case.principal, MAX_FIELD_BYTES);
    let zone_id = bounded(&case.zone_id, MAX_FIELD_BYTES);
    let timestamp = bounded(&case.timestamp, MAX_FIELD_BYTES);

    // ── (A) Determinism ─────────────────────────────────────────────
    let first =
        canonical_decision_receipt_payload_hash(&op_id, &principal, &zone_id, &timestamp, &payload);
    let second =
        canonical_decision_receipt_payload_hash(&op_id, &principal, &zone_id, &timestamp, &payload);
    assert_eq!(
        first, second,
        "INV-RECEIPT-DETERMINISM violated: identical inputs produced different hashes"
    );

    // ── (B) Output shape ────────────────────────────────────────────
    assert_eq!(
        first.len(),
        64,
        "INV-RECEIPT-OUTPUT-SHAPE violated: SHA-256 hex must be 64 chars, got {}",
        first.len()
    );
    assert!(
        first.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "INV-RECEIPT-OUTPUT-SHAPE violated: hash hex must be lowercase ASCII hex digits, got {first:?}"
    );

    // ── (C) Field sensitivity — flip one scalar field, hash must differ ──
    let flipped_hash = match case.flip_selector % 5 {
        0 => canonical_decision_receipt_payload_hash(
            &flip_field(&op_id),
            &principal,
            &zone_id,
            &timestamp,
            &payload,
        ),
        1 => canonical_decision_receipt_payload_hash(
            &op_id,
            &flip_field(&principal),
            &zone_id,
            &timestamp,
            &payload,
        ),
        2 => canonical_decision_receipt_payload_hash(
            &op_id,
            &principal,
            &flip_field(&zone_id),
            &timestamp,
            &payload,
        ),
        3 => canonical_decision_receipt_payload_hash(
            &op_id,
            &principal,
            &zone_id,
            &flip_field(&timestamp),
            &payload,
        ),
        _ => {
            let mut flipped_payload = payload.clone();
            flipped_payload.action_type = flip_field(&flipped_payload.action_type);
            canonical_decision_receipt_payload_hash(
                &op_id,
                &principal,
                &zone_id,
                &timestamp,
                &flipped_payload,
            )
        }
    };
    assert_ne!(
        first, flipped_hash,
        "INV-RECEIPT-FIELD-SENSITIVITY violated: flipping field selector {} \
         produced the same hash — a field was dropped from the preimage",
        case.flip_selector % 5,
    );

    // ── (D) Length-prefix safety ────────────────────────────────────
    // ("ab", "cd") and ("a", "bcd") have the same concatenated content but
    // different length prefixes; their hashes MUST differ.
    let split_a = canonical_decision_receipt_payload_hash(
        "ab",
        "cd",
        &zone_id,
        &timestamp,
        &payload,
    );
    let split_b = canonical_decision_receipt_payload_hash(
        "a",
        "bcd",
        &zone_id,
        &timestamp,
        &payload,
    );
    assert_ne!(
        split_a, split_b,
        "INV-RECEIPT-LENGTH-PREFIX violated: (\"ab\", \"cd\") collided with \
         (\"a\", \"bcd\") — the length prefix was dropped"
    );
});

fn build_payload(case: &FleetReceiptHashFuzzCase) -> DecisionReceiptPayload {
    DecisionReceiptPayload {
        action_type: bounded(&case.action_type, MAX_FIELD_BYTES),
        extension_id: case
            .extension_id
            .as_ref()
            .map(|s| bounded(s, MAX_FIELD_BYTES)),
        incident_id: case
            .incident_id
            .as_ref()
            .map(|s| bounded(s, MAX_FIELD_BYTES)),
        scope: DecisionReceiptScope {
            zone_id: bounded(&case.payload_zone_id, MAX_FIELD_BYTES),
            tenant_id: case.tenant_id.as_ref().map(|s| bounded(s, MAX_FIELD_BYTES)),
            affected_nodes: case.affected_nodes,
            revocation_severity: case
                .revocation_severity_selector
                .map(|sel| pick_revocation_severity(sel)),
        },
        reason: bounded(&case.reason, MAX_FIELD_BYTES),
        event_code: bounded(&case.event_code, MAX_FIELD_BYTES),
    }
}

fn pick_revocation_severity(selector: u8) -> RevocationSeverity {
    match selector % 3 {
        0 => RevocationSeverity::Advisory,
        1 => RevocationSeverity::Mandatory,
        _ => RevocationSeverity::Emergency,
    }
}

fn bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut out = String::with_capacity(max_bytes);
    for ch in s.chars() {
        if out.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

/// Mutate the field deterministically so the post-flip value cannot equal the
/// pre-flip value: prepend an ASCII marker byte that is NOT in standard
/// identifier sets. Even if `field == ""`, the result is `"\u{00}"` which
/// differs from the original empty string.
fn flip_field(field: &str) -> String {
    let mut out = String::with_capacity(field.len().saturating_add(1));
    out.push('\u{00}');
    out.push_str(field);
    out
}
