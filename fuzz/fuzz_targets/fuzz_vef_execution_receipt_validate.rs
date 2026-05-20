#![no_main]
#![forbid(unsafe_code)]

//! Fuzz the `ExecutionReceipt` JSON deserialization + `validate_receipt` +
//! `serialize_canonical` + `receipt_hash_sha256` + `round_trip_canonical_bytes`
//! pipeline at `crates/franken-node/src/connector/vef_execution_receipt.rs`.
//!
//! `ExecutionReceipt` is `#[derive(Deserialize)]` and is consumed by the
//! verifier-economy flow. The receipt's text fields (`actor_identity`,
//! `artifact_identity`, `trace_id`, `capability_context` keys/values) each
//! go through their own validator. The validators reject empty / leading-
//! or-trailing-whitespace / NUL — but unlike the validators hardened across
//! the rest of the codebase this push window, they do NOT reject other
//! control characters. A separate review-only audit cycle filed this as a
//! [LOW] defense-in-depth observation (no demonstrated raw-render exploit
//! sink), so the harness here is the coverage-gap counterpart: prove that
//! the validator + canonical-serializer + hash pipeline never panics on
//! any byte sequence and that the round-trip invariants hold on every
//! input that passes validation.
//!
//! Invariants pinned (after `validate_receipt` returns Ok):
//!   - `serialize_canonical(&receipt)` succeeds.
//!   - `receipt_hash_sha256(&receipt)` succeeds and emits a value with
//!     the `"sha256:"` prefix and a 64-char ASCII-hex suffix.
//!   - `round_trip_canonical_bytes(&receipt)` (which serializes,
//!     deserializes, and re-serializes internally) succeeds and produces
//!     bytes byte-equal to the first `serialize_canonical` pass — i.e.
//!     the canonical form is a fixed-point.

use frankenengine_node::connector::vef_execution_receipt::{
    receipt_hash_sha256, round_trip_canonical_bytes, serialize_canonical, validate_receipt,
    ExecutionReceipt,
};
use libfuzzer_sys::fuzz_target;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Cap input to keep per-iteration cost bounded; real receipts are
    // well under this.
    if data.len() > 256 * 1024 {
        return;
    }

    let Ok(json_str) = str::from_utf8(data) else {
        return;
    };

    let Ok(receipt) = serde_json::from_str::<ExecutionReceipt>(json_str) else {
        return;
    };

    if validate_receipt(&receipt).is_err() {
        // Validation errors are a valid outcome; only the success path is
        // load-bearing for the round-trip / hash invariants below.
        return;
    }

    let canonical = serialize_canonical(&receipt)
        .expect("validate_receipt = Ok implies serialize_canonical must succeed");

    let digest = receipt_hash_sha256(&receipt)
        .expect("validate_receipt = Ok implies receipt_hash_sha256 must succeed");
    assert!(
        digest.starts_with("sha256:"),
        "receipt hash must carry the sha256 prefix; got {digest}"
    );
    let hex_part = &digest["sha256:".len()..];
    assert_eq!(
        hex_part.len(),
        64,
        "sha256 hex tail must be 64 chars; got {} for {digest}",
        hex_part.len()
    );
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "sha256 hex tail must be ASCII hex digits; got {digest}"
    );

    let second_pass = round_trip_canonical_bytes(&receipt)
        .expect("validated receipt must round-trip canonical bytes");

    assert_eq!(
        canonical, second_pass,
        "canonical form must be a fixed-point: serialize == serialize ∘ deserialize ∘ serialize"
    );
});
