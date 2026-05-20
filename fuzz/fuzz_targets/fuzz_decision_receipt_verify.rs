#![no_main]
#![forbid(unsafe_code)]

//! Fuzz the `SignedReceipt` JSON deserialization + `verify_receipt` pipeline at
//! `crates/franken-node/src/security/decision_receipt.rs`.
//!
//! `Receipt` and `SignedReceipt` are `#[derive(Deserialize)]` and consumed by
//! the high-impact-action audit-receipt flow (bd-21z). The verify pipeline
//! routes through `Ed25519Scheme::verify_raw` per bd-dwx4l. Existing fuzz
//! coverage indexes the *fleet-quarantine* decision receipt
//! (`fuzz_fleet_decision_receipt_parse.rs`) — a separate type in
//! `api/fleet_quarantine.rs` — but not the `security::decision_receipt`
//! high-impact-action receipt that bd-dwx4l migrated to the crypto trait.
//! This harness closes that gap.
//!
//! Invariants pinned on every input:
//!   - `verify_receipt` never panics; it returns `Ok(bool)` or `Err(ReceiptError)`.
//!   - If `verify_receipt(&signed, &pk) == Ok(true)`, then a sign-then-verify
//!     round-trip on the inner `receipt` with a fresh fixture key reproduces
//!     a *valid* signature — i.e. the canonical preimage that the fuzz
//!     input's signature happened to match is a stable fixed-point of the
//!     production canonicalizer (no validator drift between
//!     deserialize+verify and sign+verify).
//!
//! Note: we cannot in general expect the fuzzer to produce a JSON blob whose
//! signature *matches* the fixture key — that's a low-probability event. The
//! first invariant (no-panic on arbitrary input) is the load-bearing one;
//! the second invariant only triggers on the rare success path and pins a
//! cross-check between the verify and sign canonicalizers.

use ed25519_dalek::SigningKey;
use frankenengine_node::security::decision_receipt::{
    sign_receipt, verify_receipt, SignedReceipt,
};
use libfuzzer_sys::fuzz_target;
use std::str;

const FUZZ_SIGNING_SEED: [u8; 32] = [0x5b; 32];

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let Ok(json_str) = str::from_utf8(data) else {
        return;
    };

    let Ok(signed) = serde_json::from_str::<SignedReceipt>(json_str) else {
        return;
    };

    // Construct a fixture verifying key. The fuzzer is essentially certain
    // not to produce a JSON whose signature matches this key, so the
    // expected outcome is `Ok(false)` or any `Err(_)` — but never a panic.
    let signing_key = SigningKey::from_bytes(&FUZZ_SIGNING_SEED);
    let verifying_key = signing_key.verifying_key();

    let outcome = verify_receipt(&signed, &verifying_key);

    if matches!(outcome, Ok(true)) {
        // Extremely rare success path: the fuzzer happened to produce a
        // signature that validates under the fixture key. Cross-check by
        // signing the same receipt body with the same fixture key — the
        // resulting signature must also verify, since the canonical
        // preimage is the same on both sides.
        let resigned = sign_receipt(&signed.receipt, &signing_key)
            .expect("sign_receipt must succeed on a receipt that already validates");
        let re_verified = verify_receipt(&resigned, &verifying_key)
            .expect("verify_receipt must not error on a freshly signed receipt");
        assert!(
            re_verified,
            "sign_receipt → verify_receipt round-trip must succeed (canonicalizer fixed-point invariant)"
        );
    }
});
