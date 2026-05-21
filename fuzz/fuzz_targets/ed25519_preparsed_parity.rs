//! Fuzz target: byte-parity between Ed25519Scheme stateless API and the
//! Ed25519Preparsed{Signer,Verifier} handle types (bd-98xo5.2.7).
//!
//! ## What this harness pins
//!
//! The bd-98xo5.2 perf optimisation introduced preparsed key handles
//! that cache `SigningKey` / `VerifyingKey` once at construction
//! instead of re-parsing on every call. The optimisation is only safe
//! if the preparsed path produces identical output bytes and identical
//! verifier verdicts on every input — any divergence is a silent
//! interop break, since one decision-path may accept what the other
//! rejects (or sign different bytes from the same key).
//!
//! The harness pulls 32-byte secret bytes + a payload + a signature
//! from `Unstructured`, then asserts:
//!
//!   1. `Ed25519Scheme::sign_raw(secret, payload) == preparsed_signer.sign_raw(payload)`
//!   2. `Ed25519Scheme::verify_raw(pubkey, payload, sig) == preparsed_verifier.verify_raw(payload, sig)`
//!      (for arbitrary signatures, including tampered or junk bytes)
//!
//! Panic on any divergence. The libfuzzer driver shrinks the offending
//! input automatically.
//!
//! ## Out-of-scope here
//!
//! - Domain-separated paths (`sign_with_domain` / `verify_with_domain`):
//!   the inline tests `preparsed_signer_sign_with_domain_matches_scheme`
//!   and `preparsed_verifier_verify_with_domain_matches_scheme` cover
//!   the deterministic preimage parity; the fuzz harness sticks to the
//!   raw path which is what hot call sites actually use.
//! - Malleability: the inline test
//!   `preparsed_verifier_rejects_malleable_canonical_s` builds the
//!   specific s ≥ ℓ case; fuzz tampering generates malleable signatures
//!   probabilistically and the parity property still holds (both paths
//!   reject), so this harness exercises that case incidentally.

#![no_main]

use libfuzzer_sys::fuzz_target;

use arbitrary::{Arbitrary, Unstructured};
use frankenengine_node::crypto::{
    Ed25519PreparsedSigner, Ed25519PreparsedVerifier, Ed25519Scheme, SignatureScheme,
};

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    secret_bytes: [u8; 32],
    payload: Vec<u8>,
    signature_bytes: [u8; 64],
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut u) else {
        return;
    };

    let signer = Ed25519PreparsedSigner::from_secret_bytes(&input.secret_bytes);
    let pubkey = signer.public_key();

    // Property 1: sign_raw byte-parity.
    let stateless_sig = Ed25519Scheme::sign_raw(&input.secret_bytes, &input.payload)
        .expect("sign_raw should not fail");
    let preparsed_sig = signer.sign_raw(&input.payload);
    assert_eq!(
        stateless_sig, preparsed_sig,
        "sign_raw divergence: stateless vs preparsed produced different signatures"
    );

    // Property 2: verify_raw boolean parity (on the freshly-signed sig).
    let stateless_ok_valid = Ed25519Scheme::verify_raw(&pubkey, &input.payload, &stateless_sig);
    let verifier = match Ed25519PreparsedVerifier::from_public_bytes(&pubkey) {
        Ok(v) => v,
        Err(_) => {
            // SigningKey::from_bytes is infallible — a non-decompressable
            // pubkey here would be a dalek invariant break, not a wrapper
            // bug. Treat as a fuzz-corpus oddity, not a harness failure.
            return;
        }
    };
    let preparsed_ok_valid = verifier.verify_raw(&input.payload, &preparsed_sig);
    assert_eq!(
        stateless_ok_valid, preparsed_ok_valid,
        "verify_raw divergence on valid signature"
    );
    assert!(stateless_ok_valid, "freshly-signed signature must verify");

    // Property 3: verify_raw boolean parity on an arbitrary (likely
    // invalid) signature pulled from the fuzz input. Both must agree —
    // either both accept (extremely unlikely on random 64 bytes) or both
    // reject.
    let stateless_ok_arbitrary =
        Ed25519Scheme::verify_raw(&pubkey, &input.payload, &input.signature_bytes);
    let preparsed_ok_arbitrary = verifier.verify_raw(&input.payload, &input.signature_bytes);
    assert_eq!(
        stateless_ok_arbitrary, preparsed_ok_arbitrary,
        "verify_raw divergence on arbitrary signature bytes"
    );
});
