//! Regression test for the security::crypto::Ed25519Verifier malleability seam.
//!
//! Background. `Ed25519Verifier::verify` previously called the lenient
//! `ed25519_dalek::VerifyingKey::verify`, which accepts non-canonical
//! s-values (s >= L) under RFC 8032 — the classic Ed25519 signature
//! malleability surface. Two production callers route Ed25519 verification
//! through this wrapper:
//!   - `crates/franken-node/src/observability/evidence_ledger.rs:675`
//!     (`verify_evidence_entry_bytes_with_payload_bytes`)
//!   - `crates/franken-node/src/supply_chain/artifact_signing.rs:468`
//!     (`verify_signature`)
//! The evidence-ledger consumer derives its replay key from the literal
//! signature bytes (see `replay_key` at evidence_ledger.rs:268), so an
//! s-malleated signature bypasses replay detection: same `(timestamp,
//! message, signer)` but a different signature byte string yields a
//! different replay key, and the ledger admits the second copy as if it
//! were a brand-new entry. The README at line 348 advertises the evidence
//! ledger as "append-only, signature-chained, and witness-traced"; the
//! signature-chain integrity claim is the load-bearing one this regression
//! pins.
//!
//! Test plan. Build a real Ed25519 signature with a fixed key, then
//! construct the canonical s-malleated form `s' = s + L (mod 2^256)`.
//! Two assertions:
//!   (1) the canonical signature still verifies through the wrapper
//!       (no regression on the success path);
//!   (2) the malleated signature is rejected with `VerificationFailed`
//!       (the actual fix — `verify_strict` would have returned `Err`
//!       on the non-canonical s, while the pre-fix lenient `verify`
//!       would have returned `Ok`).

use frankenengine_node::security::crypto::{
    Ed25519Verifier, SignatureVerificationError, SignatureVerifier,
};

use ed25519_dalek::{Signer, SigningKey};

/// Subgroup order L for Ed25519's base point (little-endian, 32 bytes).
/// RFC 8032 §5.1: L = 2^252 + 27742317777372353535851937790883648493.
const ED25519_L_LE: [u8; 32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Add the curve order L to the scalar `s` (little-endian, 32 bytes),
/// producing the non-canonical s-malleable counterpart `s' = s + L mod 2^256`.
/// For every canonical signature emitted by `SigningKey::sign` the canonical
/// s is < L < 2^253, so s + L < 2L < 2^254 — well within u256, no wrap.
fn malleate_scalar(s: [u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = u16::from(s[i]) + u16::from(ED25519_L_LE[i]) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    // The high bit of L is 0x10 and canonical s < L, so the addition cannot
    // overflow into a 33rd byte. If it ever does, our test fixture is wrong.
    assert_eq!(
        carry, 0,
        "malleated s should not wrap mod 2^256 for canonical inputs"
    );
    out
}

#[test]
fn ed25519_verifier_rejects_s_malleable_signature() {
    let signing_key = SigningKey::from_bytes(&[0x42_u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let message = b"evidence-ledger-malleability-pin";

    let canonical = signing_key.sign(message).to_bytes();

    // (1) Canonical signature must continue to verify.
    let verifier = Ed25519Verifier::new(verifying_key);
    verifier
        .verify(message, &canonical)
        .expect("canonical signature must verify post-fix");

    // (2) Build the s-malleated counterpart.
    let mut s = [0_u8; 32];
    s.copy_from_slice(&canonical[32..]);
    let s_prime = malleate_scalar(s);

    let mut malleated = canonical;
    malleated[32..].copy_from_slice(&s_prime);
    assert_ne!(
        canonical, malleated,
        "malleated signature must differ byte-for-byte from canonical"
    );

    // (3) Pre-fix, this signature passed `verify` (lenient). Post-fix, it
    // must be rejected with `VerificationFailed` — exactly what
    // `verify_strict` returns when s is out of canonical range.
    match verifier.verify(message, &malleated) {
        Err(SignatureVerificationError::VerificationFailed) => {}
        Err(other) => panic!("expected VerificationFailed on malleated signature, got {other:?}"),
        Ok(()) => panic!(
            "Ed25519Verifier::verify accepted s-malleated signature — \
             verify_strict regression at security/crypto.rs"
        ),
    }
}

/// Companion: ensure the wrapper still surfaces `MalformedSignature` for
/// length-wrong signatures (the structural-error branch is unchanged by the
/// strict-vs-lenient flip). This keeps the two error variants distinct so
/// callers that match on the discriminant — e.g.
/// `evidence_ledger::verify_evidence_entry_bytes_with_payload_bytes` — keep
/// their existing semantics for "malformed bytes" vs "wrong signer".
#[test]
fn ed25519_verifier_still_returns_malformed_signature_for_wrong_length() {
    let signing_key = SigningKey::from_bytes(&[0x42_u8; 32]);
    let verifier = Ed25519Verifier::new(signing_key.verifying_key());

    let message = b"length-check";
    let too_short = [0_u8; 32];
    match verifier.verify(message, &too_short) {
        Err(SignatureVerificationError::MalformedSignature) => {}
        other => panic!("expected MalformedSignature for 32-byte input, got {other:?}"),
    }
}
