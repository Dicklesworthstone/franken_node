//! Metamorphic proptest harness for decision_receipt sign/serialize/parse/verify (bd-80a78).
//!
//! Properties tested:
//!
//! 1. **Direct verification** — `verify_receipt(sign_receipt(r), pk)` returns `Ok(true)`.
//! 2. **JSON round-trip preservation** — `from_str(to_string(signed)) == signed`.
//! 3. **Round-trip-then-verify** — verification succeeds after a JSON round-trip.
//! 4. **Cross-key rejection** — verification under a different `VerifyingKey` returns
//!    `Ok(false)` (the receipt commits the signer key id and the signature itself).
//! 5. **Tampered signature detection** — flipping any single bit of the Ed25519
//!    signature bytes causes verification to fail (`Err` or `Ok(false)`, never `Ok(true)`).
//! 6. **Tampered chain hash detection** — appending bytes to `chain_hash` causes
//!    verification to fail.
//! 7. **Tampered receipt body detection** — mutating `receipt.action_name` after signing
//!    causes verification to fail.
//!
//! These are the load-bearing safety properties for high-impact decision receipts:
//! if any of them break, signed audit records can be forged or laundered.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::SigningKey;
use frankenengine_node::security::decision_receipt::{
    Decision, Ed25519PrivateKey, Receipt, SignedReceipt, sign_receipt, verify_receipt,
};
use proptest::prelude::*;
use serde_json::json;

fn signing_key_from_seed(seed: u64) -> Ed25519PrivateKey {
    let mut bytes = [0_u8; 32];
    let s = seed.to_le_bytes();
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&s);
    }
    SigningKey::from_bytes(&bytes)
}

fn decision_strategy() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Approved),
        Just(Decision::Denied),
        Just(Decision::Escalated),
    ]
}

fn build_receipt(
    action_name: &str,
    actor_identity: &str,
    audience: &str,
    rationale: &str,
    rollback_command: &str,
    decision: Decision,
    confidence: f64,
    evidence_refs: Vec<String>,
    policy_rule_chain: Vec<String>,
) -> Receipt {
    Receipt::new(
        action_name,
        actor_identity,
        audience,
        &json!({"input_field": action_name, "n": 1}),
        &json!({"output_field": "ok"}),
        decision,
        rationale,
        evidence_refs,
        policy_rule_chain,
        confidence,
        rollback_command,
    )
    .expect("receipt construction with valid confidence must succeed")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Properties 1-4: direct verify, JSON round-trip preservation, round-trip-then-verify,
    /// and cross-key rejection.
    #[test]
    fn signed_receipt_round_trip_then_verify(
        action_name in "[a-z][a-z0-9_]{0,31}",
        actor_identity in "[a-zA-Z0-9_@.\\-]{1,64}",
        audience in "[a-zA-Z0-9_\\-]{1,32}",
        rationale in "[ -~]{0,256}",
        rollback_command in "[ -~]{0,128}",
        evidence_refs in proptest::collection::vec("[a-zA-Z0-9_\\-]{1,32}", 0..5),
        policy_rule_chain in proptest::collection::vec("[a-zA-Z0-9_\\-]{1,32}", 0..5),
        confidence in 0.0_f64..=1.0_f64,
        decision in decision_strategy(),
        seed in 1_u64..=u64::MAX,
    ) {
        let signing_key = signing_key_from_seed(seed);
        let public_key = signing_key.verifying_key();

        let receipt = build_receipt(
            &action_name,
            &actor_identity,
            &audience,
            &rationale,
            &rollback_command,
            decision,
            confidence,
            evidence_refs,
            policy_rule_chain,
        );

        let signed = sign_receipt(&receipt, &signing_key)
            .expect("sign_receipt must succeed for in-range confidence");

        // Property 1: directly signed receipt verifies.
        let direct = verify_receipt(&signed, &public_key)
            .expect("verify_receipt must not error on a freshly signed receipt");
        prop_assert!(direct, "freshly signed receipt failed direct verification");

        // Property 2: JSON round-trip preserves the SignedReceipt structure.
        let json = serde_json::to_string(&signed)
            .expect("SignedReceipt must serialize to JSON");
        let restored: SignedReceipt = serde_json::from_str(&json)
            .expect("SignedReceipt JSON must round-trip back");
        prop_assert_eq!(&signed, &restored, "JSON round-trip changed SignedReceipt contents");

        // Property 3: verification succeeds against the round-tripped receipt.
        let post = verify_receipt(&restored, &public_key)
            .expect("verify_receipt after round-trip must not error");
        prop_assert!(post, "verification failed after JSON round-trip");

        // Property 4: a different signing key fails verification (signer_key_id mismatch
        // or signature mismatch — both surface as Ok(false)).
        let other_key = signing_key_from_seed(seed.wrapping_add(0x9E37_79B9_7F4A_7C15));
        let other_public = other_key.verifying_key();
        let cross = verify_receipt(&restored, &other_public)
            .expect("verify_receipt under a different key must not error");
        prop_assert!(!cross, "verification succeeded under a different verifying key");
    }

    /// Property 5: any single-bit flip in the Ed25519 signature bytes causes
    /// verification to fail.
    #[test]
    fn tampered_signature_bit_flip_fails_verification(
        action_name in "[a-z][a-z0-9_]{0,15}",
        confidence in 0.0_f64..=1.0_f64,
        decision in decision_strategy(),
        seed in 1_u64..=u64::MAX,
        bit_index in 0_usize..512, // 64-byte Ed25519 signature → 512 bits
    ) {
        let signing_key = signing_key_from_seed(seed);
        let public_key = signing_key.verifying_key();

        let receipt = build_receipt(
            &action_name,
            "actor",
            "audience",
            "rationale",
            "rollback",
            decision,
            confidence,
            vec![],
            vec![],
        );
        let mut signed = sign_receipt(&receipt, &signing_key)
            .expect("sign_receipt must succeed");

        let mut sig_bytes = BASE64_STANDARD
            .decode(&signed.signature)
            .expect("signature is base64 produced by sign_receipt");
        prop_assert_eq!(sig_bytes.len(), 64, "Ed25519 signature must be 64 bytes");
        let byte_idx = bit_index / 8;
        let bit_in_byte = (bit_index % 8) as u8;
        sig_bytes[byte_idx] ^= 1_u8 << bit_in_byte;
        signed.signature = BASE64_STANDARD.encode(&sig_bytes);

        match verify_receipt(&signed, &public_key) {
            Ok(verified) => prop_assert!(
                !verified,
                "bit-flipped signature must not verify (bit {})",
                bit_index
            ),
            // Some tampered byte sequences are caught by Signature::from_slice / verify
            // and surface as Err — that is also a valid rejection.
            Err(_) => {}
        }
    }

    /// Property 6: appending bytes to `chain_hash` causes verification to fail.
    #[test]
    fn tampered_chain_hash_fails_verification(
        action_name in "[a-z][a-z0-9_]{0,15}",
        confidence in 0.0_f64..=1.0_f64,
        decision in decision_strategy(),
        seed in 1_u64..=u64::MAX,
        suffix in "[a-f0-9]{1,8}",
    ) {
        let signing_key = signing_key_from_seed(seed);
        let public_key = signing_key.verifying_key();

        let receipt = build_receipt(
            &action_name,
            "actor",
            "audience",
            "rationale",
            "rollback",
            decision,
            confidence,
            vec![],
            vec![],
        );
        let mut signed = sign_receipt(&receipt, &signing_key)
            .expect("sign_receipt must succeed");

        signed.chain_hash.push_str(&suffix);

        match verify_receipt(&signed, &public_key) {
            Ok(verified) => prop_assert!(
                !verified,
                "verification must reject a tampered chain_hash"
            ),
            Err(_) => {}
        }
    }

    /// Property 7: mutating the receipt body (action_name) after signing breaks the
    /// canonical-JSON-bound signature.
    #[test]
    fn tampered_action_name_fails_verification(
        action_name in "[a-z][a-z0-9_]{0,15}",
        replacement in "[a-z][a-z0-9_]{0,15}",
        confidence in 0.0_f64..=1.0_f64,
        decision in decision_strategy(),
        seed in 1_u64..=u64::MAX,
    ) {
        prop_assume!(action_name != replacement);

        let signing_key = signing_key_from_seed(seed);
        let public_key = signing_key.verifying_key();

        let receipt = build_receipt(
            &action_name,
            "actor",
            "audience",
            "rationale",
            "rollback",
            decision,
            confidence,
            vec![],
            vec![],
        );
        let mut signed = sign_receipt(&receipt, &signing_key)
            .expect("sign_receipt must succeed");

        signed.receipt.action_name = replacement;

        match verify_receipt(&signed, &public_key) {
            Ok(verified) => prop_assert!(
                !verified,
                "verification must reject a tampered receipt body"
            ),
            Err(_) => {}
        }
    }
}
