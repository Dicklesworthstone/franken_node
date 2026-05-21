//! Regression coverage for replay-bundle adoption of the crypto trait raw path.
//!
//! `sign_replay_bundle` / `verify_replay_bundle_signature` now route signing
//! and verification through `frankenengine_node::crypto::Ed25519Scheme::{sign_raw,
//! verify_raw}` instead of calling `SigningKey::sign` / `Ed25519Verifier::verify`
//! directly. The migration must be a no-op on the wire — picking
//! `sign_with_domain` instead of `sign_raw` would prepend a wrapper digest
//! and invalidate every `.fnbundle` artifact ever issued, plus every
//! checked-in replay-bundle golden.
//!
//! Bead: bd-lbnkf (parent design: docs/specs/crypto_trait_abstraction.md,
//! follow-on to bd-dwx4l which added the `_raw` trait methods).

use ed25519_dalek::{Signature, Signer as _, SigningKey};
use frankenengine_node::crypto::{Ed25519Scheme, SignatureScheme};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, ReplayBundleSigningMaterial, generate_replay_bundle,
    sign_replay_bundle, verify_replay_bundle_signature,
};

/// The signature payload domain separator. Kept in lockstep with
/// `REPLAY_BUNDLE_SIGNATURE_PAYLOAD_DOMAIN` in the production module —
/// drift surfaces as a byte-identity test failure, which is the intended
/// fail-loudly behavior because the on-the-wire signed bytes would then
/// have changed.
const REPLAY_BUNDLE_SIGNATURE_PAYLOAD_DOMAIN: &[u8] = b"replay_bundle_sig_v1:";

fn signature_payload_for(bundle: &ReplayBundle) -> Vec<u8> {
    let integrity_hash = bundle.integrity_hash.as_bytes();
    let mut payload =
        Vec::with_capacity(REPLAY_BUNDLE_SIGNATURE_PAYLOAD_DOMAIN.len() + 8 + integrity_hash.len());
    payload.extend_from_slice(REPLAY_BUNDLE_SIGNATURE_PAYLOAD_DOMAIN);
    payload.extend_from_slice(&(integrity_hash.len() as u64).to_le_bytes());
    payload.extend_from_slice(integrity_hash);
    payload
}

fn fixture_events() -> Vec<RawEvent> {
    vec![
        RawEvent::new(
            "2026-01-15T14:30:00.000100Z",
            EventType::ExternalSignal,
            serde_json::json!({"signal": "anomaly", "severity": "critical"}),
        ),
        RawEvent::new(
            "2026-01-15T14:30:00.000200Z",
            EventType::PolicyEval,
            serde_json::json!({"decision": "isolate", "rule_id": "R-2847"}),
        )
        .with_causal_parent(1),
        RawEvent::new(
            "2026-01-15T14:30:00.000300Z",
            EventType::OperatorAction,
            serde_json::json!({"action": "log", "operator": "alice"}),
        )
        .with_causal_parent(2),
    ]
}

fn signed_fixture_bundle(seed: u8) -> (ReplayBundle, SigningKey, String) {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let mut bundle =
        generate_replay_bundle("INC-CRYPTO-TRAIT-ADOPTION", &fixture_events()).expect("bundle");
    let signing_material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "env",
        signing_identity: "incident-control-plane",
    };
    sign_replay_bundle(&mut bundle, &signing_material).expect("sign through trait-routed path");
    let trusted_key_id =
        frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
            &signing_key.verifying_key(),
        )
        .to_string();
    (bundle, signing_key, trusted_key_id)
}

/// Load-bearing on-the-wire compatibility check.
///
/// Post-migration `sign_replay_bundle` (which routes through
/// `Ed25519Scheme::sign_raw`) MUST produce byte-identical signature bytes
/// to a pre-migration direct `SigningKey::sign(signature_payload)`. If this
/// ever fails, every `.fnbundle` artifact already issued and every
/// checked-in replay-bundle golden has just been invalidated by the change
/// under test.
#[test]
fn replay_bundle_trait_raw_path_preserves_legacy_signature_bytes() {
    let (bundle, signing_key, _trusted_key_id) = signed_fixture_bundle(11);
    let signature = bundle.signature.as_ref().expect("bundle is signed");

    let trait_signature_bytes = hex::decode(&signature.signature_hex).expect("hex");
    let payload = signature_payload_for(&bundle);

    // Pre-migration sign path: direct `SigningKey::sign(payload)`.
    let legacy_direct_signature = signing_key.sign(&payload).to_bytes();

    assert_eq!(
        trait_signature_bytes.as_slice(),
        legacy_direct_signature.as_slice(),
        "post-migration sign_replay_bundle must produce byte-identical \
         signatures to a direct ed25519_dalek::SigningKey::sign over the \
         canonical signature payload; otherwise every existing .fnbundle in \
         the wild and every checked-in golden is invalidated by this change",
    );

    // And: the trait verifier accepts the bytes.
    let signature_array =
        Ed25519Scheme::signature_from_bytes(&trait_signature_bytes).expect("signature bytes");
    let public_key = signing_key.verifying_key();
    assert!(Ed25519Scheme::verify_raw(
        public_key.as_bytes(),
        &payload,
        &signature_array
    ));

    // And: direct ed25519-dalek strict-verify accepts the same bytes,
    // closing the byte-identity circle.
    let sig = Signature::from_slice(&trait_signature_bytes).expect("64-byte signature");
    public_key
        .verify_strict(&payload, &sig)
        .expect("direct strict-verify must accept the trait-emitted signature");
}

/// `verify_replay_bundle_signature` (post-migration, trait-routed) must
/// accept signatures produced by the production `sign_replay_bundle`.
/// Happy-path regression for the migrated verifier surface.
#[test]
fn verify_replay_bundle_signature_accepts_trait_routed_sign_output() {
    let (bundle, _signing_key, trusted_key_id) = signed_fixture_bundle(42);

    verify_replay_bundle_signature(&bundle, Some(&trusted_key_id))
        .expect("trait-routed verify must accept trait-routed sign output");
}

/// Guard against a well-meaning later refactor that swaps `sign_raw` for
/// `sign_with_domain` in `sign_replay_bundle`. The wrapper digest would
/// invalidate every existing bundle — this test catches that drift.
#[test]
fn verify_replay_bundle_signature_rejects_wrapper_domain_signatures() {
    let signing_key = SigningKey::from_bytes(&[77_u8; 32]);
    let mut bundle =
        generate_replay_bundle("INC-WRAPPER-REJECT", &fixture_events()).expect("bundle");

    // Build the canonical signature payload exactly the way
    // `sign_replay_bundle` does.
    let payload = signature_payload_for(&bundle);

    // Sign through the WRAPPING surface (the bug we are guarding against).
    let wrapped_sig_bytes =
        Ed25519Scheme::sign_with_domain(&signing_key.to_bytes(), b"replay_bundle", &payload)
            .expect("sign_with_domain must succeed");

    // The wrapper-signed bytes must NOT verify under the trait verifier
    // path that `sign_replay_bundle` uses.
    assert!(
        !Ed25519Scheme::verify_raw(
            signing_key.verifying_key().as_bytes(),
            &payload,
            &wrapped_sig_bytes
        ),
        "Ed25519Scheme::verify_raw must reject sign_with_domain-produced \
         bytes over the canonical signature payload",
    );

    // Hand-install the forged signature on the bundle and confirm the
    // public verify surface rejects it.
    let trusted_key_id =
        frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
            &signing_key.verifying_key(),
        )
        .to_string();
    bundle.signature = Some(
        frankenengine_node::tools::replay_bundle::ReplayBundleSignature {
            algorithm: "ed25519".to_string(),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            key_id: trusted_key_id.clone(),
            key_source: "env".to_string(),
            signing_identity: "incident-control-plane".to_string(),
            trust_scope: "incident_replay_bundle".to_string(),
            signed_payload_sha256: hex::encode(sha2::Sha256::digest(&payload)),
            signature_hex: hex::encode(wrapped_sig_bytes),
        },
    );

    let err = verify_replay_bundle_signature(&bundle, Some(&trusted_key_id))
        .expect_err("wrapper-domain signature must be rejected");
    let formatted = format!("{err:?}");
    assert!(
        formatted.contains("SignatureInvalid"),
        "expected SignatureInvalid, got {formatted}",
    );
}

// Re-export sha2::Digest into scope for the forged-bundle test above.
use sha2::Digest as _;
