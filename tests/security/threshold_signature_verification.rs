//! Threshold signature verification security tests (bd-35q1).
//!
//! Verifies quorum enforcement, partial rejection, duplicate handling,
//! unknown signer rejection, and stable failure reasons.

use ed25519_dalek::SigningKey;
use frankenengine_node::security::threshold_sig::*;
use sha2::{Digest, Sha256};

/// Deterministically generate an Ed25519 signing key from an index.
fn signing_key(i: u32) -> SigningKey {
    let mut h = Sha256::new();
    h.update(b"test_signing_key_seed_v1:");
    h.update(i.to_le_bytes());
    let seed: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn keys(n: u32) -> (Vec<SigningKey>, Vec<SignerKey>) {
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for i in 0..n {
        let sk = signing_key(i);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        pks.push(SignerKey {
            key_id: format!("signer-{i}"),
            public_key_hex: pk_hex,
        });
        sks.push(sk);
    }
    (sks, pks)
}

fn config(k: u32, n: u32) -> (Vec<SigningKey>, ThresholdConfig) {
    let (sks, pks) = keys(n);
    let cfg = ThresholdConfig {
        threshold: k,
        total_signers: n,
        signer_keys: pks,
    };
    (sks, cfg)
}

fn artifact_with_sigs(
    sks: &[SigningKey],
    cfg: &ThresholdConfig,
    hash: &str,
    count: usize,
) -> PublicationArtifact {
    PublicationArtifact {
        artifact_id: "art-test".into(),
        connector_id: "conn-test".into(),
        content_hash: hash.to_string(),
        signatures: sks
            .iter()
            .zip(cfg.signer_keys.iter())
            .take(count)
            .map(|(sk, key)| sign(sk, &key.key_id, "art-test", "conn-test", hash))
            .collect(),
    }
}

#[test]
fn quorum_met_admits() {
    let (sks, cfg) = config(2, 3);
    let art = artifact_with_sigs(&sks, &cfg, "h1", 2);
    let result = verify_threshold(&cfg, &art, "t1", "ts");
    assert!(result.verified);
}

#[test]
fn partial_set_rejected() {
    let (sks, cfg) = config(2, 3);
    let art = artifact_with_sigs(&sks, &cfg, "h2", 1);
    let result = verify_threshold(&cfg, &art, "t2", "ts");
    assert!(!result.verified);
}

#[test]
fn empty_set_rejected() {
    let (sks, cfg) = config(2, 3);
    let art = artifact_with_sigs(&sks, &cfg, "h3", 0);
    let result = verify_threshold(&cfg, &art, "t3", "ts");
    assert!(!result.verified);
}

#[test]
fn unknown_signer_ignored() {
    let (sks, cfg) = config(2, 3);
    let mut art = artifact_with_sigs(&sks, &cfg, "h4", 1);
    art.signatures.push(PartialSignature {
        signer_id: "rogue".into(),
        key_id: "rogue-key".into(),
        signature_hex: "0000000000000000".into(),
    });
    let result = verify_threshold(&cfg, &art, "t4", "ts");
    assert!(!result.verified);
    assert_eq!(result.valid_signatures, 1);
}

#[test]
fn invalid_sig_ignored() {
    let (sks, cfg) = config(2, 3);
    let mut art = artifact_with_sigs(&sks, &cfg, "h5", 1);
    art.signatures.push(PartialSignature {
        signer_id: "signer-1".into(),
        key_id: "signer-1".into(),
        signature_hex: "ffffffffffffffff".into(),
    });
    let result = verify_threshold(&cfg, &art, "t5", "ts");
    assert!(!result.verified);
}

#[test]
fn duplicate_counted_once() {
    let (sks, cfg) = config(2, 3);
    let mut art = artifact_with_sigs(&sks, &cfg, "h6", 1);
    art.signatures.push(sign(
        &sks[0],
        &cfg.signer_keys[0].key_id,
        "art-test",
        "conn-test",
        "h6",
    ));
    let result = verify_threshold(&cfg, &art, "t6", "ts");
    assert!(!result.verified);
    assert_eq!(result.valid_signatures, 1);
}

#[test]
fn failure_reason_is_stable() {
    let (sks, cfg) = config(3, 3);
    let art = artifact_with_sigs(&sks, &cfg, "h7", 1);
    let r1 = verify_threshold(&cfg, &art, "t7a", "ts");
    let r2 = verify_threshold(&cfg, &art, "t7b", "ts");
    assert_eq!(r1.failure_reason, r2.failure_reason);
}

#[test]
fn trace_id_preserved() {
    let (sks, cfg) = config(1, 3);
    let art = artifact_with_sigs(&sks, &cfg, "h8", 1);
    let result = verify_threshold(&cfg, &art, "trace-abc", "ts");
    assert_eq!(result.trace_id, "trace-abc");
}

#[test]
fn invalid_config_rejected() {
    let (_sks, mut cfg) = config(5, 3);
    cfg.threshold = 5;
    let (sks2, cfg2) = config(2, 3);
    let art = artifact_with_sigs(&sks2, &cfg2, "h9", 2);
    let result = verify_threshold(&cfg, &art, "t9", "ts");
    assert!(!result.verified);
}

#[test]
fn content_hash_mismatch_rejected() {
    let (sks, cfg) = config(2, 3);
    let mut art = artifact_with_sigs(&sks, &cfg, "h10-original", 2);
    art.content_hash = "h10-tampered".into();
    let result = verify_threshold(&cfg, &art, "t10", "ts");
    assert!(!result.verified);
    assert_eq!(result.valid_signatures, 0);
    assert!(matches!(
        result.failure_reason,
        Some(FailureReason::InvalidSignature { .. })
    ));
}

#[test]
fn signer_identity_must_match_key_id() {
    let (sks, cfg) = config(2, 3);
    let mut art = artifact_with_sigs(&sks, &cfg, "h11", 2);
    art.signatures[0].signer_id = cfg.signer_keys[1].key_id.clone();
    let result = verify_threshold(&cfg, &art, "t11", "ts");
    assert!(!result.verified);
    assert_eq!(result.valid_signatures, 1);
    assert!(matches!(
        result.failure_reason,
        Some(FailureReason::InvalidSignature { .. })
    ));
}

#[test]
fn preparsed_verifier_matches_standard_verifier() {
    let (sks, cfg) = config(2, 3);
    let art = artifact_with_sigs(&sks, &cfg, "h12", 2);
    let preparsed =
        PreparsedThresholdConfig::from_config(cfg.clone()).expect("valid threshold config");
    let standard = verify_threshold(&cfg, &art, "t12", "ts");
    let preparsed_result = verify_threshold_preparsed(&preparsed, &art, "t12", "ts");
    assert_eq!(standard.verified, preparsed_result.verified);
    assert_eq!(standard.valid_signatures, preparsed_result.valid_signatures);
    assert_eq!(standard.failure_reason, preparsed_result.failure_reason);
}

#[test]
fn invalid_artifact_id_rejected_before_counting_signatures() {
    let (sks, cfg) = config(2, 3);
    let mut art = artifact_with_sigs(&sks, &cfg, "h13", 2);
    art.artifact_id = "../escape".into();
    let result = verify_threshold(&cfg, &art, "t13", "ts");
    assert!(!result.verified);
    assert_eq!(result.valid_signatures, 0);
    assert!(matches!(
        result.failure_reason,
        Some(FailureReason::InvalidArtifactId { .. })
    ));
}

#[test]
fn zero_threshold_rejected_as_invalid_config() {
    let (sks, mut cfg) = config(1, 3);
    cfg.threshold = 0;
    let art = artifact_with_sigs(&sks, &cfg, "h14", 1);
    let result = verify_threshold(&cfg, &art, "t14", "ts");
    assert!(!result.verified);
    assert!(matches!(
        result.failure_reason,
        Some(FailureReason::ConfigInvalid { .. })
    ));
}

#[test]
fn total_signer_count_mismatch_rejected_as_invalid_config() {
    let (sks, mut cfg) = config(2, 3);
    cfg.total_signers = 2;
    let art = artifact_with_sigs(&sks, &cfg, "h15", 2);
    let result = verify_threshold(&cfg, &art, "t15", "ts");
    assert!(!result.verified);
    assert!(matches!(
        result.failure_reason,
        Some(FailureReason::ConfigInvalid { .. })
    ));
}
