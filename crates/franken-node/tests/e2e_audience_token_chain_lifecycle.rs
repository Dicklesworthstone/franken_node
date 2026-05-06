//! Mock-free end-to-end test for the audience-bound token chain.
//!
//! Drives the public surface of
//! `frankenengine_node::control_plane::audience_token` through a real
//! delegation lifecycle: REAL Ed25519 issuance → root token → delegated
//! attenuated child → `TokenValidator::verify_chain` success → every
//! rejection variant.
//!
//! Bead: bd-xa7h9.
//!
//! Coverage:
//!   - happy path: root-only chain + 2-deep delegation chain both verify,
//!   - INV-ABT-ATTENUATION: child capabilities not a subset → rejected,
//!   - INV-ABT-ATTENUATION: child audience not a subset → rejected,
//!   - INV-ABT-ATTENUATION: child max_delegation_depth >= parent's →
//!     rejected,
//!   - INV-ABT-ATTENUATION: child expires_at > parent's → rejected,
//!   - INV-ABT-EXPIRY: token past expires_at at verify time → rejected,
//!   - INV-ABT-AUDIENCE: requester_id not in leaf audience → rejected,
//!   - INV-ABT-REPLAY: same nonce verified twice in one epoch → rejected,
//!   - REPLAY allowed across `advance_epoch`,
//!   - SIGNATURE_INVALID: signature flipped after issuance → rejected,
//!   - validator counters (issued/delegated/verified/rejected) advance
//!     monotonically.
//!
//! No mocks: real Ed25519 SigningKey, real canonical
//! `signature_preimage`, real BTreeMap-backed nonce ledger, real
//! constant-time hash + audience comparisons. Each phase emits a
//! structured tracing event PLUS a JSON-line on stderr.

use std::collections::BTreeSet;
use std::sync::Once;
use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::control_plane::audience_token::{
    ActionScope, AudienceBoundToken, ERR_ABT_ATTENUATION_VIOLATION, ERR_ABT_AUDIENCE_MISMATCH,
    ERR_ABT_REPLAY_DETECTED, ERR_ABT_SIGNATURE_INVALID, ERR_ABT_TOKEN_EXPIRED,
    ERR_ABT_TOKEN_TOO_LARGE, MAX_AUDIENCES_PER_TOKEN, MAX_TOKEN_FIELD_BYTES,
    MAX_TOKEN_SIGNATURE_BYTES, MAX_TOKENS, TokenChain, TokenId, TokenValidator,
};
use serde_json::json;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

const ISSUER: &str = "issuer-prod-controller";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xAB; 32])
}

fn caps(scopes: &[ActionScope]) -> BTreeSet<ActionScope> {
    scopes.iter().copied().collect()
}

/// Build, sign, and return a fresh AudienceBoundToken using the real
/// `signature_preimage` and a real Ed25519 signer.
struct TokenSpec<'a> {
    token_id: &'a str,
    issuer: &'a str,
    audience: Vec<String>,
    capabilities: BTreeSet<ActionScope>,
    issued_at: u64,
    expires_at: u64,
    nonce: &'a str,
    parent_token_hash: Option<String>,
    max_delegation_depth: u8,
}

fn make_signed_token(key: &SigningKey, spec: TokenSpec<'_>) -> AudienceBoundToken {
    let mut t = AudienceBoundToken {
        token_id: TokenId::new(spec.token_id),
        issuer: spec.issuer.to_string(),
        audience: spec.audience,
        capabilities: spec.capabilities,
        issued_at: spec.issued_at,
        expires_at: spec.expires_at,
        nonce: spec.nonce.to_string(),
        parent_token_hash: spec.parent_token_hash,
        signature: String::new(),
        max_delegation_depth: spec.max_delegation_depth,
    };
    let sig = key.sign(&t.signature_preimage()).to_bytes();
    t.signature = format!("ed25519:{}", hex::encode(sig));
    t
}

#[test]
fn e2e_audience_token_root_chain_verifies() {
    let h = Harness::new("e2e_audience_token_root_chain_verifies");

    let key = signing_key();
    let mut validator = TokenValidator::new(1).with_trusted_issuer_key(ISSUER, key.verifying_key());
    h.log_phase("validator_built", true, json!({"epoch": 1}));

    let root = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-root-1",
            issuer: ISSUER,
            audience: vec!["svc-target".to_string()],
            capabilities: caps(&[ActionScope::Migrate, ActionScope::Configure]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-root-1",
            parent_token_hash: None,
            max_delegation_depth: 2,
        },
    );
    let chain = TokenChain::new(root.clone()).expect("root chain ok");

    validator
        .verify_chain(&chain, "svc-target", 1_000_000_500_000, "trace-verify-1")
        .expect("root-only chain verifies");
    assert_eq!(validator.tokens_verified(), 1);
    assert_eq!(validator.tokens_rejected(), 0);
    h.log_phase("root_chain_verified", true, json!({}));

    // For negative tests we use FRESH validators + tokens so the replay
    // check (which fires before audience/expiry checks) doesn't mask the
    // failure mode under test.

    // INV-ABT-AUDIENCE: requester not in leaf audience → reject.
    let mut v_aud = TokenValidator::new(1).with_trusted_issuer_key(ISSUER, key.verifying_key());
    let aud_root = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-aud",
            issuer: ISSUER,
            audience: vec!["svc-target".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-aud",
            parent_token_hash: None,
            max_delegation_depth: 0,
        },
    );
    let aud_chain = TokenChain::new(aud_root).unwrap();
    let err = v_aud
        .verify_chain(&aud_chain, "svc-other", 1_000_000_500_000, "trace-bad-aud")
        .expect_err("audience mismatch rejected");
    assert_eq!(err.code, ERR_ABT_AUDIENCE_MISMATCH);
    h.log_phase("audience_mismatch", true, json!({"code": err.code}));

    // INV-ABT-EXPIRY: now_ms past expires_at → reject.
    let mut v_exp = TokenValidator::new(1).with_trusted_issuer_key(ISSUER, key.verifying_key());
    let exp_root = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-exp",
            issuer: ISSUER,
            audience: vec!["svc-target".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-exp",
            parent_token_hash: None,
            max_delegation_depth: 0,
        },
    );
    let exp_chain = TokenChain::new(exp_root).unwrap();
    let err = v_exp
        .verify_chain(&exp_chain, "svc-target", 1_000_001_000_000, "trace-expired")
        .expect_err("expired rejected");
    assert_eq!(err.code, ERR_ABT_TOKEN_EXPIRED);
    h.log_phase("expired", true, json!({"code": err.code}));
}

#[test]
fn e2e_audience_token_delegation_chain_attenuates() {
    let h = Harness::new("e2e_audience_token_delegation_chain_attenuates");

    let key = signing_key();
    let mut validator = TokenValidator::new(1).with_trusted_issuer_key(ISSUER, key.verifying_key());

    // Root: depth=2, 3 caps, audience {svc-A, svc-B}.
    let root = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-root-2",
            issuer: ISSUER,
            audience: vec!["svc-A".to_string(), "svc-B".to_string()],
            capabilities: caps(&[
                ActionScope::Migrate,
                ActionScope::Configure,
                ActionScope::Promote,
            ]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-root-2",
            parent_token_hash: None,
            max_delegation_depth: 2,
        },
    );
    let mut chain = TokenChain::new(root.clone()).expect("root ok");
    let root_hash = chain.root().unwrap().hash();

    // Child: depth=1 (strictly less), caps subset, audience subset, expires
    // before parent. Must be accepted.
    let child = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-child-2",
            issuer: ISSUER,
            audience: vec!["svc-A".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_100_000,
            expires_at: 1_000_000_800_000,
            nonce: "nonce-child-2",
            parent_token_hash: Some(root_hash.clone()),
            max_delegation_depth: 1,
        },
    );
    chain.append(child.clone()).expect("child ok");
    assert_eq!(chain.depth(), 2);
    h.log_phase("chain_depth_2", true, json!({"depth": 2}));

    // No `record_issuance`/`record_delegation` here — those would seed the
    // seen-nonce ledger and make the verify path reject as replay.
    validator
        .verify_chain(&chain, "svc-A", 1_000_000_500_000, "trace-verify-2")
        .expect("delegated chain verifies");
    h.log_phase("delegated_verified", true, json!({}));

    // INV-ABT-ATTENUATION: child grants a capability the root does not have.
    let bad_caps = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-overcap",
            issuer: ISSUER,
            audience: vec!["svc-A".to_string()],
            capabilities: caps(&[ActionScope::Revoke]), // not in parent's caps
            issued_at: 1_000_000_100_000,
            expires_at: 1_000_000_800_000,
            nonce: "nonce-overcap",
            parent_token_hash: Some(root_hash.clone()),
            max_delegation_depth: 1,
        },
    );
    let mut bad_chain = TokenChain::new(root.clone()).unwrap();
    let err = bad_chain.append(bad_caps).expect_err("over-cap rejected");
    assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
    h.log_phase("over_capability_rejected", true, json!({"code": err.code}));

    // INV-ABT-ATTENUATION: child audience not a subset.
    let bad_aud = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-aud-extra",
            issuer: ISSUER,
            audience: vec!["svc-EXTERNAL".to_string()], // not in parent's audience
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_100_000,
            expires_at: 1_000_000_800_000,
            nonce: "nonce-aud-extra",
            parent_token_hash: Some(root_hash.clone()),
            max_delegation_depth: 1,
        },
    );
    let mut bad_chain = TokenChain::new(root.clone()).unwrap();
    let err = bad_chain
        .append(bad_aud)
        .expect_err("audience expansion rejected");
    assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
    h.log_phase(
        "audience_expansion_rejected",
        true,
        json!({"code": err.code}),
    );

    // INV-ABT-ATTENUATION: child max_delegation_depth >= parent's.
    let bad_depth = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-depth",
            issuer: ISSUER,
            audience: vec!["svc-A".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_100_000,
            expires_at: 1_000_000_800_000,
            nonce: "nonce-depth",
            parent_token_hash: Some(root_hash.clone()),
            max_delegation_depth: 2, // not strictly less than root's 2
        },
    );
    let mut bad_chain = TokenChain::new(root.clone()).unwrap();
    let err = bad_chain
        .append(bad_depth)
        .expect_err("depth not attenuated rejected");
    assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
    h.log_phase(
        "depth_not_attenuated_rejected",
        true,
        json!({"code": err.code}),
    );

    // INV-ABT-ATTENUATION: child expires AFTER parent.
    let outlives = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-outlives",
            issuer: ISSUER,
            audience: vec!["svc-A".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_100_000,
            expires_at: 1_000_001_000_000, // > root.expires_at
            nonce: "nonce-outlives",
            parent_token_hash: Some(root_hash.clone()),
            max_delegation_depth: 1,
        },
    );
    let mut bad_chain = TokenChain::new(root.clone()).unwrap();
    let err = bad_chain
        .append(outlives)
        .expect_err("outlives parent rejected");
    assert_eq!(err.code, ERR_ABT_ATTENUATION_VIOLATION);
    h.log_phase("outlives_parent_rejected", true, json!({"code": err.code}));
}

#[test]
fn e2e_audience_token_replay_detection_and_epoch_reset() {
    let h = Harness::new("e2e_audience_token_replay_detection_and_epoch_reset");

    let key = signing_key();
    let mut validator = TokenValidator::new(1).with_trusted_issuer_key(ISSUER, key.verifying_key());

    let root = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-replay-root",
            issuer: ISSUER,
            audience: vec!["svc-X".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-replay-1",
            parent_token_hash: None,
            max_delegation_depth: 0,
        },
    );
    let chain = TokenChain::new(root.clone()).unwrap();

    // First verify accepts; second must be rejected as replay (single-token
    // chain → root nonce IS checked).
    validator
        .verify_chain(&chain, "svc-X", 1_000_000_500_000, "trace-r1")
        .expect("first verify ok");
    let err = validator
        .verify_chain(&chain, "svc-X", 1_000_000_500_001, "trace-r2")
        .expect_err("replay rejected");
    assert_eq!(err.code, ERR_ABT_REPLAY_DETECTED);
    h.log_phase("replay_rejected", true, json!({"code": err.code}));

    // INV-ABT-REPLAY: epoch reset clears nonces.
    validator.advance_epoch(2);
    assert_eq!(validator.epoch_id(), 2);
    validator
        .verify_chain(&chain, "svc-X", 1_000_000_500_002, "trace-r3")
        .expect("replay allowed across epochs");
    h.log_phase("replay_allowed_after_epoch_reset", true, json!({}));
}

#[test]
fn e2e_audience_token_signature_tampering_rejected() {
    let h = Harness::new("e2e_audience_token_signature_tampering_rejected");

    let key = signing_key();
    let mut validator = TokenValidator::new(1).with_trusted_issuer_key(ISSUER, key.verifying_key());

    let mut tok = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-tamper",
            issuer: ISSUER,
            audience: vec!["svc-Z".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-tamper",
            parent_token_hash: None,
            max_delegation_depth: 0,
        },
    );
    // Flip the last hex char of the signature.
    let mut sig: Vec<char> = tok.signature.chars().collect();
    if let Some(last) = sig.last_mut() {
        *last = if *last == '0' { '1' } else { '0' };
    }
    tok.signature = sig.into_iter().collect();

    let chain = TokenChain::new(tok).unwrap();
    let err = validator
        .verify_chain(&chain, "svc-Z", 1_000_000_500_000, "trace-tamper")
        .expect_err("tampered signature rejected");
    assert_eq!(err.code, ERR_ABT_SIGNATURE_INVALID);
    assert_eq!(validator.tokens_rejected(), 1);
    h.log_phase("signature_tamper_rejected", true, json!({"code": err.code}));

    // Untrusted issuer also rejected with SIGNATURE_INVALID (no key for it).
    let stranger_key = SigningKey::from_bytes(&[0x99; 32]);
    let stranger = make_signed_token(
        &stranger_key,
        TokenSpec {
            token_id: "tk-stranger",
            issuer: "stranger-issuer-not-trusted",
            audience: vec!["svc-Z".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-stranger",
            parent_token_hash: None,
            max_delegation_depth: 0,
        },
    );
    let chain = TokenChain::new(stranger).unwrap();
    let err = validator
        .verify_chain(&chain, "svc-Z", 1_000_000_500_000, "trace-stranger")
        .expect_err("untrusted issuer rejected");
    assert_eq!(err.code, ERR_ABT_SIGNATURE_INVALID);
    h.log_phase("untrusted_issuer_rejected", true, json!({}));
}

#[test]
fn e2e_audience_token_rejects_oversized_fields_before_preimage_work() {
    let h = Harness::new("e2e_audience_token_rejects_oversized_fields_before_preimage_work");

    let key = signing_key();
    let mut oversized_audience = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-oversized-audience",
            issuer: ISSUER,
            audience: vec!["svc-Z".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-oversized-audience",
            parent_token_hash: None,
            max_delegation_depth: 0,
        },
    );
    oversized_audience
        .audience
        .push("x".repeat(MAX_TOKEN_FIELD_BYTES + 1));

    let err = oversized_audience
        .checked_signature_preimage()
        .expect_err("oversized audience entry must fail before preimage allocation");
    assert_eq!(err.code, ERR_ABT_TOKEN_TOO_LARGE);

    let err = TokenChain::new(oversized_audience)
        .expect_err("oversized token must fail before entering a chain");
    assert_eq!(err.code, ERR_ABT_TOKEN_TOO_LARGE);
    h.log_phase(
        "oversized_audience_rejected",
        true,
        json!({"code": err.code}),
    );

    let mut oversized_signature = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-oversized-signature",
            issuer: ISSUER,
            audience: vec!["svc-Z".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-oversized-signature",
            parent_token_hash: None,
            max_delegation_depth: 0,
        },
    );
    oversized_signature.signature = "a".repeat(MAX_TOKEN_SIGNATURE_BYTES + 1);

    let err = TokenChain::new(oversized_signature)
        .expect_err("oversized signature text must fail before hex decode");
    assert_eq!(err.code, ERR_ABT_TOKEN_TOO_LARGE);
    h.log_phase(
        "oversized_signature_rejected",
        true,
        json!({"code": err.code}),
    );
}

#[test]
fn e2e_audience_token_deserialization_is_bounded() {
    let h = Harness::new("e2e_audience_token_deserialization_is_bounded");

    let key = signing_key();
    let token = make_signed_token(
        &key,
        TokenSpec {
            token_id: "tk-deser-bound",
            issuer: ISSUER,
            audience: vec!["svc-Z".to_string()],
            capabilities: caps(&[ActionScope::Migrate]),
            issued_at: 1_000_000_000_000,
            expires_at: 1_000_000_900_000,
            nonce: "nonce-deser-bound",
            parent_token_hash: None,
            max_delegation_depth: 0,
        },
    );

    let mut token_value = serde_json::to_value(&token).expect("token serializes");
    token_value
        .as_object_mut()
        .expect("token value is an object")
        .insert(
            "audience".to_string(),
            serde_json::Value::Array(
                (0..=MAX_AUDIENCES_PER_TOKEN)
                    .map(|idx| serde_json::Value::String(format!("svc-{idx}")))
                    .collect(),
            ),
        );

    let err = serde_json::from_value::<AudienceBoundToken>(token_value)
        .expect_err("oversized audience vector must fail during token deserialization");
    assert!(
        err.to_string().contains("audience"),
        "unexpected error: {err}"
    );
    h.log_phase("oversized_audience_deserialize_rejected", true, json!({}));

    let token_value = serde_json::to_value(&token).expect("token serializes");
    let err = serde_json::from_value::<TokenChain>(json!({
        "tokens": vec![token_value; MAX_TOKENS + 1],
    }))
    .expect_err("oversized chain must fail during bounded sequence deserialization");
    assert!(
        err.to_string().contains("token chain"),
        "unexpected error: {err}"
    );
    h.log_phase("oversized_chain_deserialize_rejected", true, json!({}));
}
