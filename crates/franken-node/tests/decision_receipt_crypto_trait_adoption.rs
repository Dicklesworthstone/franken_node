//! Regression coverage for decision-receipt adoption of the crypto trait raw path.
//!
//! `sign_receipt` / `verify_receipt` now route signing and verification through
//! `frankenengine_node::crypto::Ed25519Scheme::{sign_raw, verify_raw}` instead
//! of calling `SigningKey::sign` / `VerifyingKey::verify_strict` directly. The
//! migration must be a no-op on the wire: picking `sign_with_domain` instead
//! of `sign_raw` would prepend a wrapper digest and invalidate every signed
//! `Receipt` already issued, plus every checked-in golden. These tests are
//! the regression harness for that decision.
//!
//! Bead: bd-dwx4l (parent design: docs/specs/crypto_trait_abstraction.md).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use frankenengine_node::crypto::{Ed25519Scheme, SignatureScheme};
use frankenengine_node::security::blake3_adapter::{HashProvider, Sha2HmacProvider};
use frankenengine_node::security::decision_receipt::{
    Decision, Receipt, sign_receipt, verify_receipt,
};
use serde::Serialize;
use serde_json::{Value, json};

const PRE_MIGRATION_CANONICAL_RECEIPT_JSON: &str = concat!(
    r#"{"action_name":"quarantine_extension","actor_identity":"security-admin@franken-node.prod","#,
    r#""audience":"franken-node-control-plane","confidence":4605831338911806259,"decision":"approved","#,
    r#""evidence_refs":["evidence:network-anomaly-detector:2026-001","#,
    r#""evidence:behavioral-analysis:ext-scan-001","evidence:reputation-feed:threat-intel-db"],"#,
    r#""input_hash":"31649fb432998b8ee5f377ab7687c1d07a7bb993702799450c6f29af56a717aa","#,
    r#""nonce":"abcdef0123456789abcdef0123456789","#,
    r#""output_hash":"b1a29a5203c018b0ffce53cb944ee5a347d326d6204a07b9f1c07a56b0f2b1f2","#,
    r#""policy_rule_chain":["policy:network-egress-monitoring","policy:behavioral-reputation-gate","#,
    r#""policy:quarantine-on-threat-match"],"previous_receipt_hash":"previous-receipt-hash-abc123def456","#,
    r#""rationale":"Extension exhibits suspicious network behavior patterns consistent with data exfiltration","#,
    r#""receipt_id":"01234567-89ab-cdef-0123-456789abcdef","#,
    r#""rollback_command":"franken-node trust release --extension npm:@malware/data-stealer --audit-id AUD-2026-001","#,
    r#""signature_version":"ed25519-v1","timestamp":"2026-01-01T00:00:00Z"}"#
);

fn deterministic_receipt() -> Receipt {
    let input_data = json!({
        "extension_id": "npm:@malware/data-stealer",
        "action": "quarantine"
    });
    let output_data = json!({
        "status": "quarantined",
        "affected_nodes": 42
    });

    let mut receipt = Receipt::new(
        "quarantine_extension",
        "security-admin@franken-node.prod",
        "franken-node-control-plane",
        &input_data,
        &output_data,
        Decision::Approved,
        "Extension exhibits suspicious network behavior patterns consistent with data exfiltration",
        vec![
            "evidence:network-anomaly-detector:2026-001".to_string(),
            "evidence:behavioral-analysis:ext-scan-001".to_string(),
            "evidence:reputation-feed:threat-intel-db".to_string(),
        ],
        vec![
            "policy:network-egress-monitoring".to_string(),
            "policy:behavioral-reputation-gate".to_string(),
            "policy:quarantine-on-threat-match".to_string(),
        ],
        0.85,
        "franken-node trust release --extension npm:@malware/data-stealer --audit-id AUD-2026-001",
    )
    .expect("deterministic receipt should build");

    // Override the non-deterministic fields so the canonical preimage is
    // stable across runs (receipt_id / timestamp / nonce are otherwise
    // generated from clock + RNG at `Receipt::new` time).
    receipt.receipt_id = "01234567-89ab-cdef-0123-456789abcdef".to_string();
    receipt.timestamp = "2026-01-01T00:00:00Z".to_string();
    receipt.nonce = "abcdef0123456789abcdef0123456789".to_string();
    receipt.previous_receipt_hash = Some("previous-receipt-hash-abc123def456".to_string());
    receipt
}

fn fresh_receipt() -> Receipt {
    Receipt::new(
        "quarantine_extension",
        "security-admin@franken-node.prod",
        "franken-node-control-plane",
        &json!({
            "extension_id": "npm:@malware/data-stealer",
            "action": "quarantine"
        }),
        &json!({
            "status": "quarantined",
            "affected_nodes": 42
        }),
        Decision::Approved,
        "Extension exhibits suspicious network behavior patterns consistent with data exfiltration",
        vec![
            "evidence:network-anomaly-detector:2026-001".to_string(),
            "evidence:behavioral-analysis:ext-scan-001".to_string(),
            "evidence:reputation-feed:threat-intel-db".to_string(),
        ],
        vec![
            "policy:network-egress-monitoring".to_string(),
            "policy:behavioral-reputation-gate".to_string(),
            "policy:quarantine-on-threat-match".to_string(),
        ],
        0.85,
        "franken-node trust release --extension npm:@malware/data-stealer --audit-id AUD-2026-001",
    )
    .expect("fresh receipt should build")
}

fn sha2_domain_keyed_hash(domain: &str, key: &[u8], data: &[u8]) -> [u8; 32] {
    let provider = Sha2HmacProvider;
    let domain_key = provider.hash_domain_key_material(domain, key);
    provider.keyed_hash(&domain_key, data)
}

#[test]
fn hash_adapter_domain_key_material_framing_is_metamorphic() {
    let provider = Sha2HmacProvider;
    let left_flat = [b"ab".as_slice(), b"c".as_slice()].concat();
    let right_flat = [b"a".as_slice(), b"bc".as_slice()].concat();
    assert_eq!(
        left_flat, right_flat,
        "test setup must exercise the same unframed byte stream"
    );

    let left_key = provider.hash_domain_key_material("ab", b"c");
    let right_key = provider.hash_domain_key_material("a", b"bc");
    assert_ne!(
        left_key, right_key,
        "length-prefixed domain-key material must reject ambiguous framing"
    );

    let data = b"signed decision receipt transcript";
    assert_ne!(
        sha2_domain_keyed_hash("ab", b"c", data),
        sha2_domain_keyed_hash("a", b"bc", data),
        "ambiguous domain/key splits must not replay to the same keyed digest"
    );
}

#[test]
fn hash_adapter_domain_keyed_output_binds_each_input_axis_metamorphically() {
    let cases: &[(&str, &[u8], &[u8])] = &[
        (
            "security/decision-receipt",
            b"primary signing key",
            b"canonical receipt payload",
        ),
        (
            "security/artifact-manifest",
            b"artifact signer key",
            b"artifact manifest bytes",
        ),
        (
            "security/replay-bundle",
            b"replay verifier key",
            b"bundle transcript bytes",
        ),
    ];

    for (domain, key, data) in cases {
        let baseline = sha2_domain_keyed_hash(domain, key, data);
        assert_eq!(
            baseline,
            sha2_domain_keyed_hash(domain, key, data),
            "domain-keyed hash must be deterministic for {domain}"
        );

        let shifted_domain = format!("{domain}/rotated");
        let mut shifted_key = key.to_vec();
        shifted_key.extend_from_slice(b":rotated");
        let mut shifted_data = data.to_vec();
        shifted_data.extend_from_slice(b":tampered");

        for (axis, mutated) in [
            ("domain", sha2_domain_keyed_hash(&shifted_domain, key, data)),
            ("key", sha2_domain_keyed_hash(domain, &shifted_key, data)),
            (
                "payload",
                sha2_domain_keyed_hash(domain, key, &shifted_data),
            ),
        ] {
            assert_ne!(
                baseline, mutated,
                "changing the {axis} axis must change the domain-keyed digest for {domain}"
            );
        }
    }
}

/// Mirror of the private `decision_receipt::canonical_json`. Drift between
/// this helper and the production canonicalizer surfaces as a signature
/// mismatch in the test below; that divergence is the on-the-wire compat
/// break this test exists to catch.
fn canonical_json(value: &impl Serialize) -> String {
    let serialized = serde_json::to_value(value).expect("receipt should serialize");
    let canonicalized = canonicalize_value(serialized);
    serde_json::to_string(&canonicalized).expect("canonical receipt should serialize")
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            let mut canonical_map = serde_json::Map::with_capacity(entries.len());
            for (key, nested) in entries {
                canonical_map.insert(key, canonicalize_value(nested));
            }
            Value::Object(canonical_map)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        scalar => scalar,
    }
}

/// Load-bearing on-the-wire compatibility check.
///
/// Post-migration `sign_receipt` (which routes through
/// `Ed25519Scheme::sign_raw`) MUST produce byte-identical signature bytes
/// to a pre-migration direct `SigningKey::sign(canonical_preimage)`. If this
/// ever fails, every signed `Receipt` already in the wild and every
/// checked-in decision-receipt golden has just been invalidated by the
/// change under test.
#[test]
fn decision_receipt_trait_raw_path_preserves_legacy_signature_bytes() {
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let public_key = signing_key.verifying_key();
    let receipt = deterministic_receipt();
    let canonical_receipt = canonical_json(&receipt);
    assert_eq!(canonical_receipt, PRE_MIGRATION_CANONICAL_RECEIPT_JSON);

    // Path A: trait-routed (post-migration `sign_receipt`).
    let signed = sign_receipt(&receipt, &signing_key).expect("trait-mediated sign should work");
    let mut trait_signature_bytes = [0_u8; 64];
    let decoded_len = BASE64_STANDARD
        .decode_slice(&signed.signature, &mut trait_signature_bytes)
        .expect("signature should be base64");
    assert_eq!(decoded_len, trait_signature_bytes.len());

    // Path B: direct ed25519-dalek sign over the canonical preimage
    // (this is what pre-migration `sign_receipt` did internally).
    let legacy_direct_signature = signing_key.sign(canonical_receipt.as_bytes()).to_bytes();

    assert_eq!(signed.receipt, receipt);
    assert_eq!(
        trait_signature_bytes.as_slice(),
        legacy_direct_signature.as_slice(),
        "post-migration sign_receipt must produce byte-identical signatures \
         to a direct ed25519_dalek SigningKey::sign over the canonical \
         preimage; otherwise every existing signed receipt in the wild and \
         every checked-in golden is invalidated by this change",
    );

    // Cross-check: the trait verifier accepts the signature.
    let signature_array =
        Ed25519Scheme::signature_from_bytes(&trait_signature_bytes).expect("signature bytes");
    assert!(Ed25519Scheme::verify_raw(
        public_key.as_bytes(),
        canonical_receipt.as_bytes(),
        &signature_array
    ));

    // And direct ed25519-dalek strict-verify accepts the same bytes,
    // closing the byte-identity circle.
    let sig = Signature::try_from(&trait_signature_bytes[..]).expect("64-byte signature");
    public_key
        .verify_strict(canonical_receipt.as_bytes(), &sig)
        .expect("direct ed25519-dalek strict verify must accept the trait-emitted signature");
}

/// `verify_receipt` (post-migration, trait-routed) must accept signatures
/// produced by the production `sign_receipt`. Happy-path regression for the
/// migrated verifier surface.
#[test]
fn verify_receipt_accepts_trait_routed_sign_receipt_output() {
    let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let public_key = signing_key.verifying_key();
    let receipt = fresh_receipt();

    let signed = sign_receipt(&receipt, &signing_key).expect("sign_receipt must succeed");
    assert!(
        verify_receipt(&signed, &public_key).expect("verify_receipt must not error"),
        "verify_receipt must accept signatures produced by sign_receipt; \
         a regression here means the migration broke its own happy path",
    );
}

/// Guard against a well-meaning later refactor that swaps `sign_raw` for
/// `sign_with_domain` in `sign_receipt`. The wrapper domain prepends extra
/// bytes (`b"ed25519_signature_v1:" || len(domain) || domain || len(msg) || msg`,
/// then hashes the lot) before signing. A signature produced that way must
/// NOT verify against the canonical preimage under any of the verifier
/// paths, otherwise the trait abstraction no longer protects callers from
/// double-domain bugs.
#[test]
fn verify_receipt_rejects_wrapper_domain_signatures() {
    let signing_key = SigningKey::from_bytes(&[77_u8; 32]);
    let public_key = signing_key.verifying_key();
    let receipt = deterministic_receipt();
    let canonical_receipt = canonical_json(&receipt);

    // Sign through the WRAPPING surface (the bug we are guarding against).
    let wrapped_sig_bytes = Ed25519Scheme::sign_with_domain(
        &signing_key.to_bytes(),
        b"decision_receipt",
        canonical_receipt.as_bytes(),
    )
    .expect("sign_with_domain must succeed");

    // Direct strict-verify of the wrapped bytes against the canonical
    // preimage must fail; the wrapper-hashed digest is a different message.
    let sig = Signature::try_from(&wrapped_sig_bytes[..]).expect("64-byte signature");
    assert!(
        public_key
            .verify_strict(canonical_receipt.as_bytes(), &sig)
            .is_err(),
        "direct strict-verify must reject sign_with_domain-produced bytes over the canonical preimage",
    );
    assert!(
        !Ed25519Scheme::verify_raw(
            public_key.as_bytes(),
            canonical_receipt.as_bytes(),
            &wrapped_sig_bytes
        ),
        "Ed25519Scheme::verify_raw must reject sign_with_domain-produced bytes over the canonical preimage",
    );
}
