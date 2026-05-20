//! Regression coverage for decision-receipt adoption of the crypto trait raw path.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use frankenengine_node::crypto::{Ed25519Scheme, SignatureScheme};
use frankenengine_node::security::decision_receipt::{Decision, Receipt, sign_receipt};
use serde::Serialize;
use serde_json::{Value, json};

const PRE_MIGRATION_CANONICAL_RECEIPT_JSON: &str = concat!(
    r#"{"action_name":"quarantine_extension","actor_identity":"security-admin@franken-node.prod","#,
    r#""audience":"franken-node-control-plane","confidence":4605831338911806259,"decision":"approved","#,
    r#""evidence_refs":["evidence:network-anomaly-detector:2026-001","#,
    r#""evidence:behavioral-analysis:ext-scan-001","evidence:reputation-feed:threat-intel-db"],"#,
    r#""input_hash":"b406a1844ee3152574a7ed4dd0d4511dfc4736bbe57c2c9f1f8ea22c721cfb48","#,
    r#""nonce":"abcdef0123456789abcdef0123456789","#,
    r#""output_hash":"13b470cfbc16a0b6a94a7f39fc91a1b54f52bfad71e510d6d1e64f973b371452","#,
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

    receipt.receipt_id = "01234567-89ab-cdef-0123-456789abcdef".to_string();
    receipt.timestamp = "2026-01-01T00:00:00Z".to_string();
    receipt.nonce = "abcdef0123456789abcdef0123456789".to_string();
    receipt.previous_receipt_hash = Some("previous-receipt-hash-abc123def456".to_string());
    receipt
}

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

#[test]
fn decision_receipt_trait_raw_path_preserves_legacy_signature_bytes() {
    let receipt = deterministic_receipt();
    let canonical_receipt = canonical_json(&receipt);
    assert_eq!(canonical_receipt, PRE_MIGRATION_CANONICAL_RECEIPT_JSON);

    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let signed = sign_receipt(&receipt, &signing_key).expect("trait-mediated sign should work");
    let legacy_direct_signature = signing_key.sign(canonical_receipt.as_bytes()).to_bytes();

    assert_eq!(signed.receipt, receipt);
    assert_eq!(
        signed.signature,
        BASE64_STANDARD.encode(legacy_direct_signature)
    );

    let signature_array =
        Ed25519Scheme::signature_from_bytes(&legacy_direct_signature).expect("signature bytes");
    let public_key = signing_key.verifying_key();
    assert!(Ed25519Scheme::verify_raw(
        public_key.as_bytes(),
        canonical_receipt.as_bytes(),
        &signature_array
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        public_key.as_bytes(),
        b"decision_receipt",
        canonical_receipt.as_bytes(),
        &signature_array
    ));
}
