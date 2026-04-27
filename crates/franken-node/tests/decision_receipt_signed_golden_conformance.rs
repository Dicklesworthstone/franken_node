//! Golden-vector conformance harness for signed decision receipt encoding.
//!
//! Coverage matrix:
//! - MUST: canonical receipt JSON stays byte-stable for representative signed receipts
//! - MUST: signer key id, chain hash, and detached signature stay stable for golden inputs
//! - MUST: live signatures verify against the canonical payload committed by the golden vector
//! - MUST: chained receipts preserve append-only linkage through `previous_receipt_hash`

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signature, SigningKey, Verifier};
use frankenengine_node::security::decision_receipt::{
    DECISION_RECEIPT_SIGNATURE_VERSION, Decision, Receipt, SignedReceipt, sign_receipt,
    signing_key_id, verify_hash_chain,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const EXPECTED_GOLDEN_VECTORS_JSON: &str = r#"[
  {
    "name": "quarantine_release_genesis",
    "canonical_receipt_json": "{\"action_name\":\"fleet_quarantine_release\",\"actor_identity\":\"operator://control-plane\",\"audience\":\"fleet://prod-us-east\",\"confidence\":4606056518893174784,\"decision\":\"approved\",\"evidence_refs\":[\"evidence://incidents/INC-2026-0042/review.md\",\"receipt://fleet/reconcile/2026-04-26T23:40:00Z\"],\"input_hash\":\"fd4ca1cd64bdec77ef764e9f329cadfbe2fd6c512d9272a07088f766fcfbb037\",\"nonce\":\"nonce-golden-genesis-0001\",\"output_hash\":\"01e104c6a62d52a5c91f09775db4232c1302950e79c7835447659aa0131a1337\",\"policy_rule_chain\":[\"policy://fleet/quarantine/release\",\"policy://trust/freshness\"],\"previous_receipt_hash\":null,\"rationale\":\"Independent review cleared the quarantine after containment verification.\",\"receipt_id\":\"11111111-2222-7333-8444-555555555555\",\"rollback_command\":\"franken-node fleet release --incident INC-2026-0042 --zone prod-us-east\",\"signature_version\":\"ed25519-v1\",\"timestamp\":\"2026-04-26T23:40:00Z\"}",
    "signer_key_id": "fa3d2da5de1cf42b",
    "chain_hash": "ab8a64fce7fbccd24bf29b362d883026d10b5f92fdaf7d35012d524db8dfd54a",
    "signature": "NZqU/Jfl+mZXxdrwBks8L4yabWe+phX3oZ0R8ixu6pApitpYgp6SpMj9v2Fc6/humZI3qtEt5unnudy4doj+DQ=="
  },
  {
    "name": "quarantine_release_followup",
    "canonical_receipt_json": "{\"action_name\":\"fleet_quarantine_release\",\"actor_identity\":\"operator://control-plane\",\"audience\":\"fleet://prod-us-east\",\"confidence\":4603804719079489536,\"decision\":\"approved\",\"evidence_refs\":[\"evidence://incidents/INC-2026-0042/followup.md\",\"receipt://fleet/reconcile/2026-04-26T23:45:00Z\"],\"input_hash\":\"e9c9b5a96e56187fbfe1d6699143e7e99e7f4e43e1fab04d9dd240898ba1b6fd\",\"nonce\":\"nonce-golden-followup-0002\",\"output_hash\":\"f7a61ced5c27b7489ec62b162eed958aa0c2b921b1e4454df88602dffd727dd4\",\"policy_rule_chain\":[\"policy://fleet/quarantine/release\",\"policy://fleet/drift-check\"],\"previous_receipt_hash\":\"ab8a64fce7fbccd24bf29b362d883026d10b5f92fdaf7d35012d524db8dfd54a\",\"rationale\":\"Follow-up release completed after the final drift checks passed.\",\"receipt_id\":\"66666666-7777-7888-8999-aaaaaaaaaaaa\",\"rollback_command\":\"franken-node fleet status --zone prod-us-east --json\",\"signature_version\":\"ed25519-v1\",\"timestamp\":\"2026-04-26T23:45:00Z\"}",
    "signer_key_id": "fa3d2da5de1cf42b",
    "chain_hash": "0d627311a4b22285abd0f2b5910f88cba644ed35470ed182f21f74182c1c3695",
    "signature": "4Ic1tIXemZoP8I8ihGSexKb+bLtEIZYm7iJnWm3uz2B2D9/CgZwu5RBYhZsB1jS2LjIO60zl3OanuLXBwyW8DQ=="
  }
]"#;

#[derive(Debug, Clone)]
struct LiveVector {
    name: &'static str,
    receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GoldenVector {
    name: String,
    canonical_receipt_json: String,
    signer_key_id: String,
    chain_hash: String,
    signature: String,
}

fn conformance_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[13_u8; 32])
}

fn make_receipt(
    action_name: &str,
    actor_identity: &str,
    audience: &str,
    input: Value,
    output: Value,
    decision: Decision,
    rationale: &str,
    evidence_refs: Vec<&str>,
    policy_rule_chain: Vec<&str>,
    confidence: f64,
    rollback_command: &str,
    receipt_id: &str,
    timestamp: &str,
    nonce: &str,
) -> Receipt {
    let mut receipt = Receipt::new(
        action_name,
        actor_identity,
        audience,
        &input,
        &output,
        decision,
        rationale,
        evidence_refs.into_iter().map(str::to_string).collect(),
        policy_rule_chain.into_iter().map(str::to_string).collect(),
        confidence,
        rollback_command,
    )
    .expect("golden receipt inputs must be valid");
    receipt.receipt_id = receipt_id.to_string();
    receipt.timestamp = timestamp.to_string();
    receipt.nonce = nonce.to_string();
    receipt
}

fn live_vectors() -> Vec<LiveVector> {
    vec![
        LiveVector {
            name: "quarantine_release_genesis",
            receipt: make_receipt(
                "fleet_quarantine_release",
                "operator://control-plane",
                "fleet://prod-us-east",
                json!({
                    "zone": "prod-us-east",
                    "extensions": ["npm:@acme/payments", "npm:@acme/search"],
                    "risk_score_micros": 912_500,
                    "incident_id": "INC-2026-0042"
                }),
                json!({
                    "status": "released",
                    "released_nodes": 17,
                    "quarantine_epoch": 44
                }),
                Decision::Approved,
                "Independent review cleared the quarantine after containment verification.",
                vec![
                    "evidence://incidents/INC-2026-0042/review.md",
                    "receipt://fleet/reconcile/2026-04-26T23:40:00Z",
                ],
                vec![
                    "policy://fleet/quarantine/release",
                    "policy://trust/freshness",
                ],
                0.875,
                "franken-node fleet release --incident INC-2026-0042 --zone prod-us-east",
                "11111111-2222-7333-8444-555555555555",
                "2026-04-26T23:40:00Z",
                "nonce-golden-genesis-0001",
            ),
        },
        LiveVector {
            name: "quarantine_release_followup",
            receipt: make_receipt(
                "fleet_quarantine_release",
                "operator://control-plane",
                "fleet://prod-us-east",
                json!({
                    "zone": "prod-us-east",
                    "extensions": ["npm:@acme/search"],
                    "risk_score_micros": 318_000,
                    "incident_id": "INC-2026-0042",
                    "followup": true
                }),
                json!({
                    "status": "released",
                    "released_nodes": 3,
                    "quarantine_epoch": 45
                }),
                Decision::Approved,
                "Follow-up release completed after the final drift checks passed.",
                vec![
                    "evidence://incidents/INC-2026-0042/followup.md",
                    "receipt://fleet/reconcile/2026-04-26T23:45:00Z",
                ],
                vec![
                    "policy://fleet/quarantine/release",
                    "policy://fleet/drift-check",
                ],
                0.625,
                "franken-node fleet status --zone prod-us-east --json",
                "66666666-7777-7888-8999-aaaaaaaaaaaa",
                "2026-04-26T23:45:00Z",
                "nonce-golden-followup-0002",
            ),
        },
    ]
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));

            let mut canonical = serde_json::Map::with_capacity(entries.len());
            for (key, nested) in entries {
                canonical.insert(key, canonicalize_value(nested));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn canonical_json(value: &impl Serialize) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|err| format!("serialize canonical value: {err}"))?;
    serde_json::to_string(&canonicalize_value(value))
        .map_err(|err| format!("encode canonical json: {err}"))
}

fn compute_chain_hash(previous_hash: Option<&str>, payload: &str) -> String {
    let previous = previous_hash.unwrap_or("GENESIS");
    let mut hasher = Sha256::new();
    hasher.update(b"decision_receipt_chain_v1:");
    hasher.update(u64::try_from(previous.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(previous.as_bytes());
    hasher.update(u64::try_from(payload.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

fn materialize_signed_vectors() -> Result<Vec<(GoldenVector, SignedReceipt)>, String> {
    let signing_key = conformance_signing_key();
    let mut vectors = live_vectors();
    let mut signed = Vec::with_capacity(vectors.len());

    for index in 0..vectors.len() {
        if index > 0 {
            let previous_hash = signed[index - 1].chain_hash.clone();
            vectors[index].receipt.previous_receipt_hash = Some(previous_hash);
        }

        signed.push(
            sign_receipt(&vectors[index].receipt, &signing_key)
                .map_err(|err| format!("sign {}: {err}", vectors[index].name))?,
        );
    }

    let goldens = signed
        .iter()
        .zip(vectors.iter())
        .map(|(signed, vector)| {
            Ok((
                GoldenVector {
                    name: vector.name.to_string(),
                    canonical_receipt_json: canonical_json(&signed.receipt)?,
                    signer_key_id: signed.signer_key_id.clone(),
                    chain_hash: signed.chain_hash.clone(),
                    signature: signed.signature.clone(),
                },
                signed.clone(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(goldens)
}

fn expected_golden_vectors() -> Result<Vec<GoldenVector>, String> {
    serde_json::from_str(EXPECTED_GOLDEN_VECTORS_JSON)
        .map_err(|err| format!("parse expected golden vectors: {err}"))
}

#[test]
fn decision_receipt_signed_golden_vectors_conformance() -> Result<(), String> {
    let actual_pairs = materialize_signed_vectors()?;
    let actual_vectors: Vec<GoldenVector> = actual_pairs.iter().map(|(golden, _)| golden.clone()).collect();

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        let rendered = serde_json::to_string_pretty(&actual_vectors)
            .map_err(|err| format!("render actual golden vectors: {err}"))?;
        println!("DECISION_RECEIPT_SIGNED_GOLDEN_VECTORS={rendered}");
        return Ok(());
    }

    let expected_vectors = expected_golden_vectors()?;
    if expected_vectors.is_empty() {
        return Err(
            "expected golden vectors are empty; rerun with UPDATE_GOLDENS=1 and commit reviewed vectors"
                .to_string(),
        );
    }
    if actual_vectors != expected_vectors {
        return Err(format!(
            "signed decision receipt golden drift detected\nexpected={}\nactual={}",
            serde_json::to_string_pretty(&expected_vectors)
                .map_err(|err| format!("render expected vectors: {err}"))?,
            serde_json::to_string_pretty(&actual_vectors)
                .map_err(|err| format!("render actual vectors: {err}"))?
        ));
    }

    let signing_key = conformance_signing_key();
    let public_key = signing_key.verifying_key();
    let expected_key_id = signing_key_id(&public_key);
    let signed_receipts: Vec<SignedReceipt> = actual_pairs
        .iter()
        .map(|(_, signed)| signed.clone())
        .collect();

    verify_hash_chain(&signed_receipts).map_err(|err| format!("verify receipt hash chain: {err}"))?;

    for (golden, signed) in &actual_pairs {
        if signed.receipt.signature_version != DECISION_RECEIPT_SIGNATURE_VERSION {
            return Err(format!(
                "{} signature_version drifted: expected {}, got {}",
                golden.name, DECISION_RECEIPT_SIGNATURE_VERSION, signed.receipt.signature_version
            ));
        }
        if signed.signer_key_id != expected_key_id {
            return Err(format!(
                "{} signer key id drifted: expected {}, got {}",
                golden.name, expected_key_id, signed.signer_key_id
            ));
        }

        let payload = canonical_json(&signed.receipt)?;
        if payload != golden.canonical_receipt_json {
            return Err(format!(
                "{} canonical receipt payload drifted",
                golden.name
            ));
        }

        let expected_chain_hash =
            compute_chain_hash(signed.receipt.previous_receipt_hash.as_deref(), &payload);
        if signed.chain_hash != expected_chain_hash {
            return Err(format!(
                "{} chain hash drifted: expected {}, got {}",
                golden.name, expected_chain_hash, signed.chain_hash
            ));
        }

        let signature_bytes = BASE64_STANDARD
            .decode(&signed.signature)
            .map_err(|err| format!("decode {} signature: {err}", golden.name))?;
        if signature_bytes.len() != 64 {
            return Err(format!(
                "{} signature length drifted: expected 64 bytes, got {}",
                golden.name,
                signature_bytes.len()
            ));
        }
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| format!("{} signature bytes are malformed", golden.name))?;
        public_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|err| format!("verify {} detached signature: {err}", golden.name))?;
    }

    Ok(())
}
