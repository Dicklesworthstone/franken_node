//! Signed decision receipts for high-impact policy/control actions (bd-21z).
//!
//! This module provides:
//! - Deterministic receipt payload hashing (`SHA-256`)
//! - Ed25519 detached signing/verification over canonical JSON
//! - Append-only hash-chain linkage for tamper evidence
//! - JSON + CBOR export/import and query filtering
//! - High-impact action receipt enforcement

use std::collections::BTreeSet;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub type Ed25519PrivateKey = SigningKey;
pub type Ed25519PublicKey = VerifyingKey;

/// High-impact decision classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Denied,
    Escalated,
}

/// Unsigned receipt payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub action_name: String,
    pub actor_identity: String,
    pub timestamp: String,
    pub input_hash: String,
    pub output_hash: String,
    pub decision: Decision,
    pub rationale: String,
    pub evidence_refs: Vec<String>,
    pub policy_rule_chain: Vec<String>,
    pub confidence: f64,
    pub rollback_command: String,
    pub previous_receipt_hash: Option<String>,
}

/// Signed receipt with hash-chain evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedReceipt {
    #[serde(flatten)]
    pub receipt: Receipt,
    pub chain_hash: String,
    pub signature: String,
}

/// Query filter for exporting receipt subsets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptQuery {
    pub action_name: Option<String>,
    pub from_timestamp: Option<String>,
    pub to_timestamp: Option<String>,
    pub limit: Option<usize>,
}

/// Runtime registry for actions that require receipts.
#[derive(Debug, Clone, Default)]
pub struct HighImpactActionRegistry {
    actions: BTreeSet<String>,
}

/// Errors for receipt processing.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("failed to serialize canonical JSON: {0}")]
    CanonicalJson(serde_json::Error),
    #[error("failed to encode receipts as JSON: {0}")]
    JsonEncode(serde_json::Error),
    #[error("failed to encode receipts as CBOR: {0}")]
    CborEncode(serde_cbor::Error),
    #[error("failed to decode receipts from CBOR: {0}")]
    CborDecode(serde_cbor::Error),
    #[error("failed to decode signature: {0}")]
    SignatureDecode(base64::DecodeError),
    #[error("invalid Ed25519 signature bytes")]
    SignatureBytes,
    #[error("failed to parse timestamp '{timestamp}': {source}")]
    TimestampParse {
        timestamp: String,
        source: chrono::ParseError,
    },
    #[error("high-impact action '{action_name}' requires a signed receipt")]
    MissingHighImpactReceipt { action_name: String },
    #[error("hash-chain mismatch: expected {expected}, got {actual}")]
    HashChainMismatch { expected: String, actual: String },
    #[error("failed to write receipt export to {path}: {source}")]
    WriteFailed {
        path: String,
        source: std::io::Error,
    },
}

impl Receipt {
    /// Construct a new receipt with canonical input/output hashes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_name: &str,
        actor_identity: &str,
        input: &impl Serialize,
        output: &impl Serialize,
        decision: Decision,
        rationale: &str,
        evidence_refs: Vec<String>,
        policy_rule_chain: Vec<String>,
        confidence: f64,
        rollback_command: &str,
    ) -> Result<Self, ReceiptError> {
        Ok(Self {
            receipt_id: Uuid::now_v7().to_string(),
            action_name: action_name.to_string(),
            actor_identity: actor_identity.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            input_hash: hash_canonical_json(input)?,
            output_hash: hash_canonical_json(output)?,
            decision,
            rationale: rationale.to_string(),
            evidence_refs,
            policy_rule_chain,
            confidence,
            rollback_command: rollback_command.to_string(),
            previous_receipt_hash: None,
        })
    }

    /// Attach previous hash link for append-only chain usage.
    pub fn with_previous_hash(mut self, previous_receipt_hash: Option<String>) -> Self {
        self.previous_receipt_hash = previous_receipt_hash;
        self
    }
}

impl HighImpactActionRegistry {
    /// Registry with default high-impact action classes from the bead contract.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut registry = Self::default();
        for action in [
            "quarantine",
            "revocation",
            "policy_change",
            "deployment_promotion",
            "trust_level_transition",
        ] {
            registry.register(action);
        }
        registry
    }

    pub fn register(&mut self, action_name: &str) {
        self.actions.insert(action_name.to_string());
    }

    #[must_use]
    pub fn is_high_impact(&self, action_name: &str) -> bool {
        self.actions.contains(action_name)
    }
}

/// Enforce that high-impact actions produce signed receipts.
pub fn enforce_high_impact_receipt(
    action_name: &str,
    registry: &HighImpactActionRegistry,
    receipt: Option<&SignedReceipt>,
) -> Result<(), ReceiptError> {
    if registry.is_high_impact(action_name) && receipt.is_none() {
        return Err(ReceiptError::MissingHighImpactReceipt {
            action_name: action_name.to_string(),
        });
    }
    Ok(())
}

/// Create a detached Ed25519 signature over canonical receipt JSON.
pub fn sign_receipt(
    receipt: &Receipt,
    signing_key: &Ed25519PrivateKey,
) -> Result<SignedReceipt, ReceiptError> {
    let payload = canonical_json(receipt)?;
    let signature = signing_key.sign(payload.as_bytes());
    let signature_b64 = BASE64_STANDARD.encode(signature.to_bytes());
    let chain_hash = compute_chain_hash(receipt.previous_receipt_hash.as_deref(), &payload);

    Ok(SignedReceipt {
        receipt: receipt.clone(),
        chain_hash,
        signature: signature_b64,
    })
}

/// Verify signature and hash-chain material for a signed receipt.
pub fn verify_receipt(
    signed: &SignedReceipt,
    public_key: &Ed25519PublicKey,
) -> Result<bool, ReceiptError> {
    let payload = canonical_json(&signed.receipt)?;
    let sig_bytes = BASE64_STANDARD
        .decode(&signed.signature)
        .map_err(ReceiptError::SignatureDecode)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| ReceiptError::SignatureBytes)?;

    if public_key.verify(payload.as_bytes(), &signature).is_err() {
        return Ok(false);
    }

    let expected_chain_hash =
        compute_chain_hash(signed.receipt.previous_receipt_hash.as_deref(), &payload);
    Ok(crate::security::constant_time::ct_eq(
        &expected_chain_hash,
        &signed.chain_hash,
    ))
}

/// Append and sign a receipt while preserving chain linkage.
pub fn append_signed_receipt(
    chain: &mut Vec<SignedReceipt>,
    receipt: Receipt,
    signing_key: &Ed25519PrivateKey,
) -> Result<SignedReceipt, ReceiptError> {
    let previous = chain.last().map(|r| r.chain_hash.clone());
    let signed = sign_receipt(&receipt.with_previous_hash(previous), signing_key)?;
    chain.push(signed.clone());
    Ok(signed)
}

/// Verify append-only hash-chain linkage and deterministic hash material.
pub fn verify_hash_chain(receipts: &[SignedReceipt]) -> Result<(), ReceiptError> {
    for (idx, signed) in receipts.iter().enumerate() {
        let expected_previous = if idx == 0 {
            None
        } else {
            Some(receipts[idx - 1].chain_hash.clone())
        };
        if signed.receipt.previous_receipt_hash != expected_previous {
            return Err(ReceiptError::HashChainMismatch {
                expected: expected_previous.unwrap_or_else(|| "<none>".to_string()),
                actual: signed
                    .receipt
                    .previous_receipt_hash
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string()),
            });
        }

        let payload = canonical_json(&signed.receipt)?;
        let expected_chain =
            compute_chain_hash(signed.receipt.previous_receipt_hash.as_deref(), &payload);
        if signed.chain_hash != expected_chain {
            return Err(ReceiptError::HashChainMismatch {
                expected: expected_chain,
                actual: signed.chain_hash.clone(),
            });
        }
    }
    Ok(())
}

/// Filter receipts by action and time window.
#[must_use]
pub fn export_receipts(receipts: &[SignedReceipt], filter: &ReceiptQuery) -> Vec<SignedReceipt> {
    let from = filter
        .from_timestamp
        .as_ref()
        .and_then(|ts| parse_timestamp(ts).ok());
    let to = filter
        .to_timestamp
        .as_ref()
        .and_then(|ts| parse_timestamp(ts).ok());

    let mut selected: Vec<SignedReceipt> = receipts
        .iter()
        .filter(|receipt| {
            if let Some(action_name) = filter.action_name.as_deref()
                && receipt.receipt.action_name != action_name
            {
                return false;
            }

            let timestamp = match parse_timestamp(&receipt.receipt.timestamp) {
                Ok(value) => value,
                Err(_) => return false,
            };

            if let Some(from_ts) = from
                && timestamp < from_ts
            {
                return false;
            }
            if let Some(to_ts) = to
                && timestamp > to_ts
            {
                return false;
            }
            true
        })
        .cloned()
        .collect();

    if let Some(limit) = filter.limit {
        selected.truncate(limit);
    }
    selected
}

/// Export filtered receipts as JSON.
pub fn export_receipts_json(
    receipts: &[SignedReceipt],
    filter: &ReceiptQuery,
) -> Result<String, ReceiptError> {
    serde_json::to_string_pretty(&export_receipts(receipts, filter))
        .map_err(ReceiptError::JsonEncode)
}

/// Export filtered receipts as CBOR.
pub fn export_receipts_cbor(
    receipts: &[SignedReceipt],
    filter: &ReceiptQuery,
) -> Result<Vec<u8>, ReceiptError> {
    serde_cbor::to_vec(&export_receipts(receipts, filter)).map_err(ReceiptError::CborEncode)
}

/// Import receipts from CBOR.
pub fn import_receipts_cbor(bytes: &[u8]) -> Result<Vec<SignedReceipt>, ReceiptError> {
    serde_cbor::from_slice(bytes).map_err(ReceiptError::CborDecode)
}

/// Write filtered receipt export to file. `.cbor` writes binary CBOR; all other
/// suffixes write JSON.
pub fn export_receipts_to_path(
    receipts: &[SignedReceipt],
    filter: &ReceiptQuery,
    path: &Path,
) -> Result<(), ReceiptError> {
    if path.extension().and_then(std::ffi::OsStr::to_str) == Some("cbor") {
        let bytes = export_receipts_cbor(receipts, filter)?;
        std::fs::write(path, bytes).map_err(|source| ReceiptError::WriteFailed {
            path: path.display().to_string(),
            source,
        })
    } else {
        let json = export_receipts_json(receipts, filter)?;
        std::fs::write(path, json).map_err(|source| ReceiptError::WriteFailed {
            path: path.display().to_string(),
            source,
        })
    }
}

/// Render a human-readable Markdown export.
#[must_use]
pub fn render_receipts_markdown(receipts: &[SignedReceipt]) -> String {
    let mut output = String::from(
        "# Signed Decision Receipts\n\n| Receipt ID | Action | Actor | Decision | Timestamp |\n|---|---|---|---|---|\n",
    );
    for receipt in receipts {
        let decision = match receipt.receipt.decision {
            Decision::Approved => "approved",
            Decision::Denied => "denied",
            Decision::Escalated => "escalated",
        };
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            receipt.receipt.receipt_id,
            receipt.receipt.action_name,
            receipt.receipt.actor_identity,
            decision,
            receipt.receipt.timestamp
        ));
    }
    output
}

pub fn write_receipts_markdown(
    receipts: &[SignedReceipt],
    path: &Path,
) -> Result<(), ReceiptError> {
    let markdown = render_receipts_markdown(receipts);
    std::fs::write(path, markdown).map_err(|source| ReceiptError::WriteFailed {
        path: path.display().to_string(),
        source,
    })
}

/// Fixed demo signing key for deterministic sample exports in the current
/// placeholder CLI.
#[must_use]
pub fn demo_signing_key() -> Ed25519PrivateKey {
    SigningKey::from_bytes(&[42_u8; 32])
}

/// Fixed demo verification key matching [`demo_signing_key`].
#[must_use]
pub fn demo_public_key() -> Ed25519PublicKey {
    demo_signing_key().verifying_key()
}

fn parse_timestamp(timestamp: &str) -> Result<DateTime<Utc>, ReceiptError> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|source| ReceiptError::TimestampParse {
            timestamp: timestamp.to_string(),
            source,
        })
}

fn hash_canonical_json(value: &impl Serialize) -> Result<String, ReceiptError> {
    let canonical = canonical_json(value)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn canonical_json(value: &impl Serialize) -> Result<String, ReceiptError> {
    let serialized = serde_json::to_value(value).map_err(ReceiptError::CanonicalJson)?;
    let canonicalized = canonicalize_value(serialized);
    serde_json::to_string(&canonicalized).map_err(ReceiptError::CanonicalJson)
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            let mut canonical_map = serde_json::Map::with_capacity(entries.len());
            for (key, nested) in entries {
                canonical_map.insert(key, canonicalize_value(nested));
            }
            Value::Object(canonical_map)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"decision_receipt_hash_v1:");
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn compute_chain_hash(previous_hash: Option<&str>, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"decision_receipt_chain_v1:");
    hasher.update(previous_hash.unwrap_or("GENESIS").as_bytes());
    hasher.update(b":");
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_receipt(action_name: &str, decision: Decision) -> Receipt {
        Receipt::new(
            action_name,
            "control-plane@prod",
            &json!({"z": 1, "a": 2}),
            &json!({"result": "ok"}),
            decision,
            "policy gate evaluated",
            vec!["ledger-001".to_string()],
            vec!["rule-A".to_string(), "rule-B".to_string()],
            0.91,
            "franken-node trust release --incident INC-001",
        )
        .expect("receipt construction")
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let canonical = canonical_json(&json!({"b": 2, "a": 1})).expect("canonical JSON");
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let receipt = make_receipt("quarantine", Decision::Approved);
        let signed = sign_receipt(&receipt, &key).expect("sign");
        let verified = verify_receipt(&signed, &public_key).expect("verify");
        assert!(verified);
    }

    #[test]
    fn tamper_detection_fails_verification() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let receipt = make_receipt("revocation", Decision::Denied);
        let mut signed = sign_receipt(&receipt, &key).expect("sign");
        signed.receipt.rationale = "tampered".to_string();
        let verified = verify_receipt(&signed, &public_key).expect("verify");
        assert!(!verified);
    }

    #[test]
    fn hash_chain_verification_detects_breaks() {
        let key = demo_signing_key();
        let mut chain = Vec::new();

        append_signed_receipt(
            &mut chain,
            make_receipt("quarantine", Decision::Approved),
            &key,
        )
        .expect("append #1");
        append_signed_receipt(
            &mut chain,
            make_receipt("deployment_promotion", Decision::Escalated),
            &key,
        )
        .expect("append #2");

        verify_hash_chain(&chain).expect("chain should be valid");

        chain[1].receipt.previous_receipt_hash = Some("broken-link".to_string());
        let err = verify_hash_chain(&chain).expect_err("chain should fail");
        assert!(matches!(err, ReceiptError::HashChainMismatch { .. }));
    }

    #[test]
    fn cbor_roundtrip_preserves_receipts() {
        let key = demo_signing_key();
        let mut chain = Vec::new();
        append_signed_receipt(
            &mut chain,
            make_receipt("policy_change", Decision::Approved),
            &key,
        )
        .expect("append");

        let filter = ReceiptQuery::default();
        let encoded = export_receipts_cbor(&chain, &filter).expect("encode CBOR");
        let decoded = import_receipts_cbor(&encoded).expect("decode CBOR");
        assert_eq!(decoded, chain);
    }

    #[test]
    fn export_filter_supports_action_and_time_window() {
        let key = demo_signing_key();
        let mut first = make_receipt("quarantine", Decision::Approved);
        first.timestamp = "2026-02-20T10:00:00Z".to_string();
        let mut second = make_receipt("revocation", Decision::Denied);
        second.timestamp = "2026-02-20T11:00:00Z".to_string();

        let first = sign_receipt(&first, &key).expect("sign first");
        let second = sign_receipt(&second, &key).expect("sign second");
        let chain = vec![first.clone(), second];

        let filter = ReceiptQuery {
            action_name: Some("quarantine".to_string()),
            from_timestamp: Some("2026-02-20T09:30:00Z".to_string()),
            to_timestamp: Some("2026-02-20T10:30:00Z".to_string()),
            limit: Some(10),
        };
        let exported = export_receipts(&chain, &filter);
        assert_eq!(exported, vec![first]);
    }

    #[test]
    fn high_impact_registry_requires_receipt() {
        let registry = HighImpactActionRegistry::with_defaults();
        let err =
            enforce_high_impact_receipt("quarantine", &registry, None).expect_err("must fail");
        assert!(matches!(err, ReceiptError::MissingHighImpactReceipt { .. }));
        assert!(
            enforce_high_impact_receipt(
                "quarantine",
                &registry,
                Some(
                    &sign_receipt(
                        &make_receipt("quarantine", Decision::Approved),
                        &demo_signing_key(),
                    )
                    .expect("sign")
                )
            )
            .is_ok()
        );
    }

    #[test]
    fn markdown_render_contains_headers() {
        let key = demo_signing_key();
        let signed = sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).unwrap();
        let markdown = render_receipts_markdown(&[signed]);
        assert!(markdown.contains("Signed Decision Receipts"));
        assert!(markdown.contains("| Receipt ID | Action | Actor | Decision | Timestamp |"));
    }
}
