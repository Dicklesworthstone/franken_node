//! bd-p73r: Canonical ExecutionReceipt schema + deterministic serialization.
//!
//! This module defines the canonical VEF ExecutionReceipt contract used as the
//! atomic evidence unit for high-risk runtime actions.
//!
//! Invariants:
//! - INV-VEF-RECEIPT-DETERMINISTIC: identical logical receipts produce identical bytes.
//! - INV-VEF-RECEIPT-HASH-STABLE: hashing canonical bytes is deterministic.
//! - INV-VEF-RECEIPT-VERSIONED: schema_version is explicit and validated.
//! - INV-VEF-RECEIPT-TRACEABLE: receipt includes trace_id + actor/artifact/policy binding.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

pub const RECEIPT_SCHEMA_VERSION: &str = "vef-execution-receipt-v1";
const VEF_EXECUTION_RECEIPT_HASH_DOMAIN: &[u8] = b"vef_execution_receipt_v1:";
const RESERVED_ARTIFACT_ID: &str = "<unknown>";

pub mod event_codes {
    /// Receipt object created in-memory.
    #[allow(dead_code)]
    pub const VEF_RECEIPT_001_CREATED: &str = "VEF-RECEIPT-001";
    /// Canonical receipt serialization completed.
    #[allow(dead_code)]
    pub const VEF_RECEIPT_002_SERIALIZED: &str = "VEF-RECEIPT-002";
}

pub mod error_codes {
    /// Missing required field or empty value.
    pub const ERR_VEF_RECEIPT_MISSING_FIELD: &str = "VEF-RECEIPT-ERR-001";
    /// Invalid field type/range/value shape.
    pub const ERR_VEF_RECEIPT_INVALID_VALUE: &str = "VEF-RECEIPT-ERR-002";
    /// Unsupported or mismatched schema version.
    pub const ERR_VEF_RECEIPT_SCHEMA_VERSION: &str = "VEF-RECEIPT-ERR-003";
    /// Expected hash does not match computed canonical hash.
    pub const ERR_VEF_RECEIPT_HASH_MISMATCH: &str = "VEF-RECEIPT-ERR-004";
    /// Internal serialization/deserialization failure.
    pub const ERR_VEF_RECEIPT_INTERNAL: &str = "VEF-RECEIPT-ERR-005";
}

#[allow(dead_code)]
pub const INV_VEF_RECEIPT_DETERMINISTIC: &str = "INV-VEF-RECEIPT-DETERMINISTIC";
#[allow(dead_code)]
pub const INV_VEF_RECEIPT_HASH_STABLE: &str = "INV-VEF-RECEIPT-HASH-STABLE";
#[allow(dead_code)]
pub const INV_VEF_RECEIPT_VERSIONED: &str = "INV-VEF-RECEIPT-VERSIONED";
#[allow(dead_code)]
pub const INV_VEF_RECEIPT_TRACEABLE: &str = "INV-VEF-RECEIPT-TRACEABLE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionActionType {
    NetworkAccess,
    FilesystemOperation,
    ProcessSpawn,
    SecretAccess,
    PolicyTransition,
    ArtifactPromotion,
}

impl ExecutionActionType {
    #[allow(dead_code)]
    pub fn all() -> &'static [ExecutionActionType] {
        &[
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::ProcessSpawn,
            ExecutionActionType::SecretAccess,
            ExecutionActionType::PolicyTransition,
            ExecutionActionType::ArtifactPromotion,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionActionType::NetworkAccess => "network_access",
            ExecutionActionType::FilesystemOperation => "filesystem_operation",
            ExecutionActionType::ProcessSpawn => "process_spawn",
            ExecutionActionType::SecretAccess => "secret_access",
            ExecutionActionType::PolicyTransition => "policy_transition",
            ExecutionActionType::ArtifactPromotion => "artifact_promotion",
        }
    }
}

impl fmt::Display for ExecutionActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub schema_version: String,
    pub action_type: ExecutionActionType,
    pub capability_context: BTreeMap<String, String>,
    pub actor_identity: String,
    pub artifact_identity: String,
    pub policy_snapshot_hash: String,
    pub timestamp_millis: u64,
    pub sequence_number: u64,
    pub witness_references: Vec<String>,
    pub trace_id: String,
}

impl ExecutionReceipt {
    /// Returns a normalized copy suitable for deterministic serialization/hashing.
    pub fn canonicalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.witness_references.sort();
        normalized.witness_references.dedup();
        normalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReceiptError {
    pub code: &'static str,
    pub message: String,
}

impl ExecutionReceiptError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ExecutionReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ExecutionReceiptError {}

fn is_sha256_prefixed(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn contains_nul(value: &str) -> bool {
    value.contains('\0')
}

fn invalid_artifact_identity_reason(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_identity is reserved: {:?}", value));
    }
    if trimmed != value {
        return Some("artifact_identity contains leading or trailing whitespace".to_string());
    }
    if contains_nul(value) {
        return Some("artifact_identity contains NUL byte".to_string());
    }
    None
}

pub fn validate_receipt(receipt: &ExecutionReceipt) -> Result<(), ExecutionReceiptError> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_SCHEMA_VERSION,
            format!(
                "schema_version '{}' does not match '{}'",
                receipt.schema_version, RECEIPT_SCHEMA_VERSION
            ),
        ));
    }
    if receipt.actor_identity.trim().is_empty() {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_MISSING_FIELD,
            "actor_identity must be non-empty",
        ));
    }
    if receipt.actor_identity.trim() != receipt.actor_identity.as_str() {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "actor_identity contains leading or trailing whitespace",
        ));
    }
    if contains_nul(&receipt.actor_identity) {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "actor_identity contains NUL byte",
        ));
    }
    if receipt.artifact_identity.trim().is_empty() {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_MISSING_FIELD,
            "artifact_identity must be non-empty",
        ));
    }
    if let Some(reason) = invalid_artifact_identity_reason(&receipt.artifact_identity) {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            reason,
        ));
    }
    if receipt.trace_id.trim().is_empty() {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_MISSING_FIELD,
            "trace_id must be non-empty",
        ));
    }
    if receipt.trace_id.trim() != receipt.trace_id.as_str() {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "trace_id contains leading or trailing whitespace",
        ));
    }
    if contains_nul(&receipt.trace_id) {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "trace_id contains NUL byte",
        ));
    }
    if receipt.capability_context.is_empty() {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_MISSING_FIELD,
            "capability_context must include at least one key",
        ));
    }
    if receipt
        .capability_context
        .iter()
        .any(|(k, v)| k.trim().is_empty() || v.trim().is_empty())
    {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "capability_context keys/values must be non-empty strings",
        ));
    }
    if receipt
        .capability_context
        .iter()
        .any(|(k, v)| k.trim() != k.as_str() || v.trim() != v.as_str())
    {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "capability_context keys/values must not contain leading or trailing whitespace",
        ));
    }
    if receipt
        .capability_context
        .iter()
        .any(|(k, v)| contains_nul(k) || contains_nul(v))
    {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "capability_context keys/values must not contain NUL bytes",
        ));
    }
    if !is_sha256_prefixed(&receipt.policy_snapshot_hash) {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "policy_snapshot_hash must match sha256:<64 hex chars>",
        ));
    }
    if receipt
        .witness_references
        .iter()
        .any(|item| item.trim().is_empty())
    {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "witness_references entries must be non-empty strings",
        ));
    }
    if receipt
        .witness_references
        .iter()
        .any(|item| contains_nul(item))
    {
        return Err(ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INVALID_VALUE,
            "witness_references entries must not contain NUL bytes",
        ));
    }
    Ok(())
}

pub fn serialize_canonical(receipt: &ExecutionReceipt) -> Result<Vec<u8>, ExecutionReceiptError> {
    validate_receipt(receipt)?;
    serde_json::to_vec(&receipt.canonicalized()).map_err(|err| {
        ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INTERNAL,
            format!("serialization failure: {err}"),
        )
    })
}

pub fn receipt_hash_sha256(receipt: &ExecutionReceipt) -> Result<String, ExecutionReceiptError> {
    let bytes = serialize_canonical(receipt)?;
    let mut hasher = Sha256::new();
    hasher.update(VEF_EXECUTION_RECEIPT_HASH_DOMAIN);
    hasher.update((u64::try_from(bytes.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(bytes.as_slice());
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Constant-time string comparison (inline to avoid cross-crate path issues in test harnesses).
fn ct_eq_inline(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

pub fn verify_hash(
    receipt: &ExecutionReceipt,
    expected_hash: &str,
) -> Result<(), ExecutionReceiptError> {
    let computed = receipt_hash_sha256(receipt)?;
    if ct_eq_inline(&computed, expected_hash) {
        return Ok(());
    }
    Err(ExecutionReceiptError::new(
        error_codes::ERR_VEF_RECEIPT_HASH_MISMATCH,
        format!("expected {expected_hash}, got {computed}"),
    ))
}

pub fn round_trip_canonical_bytes(
    receipt: &ExecutionReceipt,
) -> Result<Vec<u8>, ExecutionReceiptError> {
    let first = serialize_canonical(receipt)?;
    let parsed: ExecutionReceipt = serde_json::from_slice(&first).map_err(|err| {
        ExecutionReceiptError::new(
            error_codes::ERR_VEF_RECEIPT_INTERNAL,
            format!("deserialization failure: {err}"),
        )
    })?;
    let second = serialize_canonical(&parsed)?;
    if first == second {
        return Ok(second);
    }
    Err(ExecutionReceiptError::new(
        error_codes::ERR_VEF_RECEIPT_INTERNAL,
        "round-trip canonical bytes diverged",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt() -> ExecutionReceipt {
        let mut capability_context = BTreeMap::new();
        capability_context.insert("domain".to_string(), "extensions".to_string());
        capability_context.insert("scope".to_string(), "runtime".to_string());
        capability_context.insert("capability".to_string(), "network.egress".to_string());

        ExecutionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            action_type: ExecutionActionType::NetworkAccess,
            capability_context,
            actor_identity: "agent:purple-harbor".to_string(),
            artifact_identity: "artifact:ext:franken-node-core".to_string(),
            policy_snapshot_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            timestamp_millis: 1_745_000_001_000,
            sequence_number: 42,
            witness_references: vec![
                "witness:zeta".to_string(),
                "witness:alpha".to_string(),
                "witness:alpha".to_string(),
            ],
            trace_id: "trace-receipt-001".to_string(),
        }
    }

    #[test]
    fn test_validate_success() {
        let receipt = make_receipt();
        assert!(validate_receipt(&receipt).is_ok());
    }

    #[test]
    fn test_validate_rejects_schema_mismatch() {
        let mut receipt = make_receipt();
        receipt.schema_version = "wrong".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_SCHEMA_VERSION);
    }

    #[test]
    fn test_validate_rejects_missing_actor() {
        let mut receipt = make_receipt();
        receipt.actor_identity.clear();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_MISSING_FIELD);
    }

    #[test]
    fn test_validate_rejects_bad_policy_hash() {
        let mut receipt = make_receipt();
        receipt.policy_snapshot_hash = "sha256:not-hex".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_missing_artifact_identity() {
        let mut receipt = make_receipt();
        receipt.artifact_identity.clear();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_MISSING_FIELD);
    }

    #[test]
    fn test_validate_rejects_reserved_artifact_identity() {
        let mut receipt = make_receipt();
        receipt.artifact_identity = RESERVED_ARTIFACT_ID.to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_whitespace_artifact_identity() {
        let mut receipt = make_receipt();
        receipt.artifact_identity = " artifact:ext:franken-node-core ".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_empty_witness_reference() {
        let mut receipt = make_receipt();
        receipt.witness_references.push("".to_string());
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_empty_capability_context() {
        let mut receipt = make_receipt();
        receipt.capability_context.clear();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_MISSING_FIELD);
    }

    #[test]
    fn test_validate_rejects_missing_trace_id() {
        let mut receipt = make_receipt();
        receipt.trace_id.clear();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_MISSING_FIELD);
    }

    #[test]
    fn test_validate_rejects_blank_capability_key() {
        let mut receipt = make_receipt();
        receipt
            .capability_context
            .insert(" ".to_string(), "runtime".to_string());
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_blank_capability_value() {
        let mut receipt = make_receipt();
        receipt
            .capability_context
            .insert("scope".to_string(), "\t".to_string());
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_actor_with_edge_whitespace() {
        let mut receipt = make_receipt();
        receipt.actor_identity = " agent:purple-harbor".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("actor_identity"));
    }

    #[test]
    fn test_validate_rejects_trace_id_with_edge_whitespace() {
        let mut receipt = make_receipt();
        receipt.trace_id = "trace-receipt-001\n".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("trace_id"));
    }

    #[test]
    fn test_validate_rejects_capability_key_with_edge_whitespace() {
        let mut receipt = make_receipt();
        receipt
            .capability_context
            .insert(" scope".to_string(), "runtime".to_string());
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("capability_context"));
    }

    #[test]
    fn test_validate_rejects_capability_value_with_edge_whitespace() {
        let mut receipt = make_receipt();
        receipt
            .capability_context
            .insert("scope".to_string(), "runtime ".to_string());
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("capability_context"));
    }

    #[test]
    fn test_validate_rejects_policy_hash_without_prefix() {
        let mut receipt = make_receipt();
        receipt.policy_snapshot_hash =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_policy_hash_too_short() {
        let mut receipt = make_receipt();
        receipt.policy_snapshot_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_policy_hash_too_long() {
        let mut receipt = make_receipt();
        receipt.policy_snapshot_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_validate_rejects_policy_hash_non_hex_full_length() {
        let mut receipt = make_receipt();
        receipt.policy_snapshot_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg".to_string();
        let err = validate_receipt(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_serialize_canonical_rejects_invalid_receipt_before_serializing() {
        let mut receipt = make_receipt();
        receipt.trace_id = " trace-receipt-001".to_string();
        let err = serialize_canonical(&receipt).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_verify_hash_rejects_invalid_receipt_before_hash_compare() {
        let mut receipt = make_receipt();
        receipt.actor_identity = "agent:purple-harbor ".to_string();
        let err = verify_hash(
            &receipt,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
    }

    #[test]
    fn test_canonicalization_sorts_and_dedups_witnesses() {
        let receipt = make_receipt();
        let canonical = receipt.canonicalized();
        assert_eq!(
            canonical.witness_references,
            vec!["witness:alpha".to_string(), "witness:zeta".to_string()]
        );
    }

    #[test]
    fn test_serialize_canonical_is_deterministic() {
        let mut a = make_receipt();
        let mut b = make_receipt();
        a.witness_references = vec!["witness:b".to_string(), "witness:a".to_string()];
        b.witness_references = vec!["witness:a".to_string(), "witness:b".to_string()];
        let bytes_a = serialize_canonical(&a).unwrap();
        let bytes_b = serialize_canonical(&b).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn test_hash_stability_1000x() {
        let receipt = make_receipt();
        let expected = receipt_hash_sha256(&receipt).unwrap();
        for _ in 0..1000 {
            let current = receipt_hash_sha256(&receipt).unwrap();
            assert_eq!(current, expected);
        }
    }

    #[test]
    fn test_hash_uses_domain_separator_and_canonical_bytes() {
        let receipt = make_receipt();
        let bytes = serialize_canonical(&receipt).unwrap();
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(VEF_EXECUTION_RECEIPT_HASH_DOMAIN);
        expected_hasher.update((u64::try_from(bytes.len()).unwrap_or(u64::MAX)).to_le_bytes());
        expected_hasher.update(bytes.as_slice());

        let mut raw_hasher = Sha256::new();
        raw_hasher.update(bytes.as_slice());

        let actual = receipt_hash_sha256(&receipt).unwrap();
        let expected = format!("sha256:{:x}", expected_hasher.finalize());
        let raw = format!("sha256:{:x}", raw_hasher.finalize());

        assert_eq!(actual, expected);
        assert_ne!(actual, raw);
    }

    #[test]
    fn test_verify_hash_rejects_legacy_domain_raw_bytes_hash() {
        let receipt = make_receipt();
        let bytes = serialize_canonical(&receipt).unwrap();
        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(VEF_EXECUTION_RECEIPT_HASH_DOMAIN);
        legacy_hasher.update(bytes.as_slice());
        let legacy_hash = format!("sha256:{:x}", legacy_hasher.finalize());

        let err = verify_hash(&receipt, &legacy_hash).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_HASH_MISMATCH);
        assert_ne!(receipt_hash_sha256(&receipt).unwrap(), legacy_hash);
    }

    #[test]
    fn test_hash_changes_when_sequence_changes() {
        let mut a = make_receipt();
        let mut b = make_receipt();
        b.sequence_number = b.sequence_number.saturating_add(1);
        let hash_a = receipt_hash_sha256(&a).unwrap();
        let hash_b = receipt_hash_sha256(&b).unwrap();
        assert_ne!(hash_a, hash_b);
        a.sequence_number = a.sequence_number.saturating_add(1);
        let hash_a2 = receipt_hash_sha256(&a).unwrap();
        assert_eq!(hash_a2, hash_b);
    }

    #[test]
    fn test_round_trip_canonical_bytes_stable() {
        let receipt = make_receipt();
        let bytes = round_trip_canonical_bytes(&receipt).unwrap();
        let bytes_again = round_trip_canonical_bytes(&receipt).unwrap();
        assert_eq!(bytes, bytes_again);
    }

    #[test]
    fn test_verify_hash_success() {
        let receipt = make_receipt();
        let digest = receipt_hash_sha256(&receipt).unwrap();
        assert!(verify_hash(&receipt, &digest).is_ok());
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let receipt = make_receipt();
        let err = verify_hash(
            &receipt,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_HASH_MISMATCH);
    }

    #[test]
    fn test_action_type_serde_snake_case() {
        let value = serde_json::to_string(&ExecutionActionType::ArtifactPromotion).unwrap();
        assert_eq!(value, "\"artifact_promotion\"");
    }

    #[test]
    fn test_action_type_deserialize_rejects_unknown_variant() {
        let result: Result<ExecutionActionType, _> = serde_json::from_str(r#""kernel_bypass""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_receipt_deserialize_rejects_missing_action_type() {
        let mut value = serde_json::to_value(make_receipt()).unwrap();
        value.as_object_mut().unwrap().remove("action_type");
        let json = serde_json::to_string(&value).unwrap();

        let result: Result<ExecutionReceipt, _> = serde_json::from_str(&json);

        assert!(result.is_err());
    }

    #[test]
    fn test_receipt_deserialize_rejects_timestamp_overflow() {
        let mut value = serde_json::to_value(make_receipt()).unwrap();
        value["timestamp_millis"] = serde_json::json!(18_446_744_073_709_551_616_u128);
        let json = serde_json::to_string(&value).unwrap();

        let result: Result<ExecutionReceipt, _> = serde_json::from_str(&json);

        assert!(result.is_err());
    }

    #[test]
    fn test_receipt_deserialize_rejects_witness_type_confusion() {
        let mut value = serde_json::to_value(make_receipt()).unwrap();
        value["witness_references"] = serde_json::json!("witness:alpha");
        let json = serde_json::to_string(&value).unwrap();

        let result: Result<ExecutionReceipt, _> = serde_json::from_str(&json);

        assert!(result.is_err());
    }

    #[test]
    fn test_unicode_identity_supported() {
        let mut receipt = make_receipt();
        receipt.actor_identity = "operator:東京-node".to_string();
        assert!(validate_receipt(&receipt).is_ok());
        assert!(serialize_canonical(&receipt).is_ok());
    }

    #[test]
    fn test_large_timestamp_boundary() {
        let mut receipt = make_receipt();
        receipt.timestamp_millis = u64::MAX;
        assert!(validate_receipt(&receipt).is_ok());
    }

    #[test]
    fn test_serialized_fields_include_required_contract_elements() {
        let receipt = make_receipt();
        let bytes = serialize_canonical(&receipt).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        for field in [
            "schema_version",
            "action_type",
            "capability_context",
            "actor_identity",
            "artifact_identity",
            "policy_snapshot_hash",
            "timestamp_millis",
            "sequence_number",
            "witness_references",
            "trace_id",
        ] {
            assert!(parsed.get(field).is_some(), "missing field {field}");
        }
    }

    #[test]
    fn test_validate_rejects_actor_identity_with_nul() {
        let mut receipt = make_receipt();
        receipt.actor_identity = "agent:purple\0harbor".to_string();

        let err = validate_receipt(&receipt).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("actor_identity"));
    }

    #[test]
    fn test_validate_rejects_artifact_identity_with_nul() {
        let mut receipt = make_receipt();
        receipt.artifact_identity = "artifact:ext\0franken-node-core".to_string();

        let err = validate_receipt(&receipt).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("artifact_identity"));
    }

    #[test]
    fn test_validate_rejects_trace_id_with_nul() {
        let mut receipt = make_receipt();
        receipt.trace_id = "trace\0receipt-001".to_string();

        let err = validate_receipt(&receipt).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("trace_id"));
    }

    #[test]
    fn test_validate_rejects_capability_key_with_nul() {
        let mut receipt = make_receipt();
        receipt
            .capability_context
            .insert("scope\0shadow".to_string(), "runtime".to_string());

        let err = validate_receipt(&receipt).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("capability_context"));
    }

    #[test]
    fn test_validate_rejects_capability_value_with_nul() {
        let mut receipt = make_receipt();
        receipt
            .capability_context
            .insert("scope".to_string(), "runtime\0shadow".to_string());

        let err = validate_receipt(&receipt).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("capability_context"));
    }

    #[test]
    fn test_validate_rejects_witness_reference_with_nul() {
        let mut receipt = make_receipt();
        receipt
            .witness_references
            .push("witness:alpha\0shadow".to_string());

        let err = validate_receipt(&receipt).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_INVALID_VALUE);
        assert!(err.message.contains("witness_references"));
    }
}
