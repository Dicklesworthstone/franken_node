//! bd-12n3: Idempotency key derivation from request bytes with epoch binding.
//!
//! Derivation input contract:
//! `len(domain_prefix)_be_u64 || domain_prefix || len(computation_name)_be_u64 ||`
//! `computation_name || epoch_be_u64 || len(request_bytes)_be_u64 || request_bytes`
//!
//! This enforces:
//! - deterministic key generation
//! - domain separation (different computation_name => different key)
//! - epoch binding (same request in different epochs => different key)
//! - injective framing even when computation_name / request_bytes contain control bytes

use crate::remote::computation_registry::ComputationRegistry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub const IDEMPOTENCY_DOMAIN_PREFIX: &[u8] = b"franken_node.idempotency.v1";
pub const IDEMPOTENCY_KEY_LEN: usize = 32;
const IDEMPOTENCY_DERIVATION_TAG: &[u8] = b"idempotency_key_derive_v1:";

/// Structured event codes for key derivation telemetry.
pub mod event_codes {
    pub const IK_KEY_DERIVED: &str = "IK_KEY_DERIVED";
    pub const IK_DERIVATION_ERROR: &str = "IK_DERIVATION_ERROR";
    pub const IK_VECTOR_VERIFIED: &str = "IK_VECTOR_VERIFIED";
    pub const IK_COLLISION_CHECK_PASSED: &str = "IK_COLLISION_CHECK_PASSED";
}

/// Fixed-size idempotency key (SHA-256 digest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdempotencyKey([u8; IDEMPOTENCY_KEY_LEN]);

impl IdempotencyKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; IDEMPOTENCY_KEY_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; IDEMPOTENCY_KEY_LEN] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(input: &str) -> Result<Self, IdempotencyError> {
        let decoded = hex::decode(input).map_err(|err| IdempotencyError::InvalidHex {
            reason: err.to_string(),
        })?;
        if decoded.len() != IDEMPOTENCY_KEY_LEN {
            return Err(IdempotencyError::InvalidHex {
                reason: format!(
                    "expected {IDEMPOTENCY_KEY_LEN} bytes, got {}",
                    decoded.len()
                ),
            });
        }
        let mut out = [0_u8; IDEMPOTENCY_KEY_LEN];
        out.copy_from_slice(&decoded);
        Ok(Self(out))
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Structured derivation event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyDerivationEvent {
    pub event_code: String,
    pub computation_name: String,
    pub epoch: u64,
    pub key_fingerprint: String,
    pub trace_id: String,
    pub detail: String,
}

impl IdempotencyDerivationEvent {
    #[must_use]
    pub fn key_derived(
        computation_name: &str,
        epoch: u64,
        key: IdempotencyKey,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: event_codes::IK_KEY_DERIVED.to_string(),
            computation_name: computation_name.to_string(),
            epoch,
            key_fingerprint: key_fingerprint(&key),
            trace_id: trace_id.to_string(),
            detail: "derivation succeeded".to_string(),
        }
    }

    #[must_use]
    pub fn derivation_error(
        computation_name: &str,
        epoch: u64,
        trace_id: &str,
        error_message: &str,
    ) -> Self {
        Self {
            event_code: event_codes::IK_DERIVATION_ERROR.to_string(),
            computation_name: computation_name.to_string(),
            epoch,
            key_fingerprint: String::new(), // No key for error events
            trace_id: trace_id.to_string(),
            detail: error_message.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdempotencyError {
    EmptyComputationName,
    EmptyDomainPrefix,
    InvalidHex { reason: String },
    RegistryRejected { reason: String },
}

impl IdempotencyError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyComputationName => "IK_ERR_EMPTY_COMPUTATION_NAME",
            Self::EmptyDomainPrefix => "IK_ERR_EMPTY_DOMAIN_PREFIX",
            Self::InvalidHex { .. } => "IK_ERR_INVALID_HEX",
            Self::RegistryRejected { .. } => "IK_ERR_REGISTRY_REJECTED",
        }
    }
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyComputationName => {
                write!(f, "{}: computation_name cannot be empty", self.code())
            }
            Self::EmptyDomainPrefix => write!(f, "{}: domain_prefix cannot be empty", self.code()),
            Self::InvalidHex { reason } => write!(f, "{}: {reason}", self.code()),
            Self::RegistryRejected { reason } => write!(f, "{}: {reason}", self.code()),
        }
    }
}

impl std::error::Error for IdempotencyError {}

/// Deterministic idempotency key derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyKeyDeriver {
    domain_prefix: Vec<u8>,
}

impl Default for IdempotencyKeyDeriver {
    fn default() -> Self {
        Self {
            domain_prefix: IDEMPOTENCY_DOMAIN_PREFIX.to_vec(),
        }
    }
}

impl IdempotencyKeyDeriver {
    pub fn new(domain_prefix: &[u8]) -> Result<Self, IdempotencyError> {
        if domain_prefix.is_empty() {
            return Err(IdempotencyError::EmptyDomainPrefix);
        }
        Ok(Self {
            domain_prefix: domain_prefix.to_vec(),
        })
    }

    #[must_use]
    pub fn domain_prefix(&self) -> &[u8] {
        &self.domain_prefix
    }

    fn append_len_prefixed_field(output: &mut Vec<u8>, bytes: &[u8]) {
        output.extend_from_slice(&(u64::try_from(bytes.len()).unwrap_or(u64::MAX)).to_be_bytes());
        output.extend_from_slice(bytes);
    }

    fn canonical_input(
        &self,
        computation_name: &str,
        epoch: u64,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, IdempotencyError> {
        if computation_name.trim().is_empty() {
            return Err(IdempotencyError::EmptyComputationName);
        }

        let input_capacity = self
            .domain_prefix
            .len()
            .saturating_add(computation_name.len())
            .saturating_add(request_bytes.len())
            .saturating_add(32);
        let mut input = Vec::with_capacity(input_capacity);
        Self::append_len_prefixed_field(&mut input, &self.domain_prefix);
        Self::append_len_prefixed_field(&mut input, computation_name.as_bytes());
        input.extend_from_slice(&epoch.to_be_bytes());
        Self::append_len_prefixed_field(&mut input, request_bytes);
        Ok(input)
    }

    pub fn derive_key(
        &self,
        computation_name: &str,
        epoch: u64,
        request_bytes: &[u8],
    ) -> Result<IdempotencyKey, IdempotencyError> {
        let canonical = self.canonical_input(computation_name, epoch, request_bytes)?;
        let mut hasher = Sha256::new();
        hasher.update(IDEMPOTENCY_DERIVATION_TAG);
        hasher.update(&canonical);
        let digest = hasher.finalize();
        let mut out = [0_u8; IDEMPOTENCY_KEY_LEN];
        out.copy_from_slice(&digest);
        Ok(IdempotencyKey::from_bytes(out))
    }

    /// Registry-aware derivation that first validates the computation name.
    pub fn derive_registered_key(
        &self,
        registry: &mut ComputationRegistry,
        computation_name: &str,
        epoch: u64,
        request_bytes: &[u8],
        trace_id: &str,
    ) -> Result<IdempotencyKey, IdempotencyError> {
        registry
            .validate_computation_name(computation_name, trace_id)
            .map_err(|reason| IdempotencyError::RegistryRejected {
                reason: reason.to_string(),
            })?;
        self.derive_key(computation_name, epoch, request_bytes)
    }

    /// Empirical collision check over provided payload corpus.
    pub fn collision_count(
        &self,
        computation_name: &str,
        epoch: u64,
        payloads: &[Vec<u8>],
    ) -> Result<usize, IdempotencyError> {
        let mut seen = BTreeSet::new();
        let mut collisions = 0_usize;
        for payload in payloads {
            let key = self.derive_key(computation_name, epoch, payload)?;
            if !seen.insert(key) {
                collisions = collisions.saturating_add(1);
            }
        }
        Ok(collisions)
    }
}

#[must_use]
pub fn key_fingerprint(key: &IdempotencyKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"idempotency_fingerprint_v1:");
    hasher.update(
        u64::try_from(key.as_bytes().len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    format!("fp:{}", &hex::encode(digest)[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::computation_registry::ComputationEntry;
    use crate::security::remote_cap::RemoteOperation;

    fn legacy_separator_canonical_input(
        domain_prefix: &[u8],
        computation_name: &str,
        epoch: u64,
        request_bytes: &[u8],
    ) -> Vec<u8> {
        let mut input = Vec::with_capacity(
            domain_prefix.len() + computation_name.len() + request_bytes.len() + 11,
        );
        input.extend_from_slice(domain_prefix);
        input.push(0x1F);
        input.extend_from_slice(computation_name.as_bytes());
        input.push(0x1F);
        input.extend_from_slice(&epoch.to_be_bytes());
        input.push(0x1F);
        input.extend_from_slice(request_bytes);
        input
    }

    fn seeded_payload(seed: u64) -> Vec<u8> {
        let mut payload = vec![0_u8; 24];
        payload[..8].copy_from_slice(&seed.to_be_bytes());
        payload[8..16].copy_from_slice(&(seed.wrapping_mul(31)).to_be_bytes());
        payload[16..24].copy_from_slice(&(seed.wrapping_mul(131)).to_be_bytes());
        payload
    }

    fn demo_registry() -> ComputationRegistry {
        let mut registry = ComputationRegistry::new(1, "trace-registry");
        registry
            .register_computation(
                ComputationEntry {
                    name: "core.remote_compute.v1".to_string(),
                    description: "demo compute".to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: "{}".to_string(),
                    output_schema: "{}".to_string(),
                },
                "trace-registry",
            )
            .expect("valid registration");
        registry
    }

    // Helper function for tests to derive keys with default deriver
    fn derive_idempotency_key(
        computation_name: &str,
        epoch: u64,
        request_bytes: &[u8],
    ) -> IdempotencyKey {
        IdempotencyKeyDeriver::default()
            .derive_key(computation_name, epoch, request_bytes)
            .expect("key derivation should succeed")
    }

    #[test]
    fn same_inputs_always_produce_same_key() {
        let deriver = IdempotencyKeyDeriver::default();
        let a = deriver
            .derive_key("core.remote_compute.v1", 42, br#"{"x":1}"#)
            .expect("should succeed");
        let b = deriver
            .derive_key("core.remote_compute.v1", 42, br#"{"x":1}"#)
            .expect("should succeed");
        assert_eq!(a, b);
    }

    #[test]
    fn different_computation_names_produce_different_keys() {
        let deriver = IdempotencyKeyDeriver::default();
        let a = deriver
            .derive_key("core.remote_compute.v1", 7, b"payload")
            .expect("should succeed");
        let b = deriver
            .derive_key("core.audit.v1", 7, b"payload")
            .expect("should succeed");
        assert_ne!(a, b);
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let deriver = IdempotencyKeyDeriver::default();
        let a = deriver
            .derive_key("core.remote_compute.v1", 100, b"payload")
            .expect("should succeed");
        let b = deriver
            .derive_key("core.remote_compute.v1", 101, b"payload")
            .expect("should succeed");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_payload_is_supported() {
        let deriver = IdempotencyKeyDeriver::default();
        let key = deriver
            .derive_key("core.remote_compute.v1", 0, &[])
            .expect("empty payload should be valid");
        assert_eq!(key.to_hex().len(), 64);
    }

    #[test]
    fn max_epoch_value_is_supported() {
        let deriver = IdempotencyKeyDeriver::default();
        let key = deriver
            .derive_key("core.remote_compute.v1", u64::MAX, b"payload")
            .expect("should succeed");
        assert_eq!(key.to_hex().len(), 64);
    }

    #[test]
    fn empty_computation_name_is_rejected() {
        let deriver = IdempotencyKeyDeriver::default();
        let err = deriver.derive_key("", 1, b"x").unwrap_err();
        assert!(matches!(err, IdempotencyError::EmptyComputationName));
    }

    #[test]
    fn derive_key_rejects_whitespace_only_computation_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let err = deriver.derive_key(" \t\n ", 1, b"x").unwrap_err();

        assert!(matches!(err, IdempotencyError::EmptyComputationName));
    }

    #[test]
    fn canonical_input_rejects_newline_only_computation_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let err = deriver.canonical_input("\n\r", 1, b"x").unwrap_err();

        assert!(matches!(err, IdempotencyError::EmptyComputationName));
    }

    #[test]
    fn collision_count_rejects_tab_only_computation_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let payloads = vec![b"first".to_vec(), b"second".to_vec()];
        let err = deriver.collision_count("\t\t", 7, &payloads).unwrap_err();

        assert!(matches!(err, IdempotencyError::EmptyComputationName));
    }

    #[test]
    fn empty_domain_prefix_is_rejected() {
        let err = IdempotencyKeyDeriver::new(&[]).unwrap_err();
        assert!(matches!(err, IdempotencyError::EmptyDomainPrefix));
    }

    #[test]
    fn empty_hex_string_is_rejected_as_wrong_length() {
        let err = IdempotencyKey::from_hex("").unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
        assert_eq!(err.code(), "IK_ERR_INVALID_HEX");
        assert!(err.to_string().contains("expected 32 bytes, got 0"));
    }

    #[test]
    fn non_hex_characters_are_rejected() {
        let err = IdempotencyKey::from_hex("not-a-hex-key").unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
        assert_eq!(err.code(), "IK_ERR_INVALID_HEX");
    }

    #[test]
    fn short_valid_hex_is_rejected() {
        let short_hex = "00".repeat(IDEMPOTENCY_KEY_LEN - 1);
        let err = IdempotencyKey::from_hex(&short_hex).unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
        assert!(err.to_string().contains("expected 32 bytes, got 31"));
    }

    #[test]
    fn long_valid_hex_is_rejected() {
        let long_hex = "00".repeat(IDEMPOTENCY_KEY_LEN + 1);
        let err = IdempotencyKey::from_hex(&long_hex).unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
        assert!(err.to_string().contains("expected 32 bytes, got 33"));
    }

    #[test]
    fn canonical_input_rejects_empty_name_even_with_control_byte_payload() {
        let deriver = IdempotencyKeyDeriver::default();
        let err = deriver
            .canonical_input("", u64::MAX, b"\0\x1fpayload")
            .unwrap_err();

        assert!(matches!(err, IdempotencyError::EmptyComputationName));
    }

    #[test]
    fn collision_count_rejects_empty_computation_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let payloads = vec![b"first".to_vec(), b"second".to_vec()];
        let err = deriver.collision_count("", 7, &payloads).unwrap_err();

        assert!(matches!(err, IdempotencyError::EmptyComputationName));
    }

    #[test]
    fn registered_derivation_rejects_malformed_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let err = deriver
            .derive_registered_key(&mut registry, "not-canonical", 1, b"x", "trace-malformed")
            .unwrap_err();

        assert!(matches!(
            err,
            IdempotencyError::RegistryRejected { ref reason }
                if reason.contains("ERR_MALFORMED_COMPUTATION_NAME")
        ));
    }

    #[test]
    fn odd_length_hex_is_rejected() {
        let odd_hex = "0".repeat(IDEMPOTENCY_KEY_LEN.saturating_mul(2).saturating_sub(1));
        let err = IdempotencyKey::from_hex(&odd_hex).unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
        assert_eq!(err.code(), "IK_ERR_INVALID_HEX");
    }

    #[test]
    fn whitespace_padded_hex_is_rejected() {
        let padded = format!(" {} ", "00".repeat(IDEMPOTENCY_KEY_LEN));
        let err = IdempotencyKey::from_hex(&padded).unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
        assert_eq!(err.code(), "IK_ERR_INVALID_HEX");
    }

    #[test]
    fn hex_with_embedded_newline_is_rejected() {
        let mut input = "00".repeat(IDEMPOTENCY_KEY_LEN);
        input.replace_range(16..17, "\n");
        let err = IdempotencyKey::from_hex(&input).unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
    }

    #[test]
    fn hex_with_0x_prefix_is_rejected() {
        let prefixed = format!("0x{}", "00".repeat(IDEMPOTENCY_KEY_LEN));
        let err = IdempotencyKey::from_hex(&prefixed).unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
    }

    #[test]
    fn hex_with_colon_separator_is_rejected() {
        let mut separated = "00".repeat(IDEMPOTENCY_KEY_LEN);
        separated.replace_range(16..17, ":");
        let err = IdempotencyKey::from_hex(&separated).unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
    }

    #[test]
    fn hex_with_internal_space_is_rejected() {
        let mut input = "00".repeat(IDEMPOTENCY_KEY_LEN);
        input.replace_range(20..21, " ");
        let err = IdempotencyKey::from_hex(&input).unwrap_err();

        assert!(matches!(err, IdempotencyError::InvalidHex { .. }));
    }

    #[test]
    fn registered_derivation_rejects_empty_name_as_registry_failure() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let err = deriver
            .derive_registered_key(&mut registry, "", 1, b"x", "trace-empty")
            .unwrap_err();

        assert!(matches!(
            err,
            IdempotencyError::RegistryRejected { ref reason }
                if reason.contains("ERR_MALFORMED_COMPUTATION_NAME")
        ));
    }

    #[test]
    fn registered_derivation_rejects_space_padded_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let err = deriver
            .derive_registered_key(
                &mut registry,
                " core.remote_compute.v1 ",
                1,
                b"x",
                "trace-spaces",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            IdempotencyError::RegistryRejected { ref reason }
                if reason.contains("ERR_MALFORMED_COMPUTATION_NAME")
        ));
    }

    #[test]
    fn registered_derivation_rejects_version_without_v_prefix() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let err = deriver
            .derive_registered_key(
                &mut registry,
                "core.remote_compute.1",
                1,
                b"x",
                "trace-version-prefix",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            IdempotencyError::RegistryRejected { ref reason }
                if reason.contains("ERR_MALFORMED_COMPUTATION_NAME")
        ));
    }

    #[test]
    fn registered_derivation_rejects_uppercase_domain_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let err = deriver
            .derive_registered_key(
                &mut registry,
                "Core.remote_compute.v1",
                1,
                b"x",
                "trace-uppercase-domain",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            IdempotencyError::RegistryRejected { ref reason }
                if reason.contains("ERR_MALFORMED_COMPUTATION_NAME")
        ));
    }

    #[test]
    fn registered_derivation_rejects_extra_name_component() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let err = deriver
            .derive_registered_key(
                &mut registry,
                "core.remote.compute.v1",
                1,
                b"x",
                "trace-extra-component",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            IdempotencyError::RegistryRejected { ref reason }
                if reason.contains("ERR_MALFORMED_COMPUTATION_NAME")
        ));
    }

    #[test]
    fn registered_derivation_rejects_unknown_name_with_reason_code() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let err = deriver
            .derive_registered_key(
                &mut registry,
                "core.unregistered.v1",
                1,
                b"x",
                "trace-unknown",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            IdempotencyError::RegistryRejected { ref reason }
                if reason.contains("ERR_UNKNOWN_COMPUTATION")
        ));
    }

    #[test]
    fn collision_count_reports_duplicate_payloads() {
        let deriver = IdempotencyKeyDeriver::default();
        let payloads = vec![b"same".to_vec(), b"same".to_vec(), b"different".to_vec()];
        let collisions = deriver
            .collision_count("core.remote_compute.v1", 7, &payloads)
            .expect("duplicate payloads should be counted");

        assert_eq!(collisions, 1);
    }

    #[test]
    fn key_hex_roundtrip_is_stable() {
        let deriver = IdempotencyKeyDeriver::default();
        let key = deriver
            .derive_key("core.remote_compute.v1", 9, b"hex-roundtrip")
            .expect("should succeed");
        let decoded = IdempotencyKey::from_hex(&key.to_hex()).expect("should succeed");
        assert_eq!(decoded, key);
    }

    #[test]
    fn derive_registered_key_rejects_unknown_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let err = deriver
            .derive_registered_key(&mut registry, "unknown.op.v1", 1, b"x", "trace")
            .unwrap_err();
        assert!(matches!(err, IdempotencyError::RegistryRejected { .. }));
    }

    #[test]
    fn derive_registered_key_accepts_known_name() {
        let deriver = IdempotencyKeyDeriver::default();
        let mut registry = demo_registry();
        let key = deriver
            .derive_registered_key(&mut registry, "core.remote_compute.v1", 1, b"x", "trace")
            .expect("should succeed");
        assert_eq!(key.to_hex().len(), 64);
    }

    #[test]
    fn collision_check_10000_payloads_is_clean() {
        let deriver = IdempotencyKeyDeriver::default();
        let payloads = (0_u64..10_000).map(seeded_payload).collect::<Vec<_>>();
        let collisions = deriver
            .collision_count("core.remote_compute.v1", 7, &payloads)
            .expect("collision check should run");
        assert_eq!(collisions, 0);
    }

    #[test]
    fn separator_collision_inputs_do_not_alias_after_derivation_fix() {
        let deriver = IdempotencyKeyDeriver::default();
        let computation_a = "core.remote_compute.v1";
        let computation_b = "core.remote_compute.v1\u{1f}\0\0\0\0\0\0\0\0\u{1f}suffix";
        let request_a = b"suffix\x1f\0\0\0\0\0\0\0\x01\x1frest";
        let request_b = b"rest";

        let legacy_a =
            legacy_separator_canonical_input(deriver.domain_prefix(), computation_a, 0, request_a);
        let legacy_b =
            legacy_separator_canonical_input(deriver.domain_prefix(), computation_b, 1, request_b);
        assert_eq!(
            legacy_a, legacy_b,
            "the old separator framing admitted tuple aliasing"
        );

        let canonical_a = deriver
            .canonical_input(computation_a, 0, request_a)
            .expect("canonical input a");
        let canonical_b = deriver
            .canonical_input(computation_b, 1, request_b)
            .expect("canonical input b");
        assert_ne!(
            canonical_a, canonical_b,
            "length-prefixed framing must remain injective"
        );

        let key_a = deriver
            .derive_key(computation_a, 0, request_a)
            .expect("derive key a");
        let key_b = deriver
            .derive_key(computation_b, 1, request_b)
            .expect("derive key b");
        assert_ne!(key_a, key_b, "distinct tuples must not alias");
    }

    #[test]
    fn key_derived_event_uses_expected_code_and_fingerprint() {
        let deriver = IdempotencyKeyDeriver::default();
        let key = deriver
            .derive_key("core.remote_compute.v1", 1, b"event")
            .expect("should succeed");
        let event = IdempotencyDerivationEvent::key_derived(
            "core.remote_compute.v1",
            1,
            key,
            "trace-event",
        );
        assert_eq!(event.event_code, event_codes::IK_KEY_DERIVED);
        assert!(!event.key_fingerprint.is_empty());
    }

    // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

    #[test]
    fn test_negative_computation_name_with_unicode_injection_attacks() {
        use crate::security::constant_time;

        let malicious_computation_names = [
            "compute\u{202E}fake\u{202C}",        // BiDi override attack
            "compute\x1b[31mred\x1b[0m",          // ANSI escape injection
            "compute\0null\r\n\t",                // Control character injection
            "compute\"}{\"admin\":true,\"bypass", // JSON injection attempt
            "compute/../../etc/passwd",           // Path traversal attempt
            "compute\u{FEFF}BOM",                 // Byte order mark
            "compute\u{200B}\u{200C}\u{200D}",    // Zero-width characters
            "compute||rm -rf /",                  // Shell injection attempt
            "compute'; DROP TABLE keys; --",      // SQL injection attempt
            "COMPUTE",                            // Case variation (should produce different key)
            "compute",                            // Base case for comparison
        ];

        let test_request = b"test request data";
        let test_epoch = 1234567890;

        let mut derived_keys = Vec::new();

        for malicious_name in malicious_computation_names {
            // Test key derivation with malicious computation name
            let key = derive_idempotency_key(malicious_name, test_epoch, test_request);

            // Verify each computation name produces a different key (domain separation)
            for (i, existing_key) in derived_keys.iter().enumerate() {
                assert!(
                    !constant_time::ct_eq(&key.to_hex(), &existing_key.to_hex()),
                    "computation names '{}' and '{}' should produce different keys",
                    malicious_name,
                    malicious_computation_names[i]
                );
            }

            derived_keys.push(key);

            // Test event generation with malicious name
            let event = IdempotencyDerivationEvent::key_derived(
                malicious_name,
                test_epoch,
                key,
                "test-trace",
            );

            // Verify event preserves malicious name exactly for forensics
            assert_eq!(
                event.computation_name, malicious_name,
                "computation name should be preserved"
            );

            // Test JSON serialization safety
            let json = serde_json::to_string(&event).expect("serialization should work");
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("JSON should be valid");

            // Verify no injection occurred in JSON structure
            assert!(
                parsed.get("admin").is_none(),
                "JSON injection should not create admin field"
            );
            assert!(
                parsed.get("bypass").is_none(),
                "JSON injection should not create bypass field"
            );

            // Verify key fingerprint is properly formatted
            assert!(
                event.key_fingerprint.starts_with("fp:"),
                "fingerprint should have proper prefix"
            );
            assert_eq!(
                event.key_fingerprint.len(),
                19,
                "fingerprint should be 16 hex chars + prefix"
            );
        }

        // Test with extremely long computation name (memory stress)
        let massive_name = "x".repeat(1_000_000); // 1MB computation name
        let massive_key = derive_idempotency_key(&massive_name, test_epoch, test_request);

        // Should handle massive input without panic
        assert_eq!(massive_key.as_bytes().len(), IDEMPOTENCY_KEY_LEN);

        // Should produce different key than normal names
        let normal_key = derive_idempotency_key("normal", test_epoch, test_request);
        assert!(
            !constant_time::ct_eq(&massive_key.to_hex(), &normal_key.to_hex()),
            "massive name should produce different key"
        );
    }

    #[test]
    fn test_negative_request_bytes_with_malicious_collision_attempts() {
        let computation_name = "test.compute";
        let epoch = 1234567890;

        // Test various request patterns that might cause hash collisions
        let collision_attempts = [
            b"request1".as_slice(),
            b"request2".as_slice(),
            b"request1\0".as_slice(),       // Null termination
            b"request1\0\0\0\0".as_slice(), // Multiple nulls
            b"\0request1".as_slice(),       // Leading null
            b"request\01".as_slice(),       // Embedded null
            b"req\0uest1".as_slice(),       // Split with null
            b"".as_slice(),                 // Empty request
            &[0u8; 1000],                   // Large zero buffer
            &[0xFFu8; 1000],                // Large 0xFF buffer
            b"request1\r\n\r\n",            // HTTP-style separators
            b"request1||request2",          // Delimiter confusion
            b"request1\x1f\x1e\x1d\x1c",    // ASCII separators
            &vec![0u8; 10_000_000],         // 10MB zero request (memory stress)
            &b"A".repeat(10_000_000),       // 10MB non-zero request
        ];

        let mut derived_keys = Vec::new();

        for (i, request_bytes) in collision_attempts.iter().enumerate() {
            let key = derive_idempotency_key(computation_name, epoch, request_bytes);

            // Verify key is always 32 bytes regardless of input size
            assert_eq!(key.as_bytes().len(), IDEMPOTENCY_KEY_LEN);

            // Verify each request produces a unique key (collision resistance)
            for (j, existing_key) in derived_keys.iter().enumerate() {
                assert!(
                    !constant_time::ct_eq(&key.to_hex(), &existing_key.to_hex()),
                    "request {} and {} should produce different keys",
                    i,
                    j
                );
            }

            derived_keys.push(key);

            // Test hex conversion roundtrip
            let hex = key.to_hex();
            let reconstructed = IdempotencyKey::from_hex(&hex).expect("hex roundtrip should work");
            assert_eq!(reconstructed, key, "hex roundtrip should preserve key");

            // Test display format
            let display = format!("{}", key);
            assert_eq!(display, hex, "display should match hex");
        }

        // Test that reordering bytes produces different keys (order sensitivity)
        let original_request = b"abcdefghijklmnop";
        let reversed_request = b"ponmlkjihgfedcba";

        let original_key = derive_idempotency_key(computation_name, epoch, original_request);
        let reversed_key = derive_idempotency_key(computation_name, epoch, reversed_request);

        assert!(
            !constant_time::ct_eq(&original_key.to_hex(), &reversed_key.to_hex()),
            "byte order should affect key derivation"
        );

        // Test that similar requests with small differences produce different keys
        let request_a = b"request_data_version_1";
        let request_b = b"request_data_version_2";

        let key_a = derive_idempotency_key(computation_name, epoch, request_a);
        let key_b = derive_idempotency_key(computation_name, epoch, request_b);

        assert!(
            !constant_time::ct_eq(&key_a.to_hex(), &key_b.to_hex()),
            "similar requests should produce different keys"
        );
    }

    #[test]
    fn test_negative_epoch_manipulation_for_key_separation() {
        let computation_name = "test.compute";
        let request_bytes = b"test request";

        // Test epoch values that might cause collisions or bypass epoch binding
        let epoch_values = [
            0,                     // Zero epoch
            1,                     // Minimal epoch
            u64::MAX,              // Maximum epoch
            u64::MAX - 1,          // Near maximum
            1234567890,            // Standard timestamp
            1234567890 + 1,        // Adjacent timestamp
            0x0100000000000000u64, // High bit patterns
            0x00000000FFFFFFFFu64, // Low bit patterns
            0xAAAAAAAAAAAAAAAAu64, // Alternating bit pattern
            0x5555555555555555u64, // Inverse alternating pattern
        ];

        let mut epoch_keys = Vec::new();

        for epoch in epoch_values {
            let key = derive_idempotency_key(computation_name, epoch, request_bytes);

            // Verify each epoch produces a unique key (epoch binding)
            for (existing_epoch, existing_key) in &epoch_keys {
                assert!(
                    !constant_time::ct_eq(&key.to_hex(), &existing_key.to_hex()),
                    "epochs {} and {} should produce different keys",
                    epoch,
                    existing_epoch
                );
            }

            epoch_keys.push((epoch, key));

            // Test derivation event with extreme epoch values
            let event = IdempotencyDerivationEvent::key_derived(
                computation_name,
                epoch,
                key,
                &format!("trace-{}", epoch),
            );

            assert_eq!(event.epoch, epoch, "event should preserve epoch exactly");

            // Test JSON serialization with extreme epoch values
            let json = serde_json::to_string(&event).expect("serialization should work");
            let parsed: IdempotencyDerivationEvent =
                serde_json::from_str(&json).expect("deserialization should work");
            assert_eq!(parsed.epoch, epoch, "epoch should survive JSON roundtrip");
        }

        // Test epoch rollover scenario (adjacent epochs around boundaries)
        let boundary_epochs = [
            (u64::MAX - 1, u64::MAX),
            (0, 1),
            (0x7FFFFFFFFFFFFFFF, 0x8000000000000000), // Sign bit flip
        ];

        for (epoch_a, epoch_b) in boundary_epochs {
            let key_a = derive_idempotency_key(computation_name, epoch_a, request_bytes);
            let key_b = derive_idempotency_key(computation_name, epoch_b, request_bytes);

            assert!(
                !constant_time::ct_eq(&key_a.to_hex(), &key_b.to_hex()),
                "boundary epochs {} and {} should produce different keys",
                epoch_a,
                epoch_b
            );
        }
    }

    #[test]
    fn test_negative_hex_parsing_with_malicious_input() {
        let malicious_hex_inputs = [
            "",                                                                                 // Empty string
            "0",             // Too short (odd length)
            "00",            // Too short (1 byte)
            "g",             // Invalid hex character
            "0g",            // Invalid hex character
            "00gg00",        // Invalid hex in middle
            "Z".repeat(64),  // All invalid hex chars
            "0".repeat(63),  // One char short
            "0".repeat(65),  // One char long
            "0".repeat(128), // Double length
            "x".repeat(64),  // Valid length, invalid chars
            "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE", // 63 chars
            "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEG", // 64 chars with invalid last char
            "\0".repeat(64),                                                    // Null bytes
            "\u{202E}0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF\u{202C}", // BiDi override
            "\x1b[31m0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF\x1b[0m", // ANSI escape
        ];

        for malicious_input in malicious_hex_inputs {
            let result = IdempotencyKey::from_hex(malicious_input);

            match result {
                Ok(_key) => {
                    // If parsing succeeds, the input must have been exactly 64 valid hex chars
                    assert_eq!(
                        malicious_input.len(),
                        64,
                        "only valid 64-char hex should succeed"
                    );
                    for ch in malicious_input.chars() {
                        assert!(ch.is_ascii_hexdigit(), "all chars should be valid hex");
                    }
                }
                Err(error) => {
                    // Expected for malicious inputs - verify error is appropriate
                    assert!(matches!(error, IdempotencyError::InvalidHex { .. }));

                    // Test error display is safe
                    let error_str = format!("{}", error);
                    assert!(
                        !error_str.contains('\0'),
                        "error display should not contain nulls"
                    );
                    assert!(
                        !error_str.contains('\x1b'),
                        "error display should not contain ANSI"
                    );
                }
            }
        }

        // Test with valid hex string to ensure we don't break normal functionality
        let valid_hex = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";
        let key = IdempotencyKey::from_hex(valid_hex).expect("valid hex should parse");
        assert_eq!(key.to_hex(), valid_hex.to_lowercase());

        // Test case insensitivity
        let upper_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let key_upper = IdempotencyKey::from_hex(upper_hex).expect("uppercase hex should parse");
        assert_eq!(key, key_upper, "hex parsing should be case insensitive");
    }

    #[test]
    fn test_negative_trace_id_with_injection_patterns() {
        use crate::security::constant_time;

        let malicious_trace_ids = [
            "trace\u{202E}fake\u{202C}",          // BiDi override attack
            "trace\x1b[31mred\x1b[0m",            // ANSI escape injection
            "trace\0null\r\n\t",                  // Control character injection
            "trace\"}{\"admin\":true,\"bypass\"", // JSON injection attempt
            "trace/../../etc/passwd",             // Path traversal attempt
            "trace\u{FEFF}BOM",                   // Byte order mark
            "trace\u{200B}\u{200C}\u{200D}",      // Zero-width characters
            "trace<script>alert(1)</script>",     // XSS attempt
            "trace'; SELECT * FROM keys; --",     // SQL injection attempt
            "trace||rm -rf /",                    // Shell injection attempt
            "x".repeat(10_000),                   // Extremely long trace ID
        ];

        let key = derive_idempotency_key("test.compute", 123, b"test");

        for malicious_trace_id in malicious_trace_ids {
            // Test derivation event with malicious trace ID
            let event = IdempotencyDerivationEvent::key_derived(
                "test.compute",
                123,
                key,
                malicious_trace_id,
            );

            // Verify trace ID is preserved exactly for forensics
            assert_eq!(
                event.trace_id, malicious_trace_id,
                "trace ID should be preserved"
            );

            // Test JSON serialization safety
            let json = serde_json::to_string(&event).expect("serialization should work");
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("JSON should be valid");

            // Verify no injection occurred in JSON structure
            assert!(
                parsed.get("admin").is_none(),
                "JSON injection should not create admin field"
            );
            assert!(
                parsed.get("bypass").is_none(),
                "JSON injection should not create bypass field"
            );

            // Verify trace ID is properly escaped in JSON
            if let Some(trace_id) = parsed.get("trace_id").and_then(|t| t.as_str()) {
                assert_eq!(
                    trace_id, malicious_trace_id,
                    "trace ID should be preserved in JSON"
                );
            }

            // Test constant-time comparison for trace IDs
            let normal_trace = "normal-trace-123";
            assert!(
                !constant_time::ct_eq(malicious_trace_id, normal_trace),
                "trace ID comparison should be constant-time"
            );

            // Test other event types with malicious trace ID
            let error_event = IdempotencyDerivationEvent::derivation_error(
                "test.compute",
                123,
                malicious_trace_id,
                "test error message",
            );

            assert_eq!(
                error_event.trace_id, malicious_trace_id,
                "error event should preserve trace ID"
            );
            assert_eq!(error_event.event_code, event_codes::IK_DERIVATION_ERROR);
        }

        // Test event with massive detail field
        let massive_detail = "Y".repeat(1_000_000); // 1MB detail
        let massive_event = IdempotencyDerivationEvent {
            event_code: event_codes::IK_KEY_DERIVED.to_string(),
            computation_name: "test.compute".to_string(),
            epoch: 123,
            key_fingerprint: key_fingerprint(&key),
            trace_id: "massive-detail-test".to_string(),
            detail: massive_detail.clone(),
        };

        // Verify serialization handles massive detail
        let json = serde_json::to_string(&massive_event)
            .expect("massive detail serialization should work");
        assert!(
            json.len() >= massive_detail.len(),
            "JSON should include massive detail"
        );

        let parsed: IdempotencyDerivationEvent =
            serde_json::from_str(&json).expect("massive detail deserialization should work");
        assert_eq!(
            parsed.detail, massive_detail,
            "massive detail should be preserved"
        );
    }

    #[test]
    fn test_negative_key_fingerprint_collision_resistance() {
        use crate::security::constant_time;

        // Generate many keys to test fingerprint collision resistance
        let mut fingerprints = std::collections::BTreeSet::new();
        let mut keys = Vec::new();

        for i in 0..10_000 {
            let computation_name = format!("compute.test.{}", i);
            let request_bytes = format!("request_{}", i).as_bytes();
            let key = derive_idempotency_key(&computation_name, i as u64, request_bytes);

            keys.push(key);

            let fingerprint = key_fingerprint(&key);

            // Verify fingerprint format
            assert!(
                fingerprint.starts_with("fp:"),
                "fingerprint should have fp: prefix"
            );
            assert_eq!(
                fingerprint.len(),
                19,
                "fingerprint should be 19 chars total"
            );

            // Verify fingerprint is hex (after prefix)
            let hex_part = &fingerprint[3..];
            for ch in hex_part.chars() {
                assert!(
                    ch.is_ascii_hexdigit(),
                    "fingerprint should contain only hex chars"
                );
            }

            // Check for collisions
            assert!(
                !fingerprints.contains(&fingerprint),
                "fingerprint collision detected for key {}: {}",
                i,
                fingerprint
            );
            fingerprints.insert(fingerprint);
        }

        // Test fingerprints of similar keys
        let base_key = derive_idempotency_key("test", 0, b"data");
        let similar_key = derive_idempotency_key("test", 1, b"data"); // Only epoch differs

        let fingerprint1 = key_fingerprint(&base_key);
        let fingerprint2 = key_fingerprint(&similar_key);

        assert!(
            !constant_time::ct_eq(&fingerprint1, &fingerprint2),
            "similar keys should have different fingerprints"
        );

        // Test fingerprints with identical first bytes (collision resistance)
        let mut collision_attempt_keys = Vec::new();
        for i in 0..1000 {
            let mut key_bytes = [0u8; 32];
            key_bytes[0] = 0xAA; // Force same first byte
            key_bytes[1] = (i & 0xFF) as u8;
            key_bytes[2] = ((i >> 8) & 0xFF) as u8;
            // Fill remaining bytes with pattern to ensure uniqueness
            for j in 3..32 {
                key_bytes[j] = ((i + j) & 0xFF) as u8;
            }

            let key = IdempotencyKey::from_bytes(key_bytes);
            collision_attempt_keys.push(key);
        }

        let mut collision_fingerprints = std::collections::BTreeSet::new();
        for key in collision_attempt_keys {
            let fingerprint = key_fingerprint(&key);
            assert!(
                !collision_fingerprints.contains(&fingerprint),
                "fingerprint collision in manufactured collision test"
            );
            collision_fingerprints.insert(fingerprint);
        }
    }

    #[test]
    fn test_negative_domain_separation_bypass_attempts() {
        let request_bytes = b"shared request data";
        let epoch = 1234567890;

        // Test domain separation with computation names that might bypass separation
        let binary_suffix_a = String::from_utf8_lossy(b"suffix\xFF").into_owned();
        let binary_suffix_b = String::from_utf8_lossy(b"suffix\xFE").into_owned();

        let separation_tests = [
            // Basic separation
            ("domain1", "domain2"),
            // Length-based confusion attempts
            ("abc", "ab\x01c"),       // Embedded length confusion
            ("test", "tes\x01t"),     // Embedded separator
            ("name", "nam\x00e"),     // Null byte injection
            ("compute", "comp\0ute"), // Null in middle
            // Prefix/suffix attempts
            ("prefix", "prefix_suffix"),            // Prefix extension
            ("test.compute", "test.compute.extra"), // Domain extension
            ("a", "aa"),                            // Doubling
            ("xyz", "xyza"),                        // Suffix addition
            // Unicode normalization bypass attempts
            ("café", "cafe\u{0301}"), // Combining character
            ("test", "test\u{200B}"), // Zero-width space
            ("name", "name\u{FEFF}"), // BOM suffix
            // Case and encoding variations
            ("Test", "test"),           // Case variation
            ("ASCII", "ASCII\u{0300}"), // Unicode combining
            // Delimiter confusion
            ("a|b", "a||b"), // Pipe confusion
            ("x,y", "x,,y"), // Comma confusion
            ("p:q", "p::q"), // Colon confusion
            // Binary patterns
            ("binary\x01\x02", "binary\x01\x03"), // Binary difference
            ("\x00prefix", "\x01prefix"),         // Binary prefix
            (binary_suffix_a.as_str(), binary_suffix_b.as_str()), // Binary suffix
        ];

        for (name1, name2) in separation_tests {
            let key1 = derive_idempotency_key(name1, epoch, request_bytes);
            let key2 = derive_idempotency_key(name2, epoch, request_bytes);

            // Domain separation should ensure different computation names produce different keys
            assert!(
                !constant_time::ct_eq(&key1.to_hex(), &key2.to_hex()),
                "computation names '{}' and '{}' should produce different keys (domain separation)",
                name1,
                name2
            );

            // Test the reverse direction as well (symmetry)
            let key2_reverse = derive_idempotency_key(name2, epoch, request_bytes);
            let key1_reverse = derive_idempotency_key(name1, epoch, request_bytes);

            assert_eq!(key1, key1_reverse, "key derivation should be deterministic");
            assert_eq!(key2, key2_reverse, "key derivation should be deterministic");
        }

        // Test with extremely similar computation names
        for i in 0..1000 {
            let name1 = format!("compute_{:03}", i);
            let name2 = format!("compute_{:03}", i + 1);

            let key1 = derive_idempotency_key(&name1, epoch, request_bytes);
            let key2 = derive_idempotency_key(&name2, epoch, request_bytes);

            assert!(
                !constant_time::ct_eq(&key1.to_hex(), &key2.to_hex()),
                "sequential computation names should produce different keys: {} vs {}",
                name1,
                name2
            );
        }
    }

    #[test]
    fn test_negative_derivation_input_length_prefix_attack() {
        let epoch = 1234567890;

        // Test length prefix confusion attacks
        // The derivation uses length prefixes to prevent injection
        let length_confusion_tests = [
            // Domain prefix confusion
            ("a", b"bc".as_slice()),
            ("ab", b"c".as_slice()),
            ("abc", b"".as_slice()),
            // Computation name vs request bytes confusion
            (
                "short",
                b"very_long_request_data_that_might_confuse_length_prefixing".as_slice(),
            ),
            (
                "very_long_computation_name_that_might_confuse",
                b"short".as_slice(),
            ),
            // Zero-length field tests
            ("", b"request".as_slice()),
            ("compute", b"".as_slice()),
            ("", b"".as_slice()),
            // Length boundary tests
            ("x", b"y".as_slice()),
            ("x".repeat(255).as_str(), b"y".as_slice()),
            ("x", &vec![b'y'; 255]),
            (&"x".repeat(65535), &vec![b'y'; 65535]),
        ];

        let mut derived_keys = Vec::new();

        for (computation_name, request_bytes) in length_confusion_tests {
            let key = derive_idempotency_key(computation_name, epoch, request_bytes);

            // Each unique input should produce a unique key
            for (existing_comp, existing_req, existing_key) in &derived_keys {
                if computation_name != *existing_comp || request_bytes != existing_req.as_slice() {
                    assert!(
                        !constant_time::ct_eq(&key.to_hex(), &existing_key.to_hex()),
                        "different inputs should produce different keys: ('{}', {:?}) vs ('{}', {:?})",
                        computation_name,
                        request_bytes,
                        existing_comp,
                        existing_req
                    );
                }
            }

            derived_keys.push((computation_name, request_bytes.to_vec(), key));
        }

        // Test that prepending/appending data to fields doesn't create collisions
        let base_comp = "test_compute";
        let base_req = b"test_request";
        let base_key = derive_idempotency_key(base_comp, epoch, base_req);

        // Prepend/append to computation name
        let prefixed_comp_key =
            derive_idempotency_key(&format!("prefix_{}", base_comp), epoch, base_req);
        let suffixed_comp_key =
            derive_idempotency_key(&format!("{}_suffix", base_comp), epoch, base_req);

        assert!(
            !constant_time::ct_eq(&base_key.to_hex(), &prefixed_comp_key.to_hex()),
            "prefixed computation name should produce different key"
        );
        assert!(
            !constant_time::ct_eq(&base_key.to_hex(), &suffixed_comp_key.to_hex()),
            "suffixed computation name should produce different key"
        );

        // Prepend/append to request bytes
        let mut prefixed_req = b"prefix_".to_vec();
        prefixed_req.extend_from_slice(base_req);
        let prefixed_req_key = derive_idempotency_key(base_comp, epoch, &prefixed_req);

        let mut suffixed_req = base_req.to_vec();
        suffixed_req.extend_from_slice(b"_suffix");
        let suffixed_req_key = derive_idempotency_key(base_comp, epoch, &suffixed_req);

        assert!(
            !constant_time::ct_eq(&base_key.to_hex(), &prefixed_req_key.to_hex()),
            "prefixed request should produce different key"
        );
        assert!(
            !constant_time::ct_eq(&base_key.to_hex(), &suffixed_req_key.to_hex()),
            "suffixed request should produce different key"
        );
    }
}
