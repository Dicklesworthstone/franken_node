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
        output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        output.extend_from_slice(bytes);
    }

    fn canonical_input(
        &self,
        computation_name: &str,
        epoch: u64,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, IdempotencyError> {
        if computation_name.is_empty() {
            return Err(IdempotencyError::EmptyComputationName);
        }

        let mut input = Vec::with_capacity(
            self.domain_prefix.len() + computation_name.len() + request_bytes.len() + 32,
        );
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
    let digest = Sha256::digest([b"idempotency_fingerprint_v1:" as &[u8], key.as_bytes()].concat());
    hex::encode(digest)[..16].to_string()
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
    fn empty_domain_prefix_is_rejected() {
        let err = IdempotencyKeyDeriver::new(&[]).unwrap_err();
        assert!(matches!(err, IdempotencyError::EmptyDomainPrefix));
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
}
