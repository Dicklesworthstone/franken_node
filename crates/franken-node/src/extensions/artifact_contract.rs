//! bd-3ku8: Capability-carrying extension artifact admission and enforcement.
//!
//! Extension artifacts carry embedded capability contracts that declare the exact
//! set of capabilities the extension requires. Admission is fail-closed: missing or
//! invalid contracts cause immediate rejection. At runtime, the enforced capability
//! envelope must match the admitted contract without drift.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::capacity_defaults::aliases::MAX_TRUSTED_SIGNERS;

/// Report schema version for capability artifact vectors.
pub const SCHEMA_VERSION: &str = "capability-artifact-v1.0";

/// Reserved placeholder for unknown artifact identifiers.
const RESERVED_ARTIFACT_ID: &str = "<unknown>";
const MAX_TOKEN_BYTES: usize = crate::capacity_defaults::base::SMALL;
const MAX_CAPABILITIES_PER_CONTRACT: usize = crate::capacity_defaults::base::STANDARD;

fn is_reserved_artifact_id(artifact_id: &str) -> bool {
    artifact_id.trim() == RESERVED_ARTIFACT_ID
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn invalid_token_detail(field_name: &str, value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Some(format!("empty {field_name}"));
    }
    if trimmed != value {
        return Some(format!(
            "{field_name} contains leading or trailing whitespace"
        ));
    }
    if !value.is_ascii() {
        return Some(format!("{field_name} contains non-ASCII characters"));
    }
    if value.len() > MAX_TOKEN_BYTES {
        return Some(format!("{field_name} exceeds {MAX_TOKEN_BYTES} bytes"));
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Some(format!("{field_name} contains control characters"));
    }
    if value.starts_with('/') {
        return Some(format!("{field_name} starts with '/'"));
    }
    if value.contains('\\') {
        return Some(format!("{field_name} contains backslash"));
    }
    if value.split('/').any(|segment| segment == "..") {
        return Some(format!("{field_name} contains path traversal segment"));
    }
    None
}

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------
pub mod event_codes {
    pub const ARTIFACT_ADMISSION_START: &str = "ARTIFACT_ADMISSION_START";
    pub const ARTIFACT_CAPABILITY_VALIDATED: &str = "ARTIFACT_CAPABILITY_VALIDATED";
    pub const ARTIFACT_ADMISSION_ACCEPTED: &str = "ARTIFACT_ADMISSION_ACCEPTED";
    pub const ARTIFACT_ENFORCEMENT_CHECK: &str = "ARTIFACT_ENFORCEMENT_CHECK";
    pub const ARTIFACT_DRIFT_DETECTED: &str = "ARTIFACT_DRIFT_DETECTED";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------
pub mod error_codes {
    pub const ERR_ARTIFACT_MISSING_CONTRACT: &str = "ERR_ARTIFACT_MISSING_CONTRACT";
    pub const ERR_ARTIFACT_INVALID_CONTRACT: &str = "ERR_ARTIFACT_INVALID_CONTRACT";
    pub const ERR_ARTIFACT_INVALID_CAPABILITY: &str = "ERR_ARTIFACT_INVALID_CAPABILITY";
    pub const ERR_ARTIFACT_SIGNATURE_INVALID: &str = "ERR_ARTIFACT_SIGNATURE_INVALID";
    pub const ERR_ARTIFACT_SCHEMA_MISMATCH: &str = "ERR_ARTIFACT_SCHEMA_MISMATCH";
    pub const ERR_ARTIFACT_ENFORCEMENT_DRIFT: &str = "ERR_ARTIFACT_ENFORCEMENT_DRIFT";
    pub const ERR_ARTIFACT_ADMISSION_DENIED: &str = "ERR_ARTIFACT_ADMISSION_DENIED";
    pub const ERR_ARTIFACT_TRUSTED_SIGNER_CAPACITY: &str = "ERR_ARTIFACT_TRUSTED_SIGNER_CAPACITY";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------
pub mod invariants {
    /// Admission denies any artifact whose capability contract is absent or invalid.
    pub const INV_ARTIFACT_FAIL_CLOSED: &str = "INV-ARTIFACT-FAIL-CLOSED";
    /// Runtime envelope exactly matches the admitted capability set.
    pub const INV_ARTIFACT_CAPABILITY_ENVELOPE: &str = "INV-ARTIFACT-CAPABILITY-ENVELOPE";
    /// No drift between admitted contract and runtime enforcement.
    pub const INV_ARTIFACT_NO_DRIFT: &str = "INV-ARTIFACT-NO-DRIFT";
    /// Capability contracts must carry a valid signature.
    pub const INV_ARTIFACT_SIGNED_CONTRACT: &str = "INV-ARTIFACT-SIGNED-CONTRACT";
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// A single capability entry within a capability contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEntry {
    pub capability_id: String,
    pub scope: String,
    pub max_calls_per_epoch: u64,
}

/// An embedded capability contract carried by an extension artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityContract {
    pub contract_id: String,
    pub extension_id: String,
    pub capabilities: Vec<CapabilityEntry>,
    pub signer_id: String,
    pub signature: String,
    pub schema_version: String,
    pub issued_epoch_ms: u64,
}

/// An extension artifact that may or may not carry a capability contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionArtifact {
    pub artifact_id: String,
    pub extension_id: String,
    pub capability_contract: Option<CapabilityContract>,
    pub payload_hash: String,
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// Reason admission was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDenialReason {
    MissingContract,
    InvalidContract { detail: String },
    InvalidCapability { detail: String },
    SignatureInvalid,
    SchemaMismatch { expected: String, actual: String },
}

impl AdmissionDenialReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingContract => error_codes::ERR_ARTIFACT_MISSING_CONTRACT,
            Self::InvalidContract { .. } => error_codes::ERR_ARTIFACT_INVALID_CONTRACT,
            Self::InvalidCapability { .. } => error_codes::ERR_ARTIFACT_INVALID_CAPABILITY,
            Self::SignatureInvalid => error_codes::ERR_ARTIFACT_SIGNATURE_INVALID,
            Self::SchemaMismatch { .. } => error_codes::ERR_ARTIFACT_SCHEMA_MISMATCH,
        }
    }
}

/// Outcome of artifact admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOutcome {
    Accepted {
        contract_id: String,
        extension_id: String,
        event_code: String,
    },
    Denied {
        reason: AdmissionDenialReason,
        event_code: String,
    },
}

/// Configuration for artifact admission gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionConfig {
    pub expected_schema_version: String,
    pub trusted_signers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionConfigError {
    InvalidTrustedSigner { detail: String },
    TrustedSignerCapacityExceeded { capacity: usize },
}

impl AdmissionConfigError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidTrustedSigner { .. } => error_codes::ERR_ARTIFACT_INVALID_CONTRACT,
            Self::TrustedSignerCapacityExceeded { .. } => {
                error_codes::ERR_ARTIFACT_TRUSTED_SIGNER_CAPACITY
            }
        }
    }
}

impl std::fmt::Display for AdmissionConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTrustedSigner { detail } => {
                write!(f, "invalid trusted signer: {detail}")
            }
            Self::TrustedSignerCapacityExceeded { capacity } => {
                write!(
                    f,
                    "trusted signer registry at capacity ({capacity}); refusing to evict existing trusted signer"
                )
            }
        }
    }
}

impl std::error::Error for AdmissionConfigError {}

impl AdmissionConfig {
    pub fn new(expected_schema_version: impl Into<String>) -> Self {
        Self {
            expected_schema_version: expected_schema_version.into(),
            trusted_signers: Vec::new(),
        }
    }

    pub fn with_signer(
        &mut self,
        signer_id: impl Into<String>,
    ) -> Result<(), AdmissionConfigError> {
        let signer_id = signer_id.into();
        if let Some(detail) = invalid_token_detail("signer_id", &signer_id) {
            return Err(AdmissionConfigError::InvalidTrustedSigner { detail });
        }
        if self.trusted_signers.contains(&signer_id) {
            return Ok(());
        }
        if self.trusted_signers.len() >= MAX_TRUSTED_SIGNERS {
            return Err(AdmissionConfigError::TrustedSignerCapacityExceeded {
                capacity: MAX_TRUSTED_SIGNERS,
            });
        }
        self.trusted_signers.push(signer_id);
        Ok(())
    }
}

/// Admission gate for capability-carrying extension artifacts.
///
/// INV-ARTIFACT-FAIL-CLOSED: admission denies any artifact whose capability
/// contract is absent, malformed, or fails validation.
/// INV-ARTIFACT-SIGNED-CONTRACT: capability contracts must carry a valid signature.
pub struct AdmissionGate {
    config: AdmissionConfig,
}

impl AdmissionGate {
    pub fn new(config: AdmissionConfig) -> Self {
        Self { config }
    }

    /// Evaluate whether an extension artifact should be admitted.
    ///
    /// INV-ARTIFACT-FAIL-CLOSED: returns Denied on any validation failure.
    /// INV-ARTIFACT-SIGNED-CONTRACT: signature must verify against trusted signers.
    pub fn evaluate(&self, artifact: &ExtensionArtifact) -> AdmissionOutcome {
        // INV-ARTIFACT-FAIL-CLOSED: missing contract -> deny
        let contract = match &artifact.capability_contract {
            Some(c) => c,
            None => {
                return AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::MissingContract,
                    event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                };
            }
        };

        if let Some(detail) = invalid_token_detail("schema_version", &contract.schema_version) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { detail },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        // Schema version check
        if contract.schema_version != self.config.expected_schema_version {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SchemaMismatch {
                    expected: self.config.expected_schema_version.clone(),
                    actual: contract.schema_version.clone(),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if let Some(detail) = invalid_token_detail("contract_id", &contract.contract_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { detail },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if is_reserved_artifact_id(&contract.extension_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: format!(
                        "contract extension_id is reserved: {:?}",
                        contract.extension_id
                    ),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if let Some(detail) = invalid_token_detail("contract extension_id", &contract.extension_id)
        {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { detail },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if let Some(detail) = invalid_token_detail("signer_id", &contract.signer_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { detail },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if contract.issued_epoch_ms == 0 {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: "issued_epoch_ms must be > 0".to_string(),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if is_reserved_artifact_id(&artifact.artifact_id) {
            let reason = AdmissionDenialReason::InvalidContract {
                detail: format!("artifact_id is reserved: {:?}", artifact.artifact_id),
            };
            return AdmissionOutcome::Denied {
                event_code: reason.code().to_string(),
                reason,
            };
        }

        if let Some(detail) = invalid_token_detail("artifact_id", &artifact.artifact_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { detail },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if is_reserved_artifact_id(&artifact.extension_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: format!(
                        "artifact extension_id is reserved: {:?}",
                        artifact.extension_id
                    ),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if let Some(detail) = invalid_token_detail("artifact extension_id", &artifact.extension_id)
        {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { detail },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if contract.extension_id != artifact.extension_id {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: format!(
                        "contract extension_id '{}' does not match artifact extension_id '{}'",
                        contract.extension_id, artifact.extension_id
                    ),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if contract.signature.trim().is_empty() {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: "empty signature".to_string(),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if !is_hex_sha256(&contract.signature) {
            let reason = AdmissionDenialReason::InvalidContract {
                detail: "signature must be lowercase hex sha256".to_string(),
            };
            return AdmissionOutcome::Denied {
                event_code: reason.code().to_string(),
                reason,
            };
        }

        if contract.capabilities.is_empty() {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: "capability list is empty".to_string(),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if contract.capabilities.len() > MAX_CAPABILITIES_PER_CONTRACT {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: format!(
                        "capability list exceeds maximum of {MAX_CAPABILITIES_PER_CONTRACT}"
                    ),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if !is_hex_sha256(&artifact.payload_hash) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: "payload_hash must be lowercase hex sha256".to_string(),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        // Validate each capability entry
        let mut seen_ids = BTreeSet::new();
        for cap in &contract.capabilities {
            if let Some(detail) = invalid_token_detail("capability_id", &cap.capability_id) {
                return AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::InvalidCapability { detail },
                    event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                };
            }
            if let Some(detail) = invalid_token_detail("capability scope", &cap.scope) {
                return AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::InvalidCapability { detail },
                    event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                };
            }
            if !seen_ids.insert(cap.capability_id.clone()) {
                return AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::InvalidCapability {
                        detail: format!("duplicate capability_id '{}'", cap.capability_id),
                    },
                    event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                };
            }
            if cap.max_calls_per_epoch == 0 {
                return AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::InvalidCapability {
                        detail: format!(
                            "max_calls_per_epoch must be > 0 for '{}'",
                            cap.capability_id
                        ),
                    },
                    event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                };
            }
        }

        // INV-ARTIFACT-SIGNED-CONTRACT: verify signer is trusted and signature is valid
        if !self.config.trusted_signers.contains(&contract.signer_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if !verify_contract_signature(contract) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        AdmissionOutcome::Accepted {
            contract_id: contract.contract_id.clone(),
            extension_id: contract.extension_id.clone(),
            event_code: event_codes::ARTIFACT_ADMISSION_ACCEPTED.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime enforcement
// ---------------------------------------------------------------------------

/// Drift detection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftCheckResult {
    NoDrift {
        event_code: String,
    },
    DriftDetected {
        missing: Vec<String>,
        extra: Vec<String>,
        event_code: String,
    },
}

/// Runtime enforcement engine that verifies active capabilities match
/// the admitted contract envelope.
///
/// INV-ARTIFACT-CAPABILITY-ENVELOPE: runtime envelope exactly matches admitted set.
/// INV-ARTIFACT-NO-DRIFT: no drift between admitted contract and runtime enforcement.
pub struct EnforcementEngine {
    /// The admitted capability contract.
    admitted_capabilities: BTreeMap<String, CapabilityEntry>,
    contract_id: String,
}

impl EnforcementEngine {
    /// Create an enforcement engine from an admitted contract.
    pub fn from_contract(contract: &CapabilityContract) -> Self {
        let mut admitted = BTreeMap::new();
        for cap in &contract.capabilities {
            // Skip duplicates: first occurrence wins (INV-ARTIFACT-CAPABILITY-ENVELOPE).
            admitted
                .entry(cap.capability_id.clone())
                .or_insert_with(|| cap.clone());
        }
        Self {
            admitted_capabilities: admitted,
            contract_id: contract.contract_id.clone(),
        }
    }

    /// Check if a capability invocation is within the admitted envelope.
    ///
    /// INV-ARTIFACT-CAPABILITY-ENVELOPE: returns false if the capability is
    /// not in the admitted set.
    pub fn is_permitted(&self, capability_id: &str) -> bool {
        self.admitted_capabilities.contains_key(capability_id)
    }

    /// Perform a drift check between the admitted contract and the active capabilities.
    ///
    /// INV-ARTIFACT-NO-DRIFT: detects any mismatch between admitted and active sets.
    pub fn check_drift(&self, active_capabilities: &[String]) -> DriftCheckResult {
        let admitted_ids: Vec<String> = self.admitted_capabilities.keys().cloned().collect();
        let mut active_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut missing = BTreeSet::new();
        let mut extra = BTreeSet::new();

        for active_id in active_capabilities {
            let count = active_counts.entry(active_id.clone()).or_insert(0);
            *count = count.saturating_add(1);
            if !self.admitted_capabilities.contains_key(active_id) {
                extra.insert(active_id.clone());
            }
        }

        for (active_id, count) in &active_counts {
            if *count > 1 && self.admitted_capabilities.contains_key(active_id) {
                extra.insert(active_id.clone());
            }
        }

        for admitted_id in &admitted_ids {
            if !active_counts.contains_key(admitted_id) {
                missing.insert(admitted_id.clone());
            }
        }

        if missing.is_empty() && extra.is_empty() {
            DriftCheckResult::NoDrift {
                event_code: event_codes::ARTIFACT_ENFORCEMENT_CHECK.to_string(),
            }
        } else {
            DriftCheckResult::DriftDetected {
                missing: missing.into_iter().collect(),
                extra: extra.into_iter().collect(),
                event_code: event_codes::ARTIFACT_DRIFT_DETECTED.to_string(),
            }
        }
    }

    /// Return the contract ID of the admitted contract.
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// Return the count of admitted capabilities.
    pub fn admitted_count(&self) -> usize {
        self.admitted_capabilities.len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn update_len_prefixed(hasher: &mut Sha256, field: &str) {
    hasher.update(len_to_u64(field.len()).to_le_bytes());
    hasher.update(field.as_bytes());
}

fn is_hex_sha256(value: &str) -> bool {
    if value.len() != 64 {
        return false;
    }
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn verify_contract_signature(contract: &CapabilityContract) -> bool {
    let expected = compute_contract_signature(contract);
    crate::security::constant_time::ct_eq(&contract.signature, &expected)
}

/// Compute the expected signature for a capability contract.
pub fn compute_contract_signature(contract: &CapabilityContract) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"artifact_contract_digest_v1:");

    // Length-prefix each field individually to prevent delimiter collisions.
    for field in [
        contract.contract_id.as_str(),
        contract.extension_id.as_str(),
        contract.signer_id.as_str(),
        contract.schema_version.as_str(),
    ] {
        update_len_prefixed(&mut hasher, field);
    }

    // Bind the full capability envelope so post-sign tampering is rejected.
    hasher.update(len_to_u64(contract.capabilities.len()).to_le_bytes());
    for cap in &contract.capabilities {
        update_len_prefixed(&mut hasher, &cap.capability_id);
        update_len_prefixed(&mut hasher, &cap.scope);
        hasher.update(cap.max_calls_per_epoch.to_le_bytes());
    }
    hasher.update(contract.issued_epoch_ms.to_le_bytes());

    hex::encode(hasher.finalize())
}

/// Create a valid, signed capability contract for testing.
pub fn make_contract(
    contract_id: &str,
    extension_id: &str,
    capabilities: Vec<CapabilityEntry>,
    signer_id: &str,
    schema_version: &str,
    issued_epoch_ms: u64,
) -> CapabilityContract {
    let mut contract = CapabilityContract {
        contract_id: contract_id.to_string(),
        extension_id: extension_id.to_string(),
        capabilities,
        signer_id: signer_id.to_string(),
        signature: String::new(),
        schema_version: schema_version.to_string(),
        issued_epoch_ms,
    };
    contract.signature = compute_contract_signature(&contract);
    contract
}

/// Create a valid extension artifact with a signed contract for testing.
pub fn make_artifact(
    artifact_id: &str,
    extension_id: &str,
    contract: CapabilityContract,
) -> ExtensionArtifact {
    // Length-prefixed encoding prevents delimiter-collision ambiguity.
    let mut hasher = Sha256::new();
    hasher.update(b"artifact_contract_digest_v1:");
    for field in [artifact_id, extension_id] {
        hasher.update(len_to_u64(field.len()).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    let payload_hash = hex::encode(hasher.finalize());
    ExtensionArtifact {
        artifact_id: artifact_id.to_string(),
        extension_id: extension_id.to_string(),
        capability_contract: Some(contract),
        payload_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_capabilities() -> Vec<CapabilityEntry> {
        vec![
            CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 1000,
            },
            CapabilityEntry {
                capability_id: "net.egress".to_string(),
                scope: "network:egress".to_string(),
                max_calls_per_epoch: 100,
            },
        ]
    }

    fn test_contract() -> CapabilityContract {
        make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        )
    }

    fn test_gate() -> AdmissionGate {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        cfg.with_signer("signer-A")
            .expect("trusted signer registration should succeed");
        AdmissionGate::new(cfg)
    }

    #[test]
    fn trusted_signer_registration_rejects_capacity_overflow_without_eviction() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        for idx in 0..MAX_TRUSTED_SIGNERS {
            cfg.with_signer(format!("signer-{idx}"))
                .expect("signer fill should succeed");
        }

        let err = cfg
            .with_signer("overflow-signer")
            .expect_err("overflow signer must be rejected");
        assert_eq!(
            err,
            AdmissionConfigError::TrustedSignerCapacityExceeded {
                capacity: MAX_TRUSTED_SIGNERS
            }
        );
        assert_eq!(
            err.code(),
            error_codes::ERR_ARTIFACT_TRUSTED_SIGNER_CAPACITY
        );
        assert_eq!(cfg.trusted_signers.len(), MAX_TRUSTED_SIGNERS);
        assert_eq!(
            cfg.trusted_signers.first().map(String::as_str),
            Some("signer-0")
        );
        let expected_last = format!("signer-{}", MAX_TRUSTED_SIGNERS.saturating_sub(1));
        assert_eq!(
            cfg.trusted_signers.last().map(String::as_str),
            Some(expected_last.as_str())
        );
        assert!(!cfg.trusted_signers.iter().any(|s| s == "overflow-signer"));
    }

    #[test]
    fn trusted_signer_overflow_preserves_existing_admission_roots() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        cfg.with_signer("signer-A")
            .expect("initial signer registration should succeed");
        for idx in 1..MAX_TRUSTED_SIGNERS {
            cfg.with_signer(format!("signer-{idx}"))
                .expect("signer fill should succeed");
        }
        cfg.with_signer("signer-overflow")
            .expect_err("overflow signer must be rejected");

        let gate = AdmissionGate::new(cfg);
        let trusted_artifact = make_artifact("a-trusted", "ext-alpha", test_contract());
        let trusted_outcome = gate.evaluate(&trusted_artifact);
        assert!(matches!(trusted_outcome, AdmissionOutcome::Accepted { .. }));

        let overflow_contract = make_contract(
            "contract-overflow",
            "ext-alpha",
            test_capabilities(),
            "signer-overflow",
            SCHEMA_VERSION,
            20_000,
        );
        let overflow_artifact = make_artifact("a-overflow", "ext-alpha", overflow_contract);
        let overflow_outcome = gate.evaluate(&overflow_artifact);
        assert!(matches!(
            overflow_outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn trusted_signer_registration_is_idempotent() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        cfg.with_signer("signer-A")
            .expect("initial signer registration should succeed");
        cfg.with_signer("signer-A")
            .expect("duplicate signer registration should be ignored");
        assert_eq!(cfg.trusted_signers.len(), 1);
    }

    #[test]
    fn trusted_signer_registration_rejects_blank_signer() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        let err = cfg
            .with_signer("   ")
            .expect_err("blank signer registration must fail closed");
        assert!(matches!(
            &err,
            AdmissionConfigError::InvalidTrustedSigner { detail }
                if detail.contains("empty signer_id")
        ));
        assert_eq!(err.code(), error_codes::ERR_ARTIFACT_INVALID_CONTRACT);
        assert!(cfg.trusted_signers.is_empty());
    }

    #[test]
    fn trusted_signer_registration_rejects_whitespace_wrapped_signer() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        let err = cfg
            .with_signer(" signer-A ")
            .expect_err("whitespace signer registration must fail closed");
        assert!(matches!(
            &err,
            AdmissionConfigError::InvalidTrustedSigner { detail }
                if detail.contains("leading or trailing whitespace")
        ));
        assert!(cfg.trusted_signers.is_empty());
    }

    #[test]
    fn trusted_signer_registration_rejects_path_like_signers() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        for signer in ["../signer-A", "/signer-A", "signer\\A", "signer\0A"] {
            let err = cfg
                .with_signer(signer)
                .expect_err("path-like signer registration must fail closed");
            assert!(matches!(
                &err,
                AdmissionConfigError::InvalidTrustedSigner { .. }
            ));
        }
        assert!(cfg.trusted_signers.is_empty());
    }

    #[test]
    fn admission_rejects_missing_contract() {
        let gate = test_gate();
        let artifact = ExtensionArtifact {
            artifact_id: "a1".to_string(),
            extension_id: "ext-alpha".to_string(),
            capability_contract: None,
            payload_hash: "h1".to_string(),
        };
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::MissingContract,
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_schema_mismatch() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            "wrong-schema",
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SchemaMismatch { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_empty_schema_version() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            "",
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_schema_version_with_whitespace() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            " capability-artifact-v1.0 ",
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_zero_issued_epoch_ms() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            0,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_contract_id_with_whitespace() {
        let gate = test_gate();
        let contract = make_contract(
            " contract-1 ",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_empty_contract_id() {
        let gate = test_gate();
        let contract = make_contract(
            "",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected empty contract_id to be denied");
            return;
        };
        assert!(detail.contains("empty contract_id"));
    }

    #[test]
    fn admission_rejects_contract_extension_id_with_whitespace() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            " ext-alpha ",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(
                false,
                "expected whitespace contract extension_id to be denied"
            );
            return;
        };
        assert!(detail.contains("contract extension_id contains"));
    }

    #[test]
    fn admission_rejects_extension_id_mismatch() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact("a1", "ext-beta", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_empty_signer_id() {
        let gate = test_gate();
        let mut contract = test_contract();
        contract.signer_id.clear();
        contract.signature = compute_contract_signature(&contract);
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_signer_id_with_whitespace() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            " signer-A ",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected whitespace signer_id to be denied");
            return;
        };
        assert!(detail.contains("signer_id contains"));
    }

    #[test]
    fn admission_rejects_empty_signature() {
        let gate = test_gate();
        let mut contract = test_contract();
        contract.signature.clear();
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_non_hex_signature() {
        let gate = test_gate();
        let mut contract = test_contract();
        contract.signature = "not-hex".to_string();
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_uppercase_signature() {
        let gate = test_gate();
        let mut contract = test_contract();
        contract.signature = "A".repeat(64);
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected uppercase signature to be denied");
            return;
        };
        assert!(detail.contains("signature must be lowercase hex sha256"));
    }

    #[test]
    fn admission_rejects_empty_capability_list() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            Vec::new(),
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_missing_artifact_id() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        artifact.artifact_id.clear();
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_artifact_id_with_whitespace() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact(" a1 ", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected whitespace artifact_id to be denied");
            return;
        };
        assert!(detail.contains("artifact_id contains"));
    }

    #[test]
    fn admission_rejects_overlong_artifact_id() {
        let gate = test_gate();
        let contract = test_contract();
        let overlong_id = "a".repeat(MAX_TOKEN_BYTES.saturating_add(1));
        let artifact = make_artifact(&overlong_id, "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected overlong artifact_id to be denied");
            return;
        };
        assert!(detail.contains("artifact_id exceeds"));
    }

    #[test]
    fn admission_rejects_reserved_artifact_id() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact("<unknown>", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected reserved artifact_id to be denied");
            return;
        };
        assert!(detail.contains("reserved"));

        let contract = test_contract();
        let artifact = make_artifact(" <unknown> ", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected reserved artifact_id to be denied");
            return;
        };
        assert!(detail.contains("reserved"));
    }

    #[test]
    fn admission_rejects_empty_artifact_extension_id() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact("a1", "", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected empty artifact extension_id to be denied");
            return;
        };
        assert!(detail.contains("empty artifact extension_id"));
    }

    #[test]
    fn admission_rejects_artifact_extension_id_with_whitespace() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact("a1", " ext-alpha ", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(
                false,
                "expected whitespace artifact extension_id to be denied"
            );
            return;
        };
        assert!(detail.contains("artifact extension_id contains"));
    }

    #[test]
    fn admission_rejects_reserved_extension_id() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact("a1", "<unknown>", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected reserved extension_id to be denied");
            return;
        };
        assert!(detail.contains("reserved"));

        let contract = test_contract();
        let artifact = make_artifact("a1", " <unknown> ", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected reserved extension_id to be denied");
            return;
        };
        assert!(detail.contains("reserved"));
    }

    #[test]
    fn admission_rejects_invalid_payload_hash() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        artifact.payload_hash = "not-hex".to_string();
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_uppercase_payload_hash() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        artifact.payload_hash = "A".repeat(64);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_short_payload_hash() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        artifact.payload_hash = "a".repeat(63);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected short payload_hash to be denied");
            return;
        };
        assert!(detail.contains("payload_hash must be lowercase hex sha256"));
    }

    #[test]
    fn admission_rejects_invalid_capability_empty_id() {
        let gate = test_gate();
        let caps = vec![CapabilityEntry {
            capability_id: "".to_string(),
            scope: "filesystem:read".to_string(),
            max_calls_per_epoch: 100,
        }];
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidCapability { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_whitespace_capability_fields() {
        let gate = test_gate();
        let caps = vec![
            CapabilityEntry {
                capability_id: "   ".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 100,
            },
            CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "   ".to_string(),
                max_calls_per_epoch: 100,
            },
        ];
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidCapability { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_capability_fields_with_surrounding_whitespace() {
        let gate = test_gate();
        let caps = vec![CapabilityEntry {
            capability_id: " fs.read ".to_string(),
            scope: "filesystem:read".to_string(),
            max_calls_per_epoch: 100,
        }];
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidCapability { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_duplicate_capability_ids() {
        let gate = test_gate();
        let caps = vec![
            CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 100,
            },
            CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:metadata".to_string(),
                max_calls_per_epoch: 100,
            },
        ];
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidCapability { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected duplicate capability_id to be denied");
            return;
        };
        assert!(detail.contains("duplicate capability_id"));
    }

    #[test]
    fn admission_rejects_invalid_capability_zero_calls() {
        let gate = test_gate();
        let caps = vec![CapabilityEntry {
            capability_id: "fs.read".to_string(),
            scope: "filesystem:read".to_string(),
            max_calls_per_epoch: 0,
        }];
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidCapability { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_untrusted_signer() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "untrusted-signer",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_tampered_signature() {
        let gate = test_gate();
        let mut contract = test_contract();
        contract.signature = "tampered-sig".to_string();
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_scope_tampering_after_signing() {
        let gate = test_gate();
        let mut contract = test_contract();
        contract.capabilities[0].scope = "filesystem:write".to_string();
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_call_budget_tampering_after_signing() {
        let gate = test_gate();
        let mut contract = test_contract();
        contract.capabilities[0].max_calls_per_epoch = 9_999;
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn admission_accepts_valid_artifact() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(outcome, AdmissionOutcome::Accepted { .. }));
    }

    #[test]
    fn enforcement_permits_admitted_capability() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        assert!(engine.is_permitted("fs.read"));
        assert!(engine.is_permitted("net.egress"));
        assert!(!engine.is_permitted("fs.write"));
    }

    #[test]
    fn enforcement_rejects_unadmitted_capability() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        assert!(!engine.is_permitted("crypto.sign"));
    }

    #[test]
    fn drift_check_no_drift() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec!["fs.read".to_string(), "net.egress".to_string()];
        let result = engine.check_drift(&active);
        assert!(matches!(result, DriftCheckResult::NoDrift { .. }));
    }

    #[test]
    fn drift_check_detects_missing_capabilities() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec!["fs.read".to_string()]; // missing net.egress
        let result = engine.check_drift(&active);
        let DriftCheckResult::DriftDetected { missing, extra, .. } = result else {
            assert!(false, "expected drift detected");
            return;
        };
        assert!(missing.contains(&"net.egress".to_string()));
        assert!(extra.is_empty());
    }

    #[test]
    fn drift_check_detects_extra_capabilities() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec![
            "fs.read".to_string(),
            "net.egress".to_string(),
            "crypto.sign".to_string(),
        ];
        let result = engine.check_drift(&active);
        let DriftCheckResult::DriftDetected { missing, extra, .. } = result else {
            assert!(false, "expected drift detected");
            return;
        };
        assert!(missing.is_empty());
        assert!(extra.contains(&"crypto.sign".to_string()));
    }

    #[test]
    fn drift_check_detects_duplicate_capabilities() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec![
            "fs.read".to_string(),
            "fs.read".to_string(),
            "net.egress".to_string(),
        ];
        let result = engine.check_drift(&active);
        let DriftCheckResult::DriftDetected { missing, extra, .. } = result else {
            assert!(false, "expected drift detected");
            return;
        };
        assert!(missing.is_empty());
        assert!(extra.contains(&"fs.read".to_string()));
    }

    #[test]
    fn drift_check_detects_both_missing_and_extra() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec!["crypto.sign".to_string()];
        let result = engine.check_drift(&active);
        let DriftCheckResult::DriftDetected { missing, extra, .. } = result else {
            assert!(false, "expected drift detected");
            return;
        };
        assert!(!missing.is_empty());
        assert!(!extra.is_empty());
    }

    #[test]
    fn contract_signature_is_deterministic() {
        let c1 = test_contract();
        let c2 = test_contract();
        assert!(crate::security::constant_time::ct_eq(
            &c1.signature,
            &c2.signature,
        ));
    }

    #[test]
    fn len_to_u64_preserves_representable_lengths() {
        assert_eq!(len_to_u64(0), 0);
        assert_eq!(len_to_u64(64), 64);
        assert_eq!(
            len_to_u64(usize::MAX),
            u64::try_from(usize::MAX).unwrap_or(u64::MAX)
        );
    }

    #[test]
    fn contract_signature_length_prefixes_top_level_fields() {
        let left = make_contract(
            "ab",
            "c",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let right = make_contract(
            "a",
            "bc",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );

        assert!(!crate::security::constant_time::ct_eq(
            &left.signature,
            &right.signature,
        ));
    }

    #[test]
    fn contract_signature_length_prefixes_capability_fields() {
        let left = make_contract(
            "contract-prefix",
            "ext-alpha",
            vec![CapabilityEntry {
                capability_id: "ab".to_string(),
                scope: "c".to_string(),
                max_calls_per_epoch: 1,
            }],
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let right = make_contract(
            "contract-prefix",
            "ext-alpha",
            vec![CapabilityEntry {
                capability_id: "a".to_string(),
                scope: "bc".to_string(),
                max_calls_per_epoch: 1,
            }],
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );

        assert!(!crate::security::constant_time::ct_eq(
            &left.signature,
            &right.signature,
        ));
    }

    #[test]
    fn artifact_payload_hash_length_prefixes_identifier_fields() {
        let contract = test_contract();
        let left = make_artifact("ab", "c", contract.clone());
        let right = make_artifact("a", "bc", contract);

        assert!(!crate::security::constant_time::ct_eq(
            &left.payload_hash,
            &right.payload_hash,
        ));
    }

    #[test]
    fn admitted_count_matches_capabilities() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        assert_eq!(engine.admitted_count(), 2);
    }

    fn assert_json_rejected<T>(json: &str)
    where
        T: serde::de::DeserializeOwned,
    {
        assert!(
            serde_json::from_str::<T>(json).is_err(),
            "malformed json should be rejected: {json}"
        );
    }

    #[test]
    fn serde_rejects_capability_entry_string_call_budget() {
        assert_json_rejected::<CapabilityEntry>(
            r#"{
                "capability_id": "fs.read",
                "scope": "filesystem:read",
                "max_calls_per_epoch": "100"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_capability_contract_object_capabilities() {
        assert_json_rejected::<CapabilityContract>(
            r#"{
                "contract_id": "contract-1",
                "extension_id": "ext-alpha",
                "capabilities": {"capability_id": "fs.read"},
                "signer_id": "signer-A",
                "signature": "abc",
                "schema_version": "capability-artifact-v1.0",
                "issued_epoch_ms": 10000
            }"#,
        );
    }

    #[test]
    fn serde_rejects_capability_contract_missing_signature() {
        assert_json_rejected::<CapabilityContract>(
            r#"{
                "contract_id": "contract-1",
                "extension_id": "ext-alpha",
                "capabilities": [],
                "signer_id": "signer-A",
                "schema_version": "capability-artifact-v1.0",
                "issued_epoch_ms": 10000
            }"#,
        );
    }

    #[test]
    fn serde_rejects_extension_artifact_string_contract() {
        assert_json_rejected::<ExtensionArtifact>(
            r#"{
                "artifact_id": "artifact-1",
                "extension_id": "ext-alpha",
                "capability_contract": "contract-1",
                "payload_hash": "abc"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_unknown_admission_denial_reason_variant() {
        assert_json_rejected::<AdmissionDenialReason>(r#""policy_timeout""#);
    }

    #[test]
    fn serde_rejects_admission_outcome_denied_missing_reason() {
        assert_json_rejected::<AdmissionOutcome>(
            r#"{
                "denied": {
                    "event_code": "ERR_ARTIFACT_ADMISSION_DENIED"
                }
            }"#,
        );
    }

    #[test]
    fn serde_rejects_admission_outcome_accepted_numeric_contract_id() {
        assert_json_rejected::<AdmissionOutcome>(
            r#"{
                "accepted": {
                    "contract_id": 7,
                    "extension_id": "ext-alpha",
                    "event_code": "ARTIFACT_ADMISSION_ACCEPTED"
                }
            }"#,
        );
    }

    #[test]
    fn serde_rejects_admission_config_string_trusted_signers() {
        assert_json_rejected::<AdmissionConfig>(
            r#"{
                "expected_schema_version": "capability-artifact-v1.0",
                "trusted_signers": "signer-A"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_unknown_admission_config_error_variant() {
        assert_json_rejected::<AdmissionConfigError>(r#"{"untrusted_signer": {"capacity": 4096}}"#);
    }

    // ---------------------------------------------------------------------------
    // Comprehensive negative-path tests
    // ---------------------------------------------------------------------------

    mod artifact_contract_comprehensive_negative_tests {
        use super::*;
        use crate::security::constant_time;

        #[test]
        fn identifier_injection_in_artifact_identifiers() {
            let gate = test_gate();
            let malicious_identifiers = [
                "artifact\u{202E}deilav", // RLO override
                "ext\u{200B}ension",      // Zero-width space
                "id\u{FEFF}valid",        // BOM insertion
                "name\u{2028}break",      // Line separator
                "\u{1F4A9}payload",       // Non-ASCII emoji
                "test\u{0000}null",       // Null byte injection
                "../artifact",            // Path traversal segment
                "/artifact",              // Absolute path marker
                "artifact\\id",           // Windows path separator
            ];

            for malicious_id in malicious_identifiers {
                let contract = make_contract(
                    malicious_id,
                    "ext-alpha",
                    test_capabilities(),
                    "signer-A",
                    SCHEMA_VERSION,
                    10_000,
                );
                let artifact = make_artifact(malicious_id, "ext-alpha", contract);
                let outcome = gate.evaluate(&artifact);
                assert!(
                    matches!(outcome, AdmissionOutcome::Denied { .. }),
                    "Identifier injection in '{malicious_id:?}' should be rejected"
                );
            }
        }

        #[test]
        fn arithmetic_overflow_protection_in_counters() {
            let gate = test_gate();

            // Test max_calls_per_epoch overflow boundaries
            let overflow_capabilities = vec![
                CapabilityEntry {
                    capability_id: "fs.read".to_string(),
                    scope: "filesystem:read".to_string(),
                    max_calls_per_epoch: u64::MAX,
                },
                CapabilityEntry {
                    capability_id: "net.egress".to_string(),
                    scope: "network:egress".to_string(),
                    max_calls_per_epoch: u64::MAX.saturating_sub(1),
                },
            ];

            let contract = make_contract(
                "overflow-test",
                "ext-alpha",
                overflow_capabilities,
                "signer-A",
                SCHEMA_VERSION,
                u64::MAX, // Test issued_epoch_ms overflow boundary
            );
            let artifact = make_artifact("overflow-artifact", "ext-alpha", contract);

            // Should handle extreme values without panic
            let outcome = gate.evaluate(&artifact);
            // Even with extreme values, validation should proceed normally
            assert!(matches!(
                outcome,
                AdmissionOutcome::Accepted { .. } | AdmissionOutcome::Denied { .. }
            ));
        }

        #[test]
        fn memory_exhaustion_through_massive_capability_lists() {
            let gate = test_gate();

            // Create a massive capability list to test memory bounds
            let mut massive_capabilities = Vec::new();
            for i in 0..10_000 {
                massive_capabilities.push(CapabilityEntry {
                    capability_id: format!("capability_{i}"),
                    scope: format!("scope_{i}"),
                    max_calls_per_epoch: 1,
                });
            }

            let contract = make_contract(
                "memory-test",
                "ext-alpha",
                massive_capabilities,
                "signer-A",
                SCHEMA_VERSION,
                10_000,
            );
            let artifact = make_artifact("memory-artifact", "ext-alpha", contract);

            let outcome = gate.evaluate(&artifact);
            assert!(matches!(outcome, AdmissionOutcome::Denied { .. }));

            // Test enforcement engine with massive admitted set
            if let AdmissionOutcome::Accepted { .. } = outcome {
                let engine = EnforcementEngine::from_contract(&contract);
                assert!(engine.admitted_count() <= 10_000);

                // Test drift check with massive active list
                let mut massive_active = Vec::new();
                for i in 0..5_000 {
                    massive_active.push(format!("capability_{i}"));
                }

                let drift_result = engine.check_drift(&massive_active);
                assert!(matches!(
                    drift_result,
                    DriftCheckResult::DriftDetected { .. } | DriftCheckResult::NoDrift { .. }
                ));
            }
        }

        #[test]
        fn trusted_signer_capacity_boundary_testing() {
            let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);

            // Fill to exact capacity
            for i in 0..MAX_TRUSTED_SIGNERS {
                cfg.with_signer(format!("signer-{i}"))
                    .expect("should fit within capacity");
            }

            // Test boundary conditions
            assert_eq!(cfg.trusted_signers.len(), MAX_TRUSTED_SIGNERS);

            // Test overflow rejection
            let overflow_result = cfg.with_signer("overflow-signer");
            assert!(overflow_result.is_err());
            assert_eq!(cfg.trusted_signers.len(), MAX_TRUSTED_SIGNERS);

            // Test that existing signers remain functional
            let gate = AdmissionGate::new(cfg);
            let contract = make_contract(
                "boundary-test",
                "ext-alpha",
                test_capabilities(),
                "signer-0", // Should be the first signer
                SCHEMA_VERSION,
                10_000,
            );
            let artifact = make_artifact("boundary-artifact", "ext-alpha", contract);
            let outcome = gate.evaluate(&artifact);
            assert!(matches!(outcome, AdmissionOutcome::Accepted { .. }));
        }

        #[test]
        fn signature_tampering_attack_vectors() {
            let gate = test_gate();

            // Create a valid contract first
            let base_contract = test_contract();
            let original_sig = base_contract.signature.clone();

            // Test various signature tampering attacks
            let tampering_vectors = [
                "0".repeat(64),                                 // All zeros
                "f".repeat(64),                                 // All max values
                original_sig[1..].to_string() + "0",            // Bit shift
                original_sig.chars().rev().collect::<String>(), // Reverse
                original_sig.replace("a", "b"),                 // Single char mutation
                format!("{original_sig}extra"),                 // Append data
                original_sig[..32].to_string(),                 // Truncate
            ];

            for tampered_sig in tampering_vectors {
                if tampered_sig.len() == 64
                    && !crate::security::constant_time::ct_eq(&tampered_sig, &original_sig)
                {
                    let mut contract = base_contract.clone();
                    contract.signature = tampered_sig.clone();
                    let artifact = make_artifact("tamper-test", "ext-alpha", contract);

                    let outcome = gate.evaluate(&artifact);
                    assert!(
                        matches!(
                            outcome,
                            AdmissionOutcome::Denied {
                                reason: AdmissionDenialReason::SignatureInvalid
                                    | AdmissionDenialReason::InvalidContract { .. },
                                ..
                            }
                        ),
                        "Tampered signature '{tampered_sig}' should be rejected"
                    );
                }
            }
        }

        #[test]
        fn capability_injection_edge_cases() {
            let gate = test_gate();

            // Test capability injection through scope manipulation
            let injection_capabilities = vec![
                CapabilityEntry {
                    capability_id: "fs.read\nfs.write".to_string(), // Newline injection
                    scope: "filesystem:read".to_string(),
                    max_calls_per_epoch: 100,
                },
                CapabilityEntry {
                    capability_id: "net.egress".to_string(),
                    scope: "network:egress\x00admin".to_string(), // Null byte injection in scope
                    max_calls_per_epoch: 100,
                },
                CapabilityEntry {
                    capability_id: "../fs.admin".to_string(), // Path traversal in capability ID
                    scope: "filesystem:admin".to_string(),
                    max_calls_per_epoch: 100,
                },
            ];

            let contract = make_contract(
                "injection-test",
                "ext-alpha",
                injection_capabilities,
                "signer-A",
                SCHEMA_VERSION,
                10_000,
            );
            let artifact = make_artifact("injection-artifact", "ext-alpha", contract);

            // These should all be rejected due to invalid characters
            let outcome = gate.evaluate(&artifact);
            assert!(matches!(
                outcome,
                AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::InvalidCapability { .. },
                    ..
                }
            ));
        }

        #[test]
        fn drift_detection_under_extreme_conditions() {
            let contract = test_contract();
            let engine = EnforcementEngine::from_contract(&contract);

            // Test with massive duplicate active capabilities
            let mut duplicate_active = Vec::new();
            for _ in 0..1000 {
                duplicate_active.push("fs.read".to_string());
                duplicate_active.push("net.egress".to_string());
            }

            let drift_result = engine.check_drift(&duplicate_active);
            if let DriftCheckResult::DriftDetected { extra, .. } = drift_result {
                assert!(extra.contains(&"fs.read".to_string()));
                assert!(extra.contains(&"net.egress".to_string()));
            }

            // Test with empty active capabilities
            let empty_result = engine.check_drift(&[]);
            if let DriftCheckResult::DriftDetected { missing, extra, .. } = empty_result {
                assert!(!missing.is_empty());
                assert!(extra.is_empty());
            }

            // Test with massive number of unique extra capabilities
            let mut massive_extra = vec!["fs.read".to_string(), "net.egress".to_string()];
            for i in 0..5000 {
                massive_extra.push(format!("extra_capability_{i}"));
            }

            let massive_result = engine.check_drift(&massive_extra);
            assert!(matches!(
                massive_result,
                DriftCheckResult::DriftDetected { .. }
            ));
        }

        #[test]
        fn serialization_boundary_attacks() {
            // Test contract signature computation against length-extension attacks
            let base_contract = test_contract();

            // Create contracts with field content designed to cause delimiter confusion
            let malicious_contracts = [
                make_contract(
                    "contract\x00id",
                    "ext-alpha",
                    test_capabilities(),
                    "signer-A",
                    SCHEMA_VERSION,
                    10_000,
                ),
                make_contract(
                    "contract",
                    "ext\x00alpha",
                    test_capabilities(),
                    "signer-A",
                    SCHEMA_VERSION,
                    10_000,
                ),
                make_contract(
                    "contract",
                    "ext-alpha",
                    test_capabilities(),
                    "signer\x00A",
                    SCHEMA_VERSION,
                    10_000,
                ),
            ];

            // All should have different signatures due to length prefixing
            for (i, contract) in malicious_contracts.iter().enumerate() {
                assert!(
                    !crate::security::constant_time::ct_eq(
                        &contract.signature,
                        &base_contract.signature,
                    ),
                    "Malicious contract {i} should have different signature due to null bytes"
                );
            }

            // Test that contracts with same logical content but different field lengths produce different signatures
            let short_contract = make_contract(
                "a",
                "b",
                vec![CapabilityEntry {
                    capability_id: "x".to_string(),
                    scope: "y".to_string(),
                    max_calls_per_epoch: 1,
                }],
                "c",
                SCHEMA_VERSION,
                1,
            );

            let long_contract = make_contract(
                "aaaa",
                "bbbb",
                vec![CapabilityEntry {
                    capability_id: "xxxx".to_string(),
                    scope: "yyyy".to_string(),
                    max_calls_per_epoch: 1,
                }],
                "cccc",
                SCHEMA_VERSION,
                1,
            );

            assert!(
                !crate::security::constant_time::ct_eq(
                    &short_contract.signature,
                    &long_contract.signature,
                ),
                "Contracts with different field lengths should have different signatures"
            );
        }

        #[test]
        fn concurrent_admission_operations_and_hash_collision_resistance() {
            let gate = test_gate();

            // Test hash collision resistance by creating many similar contracts
            let mut signatures = BTreeSet::new();

            for i in 0..1000 {
                let epoch_offset = len_to_u64(i);
                let contract = make_contract(
                    &format!("contract-{i}"),
                    "ext-alpha",
                    vec![CapabilityEntry {
                        capability_id: format!("cap-{i}"),
                        scope: format!("scope-{i}"),
                        max_calls_per_epoch: epoch_offset.saturating_add(1),
                    }],
                    "signer-A",
                    SCHEMA_VERSION,
                    10_000_u64.saturating_add(epoch_offset),
                );

                // Each contract should have a unique signature
                assert!(
                    signatures.insert(contract.signature.clone()),
                    "Contract {i} produced a signature collision"
                );

                let artifact = make_artifact(&format!("artifact-{i}"), "ext-alpha", contract);
                let outcome = gate.evaluate(&artifact);
                assert!(matches!(outcome, AdmissionOutcome::Accepted { .. }));
            }

            // Verify we generated the expected number of unique signatures
            assert_eq!(signatures.len(), 1000, "Should have 1000 unique signatures");

            // Test that modifying any single field changes the signature
            let base = make_contract(
                "base",
                "ext-alpha",
                test_capabilities(),
                "signer-A",
                SCHEMA_VERSION,
                10_000,
            );
            let modified = make_contract(
                "base-modified",
                "ext-alpha",
                test_capabilities(),
                "signer-A",
                SCHEMA_VERSION,
                10_000,
            );

            assert!(
                !crate::security::constant_time::ct_eq(&base.signature, &modified.signature),
                "Single character change should produce different signature"
            );
        }
    }
}
