//! bd-3ku8: Capability-carrying extension artifact admission and enforcement.
//!
//! Extension artifacts carry embedded capability contracts that declare the exact
//! set of capabilities the extension requires. Admission is fail-closed: missing or
//! invalid contracts cause immediate rejection. At runtime, the enforced capability
//! envelope must match the admitted contract without drift.

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::capacity_defaults::aliases::MAX_TRUSTED_SIGNERS;
use crate::capacity_defaults::bounded_input::{
    self, AUDIT_BOUNDED_INPUT_REJECTED, BoundedInputPolicy,
};
use crate::supply_chain::artifact_signing::{sign_bytes, verify_signature};
use crate::supply_chain::trust_card::{RevocationStatus, TrustCardRegistry};

type HmacSha256 = Hmac<Sha256>;

/// Report schema version for capability artifact vectors.
pub const SCHEMA_VERSION: &str = "capability-artifact-v1.0";
/// Schema version for Macaroon-style monotonically attenuated capability envelopes.
pub const MACAROON_ENVELOPE_SCHEMA: &str = "franken-node/macaroon-capability-envelope/v1";

const CONTRACT_SIGNATURE_PREFIX: &str = "ed25519-v1:";
const CONTRACT_SIGNATURE_DOMAIN: &[u8] = b"franken-node/capability-contract-signature/v1:";
const MACAROON_ROOT_DOMAIN: &[u8] = b"franken-node/macaroon-capability-root/v1:";
const MACAROON_CAVEAT_DOMAIN: &[u8] = b"franken-node/macaroon-capability-caveat/v1:";
const MAX_CAVEATS_PER_ENVELOPE: usize = 64;
const MAX_CAVEAT_SET_ENTRIES: usize = 128;
const MAX_CAVEAT_PATH_BYTES: usize = 512;

/// Reserved placeholder for unknown artifact identifiers.
const RESERVED_ARTIFACT_ID: &str = "<unknown>";
const DEFAULT_EXTENSION_VERSION: &str = "1.0.0";
const MAX_TOKEN_BYTES: usize = crate::capacity_defaults::base::SMALL;
const MAX_CAPABILITIES_PER_CONTRACT: usize = crate::capacity_defaults::base::STANDARD;
/// Shared bounded-input policy for artifact and contract token fields.
pub const ARTIFACT_TOKEN_INPUT_POLICY: BoundedInputPolicy = BoundedInputPolicy::new(
    "extensions.artifact_contract",
    "token_field",
    MAX_TOKEN_BYTES,
    error_codes::ERR_ARTIFACT_INVALID_CONTRACT,
    AUDIT_BOUNDED_INPUT_REJECTED,
    "reject overlong artifact identifiers before admission hashing or comparison",
);
/// Shared bounded-input policy for capability contract fanout.
pub const ARTIFACT_CAPABILITY_LIST_POLICY: BoundedInputPolicy = BoundedInputPolicy::new(
    "extensions.artifact_contract",
    "capabilities",
    MAX_CAPABILITIES_PER_CONTRACT,
    error_codes::ERR_ARTIFACT_INVALID_CONTRACT,
    AUDIT_BOUNDED_INPUT_REJECTED,
    "bound capability list validation before duplicate scans and signature checks",
);

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
    if let Err(violation) = bounded_input::validate_len(
        "extensions.artifact_contract",
        field_name,
        value.len(),
        MAX_TOKEN_BYTES,
        error_codes::ERR_ARTIFACT_INVALID_CONTRACT,
        AUDIT_BOUNDED_INPUT_REJECTED,
    ) {
        return Some(format!(
            "{field_name} exceeds {MAX_TOKEN_BYTES} bytes; {violation}"
        ));
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
    pub const ERR_ARTIFACT_TRUST_REVOKED: &str = "ERR_ARTIFACT_TRUST_REVOKED";
    pub const ERR_ARTIFACT_ENFORCEMENT_DRIFT: &str = "ERR_ARTIFACT_ENFORCEMENT_DRIFT";
    pub const ERR_ARTIFACT_ADMISSION_DENIED: &str = "ERR_ARTIFACT_ADMISSION_DENIED";
    pub const ERR_ARTIFACT_TRUSTED_SIGNER_CAPACITY: &str = "ERR_ARTIFACT_TRUSTED_SIGNER_CAPACITY";
    pub const ERR_ARTIFACT_PRIVILEGE_AMPLIFICATION: &str = "ERR_ARTIFACT_PRIVILEGE_AMPLIFICATION";
    pub const ERR_ARTIFACT_MACAROON_TAG_MISMATCH: &str = "ERR_ARTIFACT_MACAROON_TAG_MISMATCH";
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityContract {
    pub contract_id: String,
    pub extension_id: String,
    pub extension_version: String,
    pub artifact_id: String,
    pub payload_hash: String,
    pub capabilities: Vec<CapabilityEntry>,
    pub signer_id: String,
    pub signature: String,
    pub schema_version: String,
    pub issued_epoch_ms: u64,
}

impl std::fmt::Debug for CapabilityContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityContract")
            .field("contract_id", &self.contract_id)
            .field("extension_id", &self.extension_id)
            .field("extension_version", &self.extension_version)
            .field("artifact_id", &self.artifact_id)
            .field("payload_hash", &"[REDACTED]")
            .field("capabilities", &self.capabilities)
            .field("signer_id", &self.signer_id)
            .field("signature", &"[REDACTED]")
            .field("schema_version", &self.schema_version)
            .field("issued_epoch_ms", &self.issued_epoch_ms)
            .finish()
    }
}

/// An extension artifact that may or may not carry a capability contract.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionArtifact {
    pub artifact_id: String,
    pub extension_id: String,
    pub extension_version: String,
    pub capability_contract: Option<CapabilityContract>,
    pub payload_hash: String,
}

impl std::fmt::Debug for ExtensionArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionArtifact")
            .field("artifact_id", &self.artifact_id)
            .field("extension_id", &self.extension_id)
            .field("extension_version", &self.extension_version)
            .field("capability_contract", &self.capability_contract)
            .field("payload_hash", &"[REDACTED]")
            .finish()
    }
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
    TrustRevoked { detail: String },
}

impl AdmissionDenialReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingContract => error_codes::ERR_ARTIFACT_MISSING_CONTRACT,
            Self::InvalidContract { .. } => error_codes::ERR_ARTIFACT_INVALID_CONTRACT,
            Self::InvalidCapability { .. } => error_codes::ERR_ARTIFACT_INVALID_CAPABILITY,
            Self::SignatureInvalid => error_codes::ERR_ARTIFACT_SIGNATURE_INVALID,
            Self::SchemaMismatch { .. } => error_codes::ERR_ARTIFACT_SCHEMA_MISMATCH,
            Self::TrustRevoked { .. } => error_codes::ERR_ARTIFACT_TRUST_REVOKED,
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
    /// Independently configured signer IDs and lowercase-hex Ed25519 public keys.
    /// Contract contents never supply their own admission trust anchor.
    pub trusted_signers: BTreeMap<String, String>,
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
            trusted_signers: BTreeMap::new(),
        }
    }

    pub fn with_signer(
        &mut self,
        signer_id: impl Into<String>,
        verifying_key: &VerifyingKey,
    ) -> Result<(), AdmissionConfigError> {
        let signer_id = signer_id.into();
        if let Some(detail) = invalid_token_detail("signer_id", &signer_id) {
            return Err(AdmissionConfigError::InvalidTrustedSigner { detail });
        }
        let public_key_hex = hex::encode(verifying_key.as_bytes());
        if let Some(existing_key) = self.trusted_signers.get(&signer_id) {
            return if existing_key == &public_key_hex {
                Ok(())
            } else {
                Err(AdmissionConfigError::InvalidTrustedSigner {
                    detail: "signer_id is already bound to a different public key".to_string(),
                })
            };
        }
        if self.trusted_signers.len() >= MAX_TRUSTED_SIGNERS {
            return Err(AdmissionConfigError::TrustedSignerCapacityExceeded {
                capacity: MAX_TRUSTED_SIGNERS,
            });
        }
        self.trusted_signers.insert(signer_id, public_key_hex);
        Ok(())
    }

    fn verifying_key(&self, signer_id: &str) -> Option<VerifyingKey> {
        // Serialized or directly constructed configurations must not bypass
        // the builder's capacity and canonical key-encoding requirements.
        if self.trusted_signers.len() > MAX_TRUSTED_SIGNERS {
            return None;
        }
        let encoded = self.trusted_signers.get(signer_id)?;
        if !is_hex_sha256(encoded) {
            return None;
        }
        let bytes: [u8; 32] = hex::decode(encoded).ok()?.try_into().ok()?;
        VerifyingKey::from_bytes(&bytes).ok()
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
    /// INV-ARTIFACT-TRUST-VALIDATED: trust card status must be checked for revocation.
    pub fn evaluate(
        &self,
        artifact: &ExtensionArtifact,
        trust_registry: Option<&mut TrustCardRegistry>,
        now_secs: u64,
    ) -> AdmissionOutcome {
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

        // INV-ARTIFACT-TRUST-VALIDATED: Check trust card status (fail-closed)
        if let Some(registry) = trust_registry {
            let extension_id = &artifact.extension_id;
            match registry.read(extension_id, now_secs, "capability-admission-trust-check") {
                Ok(Some(trust_card)) => {
                    // Fail if extension is revoked
                    if let RevocationStatus::Revoked { reason, .. } = &trust_card.revocation_status
                    {
                        return AdmissionOutcome::Denied {
                            reason: AdmissionDenialReason::TrustRevoked {
                                detail: format!(
                                    "Extension '{}' trust card revoked: {}",
                                    extension_id, reason
                                ),
                            },
                            event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                        };
                    }
                    // Fail if extension is quarantined
                    if trust_card.active_quarantine {
                        return AdmissionOutcome::Denied {
                            reason: AdmissionDenialReason::TrustRevoked {
                                detail: format!(
                                    "Extension '{}' trust card quarantined",
                                    extension_id
                                ),
                            },
                            event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                        };
                    }
                }
                Ok(None) => {
                    // Fail-closed: missing trust card = deny
                    return AdmissionOutcome::Denied {
                        reason: AdmissionDenialReason::TrustRevoked {
                            detail: format!(
                                "Extension '{}' has no trust card registered",
                                extension_id
                            ),
                        },
                        event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                    };
                }
                Err(err) => {
                    // Fail-closed: trust registry error = deny
                    return AdmissionOutcome::Denied {
                        reason: AdmissionDenialReason::TrustRevoked {
                            detail: format!(
                                "Extension '{}' trust validation failed: {}",
                                extension_id, err
                            ),
                        },
                        event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                    };
                }
            }
        } else {
            // Fail-closed: no trust registry provided = deny
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::TrustRevoked {
                    detail: "Trust registry not available for validation".to_string(),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

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

        if let Some(detail) =
            invalid_token_detail("contract extension_version", &contract.extension_version)
        {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { detail },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if is_reserved_artifact_id(&contract.artifact_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: format!(
                        "contract artifact_id is reserved: {:?}",
                        contract.artifact_id
                    ),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if let Some(detail) = invalid_token_detail("contract artifact_id", &contract.artifact_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { detail },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if !is_hex_sha256(&contract.payload_hash) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: "contract payload_hash must be lowercase hex sha256".to_string(),
                },
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

        if let Some(detail) =
            invalid_token_detail("artifact extension_version", &artifact.extension_version)
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

        if contract.extension_version != artifact.extension_version {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: format!(
                        "contract extension_version '{}' does not match artifact extension_version '{}'",
                        contract.extension_version, artifact.extension_version
                    ),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if contract.artifact_id != artifact.artifact_id {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: format!(
                        "contract artifact_id '{}' does not match artifact artifact_id '{}'",
                        contract.artifact_id, artifact.artifact_id
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

        if contract_signature_hex(&contract.signature).is_none() {
            let reason = AdmissionDenialReason::InvalidContract {
                detail: "signature must be ed25519-v1 followed by 128 lowercase hex digits"
                    .to_string(),
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

        if let Err(violation) =
            ARTIFACT_CAPABILITY_LIST_POLICY.validate_len(contract.capabilities.len())
        {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: violation.to_string(),
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

        if !crate::security::constant_time::ct_eq(&contract.payload_hash, &artifact.payload_hash) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract {
                    detail: "contract payload_hash does not match artifact payload_hash"
                        .to_string(),
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
        let Some(verifying_key) = self.config.verifying_key(&contract.signer_id) else {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        };

        if !verify_contract_signature(contract, &verifying_key) {
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

/// Reason an extension capability invocation was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationDenialReason {
    CapabilityNotAdmitted,
    ScopeMismatch { expected: String, actual: String },
    CallBudgetExceeded { max_calls_per_epoch: u64 },
}

/// Runtime decision for a single capability invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationDecision {
    Permitted {
        remaining_calls_in_epoch: u64,
        event_code: String,
    },
    Denied {
        reason: InvocationDenialReason,
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
    calls_in_epoch: BTreeMap<String, u64>,
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
            calls_in_epoch: BTreeMap::new(),
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

    /// Authoritatively decide and record a capability invocation.
    ///
    /// This is the runtime invocation guard. It validates the admitted
    /// capability ID, exact scope, and the per-epoch call budget before
    /// recording the call.
    pub fn permit_invocation(&mut self, capability_id: &str, scope: &str) -> InvocationDecision {
        let Some(capability) = self.admitted_capabilities.get(capability_id) else {
            return InvocationDecision::Denied {
                reason: InvocationDenialReason::CapabilityNotAdmitted,
                event_code: event_codes::ARTIFACT_ENFORCEMENT_CHECK.to_string(),
            };
        };

        if capability.scope != scope {
            return InvocationDecision::Denied {
                reason: InvocationDenialReason::ScopeMismatch {
                    expected: capability.scope.clone(),
                    actual: scope.to_string(),
                },
                event_code: event_codes::ARTIFACT_ENFORCEMENT_CHECK.to_string(),
            };
        }

        let calls = self
            .calls_in_epoch
            .entry(capability.capability_id.clone())
            .or_insert(0);
        if *calls >= capability.max_calls_per_epoch {
            return InvocationDecision::Denied {
                reason: InvocationDenialReason::CallBudgetExceeded {
                    max_calls_per_epoch: capability.max_calls_per_epoch,
                },
                event_code: event_codes::ARTIFACT_ENFORCEMENT_CHECK.to_string(),
            };
        }

        *calls = calls.saturating_add(1);
        InvocationDecision::Permitted {
            remaining_calls_in_epoch: capability.max_calls_per_epoch.saturating_sub(*calls),
            event_code: event_codes::ARTIFACT_ENFORCEMENT_CHECK.to_string(),
        }
    }

    /// Reset per-epoch invocation counters after an externally authenticated
    /// epoch transition.
    pub fn reset_epoch_call_counts(&mut self) {
        self.calls_in_epoch.clear();
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

fn contract_signature_hex(signature: &str) -> Option<&str> {
    let encoded = signature.strip_prefix(CONTRACT_SIGNATURE_PREFIX)?;
    (encoded.len() == 128
        && encoded
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    .then_some(encoded)
}

fn contract_signature_message(contract: &CapabilityContract) -> Vec<u8> {
    let mut message = CONTRACT_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(compute_contract_digest(contract).as_bytes());
    message
}

fn verify_contract_signature(contract: &CapabilityContract, verifying_key: &VerifyingKey) -> bool {
    let Some(encoded) = contract_signature_hex(&contract.signature) else {
        return false;
    };
    let Ok(signature) = hex::decode(encoded) else {
        return false;
    };
    verify_signature(
        verifying_key,
        &contract_signature_message(contract),
        &signature,
    )
    .is_ok()
}

/// Sign the complete capability contract with an explicitly supplied Ed25519 key.
/// The signer ID is part of the signed statement; admission independently pins
/// that ID to its public key. An unkeyed digest is never an admission signature.
pub fn compute_contract_signature(
    contract: &CapabilityContract,
    signing_key: &SigningKey,
) -> String {
    format!(
        "{CONTRACT_SIGNATURE_PREFIX}{}",
        hex::encode(sign_bytes(
            signing_key,
            &contract_signature_message(contract)
        ))
    )
}

/// Compute the canonical content digest, preserving the original v1 byte layout.
/// This public digest provides integrity only and cannot authenticate a signer.
pub fn compute_contract_digest(contract: &CapabilityContract) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"artifact_contract_digest_v1:");

    // Length-prefix each field individually to prevent delimiter collisions.
    for field in [
        contract.contract_id.as_str(),
        contract.extension_id.as_str(),
        contract.extension_version.as_str(),
        contract.artifact_id.as_str(),
        contract.payload_hash.as_str(),
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
    signing_key: &SigningKey,
) -> CapabilityContract {
    let mut contract = CapabilityContract {
        contract_id: contract_id.to_string(),
        extension_id: extension_id.to_string(),
        extension_version: DEFAULT_EXTENSION_VERSION.to_string(),
        artifact_id: String::new(),
        payload_hash: String::new(),
        capabilities,
        signer_id: signer_id.to_string(),
        signature: String::new(),
        schema_version: schema_version.to_string(),
        issued_epoch_ms,
    };
    contract.signature = compute_contract_signature(&contract, signing_key);
    contract
}

/// Create a valid extension artifact with a signed contract for testing.
pub fn make_artifact(
    artifact_id: &str,
    extension_id: &str,
    mut contract: CapabilityContract,
    signing_key: &SigningKey,
) -> ExtensionArtifact {
    // Length-prefixed encoding prevents delimiter-collision ambiguity.
    let mut hasher = Sha256::new();
    hasher.update(b"artifact_contract_digest_v1:");
    for field in [artifact_id, extension_id] {
        hasher.update(len_to_u64(field.len()).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    let payload_hash = hex::encode(hasher.finalize());
    let should_resign = verify_contract_signature(&contract, &signing_key.verifying_key());
    contract.artifact_id = artifact_id.to_string();
    contract.extension_version = DEFAULT_EXTENSION_VERSION.to_string();
    contract.payload_hash = payload_hash.clone();
    if should_resign {
        contract.signature = compute_contract_signature(&contract, signing_key);
    }
    ExtensionArtifact {
        artifact_id: artifact_id.to_string(),
        extension_id: extension_id.to_string(),
        extension_version: DEFAULT_EXTENSION_VERSION.to_string(),
        capability_contract: Some(contract),
        payload_hash,
    }
}

// ---------------------------------------------------------------------------
// Macaroon-Style Monotonically Attenuated Capability Envelope (.28)
// ---------------------------------------------------------------------------

/// Ordered authority boundary at which a capability caveat is appended.
///
/// Authority can only advance monotonically across layers
/// (`PublisherRoot <= RegistryAdmission <= DeployReleasePolicy <= ModuleImportEdge`)
/// and can never widen an already-narrowed capability, scope, or quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttenuationLayer {
    PublisherRoot,
    RegistryAdmission,
    DeployReleasePolicy,
    ModuleImportEdge,
}

impl AttenuationLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublisherRoot => "publisher_root",
            Self::RegistryAdmission => "registry_admission",
            Self::DeployReleasePolicy => "deploy_release_policy",
            Self::ModuleImportEdge => "module_import_edge",
        }
    }
}

/// First-party capability attenuation caveat chained by RFC-2104 `HMAC-SHA256`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CapabilityCaveat {
    /// Intersect allowed capabilities with this subset (cannot introduce new IDs).
    AllowedCapabilities(BTreeSet<String>),
    /// Restrict filesystem operations to paths under these normalized prefixes.
    PathPrefixes(BTreeSet<String>),
    /// Restrict network egress to exact `host` or `host:port` patterns (or `*.domain`).
    HostPorts(BTreeSet<String>),
    /// Restrict environment reads to these exact variable names.
    EnvKeys(BTreeSet<String>),
    /// Lower the per-epoch call ceiling for an admitted capability (`<= current`).
    MaxCallsPerEpoch {
        capability_id: String,
        max_calls: u64,
    },
    /// Restrict module resolution/execution authority to a normalized relative prefix.
    ModuleScopePrefix(String),
}

/// A caveat bound into the envelope's chained `HMAC-SHA256` tag sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCaveat {
    pub layer: AttenuationLayer,
    pub caveat: CapabilityCaveat,
    pub caveat_tag_hex: String,
}

/// Cryptographically authenticated root authority from which caveats attenuate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "anchor_kind", rename_all = "snake_case")]
pub enum RootAuthorityAnchor {
    /// Rooted in an Ed25519-signed [`CapabilityContract`].
    SignedCapabilityContract { contract: CapabilityContract },
    /// Rooted in a publisher-signed v2 registry manifest + `FNSGCAP1` capsule approval.
    VerifiedPublisherApproval {
        publisher_public_key_hex: String,
        manifest_sha256: String,
        artifact_sha256: String,
        capsule_digest: String,
        graph_input_hash: String,
        policy_revision: String,
        authority_commitment: String,
        initial_capabilities: Vec<CapabilityEntry>,
    },
}

/// Effective runtime capability ceiling after verifying root + all caveats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveCapabilityCeiling {
    pub contract_id: String,
    pub allowed_capabilities: BTreeSet<String>,
    pub max_calls_per_epoch: BTreeMap<String, u64>,
    pub capability_scopes: BTreeMap<String, String>,
    pub path_prefixes: Option<BTreeSet<String>>,
    pub host_ports: Option<BTreeSet<String>>,
    pub env_keys: Option<BTreeSet<String>>,
    pub module_scope_prefix: Option<String>,
}

impl EffectiveCapabilityCeiling {
    pub fn permits_capability(&self, capability_id: &str) -> bool {
        self.allowed_capabilities.contains(capability_id)
    }

    pub fn call_budget_for(&self, capability_id: &str) -> Option<u64> {
        self.allowed_capabilities
            .contains(capability_id)
            .then(|| self.max_calls_per_epoch.get(capability_id).copied())
            .flatten()
    }

    pub fn permits_path(&self, candidate_path: &str) -> bool {
        if validate_caveat_path_prefix(candidate_path, true).is_err() {
            return false;
        }
        match &self.path_prefixes {
            None => true,
            Some(prefixes) => prefixes
                .iter()
                .any(|allowed| path_is_within_prefix(candidate_path, allowed)),
        }
    }

    pub fn permits_host_port(&self, candidate_host_port: &str) -> bool {
        if validate_host_port_token(candidate_host_port).is_err() {
            return false;
        }
        match &self.host_ports {
            None => true,
            Some(allowed_set) => allowed_set
                .iter()
                .any(|pattern| host_port_is_covered_by(candidate_host_port, pattern)),
        }
    }

    pub fn permits_env_key(&self, env_key: &str) -> bool {
        if validate_env_key_token(env_key).is_err() {
            return false;
        }
        match &self.env_keys {
            None => true,
            Some(keys) => keys.contains(env_key),
        }
    }

    pub fn permits_module_path(&self, module_path: &str) -> bool {
        if validate_caveat_path_prefix(module_path, false).is_err() {
            return false;
        }
        match &self.module_scope_prefix {
            None => true,
            Some(prefix) if prefix.is_empty() => true,
            Some(prefix) => path_is_within_prefix(module_path, prefix),
        }
    }
}

/// Errors produced when minting, attenuating, or verifying a [`MacaroonCapabilityEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttenuationError {
    SchemaMismatch {
        expected: String,
        actual: String,
    },
    MissingTrustAnchor,
    InvalidRootSignature,
    InvalidRootAnchor {
        detail: String,
    },
    CaveatLimitExceeded {
        max_caveats: usize,
    },
    LayerOrderViolation {
        previous: AttenuationLayer,
        attempted: AttenuationLayer,
    },
    InvalidCaveat {
        detail: String,
    },
    PrivilegeAmplification {
        layer: AttenuationLayer,
        detail: String,
    },
    TagMismatch {
        step: Option<usize>,
    },
}

impl AttenuationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SchemaMismatch { .. } => error_codes::ERR_ARTIFACT_SCHEMA_MISMATCH,
            Self::MissingTrustAnchor | Self::InvalidRootSignature => {
                error_codes::ERR_ARTIFACT_SIGNATURE_INVALID
            }
            Self::InvalidRootAnchor { .. }
            | Self::CaveatLimitExceeded { .. }
            | Self::LayerOrderViolation { .. }
            | Self::InvalidCaveat { .. } => error_codes::ERR_ARTIFACT_INVALID_CONTRACT,
            Self::PrivilegeAmplification { .. } => {
                error_codes::ERR_ARTIFACT_PRIVILEGE_AMPLIFICATION
            }
            Self::TagMismatch { .. } => error_codes::ERR_ARTIFACT_MACAROON_TAG_MISMATCH,
        }
    }
}

impl std::fmt::Display for AttenuationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => {
                write!(
                    f,
                    "{}: expected envelope schema '{expected}', got '{actual}'",
                    self.code()
                )
            }
            Self::MissingTrustAnchor => {
                write!(
                    f,
                    "{}: independent trusted publisher key required",
                    self.code()
                )
            }
            Self::InvalidRootSignature => {
                write!(
                    f,
                    "{}: root Ed25519 publisher signature verification failed",
                    self.code()
                )
            }
            Self::InvalidRootAnchor { detail } => {
                write!(f, "{}: invalid root anchor: {detail}", self.code())
            }
            Self::CaveatLimitExceeded { max_caveats } => {
                write!(
                    f,
                    "{}: caveat chain exceeds maximum length ({max_caveats})",
                    self.code()
                )
            }
            Self::LayerOrderViolation {
                previous,
                attempted,
            } => {
                write!(
                    f,
                    "{}: attenuation layer regressed from {} to {}",
                    self.code(),
                    previous.as_str(),
                    attempted.as_str()
                )
            }
            Self::InvalidCaveat { detail } => {
                write!(f, "{}: invalid capability caveat: {detail}", self.code())
            }
            Self::PrivilegeAmplification { layer, detail } => {
                write!(
                    f,
                    "{}: privilege amplification refused at {}: {detail}",
                    self.code(),
                    layer.as_str()
                )
            }
            Self::TagMismatch { step: Some(idx) } => {
                write!(
                    f,
                    "{}: chained HMAC-SHA256 caveat tag mismatch at step {idx}",
                    self.code()
                )
            }
            Self::TagMismatch { step: None } => {
                write!(f, "{}: envelope tail HMAC-SHA256 tag mismatch", self.code())
            }
        }
    }
}

impl std::error::Error for AttenuationError {}

impl EnforcementEngine {
    /// Construct a runtime [`EnforcementEngine`] from a verified [`EffectiveCapabilityCeiling`].
    pub fn from_ceiling(ceiling: &EffectiveCapabilityCeiling) -> Self {
        let mut admitted = BTreeMap::new();
        for cap_id in &ceiling.allowed_capabilities {
            let scope = ceiling
                .capability_scopes
                .get(cap_id)
                .cloned()
                .unwrap_or_else(|| format!("runtime:{cap_id}"));
            let max_calls_per_epoch = ceiling
                .max_calls_per_epoch
                .get(cap_id)
                .copied()
                .unwrap_or(0);
            admitted.insert(
                cap_id.clone(),
                CapabilityEntry {
                    capability_id: cap_id.clone(),
                    scope,
                    max_calls_per_epoch,
                },
            );
        }
        Self {
            admitted_capabilities: admitted,
            calls_in_epoch: BTreeMap::new(),
            contract_id: ceiling.contract_id.clone(),
        }
    }
}

/// Macaroon-style capability envelope combining an Ed25519-authenticated publisher root
/// with chained RFC-2104 `HMAC-SHA256` caveats that monotonically narrow authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacaroonCapabilityEnvelope {
    pub schema_version: String,
    pub root: RootAuthorityAnchor,
    pub caveats: Vec<SignedCaveat>,
    pub tail_tag_hex: String,
}

impl MacaroonCapabilityEnvelope {
    /// Mint a root envelope from an Ed25519-signed [`CapabilityContract`] verified
    /// against an independently configured `trusted_publisher` public key.
    pub fn from_signed_contract(
        contract: CapabilityContract,
        trusted_publisher: &VerifyingKey,
    ) -> Result<Self, AttenuationError> {
        let root = RootAuthorityAnchor::SignedCapabilityContract { contract };
        let (_, root_tag) = verify_and_seed_root(&root, Some(trusted_publisher))?;
        Ok(Self {
            schema_version: MACAROON_ENVELOPE_SCHEMA.to_string(),
            root,
            caveats: Vec::new(),
            tail_tag_hex: hex::encode(root_tag),
        })
    }

    /// Mint a root envelope from an authenticated v2 publisher source-graph approval.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_publisher_approval(
        publisher_public_key: &VerifyingKey,
        manifest_sha256: impl Into<String>,
        artifact_sha256: impl Into<String>,
        capsule_digest: impl Into<String>,
        graph_input_hash: impl Into<String>,
        policy_revision: impl Into<String>,
        authority_commitment: impl Into<String>,
        initial_capabilities: Vec<CapabilityEntry>,
    ) -> Result<Self, AttenuationError> {
        let root = RootAuthorityAnchor::VerifiedPublisherApproval {
            publisher_public_key_hex: hex::encode(publisher_public_key.as_bytes()),
            manifest_sha256: manifest_sha256.into(),
            artifact_sha256: artifact_sha256.into(),
            capsule_digest: capsule_digest.into(),
            graph_input_hash: graph_input_hash.into(),
            policy_revision: policy_revision.into(),
            authority_commitment: authority_commitment.into(),
            initial_capabilities,
        };
        let (_, root_tag) = verify_and_seed_root(&root, Some(publisher_public_key))?;
        Ok(Self {
            schema_version: MACAROON_ENVELOPE_SCHEMA.to_string(),
            root,
            caveats: Vec::new(),
            tail_tag_hex: hex::encode(root_tag),
        })
    }

    /// Append a monotonically narrowing caveat at `layer` and chain its `HMAC-SHA256` tag.
    pub fn attenuate(
        &self,
        layer: AttenuationLayer,
        caveat: CapabilityCaveat,
    ) -> Result<Self, AttenuationError> {
        if self.caveats.len() >= MAX_CAVEATS_PER_ENVELOPE {
            return Err(AttenuationError::CaveatLimitExceeded {
                max_caveats: MAX_CAVEATS_PER_ENVELOPE,
            });
        }
        if let Some(last) = self.caveats.last()
            && layer < last.layer
        {
            return Err(AttenuationError::LayerOrderViolation {
                previous: last.layer,
                attempted: layer,
            });
        }
        let (mut ceiling, mut current_tag) = verify_root_without_external_key(&self.root)?;
        for (idx, existing) in self.caveats.iter().enumerate() {
            apply_caveat_monotonically(&mut ceiling, existing.layer, &existing.caveat)?;
            current_tag = compute_caveat_hmac(&current_tag, idx, existing.layer, &existing.caveat)?;
            let expected_bytes = decode_hex_tag(&existing.caveat_tag_hex)
                .ok_or(AttenuationError::TagMismatch { step: Some(idx) })?;
            if !crate::security::constant_time::ct_eq_bytes(&current_tag, &expected_bytes) {
                return Err(AttenuationError::TagMismatch { step: Some(idx) });
            }
        }
        let tail_bytes = decode_hex_tag(&self.tail_tag_hex)
            .ok_or(AttenuationError::TagMismatch { step: None })?;
        if !crate::security::constant_time::ct_eq_bytes(&current_tag, &tail_bytes) {
            return Err(AttenuationError::TagMismatch { step: None });
        }

        // Enforce monotonic narrowing before signing the new caveat into the chain.
        apply_caveat_monotonically(&mut ceiling, layer, &caveat)?;
        let next_idx = self.caveats.len();
        let next_tag = compute_caveat_hmac(&current_tag, next_idx, layer, &caveat)?;
        let next_tag_hex = hex::encode(next_tag);

        let mut next = self.clone();
        next.caveats.push(SignedCaveat {
            layer,
            caveat,
            caveat_tag_hex: next_tag_hex.clone(),
        });
        next.tail_tag_hex = next_tag_hex;
        Ok(next)
    }

    /// Cryptographically verify the root publisher anchor, every chained `HMAC-SHA256`
    /// caveat tag in constant time, layer order, and strict monotonic non-escalation.
    pub fn verify(
        &self,
        trusted_publisher: Option<&VerifyingKey>,
    ) -> Result<EffectiveCapabilityCeiling, AttenuationError> {
        if self.schema_version != MACAROON_ENVELOPE_SCHEMA {
            return Err(AttenuationError::SchemaMismatch {
                expected: MACAROON_ENVELOPE_SCHEMA.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.caveats.len() > MAX_CAVEATS_PER_ENVELOPE {
            return Err(AttenuationError::CaveatLimitExceeded {
                max_caveats: MAX_CAVEATS_PER_ENVELOPE,
            });
        }

        let (mut ceiling, mut current_tag) = verify_and_seed_root(&self.root, trusted_publisher)?;
        let mut prev_layer: Option<AttenuationLayer> = None;
        for (idx, signed) in self.caveats.iter().enumerate() {
            if let Some(previous) = prev_layer
                && signed.layer < previous
            {
                return Err(AttenuationError::LayerOrderViolation {
                    previous,
                    attempted: signed.layer,
                });
            }
            prev_layer = Some(signed.layer);

            apply_caveat_monotonically(&mut ceiling, signed.layer, &signed.caveat)?;
            current_tag = compute_caveat_hmac(&current_tag, idx, signed.layer, &signed.caveat)?;
            let step_tag = decode_hex_tag(&signed.caveat_tag_hex)
                .ok_or(AttenuationError::TagMismatch { step: Some(idx) })?;
            if !crate::security::constant_time::ct_eq_bytes(&current_tag, &step_tag) {
                return Err(AttenuationError::TagMismatch { step: Some(idx) });
            }
        }

        let tail_tag = decode_hex_tag(&self.tail_tag_hex)
            .ok_or(AttenuationError::TagMismatch { step: None })?;
        if !crate::security::constant_time::ct_eq_bytes(&current_tag, &tail_tag) {
            return Err(AttenuationError::TagMismatch { step: None });
        }

        Ok(ceiling)
    }

    /// Verify the envelope and materialize a runtime [`EnforcementEngine`] bound to
    /// the resulting attenuated ceiling.
    pub fn to_enforcement_engine(
        &self,
        trusted_publisher: Option<&VerifyingKey>,
    ) -> Result<EnforcementEngine, AttenuationError> {
        let ceiling = self.verify(trusted_publisher)?;
        Ok(EnforcementEngine::from_ceiling(&ceiling))
    }

    pub fn tail_tag_hex(&self) -> &str {
        &self.tail_tag_hex
    }

    pub fn caveats(&self) -> &[SignedCaveat] {
        &self.caveats
    }
}

fn hmac_sha256_array(key: &[u8], payload: &[u8]) -> Result<[u8; 32], AttenuationError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| AttenuationError::InvalidRootAnchor {
            detail: "HMAC-SHA256 key initialization failed".to_string(),
        })?;
    mac.update(payload);
    Ok(mac.finalize().into_bytes().into())
}

fn decode_hex_tag(encoded: &str) -> Option<[u8; 32]> {
    if !is_hex_sha256(encoded) {
        return None;
    }
    hex::decode(encoded).ok()?.try_into().ok()
}

fn is_sha256_prefixed(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_hex_sha256)
}

fn push_lp_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&len_to_u64(s.len()).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn build_ceiling_from_entries(
    contract_id: String,
    entries: &[CapabilityEntry],
) -> Result<EffectiveCapabilityCeiling, AttenuationError> {
    if entries.is_empty() || entries.len() > MAX_CAPABILITIES_PER_CONTRACT {
        return Err(AttenuationError::InvalidRootAnchor {
            detail: "root capability list must be non-empty and within contract bounds".to_string(),
        });
    }
    let mut allowed_capabilities = BTreeSet::new();
    let mut max_calls_per_epoch = BTreeMap::new();
    let mut capability_scopes = BTreeMap::new();
    for entry in entries {
        if let Some(detail) = invalid_token_detail("capability_id", &entry.capability_id) {
            return Err(AttenuationError::InvalidRootAnchor { detail });
        }
        if let Some(detail) = invalid_token_detail("capability scope", &entry.scope) {
            return Err(AttenuationError::InvalidRootAnchor { detail });
        }
        if entry.max_calls_per_epoch == 0 {
            return Err(AttenuationError::InvalidRootAnchor {
                detail: format!(
                    "root capability '{}' must have positive max_calls_per_epoch",
                    entry.capability_id
                ),
            });
        }
        if !allowed_capabilities.insert(entry.capability_id.clone()) {
            return Err(AttenuationError::InvalidRootAnchor {
                detail: format!("duplicate root capability '{}'", entry.capability_id),
            });
        }
        max_calls_per_epoch.insert(entry.capability_id.clone(), entry.max_calls_per_epoch);
        capability_scopes.insert(entry.capability_id.clone(), entry.scope.clone());
    }
    Ok(EffectiveCapabilityCeiling {
        contract_id,
        allowed_capabilities,
        max_calls_per_epoch,
        capability_scopes,
        path_prefixes: None,
        host_ports: None,
        env_keys: None,
        module_scope_prefix: None,
    })
}

fn verify_and_seed_root(
    root: &RootAuthorityAnchor,
    trusted_publisher: Option<&VerifyingKey>,
) -> Result<(EffectiveCapabilityCeiling, [u8; 32]), AttenuationError> {
    match root {
        RootAuthorityAnchor::SignedCapabilityContract { contract } => {
            let publisher_key = trusted_publisher.ok_or(AttenuationError::MissingTrustAnchor)?;
            if let Some(detail) = invalid_token_detail("contract_id", &contract.contract_id) {
                return Err(AttenuationError::InvalidRootAnchor { detail });
            }
            if !verify_contract_signature(contract, publisher_key) {
                return Err(AttenuationError::InvalidRootSignature);
            }
            compute_signed_contract_root(contract)
        }
        RootAuthorityAnchor::VerifiedPublisherApproval {
            publisher_public_key_hex,
            manifest_sha256,
            artifact_sha256,
            capsule_digest,
            graph_input_hash,
            policy_revision,
            authority_commitment,
            initial_capabilities,
        } => {
            let publisher_key = trusted_publisher.ok_or(AttenuationError::MissingTrustAnchor)?;
            let expected_pub_hex = hex::encode(publisher_key.as_bytes());
            if !crate::security::constant_time::ct_eq(&expected_pub_hex, publisher_public_key_hex) {
                return Err(AttenuationError::InvalidRootSignature);
            }
            validate_publisher_approval_fields(
                publisher_public_key_hex,
                manifest_sha256,
                artifact_sha256,
                capsule_digest,
                graph_input_hash,
                policy_revision,
                authority_commitment,
            )?;
            let ceiling =
                build_ceiling_from_entries(authority_commitment.clone(), initial_capabilities)?;
            let root_tag = compute_publisher_approval_root_tag(
                publisher_public_key_hex,
                manifest_sha256,
                artifact_sha256,
                capsule_digest,
                graph_input_hash,
                policy_revision,
                authority_commitment,
                &ceiling,
            )?;
            Ok((ceiling, root_tag))
        }
    }
}

fn verify_root_without_external_key(
    root: &RootAuthorityAnchor,
) -> Result<(EffectiveCapabilityCeiling, [u8; 32]), AttenuationError> {
    match root {
        RootAuthorityAnchor::SignedCapabilityContract { contract } => {
            if let Some(detail) = invalid_token_detail("contract_id", &contract.contract_id) {
                return Err(AttenuationError::InvalidRootAnchor { detail });
            }
            if contract_signature_hex(&contract.signature).is_none() {
                return Err(AttenuationError::InvalidRootSignature);
            }
            compute_signed_contract_root(contract)
        }
        RootAuthorityAnchor::VerifiedPublisherApproval {
            publisher_public_key_hex,
            manifest_sha256,
            artifact_sha256,
            capsule_digest,
            graph_input_hash,
            policy_revision,
            authority_commitment,
            initial_capabilities,
        } => {
            validate_publisher_approval_fields(
                publisher_public_key_hex,
                manifest_sha256,
                artifact_sha256,
                capsule_digest,
                graph_input_hash,
                policy_revision,
                authority_commitment,
            )?;
            let ceiling =
                build_ceiling_from_entries(authority_commitment.clone(), initial_capabilities)?;
            let root_tag = compute_publisher_approval_root_tag(
                publisher_public_key_hex,
                manifest_sha256,
                artifact_sha256,
                capsule_digest,
                graph_input_hash,
                policy_revision,
                authority_commitment,
                &ceiling,
            )?;
            Ok((ceiling, root_tag))
        }
    }
}

fn compute_signed_contract_root(
    contract: &CapabilityContract,
) -> Result<(EffectiveCapabilityCeiling, [u8; 32]), AttenuationError> {
    let ceiling = build_ceiling_from_entries(contract.contract_id.clone(), &contract.capabilities)?;
    let mut payload = Vec::new();
    push_lp_str(&mut payload, "signed_capability_contract");
    push_lp_str(&mut payload, &contract.signer_id);
    push_lp_str(&mut payload, &compute_contract_digest(contract));
    push_lp_str(&mut payload, &contract.signature);
    let root_tag = hmac_sha256_array(MACAROON_ROOT_DOMAIN, &payload)?;
    Ok((ceiling, root_tag))
}

fn validate_publisher_approval_fields(
    publisher_public_key_hex: &str,
    manifest_sha256: &str,
    artifact_sha256: &str,
    capsule_digest: &str,
    graph_input_hash: &str,
    policy_revision: &str,
    authority_commitment: &str,
) -> Result<(), AttenuationError> {
    if !is_hex_sha256(publisher_public_key_hex) {
        return Err(AttenuationError::InvalidRootAnchor {
            detail: "publisher_public_key_hex must be 64 lowercase hex digits".to_string(),
        });
    }
    for (label, digest) in [
        ("manifest_sha256", manifest_sha256),
        ("artifact_sha256", artifact_sha256),
        ("capsule_digest", capsule_digest),
        ("graph_input_hash", graph_input_hash),
        ("authority_commitment", authority_commitment),
    ] {
        if !is_sha256_prefixed(digest) {
            return Err(AttenuationError::InvalidRootAnchor {
                detail: format!("{label} must be sha256:<64 lowercase hex digits>"),
            });
        }
    }
    if policy_revision.is_empty()
        || policy_revision.len() > 128
        || policy_revision.trim() != policy_revision
        || policy_revision.chars().any(char::is_control)
    {
        return Err(AttenuationError::InvalidRootAnchor {
            detail: "policy_revision must be non-empty, trimmed, bounded, and control-free"
                .to_string(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compute_publisher_approval_root_tag(
    publisher_public_key_hex: &str,
    manifest_sha256: &str,
    artifact_sha256: &str,
    capsule_digest: &str,
    graph_input_hash: &str,
    policy_revision: &str,
    authority_commitment: &str,
    ceiling: &EffectiveCapabilityCeiling,
) -> Result<[u8; 32], AttenuationError> {
    let mut payload = Vec::new();
    push_lp_str(&mut payload, "verified_publisher_approval");
    for field in [
        publisher_public_key_hex,
        manifest_sha256,
        artifact_sha256,
        capsule_digest,
        graph_input_hash,
        policy_revision,
        authority_commitment,
    ] {
        push_lp_str(&mut payload, field);
    }
    payload.extend_from_slice(&len_to_u64(ceiling.allowed_capabilities.len()).to_le_bytes());
    for cap_id in &ceiling.allowed_capabilities {
        push_lp_str(&mut payload, cap_id);
        let scope = ceiling
            .capability_scopes
            .get(cap_id)
            .map_or("", String::as_str);
        push_lp_str(&mut payload, scope);
        let budget = ceiling
            .max_calls_per_epoch
            .get(cap_id)
            .copied()
            .unwrap_or(0);
        payload.extend_from_slice(&budget.to_le_bytes());
    }
    hmac_sha256_array(MACAROON_ROOT_DOMAIN, &payload)
}

fn compute_caveat_hmac(
    prior_tag: &[u8; 32],
    step_index: usize,
    layer: AttenuationLayer,
    caveat: &CapabilityCaveat,
) -> Result<[u8; 32], AttenuationError> {
    let mut payload = MACAROON_CAVEAT_DOMAIN.to_vec();
    payload.extend_from_slice(&len_to_u64(step_index).to_le_bytes());
    push_lp_str(&mut payload, layer.as_str());
    match caveat {
        CapabilityCaveat::AllowedCapabilities(caps) => {
            push_lp_str(&mut payload, "allowed_capabilities");
            payload.extend_from_slice(&len_to_u64(caps.len()).to_le_bytes());
            for cap in caps {
                push_lp_str(&mut payload, cap);
            }
        }
        CapabilityCaveat::PathPrefixes(prefixes) => {
            push_lp_str(&mut payload, "path_prefixes");
            payload.extend_from_slice(&len_to_u64(prefixes.len()).to_le_bytes());
            for prefix in prefixes {
                push_lp_str(&mut payload, prefix);
            }
        }
        CapabilityCaveat::HostPorts(hosts) => {
            push_lp_str(&mut payload, "host_ports");
            payload.extend_from_slice(&len_to_u64(hosts.len()).to_le_bytes());
            for host in hosts {
                push_lp_str(&mut payload, host);
            }
        }
        CapabilityCaveat::EnvKeys(keys) => {
            push_lp_str(&mut payload, "env_keys");
            payload.extend_from_slice(&len_to_u64(keys.len()).to_le_bytes());
            for key in keys {
                push_lp_str(&mut payload, key);
            }
        }
        CapabilityCaveat::MaxCallsPerEpoch {
            capability_id,
            max_calls,
        } => {
            push_lp_str(&mut payload, "max_calls_per_epoch");
            push_lp_str(&mut payload, capability_id);
            payload.extend_from_slice(&max_calls.to_le_bytes());
        }
        CapabilityCaveat::ModuleScopePrefix(prefix) => {
            push_lp_str(&mut payload, "module_scope_prefix");
            push_lp_str(&mut payload, prefix);
        }
    }
    hmac_sha256_array(prior_tag, &payload)
}

fn validate_caveat_path_prefix(prefix: &str, allow_leading_slash: bool) -> Result<(), String> {
    if prefix.is_empty() {
        return Err("path prefix must not be empty".to_string());
    }
    if prefix.len() > MAX_CAVEAT_PATH_BYTES {
        return Err(format!("path prefix exceeds {MAX_CAVEAT_PATH_BYTES} bytes"));
    }
    if prefix.trim() != prefix || prefix.chars().any(char::is_control) {
        return Err("path prefix contains whitespace padding or control characters".to_string());
    }
    if prefix.contains('\\') {
        return Err("path prefix must use '/' separators without '\\'".to_string());
    }
    if !allow_leading_slash && prefix.starts_with('/') {
        return Err("module scope prefix must be relative (no leading '/')".to_string());
    }
    let body = if allow_leading_slash {
        prefix.strip_prefix('/').unwrap_or(prefix)
    } else {
        prefix
    };
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() && !allow_leading_slash {
        return Err("relative scope prefix must contain at least one path segment".to_string());
    }
    if !body.is_empty()
        && body
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
    {
        return Err("path prefix contains empty, '.', or '..' traversal segment".to_string());
    }
    Ok(())
}

fn path_is_within_prefix(candidate: &str, prefix: &str) -> bool {
    let normalized_prefix = if prefix == "/" {
        "/"
    } else {
        prefix.strip_suffix('/').unwrap_or(prefix)
    };
    let normalized_candidate = if candidate == "/" {
        "/"
    } else {
        candidate.strip_suffix('/').unwrap_or(candidate)
    };
    if normalized_prefix == "/" {
        return normalized_candidate.starts_with('/');
    }
    if normalized_candidate == normalized_prefix {
        return true;
    }
    normalized_candidate
        .strip_prefix(normalized_prefix)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn validate_host_port_token(token: &str) -> Result<(), String> {
    if token.is_empty() || token.len() > 256 {
        return Err("host:port pattern must be 1..=256 bytes".to_string());
    }
    if token.trim() != token || !token.is_ascii() || token.bytes().any(|b| b.is_ascii_control()) {
        return Err("host:port pattern must be trimmed printable ASCII".to_string());
    }
    if token.contains(['/', '\\', ' ', '@', '?']) {
        return Err("host:port pattern must not contain URL path, query, or userinfo".to_string());
    }
    Ok(())
}

fn split_host_and_port(pattern: &str) -> (&str, Option<&str>) {
    if let Some((host, port)) = pattern.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return (host, Some(port));
    }
    (pattern, None)
}

fn host_port_is_covered_by(candidate: &str, allowed_pattern: &str) -> bool {
    let (cand_host, cand_port) = split_host_and_port(candidate);
    let (allow_host, allow_port) = split_host_and_port(allowed_pattern);
    if let Some(expected_port) = allow_port
        && cand_port != Some(expected_port)
    {
        return false;
    }
    let cand_lower = cand_host.to_ascii_lowercase();
    let allow_lower = allow_host.to_ascii_lowercase();
    if cand_lower == allow_lower {
        return true;
    }
    if let Some(domain_suffix) = allow_lower.strip_prefix("*.") {
        return cand_lower
            .strip_suffix(domain_suffix)
            .is_some_and(|head| head.ends_with('.') && head.len() > 1);
    }
    false
}

fn validate_env_key_token(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > 128 {
        return Err("env key must be 1..=128 bytes".to_string());
    }
    if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err("env key must contain only ASCII alphanumeric or '_' characters".to_string());
    }
    Ok(())
}

fn apply_caveat_monotonically(
    ceiling: &mut EffectiveCapabilityCeiling,
    layer: AttenuationLayer,
    caveat: &CapabilityCaveat,
) -> Result<(), AttenuationError> {
    match caveat {
        CapabilityCaveat::AllowedCapabilities(next_caps) => {
            if next_caps.len() > MAX_CAPABILITIES_PER_CONTRACT {
                return Err(AttenuationError::InvalidCaveat {
                    detail: "AllowedCapabilities exceeds contract fanout bound".to_string(),
                });
            }
            for cap in next_caps {
                if let Some(detail) = invalid_token_detail("capability_id", cap) {
                    return Err(AttenuationError::InvalidCaveat { detail });
                }
                if !ceiling.allowed_capabilities.contains(cap) {
                    return Err(AttenuationError::PrivilegeAmplification {
                        layer,
                        detail: format!(
                            "cannot grant unadmitted or previously stripped capability '{cap}'"
                        ),
                    });
                }
            }
            ceiling
                .allowed_capabilities
                .retain(|cap| next_caps.contains(cap));
            ceiling
                .max_calls_per_epoch
                .retain(|cap, _| next_caps.contains(cap));
            ceiling
                .capability_scopes
                .retain(|cap, _| next_caps.contains(cap));
        }
        CapabilityCaveat::PathPrefixes(next_prefixes) => {
            if next_prefixes.len() > MAX_CAVEAT_SET_ENTRIES {
                return Err(AttenuationError::InvalidCaveat {
                    detail: "PathPrefixes exceeds maximum caveat set size".to_string(),
                });
            }
            for prefix in next_prefixes {
                validate_caveat_path_prefix(prefix, true)
                    .map_err(|detail| AttenuationError::InvalidCaveat { detail })?;
            }
            if let Some(current_prefixes) = &ceiling.path_prefixes {
                for next in next_prefixes {
                    if !current_prefixes
                        .iter()
                        .any(|allowed| path_is_within_prefix(next, allowed))
                    {
                        return Err(AttenuationError::PrivilegeAmplification {
                            layer,
                            detail: format!(
                                "path prefix '{next}' escapes already-narrowed path ceiling"
                            ),
                        });
                    }
                }
            }
            ceiling.path_prefixes = Some(next_prefixes.clone());
        }
        CapabilityCaveat::HostPorts(next_hosts) => {
            if next_hosts.len() > MAX_CAVEAT_SET_ENTRIES {
                return Err(AttenuationError::InvalidCaveat {
                    detail: "HostPorts exceeds maximum caveat set size".to_string(),
                });
            }
            for host in next_hosts {
                validate_host_port_token(host)
                    .map_err(|detail| AttenuationError::InvalidCaveat { detail })?;
            }
            if let Some(current_hosts) = &ceiling.host_ports {
                for next in next_hosts {
                    if !current_hosts
                        .iter()
                        .any(|allowed| host_port_is_covered_by(next, allowed))
                    {
                        return Err(AttenuationError::PrivilegeAmplification {
                            layer,
                            detail: format!(
                                "host:port '{next}' escapes already-narrowed egress ceiling"
                            ),
                        });
                    }
                }
            }
            ceiling.host_ports = Some(next_hosts.clone());
        }
        CapabilityCaveat::EnvKeys(next_keys) => {
            if next_keys.len() > MAX_CAVEAT_SET_ENTRIES {
                return Err(AttenuationError::InvalidCaveat {
                    detail: "EnvKeys exceeds maximum caveat set size".to_string(),
                });
            }
            for key in next_keys {
                validate_env_key_token(key)
                    .map_err(|detail| AttenuationError::InvalidCaveat { detail })?;
            }
            if let Some(current_keys) = &ceiling.env_keys {
                for next in next_keys {
                    if !current_keys.contains(next) {
                        return Err(AttenuationError::PrivilegeAmplification {
                            layer,
                            detail: format!(
                                "env key '{next}' is outside already-narrowed env ceiling"
                            ),
                        });
                    }
                }
            }
            ceiling.env_keys = Some(next_keys.clone());
        }
        CapabilityCaveat::MaxCallsPerEpoch {
            capability_id,
            max_calls,
        } => {
            if let Some(detail) = invalid_token_detail("capability_id", capability_id) {
                return Err(AttenuationError::InvalidCaveat { detail });
            }
            let Some(current_max) = ceiling.max_calls_per_epoch.get_mut(capability_id) else {
                return Err(AttenuationError::PrivilegeAmplification {
                    layer,
                    detail: format!(
                        "cannot set call quota for unadmitted capability '{capability_id}'"
                    ),
                });
            };
            if *max_calls > *current_max {
                return Err(AttenuationError::PrivilegeAmplification {
                    layer,
                    detail: format!(
                        "max_calls_per_epoch for '{capability_id}' ({max_calls}) exceeds ceiling ({current_max})"
                    ),
                });
            }
            *current_max = *max_calls;
        }
        CapabilityCaveat::ModuleScopePrefix(next_scope) => {
            if !next_scope.is_empty() {
                validate_caveat_path_prefix(next_scope, false)
                    .map_err(|detail| AttenuationError::InvalidCaveat { detail })?;
            }
            if let Some(current_scope) = &ceiling.module_scope_prefix
                && !current_scope.is_empty()
                && (next_scope.is_empty() || !path_is_within_prefix(next_scope, current_scope))
            {
                return Err(AttenuationError::PrivilegeAmplification {
                    layer,
                    detail: format!(
                        "module scope prefix '{next_scope}' widens current module prefix '{current_scope}'"
                    ),
                });
            }
            ceiling.module_scope_prefix = Some(next_scope.clone());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42; 32])
    }

    fn make_contract(
        contract_id: &str,
        extension_id: &str,
        capabilities: Vec<CapabilityEntry>,
        signer_id: &str,
        schema_version: &str,
        issued_epoch_ms: u64,
    ) -> CapabilityContract {
        super::make_contract(
            contract_id,
            extension_id,
            capabilities,
            signer_id,
            schema_version,
            issued_epoch_ms,
            &test_signing_key(),
        )
    }

    fn make_artifact(
        artifact_id: &str,
        extension_id: &str,
        contract: CapabilityContract,
    ) -> ExtensionArtifact {
        super::make_artifact(artifact_id, extension_id, contract, &test_signing_key())
    }

    fn independently_signed_artifact() -> ExtensionArtifact {
        // Fixed vector produced independently with Python hashlib/struct and
        // cryptography's Ed25519 implementation, using the documented encoding.
        let contract = CapabilityContract {
            contract_id: "contract-ed25519-vector".to_string(),
            extension_id: "ext-alpha".to_string(),
            extension_version: "1.0.0".to_string(),
            artifact_id: "artifact-ed25519-vector".to_string(),
            payload_hash: "a".repeat(64),
            capabilities: vec![CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 2,
            }],
            signer_id: "signer-A".to_string(),
            signature: concat!(
                "ed25519-v1:",
                "2f12cc9adcc8026b1baa271620c166eb53c2d9fa738e0871952b102f9949fc8666",
                "2ac06015bd9f9836d1723fe7f1e135dd1ca608020bcf0847472784ca365e01"
            )
            .to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            issued_epoch_ms: 10_000,
        };
        ExtensionArtifact {
            artifact_id: contract.artifact_id.clone(),
            extension_id: contract.extension_id.clone(),
            extension_version: contract.extension_version.clone(),
            payload_hash: contract.payload_hash.clone(),
            capability_contract: Some(contract),
        }
    }

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
        cfg.with_signer("signer-A", &test_signing_key().verifying_key())
            .expect("trusted signer registration should succeed");
        AdmissionGate::new(cfg)
    }

    // bd-o776s: `AdmissionGate::evaluate` now enforces a mandatory, fail-closed
    // trust-registry precondition (bd-i3rdt) *before* any contract/capability
    // validation: a `None` registry — or one missing an active, non-quarantined
    // trust card for the artifact's `extension_id` — is denied immediately with
    // `TrustRevoked`, so contract-level assertions never get reached. These
    // helpers seed a valid trust card so admission proceeds to the logic under
    // test. (Prod behavior is unchanged; only the test setup was tightened.)

    /// A minimal, valid, active (non-revoked, non-quarantined) trust-card input
    /// for `extension_id`. Mirrors the proven `sample_input` in `trust_card`.
    fn active_trust_card_input(
        extension_id: &str,
        now_secs: u64,
    ) -> crate::supply_chain::trust_card::TrustCardInput {
        use crate::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
        use crate::supply_chain::trust_card::{
            BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
            DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
            ReputationTrend, RiskAssessment, RiskLevel, TrustCardInput,
        };
        TrustCardInput {
            extension: ExtensionIdentity {
                extension_id: extension_id.to_string(),
                version: "1.0.0".to_string(),
            },
            publisher: PublisherIdentity {
                publisher_id: "pub-test".to_string(),
                display_name: "Test".to_string(),
            },
            certification_level: CertificationLevel::Gold,
            capability_declarations: vec![CapabilityDeclaration {
                name: "plugin.execute".to_string(),
                description: "Run plugin".to_string(),
                risk: CapabilityRisk::Medium,
            }],
            behavioral_profile: BehavioralProfile {
                network_access: true,
                filesystem_access: false,
                subprocess_access: false,
                profile_summary: "safe".to_string(),
            },
            revocation_status: RevocationStatus::Active,
            provenance_summary: ProvenanceSummary {
                attestation_level: "slsa-l3".to_string(),
                source_uri: "registry://test/plugin".to_string(),
                artifact_hashes: vec!["sha256:".to_string() + &"e".repeat(64)],
                verified_at: "2026-01-01T00:00:00Z".to_string(),
            },
            reputation_score_basis_points: 900,
            reputation_trend: ReputationTrend::Stable,
            active_quarantine: false,
            dependency_trust_summary: vec![DependencyTrustStatus {
                dependency_id: "dep-a".to_string(),
                trust_level: "verified".to_string(),
            }],
            last_verified_timestamp: "2026-01-01T00:00:00Z".to_string(),
            user_facing_risk_assessment: RiskAssessment {
                level: RiskLevel::Low,
                summary: "low risk".to_string(),
            },
            evidence_refs: vec![VerifiedEvidenceRef {
                evidence_id: "ev-test-prov-001".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: now_secs,
                verification_receipt_hash: "c".repeat(64),
            }],
        }
    }

    /// Build an in-memory trust registry pre-seeded with an active trust card for
    /// `extension_id`. Best-effort: an unregisterable id (empty / surrounding
    /// whitespace) leaves the registry unseeded, so the trust gate fail-closes —
    /// exactly matching prod's denial of a malformed artifact extension id.
    fn admission_test_registry(extension_id: &str, now_secs: u64) -> TrustCardRegistry {
        let mut registry = TrustCardRegistry::new(3600, b"franken-node-trust-card-registry-key-v1");
        let _ = registry.create(
            active_trust_card_input(extension_id, now_secs),
            now_secs,
            "artifact-admission-test-seed",
        );
        registry
    }

    /// Evaluate `artifact` against `gate` with a trust registry pre-seeded for the
    /// artifact's own extension id (the common case for these admission tests).
    fn evaluate_trusted(
        gate: &AdmissionGate,
        artifact: &ExtensionArtifact,
        now_secs: u64,
    ) -> AdmissionOutcome {
        let mut registry = admission_test_registry(&artifact.extension_id, now_secs);
        gate.evaluate(artifact, Some(&mut registry), now_secs)
    }

    #[test]
    fn trusted_signer_registration_rejects_capacity_overflow_without_eviction() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        let verifying_key = test_signing_key().verifying_key();
        for idx in 0..MAX_TRUSTED_SIGNERS {
            cfg.with_signer(format!("signer-{idx}"), &verifying_key)
                .expect("signer fill should succeed");
        }

        let err = cfg
            .with_signer("overflow-signer", &verifying_key)
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
        assert!(cfg.trusted_signers.contains_key("signer-0"));
        let expected_last = format!("signer-{}", MAX_TRUSTED_SIGNERS.saturating_sub(1));
        assert!(cfg.trusted_signers.contains_key(&expected_last));
        assert!(!cfg.trusted_signers.contains_key("overflow-signer"));
    }

    #[test]
    fn trusted_signer_overflow_preserves_existing_admission_roots() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        let verifying_key = test_signing_key().verifying_key();
        cfg.with_signer("signer-A", &verifying_key)
            .expect("initial signer registration should succeed");
        for idx in 1..MAX_TRUSTED_SIGNERS {
            cfg.with_signer(format!("signer-{idx}"), &verifying_key)
                .expect("signer fill should succeed");
        }
        cfg.with_signer("signer-overflow", &verifying_key)
            .expect_err("overflow signer must be rejected");

        let gate = AdmissionGate::new(cfg);
        let trusted_artifact = make_artifact("a-trusted", "ext-alpha", test_contract());
        let trusted_outcome = evaluate_trusted(&gate, &trusted_artifact, 0);
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
        let overflow_outcome = evaluate_trusted(&gate, &overflow_artifact, 0);
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
        cfg.with_signer("signer-A", &test_signing_key().verifying_key())
            .expect("initial signer registration should succeed");
        cfg.with_signer("signer-A", &test_signing_key().verifying_key())
            .expect("duplicate signer registration should be ignored");
        assert_eq!(cfg.trusted_signers.len(), 1);
    }

    #[test]
    fn trusted_signer_registration_cannot_replace_an_admission_key() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        cfg.with_signer("signer-A", &test_signing_key().verifying_key())
            .expect("register independent publisher key");
        let original_roots = cfg.trusted_signers.clone();
        let other_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        assert!(matches!(
            cfg.with_signer("signer-A", &other_key),
            Err(AdmissionConfigError::InvalidTrustedSigner { .. })
        ));
        assert_eq!(cfg.trusted_signers, original_roots);
        assert!(matches!(
            evaluate_trusted(
                &AdmissionGate::new(cfg),
                &independently_signed_artifact(),
                0,
            ),
            AdmissionOutcome::Accepted { .. }
        ));
    }

    #[test]
    fn admission_accepts_independent_ed25519_vector_and_enforces_signed_budget() {
        let public_key_bytes: [u8; 32] =
            hex::decode("197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61")
                .expect("independent vector public key")
                .try_into()
                .expect("32-byte public key");
        let public_key = VerifyingKey::from_bytes(&public_key_bytes).expect("Ed25519 public key");
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        cfg.with_signer("signer-A", &public_key)
            .expect("register separately retained public key");
        let artifact = independently_signed_artifact();
        let contract = artifact.capability_contract.as_ref().expect("contract");
        assert_eq!(
            compute_contract_digest(contract),
            "10769f32aee73a0b7072a12587b854f7c702b0023d39265454c7a7b4402f4222"
        );
        assert_eq!(
            compute_contract_signature(contract, &test_signing_key()),
            contract.signature
        );
        assert!(matches!(
            evaluate_trusted(&AdmissionGate::new(cfg), &artifact, 0),
            AdmissionOutcome::Accepted { .. }
        ));
        let mut enforcement = EnforcementEngine::from_contract(contract);
        assert!(matches!(
            enforcement.permit_invocation("fs.read", "filesystem:write"),
            InvocationDecision::Denied {
                reason: InvocationDenialReason::ScopeMismatch { .. },
                ..
            }
        ));
        for remaining in [1, 0] {
            assert!(matches!(
                enforcement.permit_invocation("fs.read", "filesystem:read"),
                InvocationDecision::Permitted { remaining_calls_in_epoch, .. }
                    if remaining_calls_in_epoch == remaining
            ));
        }
        assert!(matches!(
            enforcement.permit_invocation("fs.read", "filesystem:read"),
            InvocationDecision::Denied {
                reason: InvocationDenialReason::CallBudgetExceeded {
                    max_calls_per_epoch: 2
                },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_public_digest_forgery_even_with_trusted_signer_name() {
        let gate = test_gate();
        let mut artifact = independently_signed_artifact();
        let contract = artifact.capability_contract.as_mut().expect("contract");
        contract.capabilities[0].max_calls_per_epoch = u64::MAX;
        let digest = compute_contract_digest(contract);
        contract.signature = digest.clone();
        assert!(matches!(
            evaluate_trusted(&gate, &artifact, 0),
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidContract { .. },
                ..
            }
        ));

        // A digest padded to the new signature width still cannot authenticate
        // a caller-selected capability envelope under the configured root.
        artifact
            .capability_contract
            .as_mut()
            .expect("contract")
            .signature = format!("{CONTRACT_SIGNATURE_PREFIX}{digest}{digest}");
        assert!(matches!(
            evaluate_trusted(&gate, &artifact, 0),
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_foreign_key_and_wrong_signature_domain() {
        let gate = test_gate();
        let mut artifact = independently_signed_artifact();
        let contract = artifact.capability_contract.as_mut().expect("contract");
        contract.signature =
            compute_contract_signature(contract, &SigningKey::from_bytes(&[7; 32]));
        assert!(matches!(
            evaluate_trusted(&gate, &artifact, 0),
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));

        let contract = artifact.capability_contract.as_mut().expect("contract");
        contract.signature = format!(
            "{CONTRACT_SIGNATURE_PREFIX}{}",
            hex::encode(sign_bytes(
                &test_signing_key(),
                compute_contract_digest(contract).as_bytes(),
            ))
        );
        assert!(matches!(
            evaluate_trusted(&gate, &artifact, 0),
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_malformed_or_foreign_configured_public_keys() {
        let artifact = independently_signed_artifact();
        for encoded in [
            String::new(),
            "g".repeat(64),
            "00".repeat(32),
            hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()),
        ] {
            let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
            cfg.trusted_signers.insert("signer-A".to_string(), encoded);
            assert!(matches!(
                evaluate_trusted(&AdmissionGate::new(cfg), &artifact, 0),
                AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::SignatureInvalid,
                    ..
                }
            ));
        }
        assert!(
            serde_json::from_value::<AdmissionConfig>(serde_json::json!({
                "expected_schema_version": SCHEMA_VERSION,
                "trusted_signers": ["signer-A"]
            }))
            .is_err()
        );
    }

    #[test]
    fn trusted_signer_registration_rejects_blank_signer() {
        let mut cfg = AdmissionConfig::new(SCHEMA_VERSION);
        let err = cfg
            .with_signer("   ", &test_signing_key().verifying_key())
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
            .with_signer(" signer-A ", &test_signing_key().verifying_key())
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
                .with_signer(signer, &test_signing_key().verifying_key())
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
            extension_version: DEFAULT_EXTENSION_VERSION.to_string(),
            capability_contract: None,
            payload_hash: "h1".to_string(),
        };
        let outcome = gate.evaluate(&artifact, None, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        contract.signature = compute_contract_signature(&contract, &test_signing_key());
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        contract.signature = format!("{CONTRACT_SIGNATURE_PREFIX}{}", "A".repeat(128));
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = evaluate_trusted(&gate, &artifact, 0);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected uppercase signature to be denied");
            return;
        };
        assert!(detail.contains("signature must be ed25519-v1"));
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        // bd-o776s: the mandatory trust gate (bd-i3rdt) fail-closes on the empty
        // extension id (which the registry cannot key on) BEFORE the artifact
        // extension-id format check runs, so the (still fail-closed) denial now
        // surfaces as TrustRevoked rather than InvalidContract. Intent preserved:
        // an empty artifact extension id is denied.
        let outcome = evaluate_trusted(&gate, &artifact, 0);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::TrustRevoked { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected empty artifact extension_id to be denied");
            return;
        };
        assert!(detail.contains("empty"));
    }

    #[test]
    fn admission_rejects_artifact_extension_id_with_whitespace() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact("a1", " ext-alpha ", contract);
        // bd-o776s: the mandatory trust gate (bd-i3rdt) fail-closes on the
        // whitespace-wrapped extension id (unregisterable) BEFORE the artifact
        // extension-id format check, so the (still fail-closed) denial now
        // surfaces as TrustRevoked. Intent preserved: a whitespace-wrapped
        // artifact extension id is denied, and the denial still cites whitespace.
        let outcome = evaluate_trusted(&gate, &artifact, 0);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::TrustRevoked { detail },
            ..
        } = outcome
        else {
            assert!(
                false,
                "expected whitespace artifact extension_id to be denied"
            );
            return;
        };
        assert!(detail.contains("whitespace"));
    }

    #[test]
    fn admission_rejects_reserved_extension_id() {
        let gate = test_gate();
        let contract = test_contract();
        // The reserved id "<unknown>" is a registerable id for the trust registry,
        // so the seeded trust gate clears and admission reaches the artifact
        // extension-id reserved check (InvalidContract).
        let artifact = make_artifact("a1", "<unknown>", contract);
        let outcome = evaluate_trusted(&gate, &artifact, 0);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected reserved extension_id to be denied");
            return;
        };
        assert!(detail.contains("reserved"));

        // bd-o776s: the whitespace-wrapped form " <unknown> " is unregisterable,
        // so the mandatory trust gate (bd-i3rdt) fail-closes on it BEFORE the
        // reserved check, surfacing TrustRevoked (citing whitespace) instead of
        // InvalidContract. Intent preserved: it is still denied.
        let contract = test_contract();
        let artifact = make_artifact("a1", " <unknown> ", contract);
        let outcome = evaluate_trusted(&gate, &artifact, 0);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::TrustRevoked { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected reserved extension_id to be denied");
            return;
        };
        assert!(detail.contains("whitespace"));
    }

    #[test]
    fn admission_rejects_invalid_payload_hash() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        artifact.payload_hash = "not-hex".to_string();
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
    fn admission_rejects_contract_artifact_id_mismatch() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        let contract = artifact
            .capability_contract
            .as_mut()
            .expect("fixture should carry a contract");
        contract.artifact_id = "a2".to_string();
        contract.signature = compute_contract_signature(contract, &test_signing_key());

        let outcome = evaluate_trusted(&gate, &artifact, 0);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected artifact binding mismatch to be denied");
            return;
        };
        assert!(detail.contains("contract artifact_id"));
    }

    #[test]
    fn admission_rejects_contract_payload_hash_mismatch() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        let contract = artifact
            .capability_contract
            .as_mut()
            .expect("fixture should carry a contract");
        contract.payload_hash = "b".repeat(64);
        contract.signature = compute_contract_signature(contract, &test_signing_key());

        let outcome = evaluate_trusted(&gate, &artifact, 0);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected payload hash binding mismatch to be denied");
            return;
        };
        assert!(detail.contains("payload_hash"));
    }

    #[test]
    fn admission_rejects_extension_version_mismatch() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        let contract = artifact
            .capability_contract
            .as_mut()
            .expect("fixture should carry a contract");
        contract.extension_version = "2.0.0".to_string();
        contract.signature = compute_contract_signature(contract, &test_signing_key());

        let outcome = evaluate_trusted(&gate, &artifact, 0);
        let AdmissionOutcome::Denied {
            reason: AdmissionDenialReason::InvalidContract { detail },
            ..
        } = outcome
        else {
            assert!(false, "expected extension version mismatch to be denied");
            return;
        };
        assert!(detail.contains("extension_version"));
    }

    #[test]
    fn admission_rejects_binding_tampering_after_signing() {
        let gate = test_gate();
        let contract = test_contract();
        let mut artifact = make_artifact("a1", "ext-alpha", contract);
        artifact.payload_hash = "b".repeat(64);
        let contract = artifact
            .capability_contract
            .as_mut()
            .expect("fixture should carry a contract");
        contract.payload_hash = artifact.payload_hash.clone();

        let outcome = evaluate_trusted(&gate, &artifact, 0);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        // Use the versioned Ed25519 encoding with invalid signature bytes so
        // this reaches verification rather than the separate format gate.
        contract.signature = format!("{CONTRACT_SIGNATURE_PREFIX}{}", "0".repeat(128));
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
        let outcome = evaluate_trusted(&gate, &artifact, 0);
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
    fn invocation_guard_enforces_scope_and_call_budget() {
        let contract = make_contract(
            "budgeted-contract",
            "ext-alpha",
            vec![CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 2,
            }],
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let mut engine = EnforcementEngine::from_contract(&contract);

        assert!(matches!(
            engine.permit_invocation("fs.read", "filesystem:write"),
            InvocationDecision::Denied {
                reason: InvocationDenialReason::ScopeMismatch { .. },
                ..
            }
        ));
        assert!(matches!(
            engine.permit_invocation("fs.write", "filesystem:read"),
            InvocationDecision::Denied {
                reason: InvocationDenialReason::CapabilityNotAdmitted,
                ..
            }
        ));

        assert!(matches!(
            engine.permit_invocation("fs.read", "filesystem:read"),
            InvocationDecision::Permitted {
                remaining_calls_in_epoch: 1,
                ..
            }
        ));
        assert!(matches!(
            engine.permit_invocation("fs.read", "filesystem:read"),
            InvocationDecision::Permitted {
                remaining_calls_in_epoch: 0,
                ..
            }
        ));
        assert!(matches!(
            engine.permit_invocation("fs.read", "filesystem:read"),
            InvocationDecision::Denied {
                reason: InvocationDenialReason::CallBudgetExceeded {
                    max_calls_per_epoch: 2
                },
                ..
            }
        ));
    }

    #[test]
    fn invocation_guard_can_reset_epoch_call_budget() {
        let contract = make_contract(
            "budget-reset-contract",
            "ext-alpha",
            vec![CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 1,
            }],
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let mut engine = EnforcementEngine::from_contract(&contract);

        assert!(matches!(
            engine.permit_invocation("fs.read", "filesystem:read"),
            InvocationDecision::Permitted { .. }
        ));
        assert!(matches!(
            engine.permit_invocation("fs.read", "filesystem:read"),
            InvocationDecision::Denied {
                reason: InvocationDenialReason::CallBudgetExceeded { .. },
                ..
            }
        ));

        engine.reset_epoch_call_counts();

        assert!(matches!(
            engine.permit_invocation("fs.read", "filesystem:read"),
            InvocationDecision::Permitted { .. }
        ));
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
                let outcome = gate.evaluate(&artifact, None, 0);
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
            let outcome = gate.evaluate(&artifact, None, 0);
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
            let artifact = make_artifact("memory-artifact", "ext-alpha", contract.clone());

            let outcome = gate.evaluate(&artifact, None, 0);
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
            let verifying_key = test_signing_key().verifying_key();

            // Fill to exact capacity
            for i in 0..MAX_TRUSTED_SIGNERS {
                cfg.with_signer(format!("signer-{i}"), &verifying_key)
                    .expect("should fit within capacity");
            }

            // Test boundary conditions
            assert_eq!(cfg.trusted_signers.len(), MAX_TRUSTED_SIGNERS);

            // Test overflow rejection
            let overflow_result = cfg.with_signer("overflow-signer", &verifying_key);
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
            let outcome = evaluate_trusted(&gate, &artifact, 0);
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

                    let outcome = evaluate_trusted(&gate, &artifact, 0);
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
            let outcome = evaluate_trusted(&gate, &artifact, 0);
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
            // bd-o776s: admission now requires an active trust card; seed once and
            // reuse across all iterations (all artifacts share extension "ext-alpha").
            let mut registry = admission_test_registry("ext-alpha", 0);

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
                let outcome = gate.evaluate(&artifact, Some(&mut registry), 0);
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

    // Frozen SHA-256 hex outputs of compute_contract_digest. These original
    // integrity vectors remain unchanged; they do not authenticate a signer.
    // Ed25519 signs the digest under a separate versioned signature domain.
    //
    //   SHA256(
    //     b"artifact_contract_digest_v1:"
    //     || LE64(len(contract_id))         || contract_id.as_bytes()
    //     || LE64(len(extension_id))        || extension_id.as_bytes()
    //     || LE64(len(extension_version))   || extension_version.as_bytes()
    //     || LE64(len(artifact_id))         || artifact_id.as_bytes()
    //     || LE64(len(payload_hash))        || payload_hash.as_bytes()
    //     || LE64(len(signer_id))           || signer_id.as_bytes()
    //     || LE64(len(schema_version))      || schema_version.as_bytes()
    //     || LE64(capabilities.len())
    //     || for cap in capabilities:
    //          LE64(len(cap.capability_id)) || cap.capability_id.as_bytes()
    //       || LE64(len(cap.scope))         || cap.scope.as_bytes()
    //       || cap.max_calls_per_epoch.to_le_bytes()    # raw u64
    //     || issued_epoch_ms.to_le_bytes()              # raw u64
    //   ).hex()
    //
    // Critical layout invariants pinned:
    //   - 7 string fields each LE64-len-prefixed in fixed order
    //   - capabilities Vec iterated in slice order (NOT sorted)
    //   - per-cap u64 counters fed raw LE
    //   - signature field is NOT in the signed payload (circularity)
    //
    // Three frozen fixtures + three structural invariants:
    //
    //   1. minimal (all-empty strings, no caps, epoch=0).
    //      Frozen: 0b1212fbba689029fdfac4ff0296697cf8df520e72b4858563bbf8cc894ae48f
    //
    //   2. typical (one mandatory fs:read cap with scope, epoch=1.7e12).
    //      Frozen: 4cb860e222e7625909c3ca1f7d84f069714b14bb89185806f7b24f1874bb5e33
    //
    //   3. multi-cap (two network caps, different scopes + max_calls).
    //      Frozen: 89756cf9190cdf2033104f0ce2307ff707facb712d45df17604b81506070eafc
    //
    //   4. SIGNATURE-EXCLUSION INVARIANT: changing only the `signature`
    //      field of the input contract MUST NOT change the output
    //      digest (signature is an OUTPUT, not an input).
    //
    //   5. CAPABILITY-ORDER-SENSITIVITY: reordering the capabilities
    //      Vec MUST flip the output. Pins that Vec iteration order is
    //      canonical (NOT sorted — opposite to r53 capability_artifact's
    //      BTreeMap design).
    //
    //   6. MAX-CALLS-SENSITIVITY: bumping max_calls_per_epoch by 1 MUST
    //      flip the digest. Pins that the per-cap u64 IS fed into
    //      the hasher.
    //
    // Goldens were derived offline from the canonical-byte spec via
    // Python — NOT captured from an unreviewed prior run.
    //
    // Why this matters (the contract): compute_contract_digest is
    // the integrity-binding primitive for capability contracts. If
    // two nodes compute different digests for the same logical
    // contract — because someone reordered fields, swapped Vec for
    // BTreeMap on capabilities (which would alphabetically sort caps),
    // dropped max_calls_per_epoch from the hasher, or muddled the v1
    // domain — cryptographic verification rejects legitimate extensions.
    #[test]
    fn compute_contract_digest_frozen_canonical_byte_layout_golden() {
        // 1. Minimal: empty everything.
        let minimal = CapabilityContract {
            contract_id: String::new(),
            extension_id: String::new(),
            extension_version: String::new(),
            artifact_id: String::new(),
            payload_hash: String::new(),
            capabilities: Vec::new(),
            signer_id: String::new(),
            signature: String::new(), // NOT in the signed payload
            schema_version: String::new(),
            issued_epoch_ms: 0,
        };
        assert_eq!(
            compute_contract_digest(&minimal),
            "0b1212fbba689029fdfac4ff0296697cf8df520e72b4858563bbf8cc894ae48f",
            "minimal compute_contract_digest drifted — check the v1 \
             domain separator `artifact_contract_digest_v1:`, the 7 \
             LE64(0)-empty-string framings, OR the LE64(0) zero-caps \
             count"
        );

        // 2. Typical: one capability.
        let typical = CapabilityContract {
            contract_id: "contract-1".to_string(),
            extension_id: "ext-fs-reader".to_string(),
            extension_version: "1.2.3".to_string(),
            artifact_id: "art-x".to_string(),
            payload_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            capabilities: vec![CapabilityEntry {
                capability_id: "cap:fs:read".to_string(),
                scope: "/home/user/docs".to_string(),
                max_calls_per_epoch: 100,
            }],
            signer_id: "signer-prod-7".to_string(),
            signature: String::new(),
            schema_version: "cart-v1.0".to_string(),
            issued_epoch_ms: 1_700_000_000_000,
        };
        assert_eq!(
            compute_contract_digest(&typical),
            "4cb860e222e7625909c3ca1f7d84f069714b14bb89185806f7b24f1874bb5e33"
        );

        // 3. Multi-cap.
        let multi_cap = CapabilityContract {
            contract_id: "contract-2".to_string(),
            extension_id: "ext-net".to_string(),
            extension_version: "2.0".to_string(),
            artifact_id: "art-y".to_string(),
            payload_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            capabilities: vec![
                CapabilityEntry {
                    capability_id: "cap:net:bind".to_string(),
                    scope: "0.0.0.0:8080".to_string(),
                    max_calls_per_epoch: 10,
                },
                CapabilityEntry {
                    capability_id: "cap:net:connect".to_string(),
                    scope: "api.example.com:443".to_string(),
                    max_calls_per_epoch: 50,
                },
            ],
            signer_id: "signer-2".to_string(),
            signature: String::new(),
            schema_version: "cart-v1.0".to_string(),
            issued_epoch_ms: 1_700_000_001_000,
        };
        assert_eq!(
            compute_contract_digest(&multi_cap),
            "89756cf9190cdf2033104f0ce2307ff707facb712d45df17604b81506070eafc"
        );

        // 4. SIGNATURE-EXCLUSION INVARIANT: changing only the
        // signature field MUST NOT change the output.
        let mut with_sig = typical.clone();
        with_sig.signature = "ed25519:placeholder-signature-bytes".to_string();
        assert_eq!(
            compute_contract_digest(&with_sig),
            compute_contract_digest(&typical),
            "the `signature` field MUST be EXCLUDED from \
             compute_contract_digest (it is an OUTPUT, not an input \
             — including it would be circular)"
        );

        // 5. CAPABILITY-ORDER-SENSITIVITY: reordering caps MUST flip.
        let mut reordered = multi_cap.clone();
        reordered.capabilities.reverse();
        assert_ne!(
            compute_contract_digest(&reordered),
            compute_contract_digest(&multi_cap),
            "reversing the capabilities Vec MUST flip the digest \
             — Vec<CapabilityEntry> iteration is canonical (NOT \
             sorted; opposite to r53 capability_artifact's BTreeMap)"
        );

        // 6. MAX-CALLS-SENSITIVITY: bumping max_calls MUST flip.
        let mut max_calls_bumped = typical.clone();
        max_calls_bumped.capabilities[0].max_calls_per_epoch = 101;
        assert_ne!(
            compute_contract_digest(&max_calls_bumped),
            compute_contract_digest(&typical),
            "bumping CapabilityEntry::max_calls_per_epoch from 100 to \
             101 MUST flip the digest; if it does not, the u64 \
             counter is not being fed into the hasher and capability \
             quota tampering goes undetected"
        );

        // 64-lowercase-hex length+casing contract.
        for sig in [
            compute_contract_digest(&minimal),
            compute_contract_digest(&typical),
            compute_contract_digest(&multi_cap),
        ] {
            assert_eq!(sig.len(), 64);
            assert!(
                sig.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
        }
    }

    #[test]
    fn test_admission_denies_revoked_trust_card() {
        // Regression test for bd-i3rdt: admission must check trust card status
        use crate::supply_chain::trust_card::{
            ReputationTrend, RevocationStatus, SnapshotSourceContext, TrustCardMutation,
            TrustCardRegistry,
        };
        use std::fs;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        let registry_path = tmp.path().join("test_registry.json");
        let now_secs = 1_700_000_000;

        // Create registry with trusted extension
        let mut registry = TrustCardRegistry::new(3600, b"franken-node-trust-card-registry-key-v1");
        let extension_id = "test-extension";

        // bd-o776s: `update` now requires an existing card (returns NotFound
        // otherwise), so seed the initial active card with `create`.
        registry
            .create(
                active_trust_card_input(extension_id, now_secs),
                now_secs,
                "test-setup",
            )
            .expect("setup extension");

        registry
            .persist_authoritative_state(&registry_path)
            .expect("persist initial registry");

        // Create admission gate
        let mut gate_config = AdmissionConfig::new(SCHEMA_VERSION);
        gate_config
            .with_signer("signer-A", &test_signing_key().verifying_key())
            .expect("add trusted signer");
        let gate = AdmissionGate::new(gate_config);

        // Create valid capability contract
        let contract = make_contract(
            "contract-revoked-test",
            extension_id,
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-revoked-test", extension_id, contract);

        // Load registry for admission check. bd-o776s: load via the registry's
        // default signing key (`load_authoritative_state`) instead of the config
        // path, which now mandates an explicitly configured registry_signing_key.
        let mut loaded_registry = TrustCardRegistry::load_authoritative_state(
            &registry_path,
            3600,
            now_secs,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("load registry");

        // Should succeed initially (extension not revoked)
        let outcome1 = gate.evaluate(&artifact, Some(&mut loaded_registry), now_secs);
        assert!(matches!(outcome1, AdmissionOutcome::Accepted { .. }));

        // Now revoke the extension
        registry
            .update(
                extension_id,
                TrustCardMutation {
                    certification_level: None,
                    revocation_status: Some(RevocationStatus::Revoked {
                        reason: "Security vulnerability discovered".to_string(),
                        revoked_at: chrono::DateTime::from_timestamp(now_secs as i64, 0)
                            .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string()),
                    }),
                    active_quarantine: Some(true),
                    reputation_score_basis_points: None,
                    reputation_trend: Some(ReputationTrend::Declining),
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: None,
                },
                now_secs,
                "revoke-for-test",
            )
            .expect("revoke extension");

        registry
            .persist_authoritative_state(&registry_path)
            .expect("persist revoked registry");

        // Reload registry to get updated state
        let mut revoked_registry = TrustCardRegistry::load_authoritative_state(
            &registry_path,
            3600,
            now_secs,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("reload registry");

        // Should now be denied due to revocation (bd-i3rdt fix)
        let outcome2 = gate.evaluate(&artifact, Some(&mut revoked_registry), now_secs);
        match outcome2 {
            AdmissionOutcome::Denied { reason, .. } => match reason {
                AdmissionDenialReason::TrustRevoked { detail } => {
                    assert!(detail.contains("revoked"));
                    assert!(detail.contains("Security vulnerability discovered"));
                }
                _ => panic!("Expected TrustRevoked denial reason, got {:?}", reason),
            },
            _ => panic!(
                "Expected admission denial for revoked trust card, got {:?}",
                outcome2
            ),
        }
    }

    #[test]
    fn test_admission_denies_quarantined_trust_card() {
        // Test quarantined extensions are also denied admission
        use crate::supply_chain::trust_card::{SnapshotSourceContext, TrustCardRegistry};
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        let registry_path = tmp.path().join("test_registry.json");
        let now_secs = 1_700_000_000;

        let mut registry = TrustCardRegistry::new(3600, b"franken-node-trust-card-registry-key-v1");
        let extension_id = "quarantined-extension";

        // bd-o776s: `update` now requires an existing card; create the card
        // directly in a quarantined state.
        let mut card_input = active_trust_card_input(extension_id, now_secs);
        card_input.active_quarantine = true;
        registry
            .create(card_input, now_secs, "test-quarantine-setup")
            .expect("setup quarantined extension");

        registry
            .persist_authoritative_state(&registry_path)
            .expect("persist registry");

        let mut gate_config = AdmissionConfig::new(SCHEMA_VERSION);
        gate_config
            .with_signer("signer-A", &test_signing_key().verifying_key())
            .expect("add trusted signer");
        let gate = AdmissionGate::new(gate_config);

        let contract = make_contract(
            "contract-quarantined-test",
            extension_id,
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-quarantined-test", extension_id, contract);

        // bd-o776s: load via the registry's default signing key instead of the
        // config path, which now mandates a configured registry_signing_key.
        let mut loaded_registry = TrustCardRegistry::load_authoritative_state(
            &registry_path,
            3600,
            now_secs,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("load registry");

        // Should be denied due to quarantine
        let outcome = gate.evaluate(&artifact, Some(&mut loaded_registry), now_secs);
        match outcome {
            AdmissionOutcome::Denied { reason, .. } => match reason {
                AdmissionDenialReason::TrustRevoked { detail } => {
                    assert!(detail.contains("quarantined"));
                }
                _ => panic!(
                    "Expected TrustRevoked denial reason for quarantine, got {:?}",
                    reason
                ),
            },
            _ => panic!(
                "Expected admission denial for quarantined trust card, got {:?}",
                outcome
            ),
        }
    }

    #[test]
    fn test_admission_denies_missing_trust_card_fail_closed() {
        // Test fail-closed behavior when trust card doesn't exist
        use crate::supply_chain::trust_card::{SnapshotSourceContext, TrustCardRegistry};
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        let registry_path = tmp.path().join("empty_registry.json");
        let now_secs = 1_700_000_000;

        // Create empty registry
        let registry = TrustCardRegistry::new(3600, b"franken-node-trust-card-registry-key-v1");
        registry
            .persist_authoritative_state(&registry_path)
            .expect("persist empty registry");

        let mut gate_config = AdmissionConfig::new(SCHEMA_VERSION);
        gate_config
            .with_signer("signer-A", &test_signing_key().verifying_key())
            .expect("add trusted signer");
        let gate = AdmissionGate::new(gate_config);

        let extension_id = "nonexistent-extension";
        let contract = make_contract(
            "contract-missing-trust",
            extension_id,
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-missing-trust", extension_id, contract);

        // bd-o776s: load via the registry's default signing key instead of the
        // config path, which now mandates a configured registry_signing_key.
        let mut loaded_registry = TrustCardRegistry::load_authoritative_state(
            &registry_path,
            3600,
            now_secs,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("load empty registry");

        // Should be denied due to missing trust card (fail-closed)
        let outcome = gate.evaluate(&artifact, Some(&mut loaded_registry), now_secs);
        match outcome {
            AdmissionOutcome::Denied { reason, .. } => match reason {
                AdmissionDenialReason::TrustRevoked { detail } => {
                    assert!(detail.contains("no trust card registered"));
                }
                _ => panic!(
                    "Expected TrustRevoked denial reason for missing trust card, got {:?}",
                    reason
                ),
            },
            _ => panic!(
                "Expected admission denial for missing trust card, got {:?}",
                outcome
            ),
        }
    }

    #[test]
    fn test_admission_denies_no_trust_registry_provided_fail_closed() {
        // Test fail-closed behavior when no trust registry is provided
        let mut gate_config = AdmissionConfig::new(SCHEMA_VERSION);
        gate_config
            .with_signer("signer-A", &test_signing_key().verifying_key())
            .expect("add trusted signer");
        let gate = AdmissionGate::new(gate_config);

        let extension_id = "any-extension";
        let contract = make_contract(
            "contract-no-registry",
            extension_id,
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-no-registry", extension_id, contract);

        // Should be denied when no trust registry provided (fail-closed)
        let outcome = gate.evaluate(&artifact, None, 0);
        match outcome {
            AdmissionOutcome::Denied { reason, .. } => match reason {
                AdmissionDenialReason::TrustRevoked { detail } => {
                    assert!(detail.contains("Trust registry not available"));
                }
                _ => panic!(
                    "Expected TrustRevoked denial reason for no registry, got {:?}",
                    reason
                ),
            },
            _ => panic!(
                "Expected admission denial when no trust registry provided, got {:?}",
                outcome
            ),
        }
    }

    #[test]
    fn macaroon_envelope_attenuates_monotonically_across_all_four_layers() {
        let key = test_signing_key();
        let pubkey = key.verifying_key();
        let contract = make_contract(
            "contract-macaroon-root",
            "ext-macaroon",
            vec![
                CapabilityEntry {
                    capability_id: "fs_read".to_string(),
                    scope: "filesystem:read".to_string(),
                    max_calls_per_epoch: 500,
                },
                CapabilityEntry {
                    capability_id: "network_egress".to_string(),
                    scope: "network:egress".to_string(),
                    max_calls_per_epoch: 100,
                },
                CapabilityEntry {
                    capability_id: "env_read".to_string(),
                    scope: "env:read".to_string(),
                    max_calls_per_epoch: 50,
                },
                CapabilityEntry {
                    capability_id: "process_spawn".to_string(),
                    scope: "process:spawn".to_string(),
                    max_calls_per_epoch: 5,
                },
            ],
            "signer-A",
            SCHEMA_VERSION,
            1_700_000_000_000,
        );

        let root_env = MacaroonCapabilityEnvelope::from_signed_contract(contract, &pubkey)
            .expect("mint root macaroon envelope");
        let l1 = root_env
            .attenuate(
                AttenuationLayer::PublisherRoot,
                CapabilityCaveat::PathPrefixes(
                    ["/srv/app", "config/public"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                ),
            )
            .expect("publisher root path prefix");
        let l2 = l1
            .attenuate(
                AttenuationLayer::RegistryAdmission,
                CapabilityCaveat::ModuleScopePrefix("packages/core".to_string()),
            )
            .expect("registry admission module scope");
        let l3 = l2
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::AllowedCapabilities(
                    ["fs_read", "network_egress", "env_read"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                ),
            )
            .expect("deploy strips process_spawn")
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::HostPorts(
                    ["api.example.com:443", "*.cdn.example.com:443"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                ),
            )
            .expect("deploy narrows host:ports")
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::EnvKeys(
                    ["NODE_ENV", "APP_REGION"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                ),
            )
            .expect("deploy narrows env keys")
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::MaxCallsPerEpoch {
                    capability_id: "network_egress".to_string(),
                    max_calls: 25,
                },
            )
            .expect("deploy lowers network_egress call budget");
        let l4 = l3
            .attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::PathPrefixes(["/srv/app/readonly".to_string()].into()),
            )
            .expect("module edge narrows path prefix")
            .attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::ModuleScopePrefix(
                    "packages/core/node_modules/helper".to_string(),
                ),
            )
            .expect("module edge narrows module scope");

        let ceiling = l4.verify(Some(&pubkey)).expect("verify full caveat chain");
        assert!(!ceiling.permits_capability("process_spawn"));
        assert!(ceiling.permits_capability("fs_read"));
        assert_eq!(ceiling.call_budget_for("network_egress"), Some(25));
        assert!(ceiling.permits_path("/srv/app/readonly/index.json"));
        assert!(!ceiling.permits_path("/srv/app/secrets.json"));
        assert!(!ceiling.permits_path("/srv/app/readonly/../secrets.json"));
        assert!(ceiling.permits_host_port("api.example.com:443"));
        assert!(ceiling.permits_host_port("assets.cdn.example.com:443"));
        assert!(!ceiling.permits_host_port("api.example.com:80"));
        assert!(!ceiling.permits_host_port("evil.example.org:443"));
        assert!(ceiling.permits_env_key("NODE_ENV"));
        assert!(!ceiling.permits_env_key("AWS_SECRET_ACCESS_KEY"));
        assert!(ceiling.permits_module_path("packages/core/node_modules/helper/lib/a.js"));
        assert!(!ceiling.permits_module_path("packages/core/index.js"));
    }

    #[test]
    fn macaroon_envelope_rejects_privilege_amplification_in_every_dimension() {
        let key = test_signing_key();
        let pubkey = key.verifying_key();
        let contract = make_contract(
            "contract-no-amplify",
            "ext-no-amplify",
            vec![
                CapabilityEntry {
                    capability_id: "fs_read".to_string(),
                    scope: "filesystem:read".to_string(),
                    max_calls_per_epoch: 20,
                },
                CapabilityEntry {
                    capability_id: "network_egress".to_string(),
                    scope: "network:egress".to_string(),
                    max_calls_per_epoch: 10,
                },
            ],
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let narrowed = MacaroonCapabilityEnvelope::from_signed_contract(contract, &pubkey)
            .unwrap()
            .attenuate(
                AttenuationLayer::RegistryAdmission,
                CapabilityCaveat::AllowedCapabilities(["fs_read".to_string()].into()),
            )
            .unwrap()
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::PathPrefixes(["/srv/app/sub".to_string()].into()),
            )
            .unwrap()
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::HostPorts(["api.example.com:443".to_string()].into()),
            )
            .unwrap()
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::EnvKeys(["SAFE_KEY".to_string()].into()),
            )
            .unwrap()
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::ModuleScopePrefix("pkg/sub".to_string()),
            )
            .unwrap();

        // 1. Re-introducing stripped capability `network_egress`
        assert!(matches!(
            narrowed.attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::AllowedCapabilities(
                    ["fs_read", "network_egress"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect()
                ),
            ),
            Err(AttenuationError::PrivilegeAmplification { .. })
        ));
        // 2. Raising call quota above 20
        assert!(matches!(
            narrowed.attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::MaxCallsPerEpoch {
                    capability_id: "fs_read".to_string(),
                    max_calls: 21,
                },
            ),
            Err(AttenuationError::PrivilegeAmplification { .. })
        ));
        // 3. Widening path prefix from `/srv/app/sub` back to `/srv/app`
        assert!(matches!(
            narrowed.attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::PathPrefixes(["/srv/app".to_string()].into()),
            ),
            Err(AttenuationError::PrivilegeAmplification { .. })
        ));
        // 4. Widening host:port to portless or foreign host
        assert!(matches!(
            narrowed.attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::HostPorts(["api.example.com".to_string()].into()),
            ),
            Err(AttenuationError::PrivilegeAmplification { .. })
        ));
        // 5. Widening env keys
        assert!(matches!(
            narrowed.attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::EnvKeys(["SECRET_KEY".to_string()].into()),
            ),
            Err(AttenuationError::PrivilegeAmplification { .. })
        ));
        // 6. Widening module scope prefix from `pkg/sub` back to `pkg`
        assert!(matches!(
            narrowed.attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::ModuleScopePrefix("pkg".to_string()),
            ),
            Err(AttenuationError::PrivilegeAmplification { .. })
        ));
        // 7. Regressing attenuation layer order (`DeployReleasePolicy` -> `RegistryAdmission`)
        assert!(matches!(
            narrowed.attenuate(
                AttenuationLayer::RegistryAdmission,
                CapabilityCaveat::MaxCallsPerEpoch {
                    capability_id: "fs_read".to_string(),
                    max_calls: 5,
                },
            ),
            Err(AttenuationError::LayerOrderViolation { .. })
        ));
    }

    #[test]
    fn macaroon_envelope_rejects_tampered_caveats_truncated_chains_and_wrong_keys() {
        let key = test_signing_key();
        let pubkey = key.verifying_key();
        let foreign_key = SigningKey::from_bytes(&[99; 32]).verifying_key();
        let contract = make_contract(
            "contract-tamper",
            "ext-tamper",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            10,
        );
        let env = MacaroonCapabilityEnvelope::from_signed_contract(contract, &pubkey)
            .unwrap()
            .attenuate(
                AttenuationLayer::DeployReleasePolicy,
                CapabilityCaveat::AllowedCapabilities(["fs.read".to_string()].into()),
            )
            .unwrap()
            .attenuate(
                AttenuationLayer::ModuleImportEdge,
                CapabilityCaveat::MaxCallsPerEpoch {
                    capability_id: "fs.read".to_string(),
                    max_calls: 3,
                },
            )
            .unwrap();

        // Missing trust anchor and foreign publisher key fail closed.
        assert_eq!(env.verify(None), Err(AttenuationError::MissingTrustAnchor));
        assert_eq!(
            env.verify(Some(&foreign_key)),
            Err(AttenuationError::InvalidRootSignature)
        );

        // Truncating the final caveat (attempting to recover higher call budget) fails tail HMAC check!
        let mut truncated = env.clone();
        truncated.caveats.pop();
        assert_eq!(
            truncated.verify(Some(&pubkey)),
            Err(AttenuationError::TagMismatch { step: None })
        );
        // Even copying the previous caveat tag into `tail_tag_hex` only replays a valid prefix if
        // the attacker strips a caveat they received — which is why runtime admission recomputes
        // operator DeployReleasePolicy caveats locally; mutating a caveat payload in place fails step HMAC:
        let mut mutated = env.clone();
        mutated.caveats[1].caveat = CapabilityCaveat::MaxCallsPerEpoch {
            capability_id: "fs.read".to_string(),
            max_calls: 99,
        };
        assert!(matches!(
            mutated.verify(Some(&pubkey)),
            Err(AttenuationError::TagMismatch { step: Some(1) })
        ));
    }

    #[test]
    fn macaroon_envelope_materializes_drift_free_enforcement_engine() {
        let key = test_signing_key();
        let pubkey = key.verifying_key();
        let env = MacaroonCapabilityEnvelope::from_verified_publisher_approval(
            &pubkey,
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
            format!("sha256:{}", "3".repeat(64)),
            format!("sha256:{}", "4".repeat(64)),
            "policy-rev-1",
            format!("sha256:{}", "5".repeat(64)),
            vec![
                CapabilityEntry {
                    capability_id: "console".to_string(),
                    scope: "runtime:console".to_string(),
                    max_calls_per_epoch: 10,
                },
                CapabilityEntry {
                    capability_id: "process_spawn".to_string(),
                    scope: "process:spawn".to_string(),
                    max_calls_per_epoch: 2,
                },
            ],
        )
        .unwrap()
        .attenuate(
            AttenuationLayer::DeployReleasePolicy,
            CapabilityCaveat::AllowedCapabilities(["console".to_string()].into()),
        )
        .unwrap()
        .attenuate(
            AttenuationLayer::DeployReleasePolicy,
            CapabilityCaveat::MaxCallsPerEpoch {
                capability_id: "console".to_string(),
                max_calls: 2,
            },
        )
        .unwrap();

        let mut engine = env
            .to_enforcement_engine(Some(&pubkey))
            .expect("materialize enforcement engine");
        assert!(!engine.is_permitted("process_spawn"));
        assert_eq!(
            engine.check_drift(&["console".to_string()]),
            DriftCheckResult::NoDrift {
                event_code: event_codes::ARTIFACT_ENFORCEMENT_CHECK.to_string(),
            }
        );
        assert!(matches!(
            engine.permit_invocation("console", "runtime:console"),
            InvocationDecision::Permitted {
                remaining_calls_in_epoch: 1,
                ..
            }
        ));
        assert!(matches!(
            engine.permit_invocation("console", "runtime:console"),
            InvocationDecision::Permitted {
                remaining_calls_in_epoch: 0,
                ..
            }
        ));
        assert!(matches!(
            engine.permit_invocation("console", "runtime:console"),
            InvocationDecision::Denied {
                reason: InvocationDenialReason::CallBudgetExceeded {
                    max_calls_per_epoch: 2
                },
                ..
            }
        ));
    }
}
