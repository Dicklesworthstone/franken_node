//! Signed extension package manifest schema (bd-1gx).
//!
//! Defines a trust-native signed manifest that extends the engine's
//! `ExtensionManifest` contract with provenance/trust/signature metadata.

use std::collections::BTreeSet;
use std::fmt;

use frankenengine_extension_host::{
    Capability, ExtensionManifest, ManifestValidationError,
    validate_manifest as validate_engine_manifest,
};
use serde::{Deserialize, Serialize};

pub const MANIFEST_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExtensionManifest {
    pub schema_version: String,
    pub package: PackageIdentity,
    pub entrypoint: String,
    pub capabilities: Vec<Capability>,
    pub behavioral_profile: BehavioralProfile,
    pub minimum_runtime_version: String,
    pub provenance: ProvenanceEnvelope,
    pub trust: TrustMetadata,
    pub signature: ManifestSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub author: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehavioralProfile {
    pub risk_tier: RiskTier,
    pub summary: String,
    pub declared_network_zones: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEnvelope {
    pub build_system: String,
    pub source_repository: String,
    pub source_revision: String,
    pub reproducibility_markers: Vec<String>,
    pub attestation_chain: Vec<AttestationRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRef {
    pub id: String,
    pub attestation_type: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustMetadata {
    pub certification_level: CertificationLevel,
    pub revocation_status_pointer: String,
    pub trust_card_reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationLevel {
    Community,
    Verified,
    Hardened,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSignature {
    pub scheme: SignatureScheme,
    pub publisher_key_id: String,
    pub signature: String,
    pub threshold: Option<ThresholdSignaturePolicy>,
    pub signed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    Ed25519,
    ThresholdEd25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSignaturePolicy {
    pub threshold: u8,
    pub total_signers: u8,
    pub signer_key_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManifestAuditEventCode {
    ManifestCreated,
    ManifestSigned,
    ManifestValidated,
    ManifestRejected,
}

impl ManifestAuditEventCode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManifestCreated => "MANIFEST_CREATED",
            Self::ManifestSigned => "MANIFEST_SIGNED",
            Self::ManifestValidated => "MANIFEST_VALIDATED",
            Self::ManifestRejected => "MANIFEST_REJECTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestAuditEvent {
    pub code: ManifestAuditEventCode,
    pub package_name: String,
    pub package_version: String,
    pub trace_id: String,
    pub timestamp: String,
    pub details: Option<String>,
}

impl SignedExtensionManifest {
    pub fn to_engine_manifest(&self) -> Result<ExtensionManifest, ManifestSchemaError> {
        // Build through serde to avoid compile-time coupling to extension-host
        // manifest field drift while still projecting required core fields.
        let payload = serde_json::json!({
            "name": self.package.name.clone(),
            "version": self.package.version.clone(),
            "entrypoint": self.entrypoint.clone(),
            "capabilities": self.capabilities.clone(),
        });

        serde_json::from_value(payload).map_err(|error| {
            ManifestSchemaError::EngineManifestProjection {
                reason: format!("engine manifest projection failed: {error}"),
            }
        })
    }

    pub fn validate(&self) -> Result<(), ManifestSchemaError> {
        validate_signed_manifest(self)
    }

    #[must_use]
    pub fn audit_event(
        &self,
        code: ManifestAuditEventCode,
        trace_id: &str,
        timestamp: &str,
        details: Option<String>,
    ) -> ManifestAuditEvent {
        ManifestAuditEvent {
            code,
            package_name: self.package.name.clone(),
            package_version: self.package.version.clone(),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
            details,
        }
    }
}

pub fn validate_signed_manifest(
    manifest: &SignedExtensionManifest,
) -> Result<(), ManifestSchemaError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ManifestSchemaError::InvalidSchemaVersion {
            expected: MANIFEST_SCHEMA_VERSION.to_string(),
            actual: manifest.schema_version.clone(),
        });
    }

    ensure_non_empty(&manifest.package.name, "package.name")?;
    ensure_non_empty(&manifest.package.version, "package.version")?;
    ensure_non_empty(&manifest.package.publisher, "package.publisher")?;
    ensure_non_empty(&manifest.package.author, "package.author")?;
    ensure_non_empty(&manifest.minimum_runtime_version, "minimum_runtime_version")?;
    ensure_non_empty(
        &manifest.behavioral_profile.summary,
        "behavioral_profile.summary",
    )?;
    ensure_non_empty(
        &manifest.trust.revocation_status_pointer,
        "trust.revocation_status_pointer",
    )?;
    ensure_non_empty(
        &manifest.trust.trust_card_reference,
        "trust.trust_card_reference",
    )?;
    ensure_non_empty(
        &manifest.signature.publisher_key_id,
        "signature.publisher_key_id",
    )?;
    ensure_non_empty(&manifest.signature.signed_at, "signature.signed_at")?;

    if manifest.capabilities.is_empty() {
        return Err(ManifestSchemaError::EmptyCapabilities);
    }
    ensure_capabilities_unique(&manifest.capabilities)?;

    if manifest.provenance.attestation_chain.is_empty() {
        return Err(ManifestSchemaError::MissingAttestationChain);
    }

    for (idx, attestation) in manifest.provenance.attestation_chain.iter().enumerate() {
        ensure_non_empty(
            &attestation.id,
            &format!("provenance.attestation_chain[{idx}].id"),
        )?;
        ensure_non_empty(
            &attestation.attestation_type,
            &format!("provenance.attestation_chain[{idx}].attestation_type"),
        )?;
        ensure_non_empty(
            &attestation.digest,
            &format!("provenance.attestation_chain[{idx}].digest"),
        )?;
    }

    validate_signature(&manifest.signature)?;

    // Required by bd-1gx AC(7): map into franken_engine ExtensionManifest and
    // reuse engine-level validation as part of admission checks.
    let engine_manifest = manifest.to_engine_manifest()?;
    validate_engine_manifest(&engine_manifest)
        .map_err(ManifestSchemaError::EngineManifestRejected)?;

    Ok(())
}

fn ensure_non_empty(value: &str, field: &str) -> Result<(), ManifestSchemaError> {
    if value.trim().is_empty() {
        return Err(ManifestSchemaError::MissingField {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn ensure_capabilities_unique(capabilities: &[Capability]) -> Result<(), ManifestSchemaError> {
    let mut seen = BTreeSet::new();
    for capability in capabilities {
        if !seen.insert(*capability) {
            return Err(ManifestSchemaError::DuplicateCapability(*capability));
        }
    }
    Ok(())
}

fn validate_signature(signature: &ManifestSignature) -> Result<(), ManifestSchemaError> {
    if !looks_like_base64(&signature.signature) {
        return Err(ManifestSchemaError::SignatureMalformed {
            reason: "signature must be base64-like and padded".to_string(),
        });
    }

    match signature.scheme {
        SignatureScheme::Ed25519 => {
            if signature.threshold.is_some() {
                return Err(ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "ed25519 signatures must not define threshold policy".to_string(),
                });
            }
        }
        SignatureScheme::ThresholdEd25519 => {
            let policy = signature.threshold.as_ref().ok_or_else(|| {
                ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "threshold_ed25519 signatures require threshold policy".to_string(),
                }
            })?;

            if policy.threshold == 0 || policy.total_signers == 0 {
                return Err(ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "threshold and total_signers must be > 0".to_string(),
                });
            }
            if policy.threshold > policy.total_signers {
                return Err(ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "threshold cannot exceed total_signers".to_string(),
                });
            }
            if usize::from(policy.total_signers) != policy.signer_key_ids.len() {
                return Err(ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "signer_key_ids length must equal total_signers".to_string(),
                });
            }
            if policy.signer_key_ids.iter().any(|id| id.trim().is_empty()) {
                return Err(ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "signer_key_ids must not contain empty entries".to_string(),
                });
            }
        }
    }

    Ok(())
}

fn looks_like_base64(value: &str) -> bool {
    if value.len() < 4 || !value.len().is_multiple_of(4) {
        return false;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestSchemaError {
    InvalidSchemaVersion { expected: String, actual: String },
    MissingField { field: String },
    EmptyCapabilities,
    DuplicateCapability(Capability),
    MissingAttestationChain,
    SignatureMalformed { reason: String },
    InvalidThresholdConfiguration { reason: String },
    EngineManifestProjection { reason: String },
    EngineManifestRejected(ManifestValidationError),
}

impl ManifestSchemaError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidSchemaVersion { .. } => "EMS_SCHEMA_VERSION",
            Self::MissingField { .. } => "EMS_MISSING_FIELD",
            Self::EmptyCapabilities => "EMS_EMPTY_CAPABILITIES",
            Self::DuplicateCapability(_) => "EMS_DUPLICATE_CAPABILITY",
            Self::MissingAttestationChain => "EMS_MISSING_ATTESTATION_CHAIN",
            Self::SignatureMalformed { .. } => "EMS_SIGNATURE_MALFORMED",
            Self::InvalidThresholdConfiguration { .. } => "EMS_THRESHOLD_INVALID",
            Self::EngineManifestProjection { .. } => "EMS_ENGINE_PROJECTION",
            Self::EngineManifestRejected(_) => "EMS_ENGINE_REJECTED",
        }
    }
}

impl fmt::Display for ManifestSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchemaVersion { expected, actual } => {
                write!(
                    f,
                    "EMS_SCHEMA_VERSION: schema_version mismatch: expected={expected}, actual={actual}"
                )
            }
            Self::MissingField { field } => {
                write!(f, "EMS_MISSING_FIELD: required field missing: {field}")
            }
            Self::EmptyCapabilities => {
                write!(
                    f,
                    "EMS_EMPTY_CAPABILITIES: manifest must declare at least one capability"
                )
            }
            Self::DuplicateCapability(capability) => {
                write!(
                    f,
                    "EMS_DUPLICATE_CAPABILITY: duplicate capability in manifest: {}",
                    capability.as_str()
                )
            }
            Self::MissingAttestationChain => {
                write!(
                    f,
                    "EMS_MISSING_ATTESTATION_CHAIN: provenance.attestation_chain must not be empty"
                )
            }
            Self::SignatureMalformed { reason } => {
                write!(f, "EMS_SIGNATURE_MALFORMED: {reason}")
            }
            Self::InvalidThresholdConfiguration { reason } => {
                write!(f, "EMS_THRESHOLD_INVALID: {reason}")
            }
            Self::EngineManifestProjection { reason } => {
                write!(f, "EMS_ENGINE_PROJECTION: {reason}")
            }
            Self::EngineManifestRejected(error) => {
                write!(f, "EMS_ENGINE_REJECTED: {error}")
            }
        }
    }
}

impl std::error::Error for ManifestSchemaError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &str) -> frankenengine_extension_host::Capability {
        serde_json::from_value(serde_json::json!(name)).unwrap()
    }

    fn valid_manifest() -> SignedExtensionManifest {
        SignedExtensionManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            package: PackageIdentity {
                name: "auth-guard".to_string(),
                version: "1.2.3".to_string(),
                publisher: "publisher@example.com".to_string(),
                author: "author@example.com".to_string(),
            },
            entrypoint: "dist/main.js".to_string(),
            capabilities: vec![cap("fs_read"), cap("net_client")],
            behavioral_profile: BehavioralProfile {
                risk_tier: RiskTier::Medium,
                summary: "Reads local policy and performs outbound calls to policy oracle"
                    .to_string(),
                declared_network_zones: vec!["prod-us-east".to_string()],
            },
            minimum_runtime_version: "0.1.0".to_string(),
            provenance: ProvenanceEnvelope {
                build_system: "github-actions".to_string(),
                source_repository: "https://example.com/acme/extensions".to_string(),
                source_revision: "abcdef1234567890".to_string(),
                reproducibility_markers: vec!["reproducible-build=true".to_string()],
                attestation_chain: vec![AttestationRef {
                    id: "att-01".to_string(),
                    attestation_type: "slsa".to_string(),
                    digest: "sha256:0123456789abcdef".to_string(),
                }],
            },
            trust: TrustMetadata {
                certification_level: CertificationLevel::Verified,
                revocation_status_pointer: "revocation://extensions/auth-guard".to_string(),
                trust_card_reference: "trust-card://auth-guard@1.2.3".to_string(),
            },
            signature: ManifestSignature {
                scheme: SignatureScheme::ThresholdEd25519,
                publisher_key_id: "key-publisher-01".to_string(),
                signature: "QUJDREVGR0hJSg==".to_string(),
                threshold: Some(ThresholdSignaturePolicy {
                    threshold: 2,
                    total_signers: 3,
                    signer_key_ids: vec![
                        "key-a".to_string(),
                        "key-b".to_string(),
                        "key-c".to_string(),
                    ],
                }),
                signed_at: "2026-02-20T00:00:00Z".to_string(),
            },
        }
    }

    #[test]
    fn valid_manifest_passes() {
        let manifest = valid_manifest();
        assert_eq!(validate_signed_manifest(&manifest), Ok(()));
    }

    #[test]
    fn engine_manifest_projection_maps_core_fields() {
        let manifest = valid_manifest();
        let engine_manifest = manifest
            .to_engine_manifest()
            .expect("engine manifest projection should succeed");

        assert_eq!(engine_manifest.name, "auth-guard");
        assert_eq!(engine_manifest.version, "1.2.3");
        assert_eq!(engine_manifest.entrypoint, "dist/main.js");
        assert_eq!(engine_manifest.capabilities.len(), 2);
    }

    #[test]
    fn schema_version_mismatch_fails() {
        let mut manifest = valid_manifest();
        manifest.schema_version = "2.0".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_SCHEMA_VERSION");
    }

    #[test]
    fn missing_package_field_fails() {
        let mut manifest = valid_manifest();
        manifest.package.publisher.clear();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_MISSING_FIELD");
    }

    #[test]
    fn duplicate_capability_fails() {
        let mut manifest = valid_manifest();
        manifest.capabilities.push(cap("fs_read"));

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_DUPLICATE_CAPABILITY");
    }

    #[test]
    fn missing_attestation_chain_fails() {
        let mut manifest = valid_manifest();
        manifest.provenance.attestation_chain.clear();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_MISSING_ATTESTATION_CHAIN");
    }

    #[test]
    fn malformed_signature_fails() {
        let mut manifest = valid_manifest();
        manifest.signature.signature = "not-base64!".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_SIGNATURE_MALFORMED");
    }

    #[test]
    fn threshold_policy_is_required_for_threshold_signatures() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = None;

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn ed25519_must_not_include_threshold_policy() {
        let mut manifest = valid_manifest();
        manifest.signature.scheme = SignatureScheme::Ed25519;

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn threshold_signer_count_must_match() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 2,
            total_signers: 3,
            signer_key_ids: vec!["key-a".to_string()],
        });

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
    }

    #[test]
    fn engine_manifest_validation_is_enforced() {
        let mut manifest = valid_manifest();
        manifest.entrypoint.clear();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_ENGINE_REJECTED");
        assert!(matches!(
            error,
            ManifestSchemaError::EngineManifestRejected(_)
        ));
    }

    #[test]
    fn audit_event_uses_required_codes() {
        let manifest = valid_manifest();
        let event = manifest.audit_event(
            ManifestAuditEventCode::ManifestValidated,
            "trace-1",
            "2026-02-20T00:00:00Z",
            Some("all checks passed".to_string()),
        );
        assert_eq!(event.code.as_str(), "MANIFEST_VALIDATED");
        assert_eq!(event.package_name, "auth-guard");
        assert_eq!(event.trace_id, "trace-1");
    }

    #[test]
    fn base64_guard_rejects_short_or_unpadded_values() {
        assert!(!looks_like_base64("abc"));
        assert!(!looks_like_base64("abcd*==="));
        assert!(looks_like_base64("QUJDREVGR0hJSg=="));
    }
}
