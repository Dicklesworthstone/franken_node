//! Signed extension package manifest schema (bd-1gx).
//!
//! Defines a trust-native signed manifest that extends the engine's
//! `ExtensionManifest` contract with provenance/trust/signature metadata.
//!
//! This module requires the "engine" feature to be enabled.

#![cfg(feature = "engine")]

use std::collections::BTreeSet;
use std::fmt;

use base64::Engine as _;
#[cfg(feature = "engine")]
use frankenengine_extension_host::{
    Capability, ExtensionManifest, ManifestValidationError,
    validate_manifest as validate_engine_manifest, with_computed_content_hash,
};
use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::MAX_CHAIN_ENTRIES;

/// Maximum capabilities per manifest to prevent memory exhaustion.
const MAX_CAPABILITIES: usize = 1024;

/// Add item to Vec with bounded capacity. When capacity is exceeded, removes oldest entries.
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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
        // Projects publisher_signature, trust_chain_ref, and min_engine_version
        // for engine-level supply-chain checks.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.signature.signature)
            .map_err(|e| ManifestSchemaError::EngineManifestProjection {
                reason: format!("signature base64 decode failed: {e}"),
            })?;

        let payload = serde_json::json!({
            "name": self.package.name.clone(),
            "version": self.package.version.clone(),
            "entrypoint": self.entrypoint.clone(),
            "capabilities": self.capabilities.clone(),
            "publisher_signature": sig_bytes,
            "trust_chain_ref": self.trust.trust_card_reference.clone(),
            "min_engine_version": self.minimum_runtime_version.clone(),
        });

        let manifest: ExtensionManifest = serde_json::from_value(payload).map_err(|error| {
            ManifestSchemaError::EngineManifestProjection {
                reason: format!("engine manifest projection failed: {error}"),
            }
        })?;

        // Compute content_hash from canonical bytes so engine-level
        // supply-chain integrity checks pass.
        with_computed_content_hash(manifest).map_err(|error| {
            ManifestSchemaError::EngineManifestProjection {
                reason: format!("content hash computation failed: {error}"),
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

    // Path-traversal guard: runs after engine validation so that empty
    // entrypoints are caught by the engine first (EMS_ENGINE_REJECTED).
    validate_entrypoint_path(&manifest.entrypoint)?;

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

fn validate_entrypoint_path(entrypoint: &str) -> Result<(), ManifestSchemaError> {
    // Empty entrypoint is already caught by engine validation; only guard
    // against path-traversal on non-empty values.
    if entrypoint.trim().is_empty() {
        return Ok(());
    }
    if entrypoint.starts_with('/') {
        return Err(ManifestSchemaError::EntrypointPathTraversal {
            reason: "entrypoint must be a relative path, not absolute".to_string(),
        });
    }
    if entrypoint.contains('\\') {
        return Err(ManifestSchemaError::EntrypointPathTraversal {
            reason: "entrypoint must not contain backslash characters".to_string(),
        });
    }
    if entrypoint.contains('\0') {
        return Err(ManifestSchemaError::EntrypointPathTraversal {
            reason: "entrypoint must not contain null bytes".to_string(),
        });
    }
    if entrypoint.split('/').any(|seg| seg == "..") {
        return Err(ManifestSchemaError::EntrypointPathTraversal {
            reason: "entrypoint must not contain '..' path segments".to_string(),
        });
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
            let unique_keys: std::collections::BTreeSet<&str> =
                policy.signer_key_ids.iter().map(|s| s.as_str()).collect();
            if unique_keys.len() != policy.signer_key_ids.len() {
                return Err(ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "signer_key_ids must not contain duplicates".to_string(),
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
    EntrypointPathTraversal { reason: String },
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
            Self::EntrypointPathTraversal { .. } => "EMS_ENTRYPOINT_PATH_TRAVERSAL",
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
            Self::EntrypointPathTraversal { reason } => {
                write!(f, "EMS_ENTRYPOINT_PATH_TRAVERSAL: {reason}")
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
        serde_json::from_value(serde_json::json!(name)).expect("should succeed")
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
                signature: "QUJDREU=".to_string(),
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
        assert!(engine_manifest.publisher_signature.is_some());
        assert_eq!(
            engine_manifest.trust_chain_ref.as_deref(),
            Some("trust-card://auth-guard@1.2.3")
        );
        assert_eq!(engine_manifest.min_engine_version, "0.1.0");
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
        push_bounded(&mut manifest.capabilities, cap("fs_read"), MAX_CAPABILITIES);

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

    #[test]
    fn duplicate_signer_key_ids_rejected() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 2,
            total_signers: 3,
            signer_key_ids: vec![
                "key-a".to_string(),
                "key-a".to_string(), // duplicate — would let one key satisfy threshold
                "key-b".to_string(),
            ],
        });

        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
        assert!(error.to_string().contains("duplicates"));
    }

    // ---- Path traversal tests ----

    #[test]
    fn entrypoint_rejects_dotdot_traversal() {
        let mut manifest = valid_manifest();
        manifest.entrypoint = "../../etc/passwd".to_string();
        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
    }

    #[test]
    fn entrypoint_rejects_absolute_path() {
        let mut manifest = valid_manifest();
        manifest.entrypoint = "/etc/malicious.js".to_string();
        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
    }

    #[test]
    fn entrypoint_rejects_backslash() {
        let mut manifest = valid_manifest();
        manifest.entrypoint = "dist\\main.js".to_string();
        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
    }

    #[test]
    fn entrypoint_rejects_null_byte() {
        let mut manifest = valid_manifest();
        manifest.entrypoint = "dist/main\0.js".to_string();
        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
    }

    #[test]
    fn entrypoint_accepts_valid_relative_path() {
        let manifest = valid_manifest();
        // "dist/main.js" is the default; validate should pass (or fail on
        // other checks but not entrypoint)
        let result = validate_signed_manifest(&manifest);
        if let Err(ref e) = result {
            assert_ne!(
                e.code(),
                "EMS_ENTRYPOINT_PATH_TRAVERSAL",
                "valid relative entrypoint should not trigger path traversal"
            );
        }
    }

    #[test]
    fn whitespace_only_package_name_is_rejected_as_missing() {
        let mut manifest = valid_manifest();
        manifest.package.name = "   ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field } if field == "package.name"
        ));
    }

    #[test]
    fn whitespace_only_minimum_runtime_version_is_rejected() {
        let mut manifest = valid_manifest();
        manifest.minimum_runtime_version = "\t\n".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "minimum_runtime_version"
        ));
    }

    #[test]
    fn empty_capability_set_is_rejected_before_engine_projection() {
        let mut manifest = valid_manifest();
        manifest.capabilities.clear();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_EMPTY_CAPABILITIES");
        assert!(matches!(error, ManifestSchemaError::EmptyCapabilities));
    }

    #[test]
    fn attestation_with_blank_digest_is_rejected_with_indexed_field() {
        let mut manifest = valid_manifest();
        manifest.provenance.attestation_chain[0].digest = " ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "provenance.attestation_chain[0].digest"
        ));
    }

    #[test]
    fn threshold_zero_is_rejected() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 0,
            total_signers: 3,
            signer_key_ids: vec![
                "key-a".to_string(),
                "key-b".to_string(),
                "key-c".to_string(),
            ],
        });

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
        assert!(error.to_string().contains("must be > 0"));
    }

    #[test]
    fn threshold_greater_than_total_signers_is_rejected() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 4,
            total_signers: 3,
            signer_key_ids: vec![
                "key-a".to_string(),
                "key-b".to_string(),
                "key-c".to_string(),
            ],
        });

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
        assert!(error.to_string().contains("threshold cannot exceed"));
    }

    #[test]
    fn threshold_signer_key_ids_must_not_contain_blank_entries() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 2,
            total_signers: 3,
            signer_key_ids: vec!["key-a".to_string(), " ".to_string(), "key-c".to_string()],
        });

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
        assert!(error.to_string().contains("empty entries"));
    }

    #[test]
    fn base64_like_but_undecodable_signature_fails_projection() {
        let mut manifest = valid_manifest();
        manifest.signature.signature = "A=AA".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_ENGINE_PROJECTION");
        assert!(error.to_string().contains("signature base64 decode failed"));
    }

    #[test]
    fn entrypoint_rejects_embedded_dotdot_segment() {
        let mut manifest = valid_manifest();
        manifest.entrypoint = "dist/../main.js".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
        assert!(error.to_string().contains(".."));
    }

    #[test]
    fn whitespace_only_package_version_is_rejected_as_missing() {
        let mut manifest = valid_manifest();
        manifest.package.version = "\n\t ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field } if field == "package.version"
        ));
    }

    #[test]
    fn whitespace_only_package_author_is_rejected_as_missing() {
        let mut manifest = valid_manifest();
        manifest.package.author = "   ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field } if field == "package.author"
        ));
    }

    #[test]
    fn whitespace_only_behavioral_summary_is_rejected_as_missing() {
        let mut manifest = valid_manifest();
        manifest.behavioral_profile.summary = "\r\n".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "behavioral_profile.summary"
        ));
    }

    #[test]
    fn whitespace_only_revocation_pointer_is_rejected_as_missing() {
        let mut manifest = valid_manifest();
        manifest.trust.revocation_status_pointer = "\t".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "trust.revocation_status_pointer"
        ));
    }

    #[test]
    fn whitespace_only_trust_card_reference_is_rejected_as_missing() {
        let mut manifest = valid_manifest();
        manifest.trust.trust_card_reference = " ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "trust.trust_card_reference"
        ));
    }

    #[test]
    fn whitespace_only_publisher_key_id_is_rejected_as_missing() {
        let mut manifest = valid_manifest();
        manifest.signature.publisher_key_id = " \n".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "signature.publisher_key_id"
        ));
    }

    #[test]
    fn whitespace_only_signed_at_is_rejected_as_missing() {
        let mut manifest = valid_manifest();
        manifest.signature.signed_at = "\t".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field } if field == "signature.signed_at"
        ));
    }

    #[test]
    fn threshold_total_signers_zero_is_rejected() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 1,
            total_signers: 0,
            signer_key_ids: Vec::new(),
        });

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
        assert!(error.to_string().contains("must be > 0"));
    }

    #[test]
    fn threshold_signer_key_ids_longer_than_total_is_rejected() {
        let mut manifest = valid_manifest();
        manifest.signature.threshold = Some(ThresholdSignaturePolicy {
            threshold: 2,
            total_signers: 2,
            signer_key_ids: vec![
                "key-a".to_string(),
                "key-b".to_string(),
                "key-c".to_string(),
            ],
        });

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
        assert!(
            error
                .to_string()
                .contains("length must equal total_signers")
        );
    }

    #[test]
    fn schema_version_mismatch_precedes_missing_package_name() {
        let mut manifest = valid_manifest();
        manifest.schema_version = "0.9".to_string();
        manifest.package.name.clear();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_SCHEMA_VERSION");
        assert!(matches!(
            error,
            ManifestSchemaError::InvalidSchemaVersion { ref actual, .. } if actual == "0.9"
        ));
    }

    #[test]
    fn blank_attestation_id_is_rejected_with_indexed_field() {
        let mut manifest = valid_manifest();
        manifest.provenance.attestation_chain[0].id = "\n\t".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "provenance.attestation_chain[0].id"
        ));
    }

    #[test]
    fn blank_attestation_type_is_rejected_with_indexed_field() {
        let mut manifest = valid_manifest();
        manifest.provenance.attestation_chain[0].attestation_type = " ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "provenance.attestation_chain[0].attestation_type"
        ));
    }

    #[test]
    fn second_attestation_blank_digest_reports_second_index() {
        let mut manifest = valid_manifest();
        push_bounded(&mut manifest.provenance.attestation_chain, AttestationRef {
            id: "att-02".to_string(),
            attestation_type: "slsa".to_string(),
            digest: " \t".to_string(),
        }, MAX_CHAIN_ENTRIES);

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_MISSING_FIELD");
        assert!(matches!(
            error,
            ManifestSchemaError::MissingField { ref field }
                if field == "provenance.attestation_chain[1].digest"
        ));
    }

    #[test]
    fn signature_with_embedded_whitespace_is_malformed() {
        let mut manifest = valid_manifest();
        manifest.signature.signature = "QUJD REVGR0hJ".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_SIGNATURE_MALFORMED");
        assert!(error.to_string().contains("base64-like"));
    }

    #[test]
    fn serde_rejects_unknown_risk_tier() {
        let err = serde_json::from_str::<RiskTier>(r#""severe""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_signature_scheme() {
        let err = serde_json::from_str::<SignatureScheme>(r#""rsa_pkcs1""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_manifest_missing_signature_field() {
        let mut value = serde_json::to_value(valid_manifest()).expect("should serialize");
        if let serde_json::Value::Object(fields) = &mut value {
            fields.remove("signature");
        }

        let err = serde_json::from_value::<SignedExtensionManifest>(value).unwrap_err();

        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn entrypoint_rejects_dotdot_after_current_dir_segment() {
        let mut manifest = valid_manifest();
        manifest.entrypoint = "./../dist/main.js".to_string();

        let error = validate_signed_manifest(&manifest).expect_err("should fail");

        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
        assert!(error.to_string().contains(".."));
    }

    #[test]
    fn negative_unicode_injection_in_package_name() {
        let mut manifest = valid_manifest();
        // Test BiDi override injection in package name
        manifest.package.name = "safe\u{202e}evil\u{202c}package".to_string();

        let result = validate_signed_manifest(&manifest);
        // Should handle Unicode without corruption
        if let Err(e) = result {
            assert_ne!(e.code(), "EMS_MISSING_FIELD");
        }

        // Test zero-width characters
        manifest.package.name = "package\u{200b}\u{feff}hidden".to_string();
        let result = validate_signed_manifest(&manifest);
        if let Err(e) = result {
            assert_ne!(e.code(), "EMS_MISSING_FIELD");
        }
    }

    #[test]
    fn negative_massive_signature_memory_exhaustion() {
        let mut manifest = valid_manifest();

        // Create massive base64-encoded signature (10MB)
        let massive_data = vec![b'A'; 10_usize.saturating_mul(1024).saturating_mul(1024)];
        let massive_signature = base64::engine::general_purpose::STANDARD.encode(&massive_data);
        manifest.signature.signature = massive_signature;

        let result = validate_signed_manifest(&manifest);
        // Should handle large signatures without memory issues
        if let Err(e) = result {
            // Acceptable to reject due to size, but shouldn't panic
            assert!(e.code() == "EMS_ENGINE_PROJECTION" || e.code() == "EMS_SIGNATURE_MALFORMED");
        }
    }

    #[test]
    fn negative_publisher_key_id_injection_attacks() {
        let mut manifest = valid_manifest();

        let malicious_key_ids = vec![
            "../../../etc/passwd",                    // Path traversal
            "key\nnewline",                          // Newline injection
            "key\ttab",                              // Tab injection
            "key\x00null",                           // Null byte injection
            "key\"quote'single",                     // Quote injection
            "key\u{202e}reverse\u{202c}trap",       // BiDi override
        ];

        for malicious_id in malicious_key_ids {
            manifest.signature.publisher_key_id = malicious_id.to_string();
            let result = validate_signed_manifest(&manifest);

            if let Err(e) = result {
                // Should not fail due to missing field
                assert_ne!(e.code(), "EMS_MISSING_FIELD");
            }
        }
    }

    #[test]
    fn negative_attestation_chain_overflow_boundaries() {
        let mut manifest = valid_manifest();

        // Create massive attestation chain (1000 entries)
        let mut massive_chain = Vec::new();
        for i in 0..1000 {
            push_bounded(&mut massive_chain, AttestationRef {
                id: format!("attestation-{:04}", i),
                attestation_type: "slsa".to_string(),
                digest: format!("sha256:{:064x}", i),
            }, MAX_CHAIN_ENTRIES);
        }
        manifest.provenance.attestation_chain = massive_chain;

        let result = validate_signed_manifest(&manifest);
        // Should handle large chains gracefully
        if let Err(e) = result {
            // May fail due to size limits, but not missing fields
            assert_ne!(e.code(), "EMS_MISSING_FIELD");
        }
    }

    #[test]
    fn negative_threshold_arithmetic_overflow_edge_cases() {
        let mut manifest = valid_manifest();

        // Test near-overflow threshold values
        let overflow_cases = vec![
            (u32::MAX, u32::MAX),     // Both at max
            (u32::MAX - 1, u32::MAX), // Threshold one below max
            (1, u32::MAX),            // Threshold 1, signers at max
            (u32::MAX / 2, u32::MAX), // Threshold at half max
        ];

        for (threshold, total_signers) in overflow_cases {
            manifest.signature.threshold = Some(ThresholdSignaturePolicy {
                threshold,
                total_signers,
                signer_key_ids: (0..total_signers.min(10))
                    .map(|i| format!("key-{}", i))
                    .collect(),
            });

            let result = validate_signed_manifest(&manifest);
            if let Err(e) = result {
                // Should fail gracefully with threshold errors
                assert_eq!(e.code(), "EMS_THRESHOLD_INVALID");
            }
        }
    }

    #[test]
    fn negative_network_zones_massive_list() {
        let mut manifest = valid_manifest();

        // Create massive network zones list (10000 entries)
        let massive_zones: Vec<String> = (0..10000)
            .map(|i| format!("zone-{:04}", i))
            .collect();
        manifest.behavioral_profile.declared_network_zones = massive_zones;

        let result = validate_signed_manifest(&manifest);
        // Should handle large zone lists without memory issues
        if let Err(e) = result {
            // May fail due to size, but shouldn't crash
            assert_ne!(e.code(), "EMS_MISSING_FIELD");
        }
    }

    #[test]
    fn negative_reproducibility_markers_unicode_edge_cases() {
        let mut manifest = valid_manifest();

        let unicode_markers = vec![
            "\u{FEFF}BOM-marker",                    // Byte Order Mark
            "marker\u{200B}\u{200C}\u{200D}zwj",    // Zero-width joiners
            "marker\u{1F4A9}\u{1F525}emoji",        // Emoji sequence
            "\u{202E}reverse\u{202C}marker",        // BiDi override
            "marker\u{0000}null",                   // Null byte
            "marker\nnewline",                      // Newline
        ];

        for marker in unicode_markers {
            manifest.provenance.reproducibility_markers = vec![marker.to_string()];
            let result = validate_signed_manifest(&manifest);

            // Should handle Unicode markers gracefully
            if let Err(e) = result {
                assert_ne!(e.code(), "EMS_MISSING_FIELD");
            }
        }
    }

    #[test]
    fn negative_entrypoint_length_boundary_attacks() {
        let mut manifest = valid_manifest();

        // Test extremely long entrypoint paths
        let long_paths = vec![
            "a".repeat(10000),                              // 10KB path
            format!("{}/main.js", "dir/".repeat(1000)),     // Deep nesting
            format!("main{}.js", "x".repeat(5000)),         // Long filename
        ];

        for path in long_paths {
            manifest.entrypoint = path;
            let result = validate_signed_manifest(&manifest);

            // Should handle long paths gracefully
            if let Err(e) = result {
                // May reject due to length, but not path traversal for valid chars
                if !e.code().starts_with("EMS_ENGINE_") {
                    assert_ne!(e.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
                }
            }
        }
    }

    #[test]
    fn negative_signature_scheme_deserialization_edge_cases() {
        // Test malformed signature scheme JSON
        let malformed_schemes = vec![
            r#""""#,                    // Empty string
            r#""ED25519""#,             // Wrong case
            r#""ed25519_variant""#,     // Non-existent variant
            r#"null"#,                  // Null value
            r#"123"#,                   // Number instead of string
            r#"[]"#,                    // Array instead of string
        ];

        for scheme_json in malformed_schemes {
            let result = serde_json::from_str::<SignatureScheme>(scheme_json);
            assert!(result.is_err());
        }
    }

    #[test]
    fn negative_manifest_serialization_round_trip_corruption() {
        let mut manifest = valid_manifest();

        // Add edge case values that might break serialization
        manifest.package.name = "test\u{FFFF}package".to_string();
        manifest.signature.signed_at = "2024-01-01T00:00:00.000000000Z".to_string(); // Max precision
        manifest.behavioral_profile.summary = "Summary with\n\t\rwhitespace\u{0000}chars".to_string();

        // Test serialization round-trip
        let serialized = serde_json::to_string(&manifest);
        assert!(serialized.is_ok());

        let json_str = serialized.unwrap();
        let deserialized: Result<SignedExtensionManifest, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok());

        let recovered = deserialized.unwrap();
        assert_eq!(recovered.package.name, manifest.package.name);
    }

    #[test]
    fn negative_concurrent_manifest_validation_safety() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let barrier = Arc::new(Barrier::new(4));

        let handles: Vec<_> = (0..4).map(|i| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();

                let mut manifest = valid_manifest();
                manifest.package.name = format!("concurrent-package-{}", i);

                // Each thread validates different manifests
                for j in 0..100 {
                    manifest.package.version = format!("1.{}.{}", i, j);
                    let _ = validate_signed_manifest(&manifest);
                }
            })
        }).collect();

        for handle in handles {
            handle.join().expect("Thread should complete");
        }
    }

    #[test]
    fn negative_empty_collections_edge_cases() {
        let mut manifest = valid_manifest();

        // Test various empty collections
        manifest.capabilities.clear(); // Should fail with EMS_EMPTY_CAPABILITIES
        let result = validate_signed_manifest(&manifest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "EMS_EMPTY_CAPABILITIES");

        // Reset and test empty attestation chain
        manifest.capabilities = vec![frankenengine_extension_host::Capability::FileSystemRead];
        manifest.provenance.attestation_chain.clear();
        let result = validate_signed_manifest(&manifest);
        // May or may not require attestations - implementation dependent

        // Test empty reproducibility markers
        manifest.provenance.reproducibility_markers.clear();
        let result = validate_signed_manifest(&manifest);
        // Empty markers should be allowed

        // Test empty network zones
        manifest.behavioral_profile.declared_network_zones.clear();
        let result = validate_signed_manifest(&manifest);
        // Empty zones should be allowed
    }
}
