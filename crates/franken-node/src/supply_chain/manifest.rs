//! Signed extension package manifest schema (bd-1gx).
//!
//! Defines a trust-native signed manifest that extends the engine's
//! `ExtensionManifest` contract with provenance/trust/signature metadata.
//!
//! This module requires the "engine" feature to be enabled.

#![cfg(feature = "engine")]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine as _;
#[cfg(feature = "engine")]
use frankenengine_extension_host::{
    Capability, ExtensionHostConfig, ExtensionManifest, ManifestValidationError,
    validate_manifest_with_config, with_computed_content_hash,
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::push_bounded;

pub const MANIFEST_SCHEMA_VERSION: &str = "1.0";
pub const MAX_MANIFEST_CAPABILITIES: usize = crate::capacity_defaults::base::SMALL;
pub const MAX_DECLARED_NETWORK_ZONES: usize = crate::capacity_defaults::base::SMALL;
pub const MAX_REPRODUCIBILITY_MARKERS: usize = crate::capacity_defaults::base::SMALL;
pub const MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES: usize = crate::capacity_defaults::base::SMALL;
pub const MAX_MANIFEST_FIELD_BYTES: usize = crate::capacity_defaults::base::MEDIUM;
const ED25519_SIGNATURE_BYTES: usize = 64;
const THRESHOLD_SIGNATURE_ENVELOPE_OVERHEAD_BYTES: usize = 1024;

#[cfg(test)]
const MAX_CAPABILITIES: usize = MAX_MANIFEST_CAPABILITIES;
#[cfg(test)]
const MAX_CHAIN_ENTRIES: usize = MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES;

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
    /// Full engine projection carrying `publisher_signature`, `trust_chain_ref`,
    /// and `min_engine_version` for engine-level cryptographic supply-chain
    /// (trust admission) checks.
    pub fn to_engine_manifest(&self) -> Result<ExtensionManifest, ManifestSchemaError> {
        self.project_engine_manifest(true)
    }

    /// Structural engine projection that omits `publisher_signature` and
    /// `trust_chain_ref`. The engine infers `Development` trust for this
    /// projection and validates only structural invariants (field presence,
    /// length bounds, capability lattice, engine-version compatibility) without
    /// requiring a configured trusted-publisher registry or a cryptographic
    /// signature. Schema validation uses this projection; trust admission uses
    /// the full projection plus a trusted-publisher key registry.
    fn to_structural_engine_manifest(&self) -> Result<ExtensionManifest, ManifestSchemaError> {
        self.project_engine_manifest(false)
    }

    fn project_engine_manifest(
        &self,
        include_provenance: bool,
    ) -> Result<ExtensionManifest, ManifestSchemaError> {
        // Build through serde to avoid compile-time coupling to extension-host
        // manifest field drift while still projecting required core fields.
        validate_signature(&self.signature)?;
        validate_entrypoint_path(&self.entrypoint)?;

        let mut payload = serde_json::json!({
            "name": self.package.name.clone(),
            "version": self.package.version.clone(),
            "entrypoint": self.entrypoint.clone(),
            "capabilities": self.capabilities.clone(),
            "min_engine_version": self.minimum_runtime_version.clone(),
        });

        if include_provenance {
            // Projects publisher_signature and trust_chain_ref so the engine can
            // resolve the trust chain and verify the publisher signature.
            let sig_bytes = base64::engine::general_purpose::STANDARD
                .decode(&self.signature.signature)
                .map_err(|e| ManifestSchemaError::EngineManifestProjection {
                    reason: format!("signature base64 decode failed: {e}"),
                })?;
            payload["publisher_signature"] = serde_json::json!(sig_bytes);
            payload["trust_chain_ref"] = serde_json::json!(self.trust.trust_card_reference.clone());
        }

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

/// Schema-validate a signed extension manifest.
///
/// This is *structural* validation only: every node-level schema check plus the
/// engine's structural manifest checks (field presence, length bounds,
/// capability lattice, engine-version compatibility). It deliberately does NOT
/// resolve `trust.trust_card_reference` against a trusted-publisher registry or
/// cryptographically verify the publisher signature — trust admission depends on
/// operator-supplied trust roots, which are a runtime input rather than a
/// property of the manifest schema. For the admission path that resolves trust
/// chains and verifies signatures, use
/// [`validate_signed_manifest_with_trusted_publishers`].
pub fn validate_signed_manifest(
    manifest: &SignedExtensionManifest,
) -> Result<(), ManifestSchemaError> {
    validate_signed_manifest_inner(manifest, None)
}

/// Admission-validate a signed extension manifest against a trusted-publisher
/// key registry (bd-dl6gw).
///
/// Runs every check [`validate_signed_manifest`] performs, and additionally
/// projects the publisher signature and trust chain reference into the engine,
/// requiring that the manifest's `trust.trust_card_reference` resolve to an
/// entry in `trusted_publisher_keys` whose hex-encoded Ed25519 verification key
/// validates the publisher signature. The map is keyed by the manifest's
/// `trust.trust_card_reference` (the engine `trust_chain_ref` lookup key); each
/// value is the hex-encoded Ed25519 publisher verification key. An unresolved
/// reference fails closed as `EMS_ENGINE_REJECTED` (engine `FE-MANIFEST-0013`),
/// and a signature that does not verify fails closed as `EMS_ENGINE_REJECTED`
/// (engine invalid-publisher-signature).
pub fn validate_signed_manifest_with_trusted_publishers(
    manifest: &SignedExtensionManifest,
    trusted_publisher_keys: &BTreeMap<String, String>,
) -> Result<(), ManifestSchemaError> {
    validate_signed_manifest_inner(manifest, Some(trusted_publisher_keys))
}

fn validate_signed_manifest_inner(
    manifest: &SignedExtensionManifest,
    trusted_publisher_keys: Option<&BTreeMap<String, String>>,
) -> Result<(), ManifestSchemaError> {
    // Validate schema_version BEFORE using it in error messages to prevent log injection.
    // schema_version comes from untrusted manifest JSON and could contain control characters.
    ensure_manifest_text(&manifest.schema_version, "schema_version")?;

    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ManifestSchemaError::InvalidSchemaVersion {
            expected: MANIFEST_SCHEMA_VERSION.to_string(),
            actual: manifest.schema_version.clone(),
        });
    }

    // All manifest text fields MUST use ensure_manifest_text (not ensure_non_empty)
    // to enforce MAX_MANIFEST_FIELD_BYTES and reject control characters. Using
    // ensure_non_empty alone allows multi-megabyte strings (DoS) and \r\n injection
    // (log manipulation) from attacker-supplied manifests.
    ensure_manifest_text(&manifest.package.name, "package.name")?;
    ensure_manifest_text(&manifest.package.version, "package.version")?;
    ensure_manifest_text(&manifest.package.publisher, "package.publisher")?;
    ensure_manifest_text(&manifest.package.author, "package.author")?;
    ensure_manifest_text(&manifest.minimum_runtime_version, "minimum_runtime_version")?;
    ensure_manifest_text(
        &manifest.behavioral_profile.summary,
        "behavioral_profile.summary",
    )?;
    ensure_manifest_text(
        &manifest.trust.revocation_status_pointer,
        "trust.revocation_status_pointer",
    )?;
    ensure_manifest_text(
        &manifest.trust.trust_card_reference,
        "trust.trust_card_reference",
    )?;
    ensure_manifest_text(
        &manifest.signature.publisher_key_id,
        "signature.publisher_key_id",
    )?;
    ensure_manifest_text(&manifest.signature.signed_at, "signature.signed_at")?;
    // Provenance text fields were previously unvalidated — enforce same bounds.
    ensure_manifest_text(&manifest.provenance.build_system, "provenance.build_system")?;
    ensure_manifest_text(
        &manifest.provenance.source_repository,
        "provenance.source_repository",
    )?;
    ensure_manifest_text(
        &manifest.provenance.source_revision,
        "provenance.source_revision",
    )?;

    if manifest.capabilities.is_empty() {
        return Err(ManifestSchemaError::EmptyCapabilities);
    }
    ensure_collection_len(
        &manifest.capabilities,
        "capabilities",
        MAX_MANIFEST_CAPABILITIES,
    )?;
    ensure_capabilities_unique(&manifest.capabilities)?;
    ensure_manifest_text_collection(
        &manifest.behavioral_profile.declared_network_zones,
        "behavioral_profile.declared_network_zones",
        MAX_DECLARED_NETWORK_ZONES,
    )?;
    ensure_manifest_text_collection(
        &manifest.provenance.reproducibility_markers,
        "provenance.reproducibility_markers",
        MAX_REPRODUCIBILITY_MARKERS,
    )?;

    if manifest.provenance.attestation_chain.is_empty() {
        return Err(ManifestSchemaError::MissingAttestationChain);
    }
    ensure_collection_len(
        &manifest.provenance.attestation_chain,
        "provenance.attestation_chain",
        MAX_MANIFEST_ATTESTATION_CHAIN_ENTRIES,
    )?;

    for (idx, attestation) in manifest.provenance.attestation_chain.iter().enumerate() {
        ensure_manifest_text(
            &attestation.id,
            &format!("provenance.attestation_chain[{idx}].id"),
        )?;
        ensure_manifest_text(
            &attestation.attestation_type,
            &format!("provenance.attestation_chain[{idx}].attestation_type"),
        )?;
        ensure_manifest_text(
            &attestation.digest,
            &format!("provenance.attestation_chain[{idx}].digest"),
        )?;
    }

    validate_signature(&manifest.signature)?;

    // Path-traversal and manifest-local bounds guard. Empty entrypoints still
    // flow to engine validation for EMS_ENGINE_REJECTED, but non-empty invalid
    // paths fail before the engine projection clones attacker-controlled text.
    validate_entrypoint_path(&manifest.entrypoint)?;

    // Reuse engine-level manifest validation (bd-1gx AC(7)). Schema validation
    // runs the engine's *structural* checks via a Development-trust projection
    // (no publisher_signature / trust_chain_ref), so it never requires
    // configured trust roots. Admission validation (bd-dl6gw) supplies a
    // trusted-publisher key registry and projects the full signed manifest so
    // the engine resolves trust_chain_ref and cryptographically verifies the
    // publisher signature.
    match trusted_publisher_keys {
        None => {
            let engine_manifest = manifest.to_structural_engine_manifest()?;
            let config = ExtensionHostConfig {
                allow_development_trust: true,
                ..ExtensionHostConfig::default()
            };
            validate_manifest_with_config(&engine_manifest, &config)
                .map_err(ManifestSchemaError::EngineManifestRejected)?;
        }
        Some(trusted_publisher_keys) => {
            let engine_manifest = manifest.to_engine_manifest()?;
            let config = ExtensionHostConfig {
                trusted_publisher_keys: trusted_publisher_keys.clone(),
                ..ExtensionHostConfig::default()
            };
            validate_manifest_with_config(&engine_manifest, &config)
                .map_err(ManifestSchemaError::EngineManifestRejected)?;
        }
    }

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

fn ensure_collection_len<T>(
    values: &[T],
    field: &str,
    max: usize,
) -> Result<(), ManifestSchemaError> {
    let actual = values.len();
    if actual > max {
        return Err(ManifestSchemaError::CollectionTooLarge {
            field: field.to_string(),
            max,
            actual,
        });
    }
    Ok(())
}

fn ensure_manifest_text_collection(
    values: &[String],
    field: &str,
    max: usize,
) -> Result<(), ManifestSchemaError> {
    ensure_collection_len(values, field, max)?;
    for (idx, value) in values.iter().enumerate() {
        ensure_manifest_text(value, &format!("{field}[{idx}]"))?;
    }
    Ok(())
}

fn ensure_manifest_text(value: &str, field: &str) -> Result<(), ManifestSchemaError> {
    ensure_non_empty(value, field)?;
    if value.len() > MAX_MANIFEST_FIELD_BYTES {
        return Err(ManifestSchemaError::InvalidField {
            field: field.to_string(),
            reason: format!("field exceeds {MAX_MANIFEST_FIELD_BYTES} bytes"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ManifestSchemaError::InvalidField {
            field: field.to_string(),
            reason: "field must not contain control characters".to_string(),
        });
    }
    Ok(())
}

fn validate_entrypoint_path(entrypoint: &str) -> Result<(), ManifestSchemaError> {
    // Empty entrypoint is already caught by engine validation; only guard
    // against path-traversal on non-empty values.
    if entrypoint.trim().is_empty() {
        return Ok(());
    }
    if entrypoint.len() > MAX_MANIFEST_FIELD_BYTES {
        return Err(ManifestSchemaError::EntrypointPathTraversal {
            reason: format!("entrypoint exceeds {MAX_MANIFEST_FIELD_BYTES} bytes"),
        });
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
    // Reject every control character (not just NUL) to match the manifest
    // text-validation discipline applied by ensure_manifest_text. A `\r\n`
    // here would otherwise survive validation and reach audit-log
    // formatting + the engine projection clone path with a log-injection
    // payload riding the entrypoint string.
    if entrypoint.chars().any(char::is_control) {
        return Err(ManifestSchemaError::EntrypointPathTraversal {
            reason: "entrypoint must not contain control characters".to_string(),
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

    let decoded_len = decoded_base64_len_hint(&signature.signature);
    match signature.scheme {
        SignatureScheme::Ed25519 => {
            if signature.threshold.is_some() {
                return Err(ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "ed25519 signatures must not define threshold policy".to_string(),
                });
            }
            if decoded_len != ED25519_SIGNATURE_BYTES {
                return Err(ManifestSchemaError::SignatureMalformed {
                    reason: format!(
                        "ed25519 signature must decode to exactly {ED25519_SIGNATURE_BYTES} bytes"
                    ),
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
            for (idx, signer_key_id) in policy.signer_key_ids.iter().enumerate() {
                ensure_manifest_text(
                    signer_key_id,
                    &format!("signature.threshold.signer_key_ids[{idx}]"),
                )?;
            }
            let unique_keys: std::collections::BTreeSet<&str> =
                policy.signer_key_ids.iter().map(|s| s.as_str()).collect();
            if unique_keys.len() != policy.signer_key_ids.len() {
                return Err(ManifestSchemaError::InvalidThresholdConfiguration {
                    reason: "signer_key_ids must not contain duplicates".to_string(),
                });
            }
            let max_decoded_len = threshold_signature_decoded_limit(policy.total_signers);
            if decoded_len > max_decoded_len {
                return Err(ManifestSchemaError::SignatureMalformed {
                    reason: format!(
                        "threshold_ed25519 signature decodes to {decoded_len} bytes, max {max_decoded_len}"
                    ),
                });
            }
        }
    }

    Ok(())
}

fn threshold_signature_decoded_limit(total_signers: u8) -> usize {
    usize::from(total_signers)
        .saturating_mul(ED25519_SIGNATURE_BYTES)
        .saturating_add(THRESHOLD_SIGNATURE_ENVELOPE_OVERHEAD_BYTES)
}

fn decoded_base64_len_hint(value: &str) -> usize {
    let trailing_padding = value
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .count()
        .min(2);
    value
        .len()
        .saturating_div(4)
        .saturating_mul(3)
        .saturating_sub(trailing_padding)
}

#[cfg(test)]
fn max_base64_encoded_len(decoded_len: usize) -> usize {
    decoded_len
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(4)
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
    InvalidSchemaVersion {
        expected: String,
        actual: String,
    },
    MissingField {
        field: String,
    },
    EmptyCapabilities,
    DuplicateCapability(Capability),
    MissingAttestationChain,
    CollectionTooLarge {
        field: String,
        max: usize,
        actual: usize,
    },
    InvalidField {
        field: String,
        reason: String,
    },
    SignatureMalformed {
        reason: String,
    },
    InvalidThresholdConfiguration {
        reason: String,
    },
    EntrypointPathTraversal {
        reason: String,
    },
    EngineManifestProjection {
        reason: String,
    },
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
            Self::CollectionTooLarge { .. } => "EMS_COLLECTION_TOO_LARGE",
            Self::InvalidField { .. } => "EMS_INVALID_FIELD",
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
            Self::CollectionTooLarge { field, max, actual } => {
                write!(
                    f,
                    "EMS_COLLECTION_TOO_LARGE: {field} has {actual} entries, max {max}"
                )
            }
            Self::InvalidField { field, reason } => {
                write!(f, "EMS_INVALID_FIELD: {field}: {reason}")
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
    fn admission_validation_rejects_untrusted_trust_chain_ref() {
        // Schema validation accepts the manifest, but admission validation
        // against an empty trusted-publisher registry must fail closed because
        // trust.trust_card_reference resolves to no configured key
        // (engine FE-MANIFEST-0013).
        let manifest = valid_manifest();
        assert_eq!(validate_signed_manifest(&manifest), Ok(()));

        let error = validate_signed_manifest_with_trusted_publishers(
            &manifest,
            &std::collections::BTreeMap::new(),
        )
        .expect_err("admission with no trusted publishers must fail closed");
        assert_eq!(error.code(), "EMS_ENGINE_REJECTED");
        assert!(matches!(
            error,
            ManifestSchemaError::EngineManifestRejected(
                ManifestValidationError::UntrustedTrustChainRef
            )
        ));
    }

    #[test]
    fn admission_validation_resolves_trusted_ref_then_verifies_signature() {
        // A trust_card_reference present in the registry resolves past the
        // trust-chain gate; the placeholder publisher signature then fails
        // cryptographic verification. This proves the config seam threads the
        // trusted-publisher keys through to the engine (it gets past
        // FE-MANIFEST-0013 to the signature check).
        let manifest = valid_manifest();
        let trusted = std::collections::BTreeMap::from([(
            manifest.trust.trust_card_reference.clone(),
            "ab".repeat(32), // 32-byte hex placeholder verification key
        )]);

        let error = validate_signed_manifest_with_trusted_publishers(&manifest, &trusted)
            .expect_err("placeholder publisher signature must fail verification");
        assert_eq!(error.code(), "EMS_ENGINE_REJECTED");
        assert!(matches!(
            error,
            ManifestSchemaError::EngineManifestRejected(
                ManifestValidationError::InvalidPublisherSignature
            )
        ));
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
    fn schema_version_with_control_chars_rejected() {
        let malicious_versions = [
            "1.0\nFAKE_LOG: injected",
            "1.0\rcarriage_return",
            "1.0\x1b[31mred_escape",
            "1.0\ttab",
        ];

        for bad_version in malicious_versions {
            let mut manifest = valid_manifest();
            manifest.schema_version = bad_version.to_string();

            let error = validate_signed_manifest(&manifest).expect_err("should fail");
            assert_eq!(
                error.code(),
                "EMS_INVALID_FIELD",
                "expected EMS_INVALID_FIELD for schema_version with control chars: {:?}",
                bad_version
            );
        }
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
    fn entrypoint_rejects_control_characters_carriage_return_line_feed() {
        // Regression: prior to this guard, `validate_entrypoint_path` rejected
        // only NUL bytes among control characters. A publisher-supplied
        // entrypoint like "dist/main.js\r\nINJECTED" survived validation and
        // reached audit-event formatting + the engine projection JSON, opening
        // a log-injection / surface-layout-poisoning channel. Reject every
        // control character to match the discipline ensure_manifest_text
        // applies to other manifest text fields.
        let mut manifest = valid_manifest();
        manifest.entrypoint = "dist/main.js\r\nINJECTED_LOG_LINE".to_string();
        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
        assert!(
            error.to_string().contains("control characters"),
            "error must surface the control-character reason for triage; got {error}"
        );
    }

    #[test]
    fn entrypoint_rejects_oversized_path() {
        // Regression: prior to this guard, validate_entrypoint_path had no
        // length bound, so a manifest with a multi-megabyte entrypoint would
        // pass validation and be cloned into the engine projection JSON,
        // giving an attacker an O(N) memory amplification primitive driven by
        // a single field. Bound entrypoint to the same MAX_MANIFEST_FIELD_BYTES
        // limit ensure_manifest_text enforces on every other text field.
        let mut manifest = valid_manifest();
        let oversized = "a".repeat(MAX_MANIFEST_FIELD_BYTES + 1);
        manifest.entrypoint = format!("dist/{oversized}.js");
        let error = validate_signed_manifest(&manifest).expect_err("should fail");
        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
        assert!(
            error.to_string().contains("exceeds"),
            "error must surface the length-bound reason for triage; got {error}"
        );
    }

    #[test]
    fn entrypoint_rejects_oversized_direct_engine_projection_before_clone_path() {
        let mut manifest = valid_manifest();
        manifest.entrypoint = format!("dist/{}.js", "a".repeat(MAX_MANIFEST_FIELD_BYTES + 1));

        let error = manifest
            .to_engine_manifest()
            .expect_err("oversized direct projection entrypoint must fail closed");

        assert_eq!(error.code(), "EMS_ENTRYPOINT_PATH_TRAVERSAL");
        assert!(
            error.to_string().contains("exceeds"),
            "direct projection must use manifest-local entrypoint bound; got {error}"
        );
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
        push_bounded(
            &mut manifest.provenance.attestation_chain,
            AttestationRef {
                id: "att-02".to_string(),
                attestation_type: "slsa".to_string(),
                digest: " \t".to_string(),
            },
            MAX_CHAIN_ENTRIES,
        );

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

        let max_decoded_len = threshold_signature_decoded_limit(3);
        manifest.signature.signature =
            "A".repeat(max_base64_encoded_len(max_decoded_len.saturating_add(1)));

        let result = validate_signed_manifest(&manifest);
        let error = result.expect_err("oversized signature must fail before engine projection");

        assert_eq!(error.code(), "EMS_SIGNATURE_MALFORMED");
        assert!(error.to_string().contains("threshold_ed25519"));
    }

    #[test]
    fn ed25519_signature_requires_exact_decoded_size() {
        let mut manifest = valid_manifest();
        manifest.signature.scheme = SignatureScheme::Ed25519;
        manifest.signature.threshold = None;
        manifest.signature.signature =
            base64::engine::general_purpose::STANDARD.encode([0_u8; ED25519_SIGNATURE_BYTES - 1]);

        let error = validate_signed_manifest(&manifest).expect_err("short ed25519 must fail");

        assert_eq!(error.code(), "EMS_SIGNATURE_MALFORMED");
        assert!(error.to_string().contains("exactly 64 bytes"));
    }

    #[test]
    fn negative_publisher_key_id_injection_attacks() {
        let mut manifest = valid_manifest();

        let malicious_key_ids = vec![
            "../../../etc/passwd",            // Path traversal
            "key\nnewline",                   // Newline injection
            "key\ttab",                       // Tab injection
            "key\x00null",                    // Null byte injection
            "key\"quote'single",              // Quote injection
            "key\u{202e}reverse\u{202c}trap", // BiDi override
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
            push_bounded(
                &mut massive_chain,
                AttestationRef {
                    id: format!("attestation-{:04}", i),
                    attestation_type: "slsa".to_string(),
                    digest: format!("sha256:{:064x}", i),
                },
                MAX_CHAIN_ENTRIES,
            );
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
            (u8::MAX, u8::MAX),     // Both at max
            (u8::MAX - 1, u8::MAX), // Threshold one below max
            (1, u8::MAX),           // Threshold 1, signers at max
            (u8::MAX / 2, u8::MAX), // Threshold at half max
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
        let massive_zones: Vec<String> = (0..10000).map(|i| format!("zone-{:04}", i)).collect();
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
            "\u{FEFF}BOM-marker",                // Byte Order Mark
            "marker\u{200B}\u{200C}\u{200D}zwj", // Zero-width joiners
            "marker\u{1F4A9}\u{1F525}emoji",     // Emoji sequence
            "\u{202E}reverse\u{202C}marker",     // BiDi override
            "marker\u{0000}null",                // Null byte
            "marker\nnewline",                   // Newline
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
            "a".repeat(10000),                          // 10KB path
            format!("{}/main.js", "dir/".repeat(1000)), // Deep nesting
            format!("main{}.js", "x".repeat(5000)),     // Long filename
        ];

        for path in long_paths {
            manifest.entrypoint = path;
            let result = validate_signed_manifest(&manifest);

            // Oversized entrypoints must be rejected, never silently accepted.
            // Prod's manifest-local guard now bounds entrypoint length and
            // surfaces it as EMS_ENTRYPOINT_PATH_TRAVERSAL ("exceeds ... bytes");
            // paths under that bound but over the engine entrypoint limit are
            // rejected at the engine layer (EMS_ENGINE_*). Either category is a
            // valid boundary rejection.
            let error = result.expect_err("oversized entrypoint must be rejected");
            assert!(
                error.code() == "EMS_ENTRYPOINT_PATH_TRAVERSAL"
                    || error.code().starts_with("EMS_ENGINE_"),
                "unexpected code for oversized entrypoint: {}",
                error.code()
            );
        }
    }

    #[test]
    fn negative_signature_scheme_deserialization_edge_cases() {
        // Test malformed signature scheme JSON
        let malformed_schemes = vec![
            r#""""#,                // Empty string
            r#""ED25519""#,         // Wrong case
            r#""ed25519_variant""#, // Non-existent variant
            r#"null"#,              // Null value
            r#"123"#,               // Number instead of string
            r#"[]"#,                // Array instead of string
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
        manifest.behavioral_profile.summary =
            "Summary with\n\t\rwhitespace\u{0000}chars".to_string();

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

        let handles: Vec<_> = (0..4)
            .map(|i| {
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
            })
            .collect();

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
        manifest.capabilities = vec![cap("fs_read")];
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

    #[test]
    fn manifest_text_fields_reject_overlong_and_control_chars() {
        // Regression: prior to this fix, validate_signed_manifest used
        // ensure_non_empty (not ensure_manifest_text) for most text fields,
        // allowing multi-megabyte strings (DoS) and control-char injection
        // (log manipulation) from attacker-supplied manifests. All text
        // fields must now use ensure_manifest_text for length + control-char
        // enforcement.

        // package.name overlong
        let mut manifest = valid_manifest();
        manifest.package.name = "a".repeat(MAX_MANIFEST_FIELD_BYTES + 1);
        let error = validate_signed_manifest(&manifest).expect_err("overlong name");
        assert_eq!(error.code(), "EMS_INVALID_FIELD");
        assert!(error.to_string().contains("exceeds"));

        // package.name with control char
        let mut manifest = valid_manifest();
        manifest.package.name = "valid-name\r\nINJECTED".to_string();
        let error = validate_signed_manifest(&manifest).expect_err("control char name");
        assert_eq!(error.code(), "EMS_INVALID_FIELD");
        assert!(error.to_string().contains("control"));

        // provenance.build_system overlong (was previously unvalidated)
        let mut manifest = valid_manifest();
        manifest.provenance.build_system = "x".repeat(MAX_MANIFEST_FIELD_BYTES + 1);
        let error = validate_signed_manifest(&manifest).expect_err("overlong build_system");
        assert_eq!(error.code(), "EMS_INVALID_FIELD");

        // provenance.source_repository with control char (was previously unvalidated)
        let mut manifest = valid_manifest();
        manifest.provenance.source_repository = "https://example.com\x00/repo".to_string();
        let error = validate_signed_manifest(&manifest).expect_err("nul in source_repository");
        assert_eq!(error.code(), "EMS_INVALID_FIELD");
        assert!(error.to_string().contains("control"));

        // signature.signed_at overlong
        let mut manifest = valid_manifest();
        manifest.signature.signed_at =
            "2026-01-01T00:00:00Z".to_string() + &"0".repeat(MAX_MANIFEST_FIELD_BYTES);
        let error = validate_signed_manifest(&manifest).expect_err("overlong signed_at");
        assert_eq!(error.code(), "EMS_INVALID_FIELD");
    }
}
