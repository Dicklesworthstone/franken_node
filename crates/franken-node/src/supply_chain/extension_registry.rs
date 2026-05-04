//! bd-209w / bd-3hdn: Signed extension registry with canonical admission kernel.
//!
//! Manages a registry of extensions where every entry is cryptographically
//! signed, carries provenance attestations, and supports monotonic revocation.
//! Extensions progress through a defined lifecycle: Submitted → Active →
//! Deprecated → Revoked, with audit trails at every transition.
//!
//! # Admission kernel
//!
//! All admission decisions are evaluated by a shared [`AdmissionKernel`] that
//! performs real Ed25519 signature verification, canonical provenance chain
//! validation, and optional transparency log inclusion proofs. Shape-only
//! checks (field presence, hex format, string length) are explicitly rejected
//! in favour of cryptographic verification.
//!
//! # Capabilities
//!
//! - Extension registration with Ed25519 signature verification via [`AdmissionKernel`]
//! - Provenance chain validation via canonical attestation verifier
//! - Transparency log inclusion proof verification
//! - Monotonic revocation with reason tracking
//! - Version lineage with compatibility markers
//! - Admission receipts with negative witnesses for rejections
//! - Deterministic audit log with JSONL export
//!
//! # Invariants
//!
//! - **INV-SER-SIGNED**: Every extension entry carries a verified Ed25519 signature.
//! - **INV-SER-PROVENANCE**: Provenance chain verified via canonical attestation verifier.
//! - **INV-SER-REVOCABLE**: Revocation is monotonic and irreversible.
//! - **INV-SER-MONOTONIC**: Version sequences strictly increase within lineage.
//! - **INV-SER-AUDITABLE**: Every mutation produces an immutable audit record.
//! - **INV-SER-DETERMINISTIC**: Same inputs produce same registry state.
//! - **INV-SER-NO-SHAPE-CHECKS**: No admission decision relies on field presence,
//!   hex shape, or string formatting alone.
//! - **INV-SER-NAME-UNIQUE**: Extension names are unique across active extensions.
//! - **INV-SER-INPUT-BOUNDED**: All string inputs are length-validated to prevent DoS.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::supply_chain::artifact_signing::{self, KeyId, KeyRing};
use crate::supply_chain::provenance as prov;
use crate::supply_chain::transparency_verifier as tv;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_REVOCATIONS: usize = 4096;
const MAX_ADMISSION_RECEIPTS: usize = 4096;
const MAX_VERSIONS_PER_EXTENSION: usize = 1024;

// Input validation limits to prevent DoS attacks
const MAX_EXTENSION_NAME_LEN: usize = 256;
const MAX_EXTENSION_DESCRIPTION_LEN: usize = 4096;
const MAX_PUBLISHER_ID_LEN: usize = 256;
const MAX_TAG_LEN: usize = 128;
const MAX_TAGS_COUNT: usize = 32;
const MAX_TRACE_ID_LEN: usize = 256;
const MAX_MANIFEST_BYTES: usize = crate::capacity_defaults::base::LARGE;
const MAX_SIGNATURE_BYTES: usize = 64;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items
            .len()
            .saturating_sub(cap)
            .saturating_add(1)
            .min(items.len());
        items.drain(0..overflow);
    }
    items.push(item);
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn parse_monotonic_version(version: &str) -> Option<[u64; 3]> {
    let parts: Vec<_> = version.split('.').collect();
    let [major, minor, patch] = parts.as_slice() else {
        return None;
    };

    Some([
        parse_version_component(major)?,
        parse_version_component(minor)?,
        parse_version_component(patch)?,
    ])
}

fn parse_version_component(component: &str) -> Option<u64> {
    if component.is_empty() || !component.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    component.parse().ok()
}

fn validate_monotonic_version(previous: &str, candidate: &str) -> Result<(), String> {
    let previous_version = parse_monotonic_version(previous)
        .ok_or_else(|| format!("Existing version {previous} is not a valid numeric semver"))?;
    let candidate_version = parse_monotonic_version(candidate)
        .ok_or_else(|| format!("Candidate version {candidate} is not a valid numeric semver"))?;

    if candidate_version <= previous_version {
        return Err(format!(
            "Version {candidate} must be greater than current version {previous}"
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const SER_EXTENSION_REGISTERED: &str = "SER-001";
    pub const SER_SIGNATURE_VERIFIED: &str = "SER-002";
    pub const SER_PROVENANCE_VALIDATED: &str = "SER-003";
    pub const SER_VERSION_ADDED: &str = "SER-004";
    pub const SER_EXTENSION_DEPRECATED: &str = "SER-005";
    pub const SER_EXTENSION_REVOKED: &str = "SER-006";
    pub const SER_LINEAGE_CHECKED: &str = "SER-007";
    pub const SER_AUDIT_EXPORTED: &str = "SER-008";
    pub const SER_INTEGRITY_VERIFIED: &str = "SER-009";
    pub const SER_QUERY_EXECUTED: &str = "SER-010";
    pub const SER_ADMISSION_EVALUATED: &str = "SER-011";
    pub const SER_ERR_INVALID_SIGNATURE: &str = "SER-ERR-001";
    pub const SER_ERR_MISSING_PROVENANCE: &str = "SER-ERR-002";
    pub const SER_ERR_ALREADY_REVOKED: &str = "SER-ERR-003";
    pub const SER_ERR_NOT_FOUND: &str = "SER-ERR-004";
    pub const SER_ERR_KEY_NOT_FOUND: &str = "SER-ERR-005";
    pub const SER_ERR_PROVENANCE_CHAIN_INVALID: &str = "SER-ERR-006";
    pub const SER_ERR_TRANSPARENCY_FAILED: &str = "SER-ERR-007";
    pub const SER_ERR_INTERNAL: &str = "SER-ERR-008";
    pub const SER_ERR_DUPLICATE_NAME: &str = "SER-ERR-009";
    pub const SER_ERR_INVALID_INPUT: &str = "SER-ERR-010";
}

pub mod invariants {
    pub const INV_SER_SIGNED: &str = "INV-SER-SIGNED";
    pub const INV_SER_PROVENANCE: &str = "INV-SER-PROVENANCE";
    pub const INV_SER_REVOCABLE: &str = "INV-SER-REVOCABLE";
    pub const INV_SER_MONOTONIC: &str = "INV-SER-MONOTONIC";
    pub const INV_SER_AUDITABLE: &str = "INV-SER-AUDITABLE";
    pub const INV_SER_DETERMINISTIC: &str = "INV-SER-DETERMINISTIC";
    pub const INV_SER_NO_SHAPE_CHECKS: &str = "INV-SER-NO-SHAPE-CHECKS";
}

pub const REGISTRY_VERSION: &str = "ser-v2.0";

// ---------------------------------------------------------------------------
// Extension types
// ---------------------------------------------------------------------------

/// Status of an extension in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionStatus {
    Submitted,
    Active,
    Deprecated,
    Revoked,
}

impl ExtensionStatus {
    pub fn all() -> &'static [ExtensionStatus] {
        &[
            Self::Submitted,
            Self::Active,
            Self::Deprecated,
            Self::Revoked,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Active => "active",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Revoked)
    }
}

/// Cryptographic signature for an extension entry.
/// Contains the actual Ed25519 signature bytes (not hex shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionSignature {
    pub key_id: String,
    pub algorithm: String,
    pub signature_bytes: Vec<u8>,
    pub signed_at: String,
}

/// A version entry in the extension's lineage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionEntry {
    pub version: String,
    pub parent_version: Option<String>,
    pub content_hash: String,
    pub registered_at: String,
    pub compatible_with: Vec<String>,
}

/// Revocation record for an extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub extension_id: String,
    pub revoked_at: String,
    pub reason: RevocationReason,
    pub revoked_by: String,
    pub sequence: u64,
}

/// Reason for revoking an extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    SecurityVulnerability,
    PolicyViolation,
    MaintainerRequest,
    LicenseConflict,
    Superseded,
}

/// A signed extension entry in the registry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedExtension {
    pub extension_id: String,
    pub name: String,
    pub description: String,
    pub publisher_id: String,
    pub status: ExtensionStatus,
    pub signature: ExtensionSignature,
    pub provenance: prov::ProvenanceAttestation,
    pub versions: Vec<VersionEntry>,
    pub tags: Vec<String>,
    pub registered_at: String,
    pub updated_at: String,
}

/// Audit log record for registry mutations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub extension_id: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

/// Registration request for a new extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub name: String,
    pub description: String,
    pub publisher_id: String,
    pub signature: ExtensionSignature,
    pub provenance: prov::ProvenanceAttestation,
    pub initial_version: VersionEntry,
    pub tags: Vec<String>,
    /// Canonical manifest bytes that were signed by the publisher.
    pub manifest_bytes: Vec<u8>,
    /// Optional Merkle inclusion proof from a transparency log.
    pub transparency_proof: Option<tv::InclusionProof>,
}

pub const EXTENSION_REGISTRATION_MANIFEST_SCHEMA: &str =
    "franken-node/extension-registration-manifest/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionRegistrationManifest {
    pub schema_version: String,
    pub name: String,
    pub publisher_id: String,
    pub initial_version: VersionEntry,
    pub tags: Vec<String>,
}

pub fn canonical_registration_manifest_bytes(
    name: &str,
    publisher_id: &str,
    initial_version: &VersionEntry,
    tags: &[String],
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&ExtensionRegistrationManifest {
        schema_version: EXTENSION_REGISTRATION_MANIFEST_SCHEMA.to_string(),
        name: name.to_string(),
        publisher_id: publisher_id.to_string(),
        initial_version: initial_version.clone(),
        tags: tags.to_vec(),
    })
}

#[cfg(feature = "test-support")]
pub fn parse_signed_registration_manifest(
    manifest_bytes: &[u8],
) -> Result<ExtensionRegistrationManifest, String> {
    let manifest = serde_json::from_slice::<ExtensionRegistrationManifest>(manifest_bytes)
        .map_err(|err| {
            // SECURITY: Log deserialization error internally but don't expose in client error
            tracing::warn!(
                error = %err,
                "extension registration manifest deserialization failed"
            );
            "invalid signed extension registration manifest".to_string()
        })?;
    if manifest.schema_version != EXTENSION_REGISTRATION_MANIFEST_SCHEMA {
        // SECURITY: Log schema version internally but don't expose in client error
        tracing::warn!(
            expected_version = %EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
            actual_version = %manifest.schema_version,
            "unsupported extension registration manifest schema version"
        );
        return Err("unsupported signed extension registration manifest schema".to_string());
    }
    Ok(manifest)
}

#[cfg(not(feature = "test-support"))]
fn parse_signed_registration_manifest(
    manifest_bytes: &[u8],
) -> Result<ExtensionRegistrationManifest, String> {
    let manifest = serde_json::from_slice::<ExtensionRegistrationManifest>(manifest_bytes)
        .map_err(|err| {
            // SECURITY: Log deserialization error internally but don't expose in client error
            tracing::warn!(
                error = %err,
                "extension registration manifest deserialization failed"
            );
            "invalid signed extension registration manifest".to_string()
        })?;
    if manifest.schema_version != EXTENSION_REGISTRATION_MANIFEST_SCHEMA {
        // SECURITY: Log schema version internally but don't expose in client error
        tracing::warn!(
            expected_version = %EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
            actual_version = %manifest.schema_version,
            "unsupported extension registration manifest schema version"
        );
        return Err("unsupported signed extension registration manifest schema".to_string());
    }
    Ok(manifest)
}

fn registration_manifest_divergence(
    request: &RegistrationRequest,
    manifest: &ExtensionRegistrationManifest,
) -> Option<&'static str> {
    if request.name != manifest.name {
        return Some("name");
    }
    if request.publisher_id != manifest.publisher_id {
        return Some("publisher_id");
    }
    if request.initial_version != manifest.initial_version {
        return Some("initial_version");
    }
    if request.tags != manifest.tags {
        return Some("tags");
    }
    None
}

/// Result of a registry operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryResult {
    pub success: bool,
    pub extension_id: Option<String>,
    pub error_code: Option<String>,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Negative witness and admission receipt
// ---------------------------------------------------------------------------

/// Structured explanation of why an admission was rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NegativeWitness {
    pub rejection_code: String,
    pub rejection_reason: String,
    pub checked_fields: Vec<String>,
    pub remediation: String,
}

/// Receipt of an admission evaluation, produced for every register() call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdmissionReceipt {
    pub receipt_id: String,
    pub extension_name: String,
    pub publisher_key_id: String,
    pub manifest_digest: String,
    pub provenance_level: Option<String>,
    pub admitted: bool,
    pub witness: Option<NegativeWitness>,
    pub trace_id: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Admission kernel
// ---------------------------------------------------------------------------

/// Shared admission verification engine used across publish, install, and
/// audit-log verification flows. All admission decisions are grounded in
/// canonical cryptographic verification — no shape-only shortcuts.
#[derive(Debug, Clone)]
pub struct AdmissionKernel {
    pub key_ring: KeyRing,
    pub provenance_policy: prov::VerificationPolicy,
    pub transparency_policy: tv::TransparencyPolicy,
}

impl AdmissionKernel {
    /// Evaluate an admission request. Returns an [`AdmissionReceipt`] with
    /// either `admitted: true` or a [`NegativeWitness`] explaining the
    /// rejection.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        manifest_bytes: &[u8],
        signature: &ExtensionSignature,
        provenance: &prov::ProvenanceAttestation,
        transparency_proof: Option<&tv::InclusionProof>,
        extension_name: &str,
        now_epoch: u64,
        trace_id: &str,
    ) -> AdmissionReceipt {
        let manifest_digest =
            compute_admission_digest(manifest_bytes, &signature.key_id, provenance);
        let timestamp = Utc::now().to_rfc3339();

        if signature.algorithm != "ed25519" {
            tracing::warn!(
                algorithm = %signature.algorithm,
                "unsupported extension registration signature algorithm"
            );
            return AdmissionReceipt {
                receipt_id: Uuid::now_v7().to_string(),
                extension_name: extension_name.to_string(),
                publisher_key_id: signature.key_id.clone(),
                manifest_digest,
                provenance_level: None,
                admitted: false,
                witness: Some(NegativeWitness {
                    rejection_code: event_codes::SER_ERR_INVALID_SIGNATURE.to_string(),
                    rejection_reason: "unsupported signature algorithm".to_string(),
                    checked_fields: vec!["signature.algorithm".to_string()],
                    remediation: "Use canonical ed25519 signatures over the manifest bytes."
                        .to_string(),
                }),
                trace_id: trace_id.to_string(),
                timestamp,
            };
        }

        // Step 1: Verify publisher key exists in key ring
        let key_id = KeyId(signature.key_id.clone());
        let verifying_key = match self.key_ring.get_key(&key_id) {
            Some(vk) => vk,
            None => {
                tracing::warn!(
                    key_id = %signature.key_id,
                    "publisher key missing from extension registry key ring"
                );
                return AdmissionReceipt {
                    receipt_id: Uuid::now_v7().to_string(),
                    extension_name: extension_name.to_string(),
                    publisher_key_id: signature.key_id.clone(),
                    manifest_digest,
                    provenance_level: None,
                    admitted: false,
                    witness: Some(NegativeWitness {
                        rejection_code: event_codes::SER_ERR_KEY_NOT_FOUND.to_string(),
                        rejection_reason: "publisher key not found".to_string(),
                        checked_fields: vec!["signature.key_id".to_string()],
                        remediation: "Register the publisher's public key in the admission \
                                      kernel's key ring before registration."
                            .to_string(),
                    }),
                    trace_id: trace_id.to_string(),
                    timestamp,
                };
            }
        };

        // Step 2: Verify Ed25519 signature over canonical manifest bytes
        if let Err(e) = artifact_signing::verify_signature(
            verifying_key,
            manifest_bytes,
            &signature.signature_bytes,
        ) {
            return AdmissionReceipt {
                receipt_id: Uuid::now_v7().to_string(),
                extension_name: extension_name.to_string(),
                publisher_key_id: signature.key_id.clone(),
                manifest_digest,
                provenance_level: None,
                admitted: false,
                witness: Some(NegativeWitness {
                    rejection_code: event_codes::SER_ERR_INVALID_SIGNATURE.to_string(),
                    rejection_reason: {
                        // SECURITY: Log signature error internally but don't expose in client response
                        tracing::warn!(
                            error = %e,
                            "Ed25519 signature verification failed for extension registration"
                        );
                        "Ed25519 signature verification failed".to_string()
                    },
                    checked_fields: vec![
                        "signature.signature_bytes".to_string(),
                        "manifest_bytes".to_string(),
                    ],
                    remediation: "Sign the canonical manifest bytes with the publisher's \
                                  Ed25519 signing key."
                        .to_string(),
                }),
                trace_id: trace_id.to_string(),
                timestamp,
            };
        }

        // Step 3: Verify provenance attestation chain
        let chain_report = prov::verify_attestation_chain(
            provenance,
            &self.provenance_policy,
            now_epoch,
            trace_id,
        );
        if !chain_report.chain_valid {
            let issues: Vec<String> = chain_report
                .issues
                .iter()
                .map(|i| i.message.clone())
                .collect();
            tracing::warn!(
                provenance_level = ?chain_report.provenance_level,
                issues = ?issues,
                "extension registration provenance verification failed"
            );
            return AdmissionReceipt {
                receipt_id: Uuid::now_v7().to_string(),
                extension_name: extension_name.to_string(),
                publisher_key_id: signature.key_id.clone(),
                manifest_digest,
                provenance_level: Some(format!("{:?}", chain_report.provenance_level)),
                admitted: false,
                witness: Some(NegativeWitness {
                    rejection_code: event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID.to_string(),
                    rejection_reason: "provenance chain verification failed".to_string(),
                    checked_fields: vec![
                        "provenance.links".to_string(),
                        "provenance.output_hash".to_string(),
                    ],
                    remediation: "Provide a complete, signed provenance attestation chain \
                                  meeting the policy minimum level."
                        .to_string(),
                }),
                trace_id: trace_id.to_string(),
                timestamp,
            };
        }

        // Step 4: Verify transparency proof if required
        let artifact_hash = tv::leaf_hash(&manifest_digest);
        let proof_receipt = tv::verify_inclusion(
            &self.transparency_policy,
            transparency_proof,
            &artifact_hash,
            "extension-registry",
            extension_name,
            trace_id,
            &timestamp,
        );
        if !proof_receipt.verified
            && let Some(ref failure) = proof_receipt.failure_reason
        {
            tracing::warn!(
                failure_reason = %failure,
                "extension registration transparency verification failed"
            );
            return AdmissionReceipt {
                receipt_id: Uuid::now_v7().to_string(),
                extension_name: extension_name.to_string(),
                publisher_key_id: signature.key_id.clone(),
                manifest_digest,
                provenance_level: Some(format!("{:?}", chain_report.provenance_level)),
                admitted: false,
                witness: Some(NegativeWitness {
                    rejection_code: event_codes::SER_ERR_TRANSPARENCY_FAILED.to_string(),
                    rejection_reason: "transparency verification failed".to_string(),
                    checked_fields: vec!["transparency_proof".to_string()],
                    remediation: "Submit a valid Merkle inclusion proof from a pinned \
                                  transparency log."
                        .to_string(),
                }),
                trace_id: trace_id.to_string(),
                timestamp,
            };
        }

        // All checks passed
        AdmissionReceipt {
            receipt_id: Uuid::now_v7().to_string(),
            extension_name: extension_name.to_string(),
            publisher_key_id: signature.key_id.clone(),
            manifest_digest,
            provenance_level: Some(format!("{:?}", chain_report.provenance_level)),
            admitted: true,
            witness: None,
            trace_id: trace_id.to_string(),
            timestamp,
        }
    }
}

/// Domain-separated hash of all admission-bound fields.
/// Binds: manifest bytes, publisher key ID, VCS commit, build system, output hash.
fn compute_admission_digest(
    manifest_bytes: &[u8],
    publisher_key_id: &str,
    provenance: &prov::ProvenanceAttestation,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"extension_registry_admission_v1:");
    hasher.update(len_to_u64(manifest_bytes.len()).to_le_bytes());
    hasher.update(manifest_bytes);
    hasher.update(len_to_u64(publisher_key_id.len()).to_le_bytes());
    hasher.update(publisher_key_id.as_bytes());
    hasher.update(len_to_u64(provenance.vcs_commit_sha.len()).to_le_bytes());
    hasher.update(provenance.vcs_commit_sha.as_bytes());
    hasher.update(len_to_u64(provenance.build_system_identifier.len()).to_le_bytes());
    hasher.update(provenance.build_system_identifier.as_bytes());
    hasher.update(len_to_u64(provenance.output_hash.len()).to_le_bytes());
    hasher.update(provenance.output_hash.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Registry configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub registry_version: String,
    pub require_provenance: bool,
    pub require_signature: bool,
    pub allow_self_revocation: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            registry_version: REGISTRY_VERSION.to_string(),
            require_provenance: true,
            require_signature: true,
            allow_self_revocation: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Registry engine
// ---------------------------------------------------------------------------

/// Signed extension registry with provenance and revocation.
#[derive(Debug, Clone)]
pub struct SignedExtensionRegistry {
    config: RegistryConfig,
    admission_kernel: AdmissionKernel,
    extensions: BTreeMap<String, SignedExtension>,
    revocations: Vec<RevocationRecord>,
    audit_log: Vec<RegistryAuditRecord>,
    admission_receipts: Vec<AdmissionReceipt>,
    revocation_sequence: u64,
}

impl SignedExtensionRegistry {
    pub fn new(config: RegistryConfig, admission_kernel: AdmissionKernel) -> Self {
        Self {
            config,
            admission_kernel,
            extensions: BTreeMap::new(),
            revocations: Vec::new(),
            audit_log: Vec::new(),
            admission_receipts: Vec::new(),
            revocation_sequence: 0,
        }
    }

    /// Get a reference to the admission kernel (for shared use across flows).
    pub fn admission_kernel(&self) -> &AdmissionKernel {
        &self.admission_kernel
    }

    /// Register a publisher's verifying key in the admission kernel's key ring.
    pub fn register_publisher_key(&mut self, vk: ed25519_dalek::VerifyingKey) -> KeyId {
        let key_id = self.admission_kernel.key_ring.add_key(vk);
        self.admission_kernel
            .provenance_policy
            .add_trusted_signer_key(key_id.to_string(), &vk);
        key_id
    }

    /// Get all admission receipts.
    pub fn admission_receipts(&self) -> &[AdmissionReceipt] {
        &self.admission_receipts
    }

    /// Register a new signed extension.
    pub fn register(
        &mut self,
        request: RegistrationRequest,
        trace_id: &str,
        now_epoch: u64,
    ) -> RegistryResult {
        // Input validation to prevent DoS attacks through oversized strings
        if trace_id.len() > MAX_TRACE_ID_LEN {
            // Can't log this error normally since trace_id itself is invalid
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                detail: format!(
                    "Trace ID too long: {} characters (max: {})",
                    trace_id.len(),
                    MAX_TRACE_ID_LEN
                ),
            };
        }

        if request.name.len() > MAX_EXTENSION_NAME_LEN {
            self.log(
                event_codes::SER_ERR_INVALID_INPUT,
                "",
                trace_id,
                serde_json::json!({
                    "field": "name",
                    "length": request.name.len(),
                    "max_allowed": MAX_EXTENSION_NAME_LEN,
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                detail: format!(
                    "Extension name too long: {} characters (max: {})",
                    request.name.len(),
                    MAX_EXTENSION_NAME_LEN
                ),
            };
        }

        if request.description.len() > MAX_EXTENSION_DESCRIPTION_LEN {
            self.log(
                event_codes::SER_ERR_INVALID_INPUT,
                "",
                trace_id,
                serde_json::json!({
                    "field": "description",
                    "length": request.description.len(),
                    "max_allowed": MAX_EXTENSION_DESCRIPTION_LEN,
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                detail: format!(
                    "Extension description too long: {} characters (max: {})",
                    request.description.len(),
                    MAX_EXTENSION_DESCRIPTION_LEN
                ),
            };
        }

        if request.publisher_id.len() > MAX_PUBLISHER_ID_LEN {
            self.log(
                event_codes::SER_ERR_INVALID_INPUT,
                "",
                trace_id,
                serde_json::json!({
                    "field": "publisher_id",
                    "length": request.publisher_id.len(),
                    "max_allowed": MAX_PUBLISHER_ID_LEN,
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                detail: format!(
                    "Publisher ID too long: {} characters (max: {})",
                    request.publisher_id.len(),
                    MAX_PUBLISHER_ID_LEN
                ),
            };
        }

        if request.tags.len() > MAX_TAGS_COUNT {
            self.log(
                event_codes::SER_ERR_INVALID_INPUT,
                "",
                trace_id,
                serde_json::json!({
                    "field": "tags",
                    "count": request.tags.len(),
                    "max_allowed": MAX_TAGS_COUNT,
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                detail: format!(
                    "Too many tags: {} (max: {})",
                    request.tags.len(),
                    MAX_TAGS_COUNT
                ),
            };
        }

        for (i, tag) in request.tags.iter().enumerate() {
            if tag.len() > MAX_TAG_LEN {
                self.log(
                    event_codes::SER_ERR_INVALID_INPUT,
                    "",
                    trace_id,
                    serde_json::json!({
                        "field": "tag",
                        "index": i,
                        "length": tag.len(),
                        "max_allowed": MAX_TAG_LEN,
                    }),
                );
                return RegistryResult {
                    success: false,
                    extension_id: None,
                    error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                    detail: format!(
                        "Tag {} too long: {} characters (max: {})",
                        i,
                        tag.len(),
                        MAX_TAG_LEN
                    ),
                };
            }
        }

        if request.manifest_bytes.len() > MAX_MANIFEST_BYTES {
            self.log(
                event_codes::SER_ERR_INVALID_INPUT,
                "",
                trace_id,
                serde_json::json!({
                    "field": "manifest_bytes",
                    "length": request.manifest_bytes.len(),
                    "max_allowed": MAX_MANIFEST_BYTES,
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                detail: format!(
                    "Manifest bytes too large: {} bytes (max: {})",
                    request.manifest_bytes.len(),
                    MAX_MANIFEST_BYTES
                ),
            };
        }

        if request.signature.signature_bytes.len() != MAX_SIGNATURE_BYTES {
            self.log(
                event_codes::SER_ERR_INVALID_SIGNATURE,
                "",
                trace_id,
                serde_json::json!({
                    "field": "signature.signature_bytes",
                    "length": request.signature.signature_bytes.len(),
                    "required": MAX_SIGNATURE_BYTES,
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_INVALID_SIGNATURE.to_string()),
                detail: format!(
                    "Ed25519 signature must be exactly {} bytes: got {}",
                    MAX_SIGNATURE_BYTES,
                    request.signature.signature_bytes.len()
                ),
            };
        }

        // Evaluate admission via the shared kernel
        let receipt = self.admission_kernel.evaluate(
            &request.manifest_bytes,
            &request.signature,
            &request.provenance,
            request.transparency_proof.as_ref(),
            &request.name,
            now_epoch,
            trace_id,
        );

        // Log the admission evaluation
        self.log(
            event_codes::SER_ADMISSION_EVALUATED,
            "",
            trace_id,
            serde_json::json!({
                "name": &request.name,
                "admitted": receipt.admitted,
                "publisher_key_id": &receipt.publisher_key_id,
                "manifest_digest": &receipt.manifest_digest,
            }),
        );

        // Store the receipt
        push_bounded(
            &mut self.admission_receipts,
            receipt.clone(),
            MAX_ADMISSION_RECEIPTS,
        );

        if !receipt.admitted {
            let (rejection_code, rejection_reason, remediation) =
                if let Some(witness) = receipt.witness.as_ref() {
                    (
                        witness.rejection_code.clone(),
                        witness.rejection_reason.clone(),
                        witness.remediation.clone(),
                    )
                } else {
                    (
                        event_codes::SER_ERR_INTERNAL.to_string(),
                        "Admission rejected without a witness record".to_string(),
                        "Check system logs for missing witness payload".to_string(),
                    )
                };

            self.log(
                &rejection_code,
                "",
                trace_id,
                serde_json::json!({
                    "name": &request.name,
                    "reason": &rejection_reason,
                    "remediation": &remediation,
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(rejection_code.to_string()),
                detail: rejection_reason,
            };
        }

        let signed_manifest = match parse_signed_registration_manifest(&request.manifest_bytes) {
            Ok(manifest) => manifest,
            Err(detail) => {
                self.log(
                    event_codes::SER_ERR_INVALID_INPUT,
                    "",
                    trace_id,
                    serde_json::json!({
                        "field": "manifest_bytes",
                        "reason": &detail,
                    }),
                );
                return RegistryResult {
                    success: false,
                    extension_id: None,
                    error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                    detail,
                };
            }
        };

        if let Some(field) = registration_manifest_divergence(&request, &signed_manifest) {
            let detail = format!(
                "registration request field `{field}` diverges from signed extension manifest"
            );
            self.log(
                event_codes::SER_ERR_INVALID_INPUT,
                "",
                trace_id,
                serde_json::json!({
                    "field": field,
                    "reason": "signed_manifest_divergence",
                    "signed_name": &signed_manifest.name,
                    "request_name": &request.name,
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                detail,
            };
        }

        // Check for name uniqueness after admission succeeds
        // INV-SER-NAME-UNIQUE: Extension names must be unique across active extensions
        let duplicate_extension_id = self
            .extensions
            .values()
            .find(|existing_extension| {
                existing_extension.name == signed_manifest.name
                    && existing_extension.status == ExtensionStatus::Active
            })
            .map(|existing_extension| existing_extension.extension_id.clone());
        if let Some(existing_extension_id) = duplicate_extension_id {
            self.log(
                event_codes::SER_ERR_DUPLICATE_NAME,
                "",
                trace_id,
                serde_json::json!({
                    "name": &signed_manifest.name,
                    "existing_id": &existing_extension_id,
                    "reason": "duplicate_extension_name",
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: None,
                error_code: Some(event_codes::SER_ERR_DUPLICATE_NAME.to_string()),
                detail: "Extension name already exists. Extension names must be unique."
                    .to_string(),
            };
        }

        // Signature verified
        self.log(
            event_codes::SER_SIGNATURE_VERIFIED,
            "",
            trace_id,
            serde_json::json!({
                "name": &signed_manifest.name,
                "key_id": &request.signature.key_id,
            }),
        );

        // Provenance validated
        self.log(
            event_codes::SER_PROVENANCE_VALIDATED,
            "",
            trace_id,
            serde_json::json!({
                "publisher": &request.provenance.builder_identity,
                "provenance_level": &receipt.provenance_level,
            }),
        );

        let extension_id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();

        let extension = SignedExtension {
            extension_id: extension_id.clone(),
            name: signed_manifest.name.clone(),
            description: request.description,
            publisher_id: signed_manifest.publisher_id.clone(),
            status: ExtensionStatus::Active,
            signature: request.signature,
            provenance: request.provenance,
            versions: vec![signed_manifest.initial_version.clone()],
            tags: signed_manifest.tags.clone(),
            registered_at: now.clone(),
            updated_at: now,
        };

        self.extensions.insert(extension_id.clone(), extension);

        self.log(
            event_codes::SER_EXTENSION_REGISTERED,
            &extension_id,
            trace_id,
            serde_json::json!({"name": &signed_manifest.name}),
        );

        RegistryResult {
            success: true,
            extension_id: Some(extension_id),
            error_code: None,
            detail: "Extension registered successfully".to_string(),
        }
    }

    /// Add a new version to an existing extension.
    pub fn add_version(
        &mut self,
        extension_id: &str,
        version: VersionEntry,
        trace_id: &str,
    ) -> RegistryResult {
        let is_revoked = self
            .extensions
            .get(extension_id)
            .map(|e| e.status == ExtensionStatus::Revoked);

        match is_revoked {
            None => {
                return RegistryResult {
                    success: false,
                    extension_id: Some(extension_id.to_string()),
                    error_code: Some(event_codes::SER_ERR_NOT_FOUND.to_string()),
                    detail: "Extension not found".to_string(),
                };
            }
            Some(true) => {
                self.log(
                    event_codes::SER_ERR_ALREADY_REVOKED,
                    extension_id,
                    trace_id,
                    serde_json::json!({"version": &version.version}),
                );
                return RegistryResult {
                    success: false,
                    extension_id: Some(extension_id.to_string()),
                    error_code: Some(event_codes::SER_ERR_ALREADY_REVOKED.to_string()),
                    detail: "Cannot add version to revoked extension".to_string(),
                };
            }
            Some(false) => {}
        }

        if let Some(previous_version) = self
            .extensions
            .get(extension_id)
            .and_then(|ext| ext.versions.last())
            .map(|entry| entry.version.clone())
        {
            if let Err(detail) = validate_monotonic_version(&previous_version, &version.version) {
                self.log(
                    event_codes::SER_ERR_INVALID_INPUT,
                    extension_id,
                    trace_id,
                    serde_json::json!({
                        "previous_version": previous_version,
                        "candidate_version": &version.version,
                        "reason": "non_monotonic_version",
                    }),
                );
                return RegistryResult {
                    success: false,
                    extension_id: Some(extension_id.to_string()),
                    error_code: Some(event_codes::SER_ERR_INVALID_INPUT.to_string()),
                    detail,
                };
            }
        }

        let Some(ext) = self.extensions.get_mut(extension_id) else {
            return RegistryResult {
                success: false,
                extension_id: Some(extension_id.to_string()),
                error_code: Some(event_codes::SER_ERR_NOT_FOUND.to_string()),
                detail: "Extension disappeared during version add".to_string(),
            };
        };
        push_bounded(
            &mut ext.versions,
            version.clone(),
            MAX_VERSIONS_PER_EXTENSION,
        );
        ext.updated_at = Utc::now().to_rfc3339();

        self.log(
            event_codes::SER_VERSION_ADDED,
            extension_id,
            trace_id,
            serde_json::json!({"version": &version.version}),
        );

        RegistryResult {
            success: true,
            extension_id: Some(extension_id.to_string()),
            error_code: None,
            detail: format!("Version {} added", version.version),
        }
    }

    /// Deprecate an extension.
    pub fn deprecate(&mut self, extension_id: &str, trace_id: &str) -> RegistryResult {
        let ext = match self.extensions.get_mut(extension_id) {
            Some(e) => e,
            None => {
                return RegistryResult {
                    success: false,
                    extension_id: Some(extension_id.to_string()),
                    error_code: Some(event_codes::SER_ERR_NOT_FOUND.to_string()),
                    detail: "Extension not found".to_string(),
                };
            }
        };

        if ext.status == ExtensionStatus::Revoked {
            return RegistryResult {
                success: false,
                extension_id: Some(extension_id.to_string()),
                error_code: Some(event_codes::SER_ERR_ALREADY_REVOKED.to_string()),
                detail: "Cannot deprecate a revoked extension".to_string(),
            };
        }

        ext.status = ExtensionStatus::Deprecated;
        ext.updated_at = Utc::now().to_rfc3339();
        let ext_name = ext.name.clone();

        self.log(
            event_codes::SER_EXTENSION_DEPRECATED,
            extension_id,
            trace_id,
            serde_json::json!({"name": &ext_name}),
        );

        RegistryResult {
            success: true,
            extension_id: Some(extension_id.to_string()),
            error_code: None,
            detail: "Extension deprecated".to_string(),
        }
    }

    /// Revoke an extension. Revocation is monotonic and irreversible.
    pub fn revoke(
        &mut self,
        extension_id: &str,
        reason: RevocationReason,
        revoked_by: &str,
        trace_id: &str,
    ) -> RegistryResult {
        let is_revoked = self
            .extensions
            .get(extension_id)
            .map(|e| e.status == ExtensionStatus::Revoked);

        match is_revoked {
            None => {
                return RegistryResult {
                    success: false,
                    extension_id: Some(extension_id.to_string()),
                    error_code: Some(event_codes::SER_ERR_NOT_FOUND.to_string()),
                    detail: "Extension not found".to_string(),
                };
            }
            Some(true) => {
                self.log(
                    event_codes::SER_ERR_ALREADY_REVOKED,
                    extension_id,
                    trace_id,
                    serde_json::json!({"reason": "already revoked"}),
                );
                return RegistryResult {
                    success: false,
                    extension_id: Some(extension_id.to_string()),
                    error_code: Some(event_codes::SER_ERR_ALREADY_REVOKED.to_string()),
                    detail: "Extension is already revoked".to_string(),
                };
            }
            Some(false) => {}
        }

        let Some(next_revocation_sequence) = self.revocation_sequence.checked_add(1) else {
            self.log(
                event_codes::SER_ERR_INTERNAL,
                extension_id,
                trace_id,
                serde_json::json!({
                    "reason": "revocation_sequence_exhausted",
                }),
            );
            return RegistryResult {
                success: false,
                extension_id: Some(extension_id.to_string()),
                error_code: Some(event_codes::SER_ERR_INTERNAL.to_string()),
                detail: "Revocation sequence exhausted".to_string(),
            };
        };

        let Some(ext) = self.extensions.get_mut(extension_id) else {
            return RegistryResult {
                success: false,
                extension_id: Some(extension_id.to_string()),
                error_code: Some(event_codes::SER_ERR_NOT_FOUND.to_string()),
                detail: "Extension disappeared during revocation".to_string(),
            };
        };
        ext.status = ExtensionStatus::Revoked;
        ext.updated_at = Utc::now().to_rfc3339();
        let revoked_at = ext.updated_at.clone();

        self.revocation_sequence = next_revocation_sequence;
        let record = RevocationRecord {
            extension_id: extension_id.to_string(),
            revoked_at,
            reason,
            revoked_by: revoked_by.to_string(),
            sequence: self.revocation_sequence,
        };
        push_bounded(&mut self.revocations, record, MAX_REVOCATIONS);

        self.log(
            event_codes::SER_EXTENSION_REVOKED,
            extension_id,
            trace_id,
            serde_json::json!({
                "reason": format!("{:?}", reason),
                "sequence": self.revocation_sequence,
                "revoked_by": revoked_by,
            }),
        );

        RegistryResult {
            success: true,
            extension_id: Some(extension_id.to_string()),
            error_code: None,
            detail: format!("Extension revoked (seq {})", self.revocation_sequence),
        }
    }

    /// Query an extension by ID.
    pub fn query(&self, extension_id: &str) -> Option<&SignedExtension> {
        self.extensions.get(extension_id)
    }

    /// Query an extension by name. Returns the first active extension with the given name.
    /// Due to name uniqueness enforcement, this should return at most one active extension.
    pub fn query_by_name(&self, name: &str) -> Option<&SignedExtension> {
        self.extensions
            .values()
            .find(|e| e.name == name && e.status == ExtensionStatus::Active)
    }

    /// List all extensions with optional status filter.
    pub fn list(&self, status_filter: Option<ExtensionStatus>) -> Vec<&SignedExtension> {
        self.extensions
            .values()
            .filter(|e| status_filter.map_or(true, |s| e.status == s))
            .collect()
    }

    /// Get the version lineage for an extension.
    pub fn version_lineage(&self, extension_id: &str) -> Option<&[VersionEntry]> {
        self.extensions
            .get(extension_id)
            .map(|e| e.versions.as_slice())
    }

    /// Get all revocation records.
    pub fn revocations(&self) -> &[RevocationRecord] {
        &self.revocations
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[RegistryAuditRecord] {
        &self.audit_log
    }

    /// Compute a content hash of the registry state for integrity.
    pub fn content_hash(&self) -> String {
        let state = serde_json::json!({
            "extensions": &self.extensions,
            "revocations": &self.revocations,
            "require_provenance": self.config.require_provenance,
            "require_signature": self.config.require_signature,
            "allow_self_revocation": self.config.allow_self_revocation,
            "registry_version": &self.config.registry_version,
        })
        .to_string();
        let mut hasher = Sha256::new();
        hasher.update(b"extension_registry_content_hash_v1:");
        hasher.update(len_to_u64(state.len()).to_le_bytes());
        hasher.update(state.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for record in &self.audit_log {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn log(
        &mut self,
        event_code: &str,
        extension_id: &str,
        trace_id: &str,
        details: serde_json::Value,
    ) {
        push_bounded(
            &mut self.audit_log,
            RegistryAuditRecord {
                record_id: Uuid::now_v7().to_string(),
                event_code: event_code.to_string(),
                extension_id: extension_id.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                trace_id: trace_id.to_string(),
                details,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::provenance::{
        AttestationEnvelopeFormat, AttestationLink, ChainLinkRole,
    };
    use ed25519_dalek::SigningKey;

    fn make_trace() -> String {
        Uuid::now_v7().to_string()
    }

    /// Generate an Ed25519 keypair for testing.
    fn test_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    /// Generate a second keypair (different from test_keypair).
    fn test_keypair_2() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = SigningKey::from_bytes(&[99u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn provenance_signing_keys(sk: &SigningKey) -> BTreeMap<String, SigningKey> {
        BTreeMap::from([(
            "pub-001".to_string(),
            SigningKey::from_bytes(&sk.to_bytes()),
        )])
    }

    /// Build a valid provenance attestation with signed links.
    fn valid_provenance(sk: &SigningKey, now_epoch: u64) -> prov::ProvenanceAttestation {
        let mut att = prov::ProvenanceAttestation {
            schema_version: "1.0".to_string(),
            source_repository_url: "https://github.com/example/ext".to_string(),
            build_system_identifier: "github-actions".to_string(),
            builder_identity: "pub-001".to_string(),
            builder_version: "1.0.0".to_string(),
            vcs_commit_sha: "abc123def456".to_string(),
            build_timestamp_epoch: now_epoch.saturating_sub(60),
            reproducibility_hash: "d".repeat(64),
            input_hash: "e".repeat(64),
            output_hash: "f".repeat(64),
            slsa_level_claim: 2,
            envelope_format: AttestationEnvelopeFormat::FrankenNodeEnvelopeV1,
            links: vec![AttestationLink {
                role: ChainLinkRole::Publisher,
                signer_id: "pub-001".to_string(),
                signer_version: "1.0.0".to_string(),
                signature: String::new(), // will be filled by sign_links_in_place
                signed_payload_hash: "f".repeat(64), // matches output_hash
                issued_at_epoch: now_epoch.saturating_sub(60),
                expires_at_epoch: now_epoch.saturating_add(86400),
                revoked: false,
            }],
            custom_claims: BTreeMap::new(),
        };
        // Sign links in place so the provenance verifier accepts them.
        prov::sign_links_in_place(&mut att, &provenance_signing_keys(sk)).expect("sign links");
        att
    }

    fn valid_version(ver: &str) -> VersionEntry {
        VersionEntry {
            version: ver.to_string(),
            parent_version: None,
            content_hash: "c".repeat(64),
            registered_at: Utc::now().to_rfc3339(),
            compatible_with: vec![],
        }
    }

    /// Build an admission kernel with a single trusted publisher key.
    fn test_kernel(vk: &ed25519_dalek::VerifyingKey) -> AdmissionKernel {
        let mut key_ring = KeyRing::new();
        key_ring.add_key(*vk);
        let mut provenance_policy = prov::VerificationPolicy::development_profile();
        provenance_policy.add_trusted_signer_key("pub-001", vk);
        AdmissionKernel {
            key_ring,
            provenance_policy,
            transparency_policy: tv::TransparencyPolicy {
                required: false,
                pinned_roots: vec![],
            },
        }
    }

    /// Build a registry with a test admission kernel.
    fn test_registry(vk: &ed25519_dalek::VerifyingKey) -> SignedExtensionRegistry {
        SignedExtensionRegistry::new(RegistryConfig::default(), test_kernel(vk))
    }

    fn transparency_required_registry(vk: &ed25519_dalek::VerifyingKey) -> SignedExtensionRegistry {
        let mut kernel = test_kernel(vk);
        kernel.transparency_policy.required = true;
        SignedExtensionRegistry::new(RegistryConfig::default(), kernel)
    }

    /// Build a valid registration request signed by the given key.
    fn valid_request(name: &str, sk: &SigningKey, now_epoch: u64) -> RegistrationRequest {
        let initial_version = valid_version("1.0.0");
        let tags = vec!["test".to_string()];
        let manifest_bytes =
            canonical_registration_manifest_bytes(name, "pub-001", &initial_version, &tags)
                .expect("canonical manifest");
        let signature_bytes = artifact_signing::sign_bytes(sk, &manifest_bytes);
        let key_id = KeyId::from_verifying_key(&sk.verifying_key());

        RegistrationRequest {
            name: name.to_string(),
            description: format!("Test extension: {}", name),
            publisher_id: "pub-001".to_string(),
            signature: ExtensionSignature {
                key_id: key_id.to_string(),
                algorithm: "ed25519".to_string(),
                signature_bytes,
                signed_at: Utc::now().to_rfc3339(),
            },
            provenance: valid_provenance(sk, now_epoch),
            initial_version,
            tags,
            manifest_bytes,
            transparency_proof: None,
        }
    }

    fn now_epoch() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // === Registration ===

    #[test]
    fn register_valid_extension() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let result = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        assert!(result.success, "detail: {}", result.detail);
        assert!(result.extension_id.is_some());
    }

    #[test]
    fn register_sets_active_status() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let result = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext = reg.query(result.extension_id.as_ref().unwrap()).unwrap();
        assert_eq!(ext.status, ExtensionStatus::Active);
    }

    #[test]
    fn register_duplicate_name_sanitizes_existing_extension_id() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let first = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let existing_id = first
            .extension_id
            .clone()
            .expect("first registration should return an extension id");

        let duplicate = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );

        assert!(!duplicate.success);
        assert_eq!(
            duplicate.error_code.as_deref(),
            Some(event_codes::SER_ERR_DUPLICATE_NAME)
        );
        assert_eq!(
            duplicate.detail,
            "Extension name already exists. Extension names must be unique."
        );
        assert!(!duplicate.detail.contains(&existing_id));
    }

    #[test]
    fn register_produces_admission_receipt() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        assert_eq!(reg.admission_receipts().len(), 1);
        assert!(reg.admission_receipts()[0].admitted);
        assert!(reg.admission_receipts()[0].witness.is_none());
    }

    // === Adversarial: signature verification ===

    #[test]
    fn adversarial_forged_same_length_signature_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        // Forge: replace signature bytes with same-length garbage
        req.signature.signature_bytes = vec![0xAA; 64];
        let result = reg.register(req, &make_trace(), now_epoch());
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_SIGNATURE)
        );
        // Verify negative witness exists
        let receipt = &reg.admission_receipts()[0];
        assert!(!receipt.admitted);
        let witness = receipt.witness.as_ref().unwrap();
        assert!(
            witness
                .rejection_reason
                .contains("signature verification failed")
        );
    }

    #[test]
    fn adversarial_reused_signature_over_swapped_manifest_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let req = valid_request("ext-a", &sk, now_epoch());
        // Keep the signature from ext-a but swap the manifest bytes
        let mut evil_req = valid_request("ext-b", &sk, now_epoch());
        evil_req.signature = req.signature.clone();
        evil_req.manifest_bytes = b"totally-different-manifest".to_vec();
        let result = reg.register(evil_req, &make_trace(), now_epoch());
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_SIGNATURE)
        );
    }

    #[test]
    fn adversarial_unsigned_registration_field_divergence_rejected() {
        let (sk, vk) = test_keypair();
        for field in ["name", "publisher_id", "initial_version", "tags"] {
            let mut reg = test_registry(&vk);
            let mut req = valid_request("ext-a", &sk, now_epoch());
            match field {
                "name" => req.name = "ext-forged".to_string(),
                "publisher_id" => req.publisher_id = "pub-forged".to_string(),
                "initial_version" => req.initial_version.version = "9.9.9".to_string(),
                "tags" => req.tags = vec!["forged".to_string()],
                _ => unreachable!(),
            }

            let result = reg.register(req, &make_trace(), now_epoch());

            assert!(!result.success, "{field} divergence must fail");
            assert_eq!(
                result.error_code.as_deref(),
                Some(event_codes::SER_ERR_INVALID_INPUT),
                "{field} divergence must be an invalid input error"
            );
            assert!(
                result.detail.contains(field),
                "{field} divergence detail should name field: {}",
                result.detail
            );
            assert!(
                reg.list(None).is_empty(),
                "{field} divergence must not register an extension"
            );
        }
    }

    #[test]
    fn adversarial_unknown_publisher_key_rejected() {
        let (sk, _vk) = test_keypair();
        let (_sk2, vk2) = test_keypair_2();
        // Registry only trusts vk2, but request is signed with sk (vk)
        let mut reg = test_registry(&vk2);
        let request = valid_request("ext-a", &sk, now_epoch());
        let leaked_key_id = request.signature.key_id.clone();
        let result = reg.register(request, &make_trace(), now_epoch());
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_KEY_NOT_FOUND)
        );
        assert_eq!(result.detail, "publisher key not found");
        assert!(!result.detail.contains(&leaked_key_id));
    }

    #[test]
    fn adversarial_truncated_signature_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        // Truncate signature to 32 bytes (should be 64)
        req.signature.signature_bytes.truncate(32);
        let result = reg.register(req, &make_trace(), now_epoch());
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_SIGNATURE)
        );
    }

    #[test]
    fn adversarial_empty_signature_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.signature.signature_bytes = vec![];
        let result = reg.register(req, &make_trace(), now_epoch());
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_SIGNATURE)
        );
    }

    #[test]
    fn adversarial_oversized_signature_rejected_before_admission_evaluation() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.signature.signature_bytes = vec![0xAA; MAX_SIGNATURE_BYTES + 1];

        let result = reg.register(req, &make_trace(), now_epoch());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_SIGNATURE)
        );
        assert!(result.detail.contains("exactly 64 bytes"));
        assert!(
            reg.admission_receipts().is_empty(),
            "oversized signatures must fail before admission receipt hashing"
        );
        let audit = reg.audit_log().last().expect("invalid input audit");
        assert_eq!(audit.event_code, event_codes::SER_ERR_INVALID_SIGNATURE);
        assert_eq!(audit.details["field"], "signature.signature_bytes");
    }

    #[test]
    fn adversarial_oversized_manifest_rejected_before_admission_evaluation() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.manifest_bytes = vec![b'a'; MAX_MANIFEST_BYTES + 1];

        let result = reg.register(req, &make_trace(), now_epoch());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_INPUT)
        );
        assert!(result.detail.contains("Manifest bytes too large"));
        assert!(
            reg.admission_receipts().is_empty(),
            "oversized manifests must fail before admission digest hashing"
        );
        let audit = reg.audit_log().last().expect("invalid input audit");
        assert_eq!(audit.event_code, event_codes::SER_ERR_INVALID_INPUT);
        assert_eq!(audit.details["field"], "manifest_bytes");
    }

    #[test]
    fn adversarial_unsupported_signature_algorithm_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.signature.algorithm = "ed25519ph".to_string();

        let result = reg.register(req, &make_trace(), now_epoch());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_SIGNATURE)
        );
        let witness = reg.admission_receipts()[0]
            .witness
            .as_ref()
            .expect("negative witness");
        assert_eq!(result.detail, "unsupported signature algorithm");
        assert_eq!(witness.rejection_reason, "unsupported signature algorithm");
        assert!(!result.detail.contains("ed25519ph"));
        assert!(
            witness
                .checked_fields
                .contains(&"signature.algorithm".to_string())
        );
        assert!(reg.list(None).is_empty());
    }

    #[test]
    fn adversarial_trusted_key_id_with_wrong_signing_key_rejected() {
        let (_trusted_sk, trusted_vk) = test_keypair();
        let (untrusted_sk, _untrusted_vk) = test_keypair_2();
        let mut reg = test_registry(&trusted_vk);
        let mut req = valid_request("ext-a", &untrusted_sk, now_epoch());
        req.signature.key_id = KeyId::from_verifying_key(&trusted_vk).to_string();

        let result = reg.register(req, &make_trace(), now_epoch());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_SIGNATURE)
        );
        assert!(reg.list(None).is_empty());
    }

    #[test]
    fn adversarial_missing_transparency_proof_rejected_when_required() {
        let (sk, vk) = test_keypair();
        let mut reg = transparency_required_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.transparency_proof = None;

        let result = reg.register(req, &make_trace(), now_epoch());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_TRANSPARENCY_FAILED)
        );
        let witness = reg.admission_receipts()[0]
            .witness
            .as_ref()
            .expect("witness");
        assert_eq!(result.detail, "transparency verification failed");
        assert_eq!(witness.rejection_reason, "transparency verification failed");
        assert!(
            witness
                .checked_fields
                .contains(&"transparency_proof".to_string())
        );
        assert!(reg.list(None).is_empty());
    }

    #[test]
    fn rejected_admission_does_not_insert_extension() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.signature.signature_bytes = vec![0x11; 64];

        let result = reg.register(req, &make_trace(), now_epoch());

        assert!(!result.success);
        assert!(reg.list(None).is_empty());
        assert_eq!(reg.admission_receipts().len(), 1);
        assert!(
            reg.audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::SER_ERR_INVALID_SIGNATURE)
        );
    }

    // === Adversarial: provenance chain ===

    #[test]
    fn adversarial_empty_provenance_chain_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.provenance.links.clear();
        let result = reg.register(req, &make_trace(), now_epoch());
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID)
        );
        let witness = reg.admission_receipts()[0]
            .witness
            .as_ref()
            .expect("witness");
        assert_eq!(result.detail, "provenance chain verification failed");
        assert_eq!(
            witness.rejection_reason,
            "provenance chain verification failed"
        );
    }

    #[test]
    fn adversarial_revoked_attestation_link_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        // Mark the publisher link as revoked
        if let Some(link) = req.provenance.links.first_mut() {
            link.revoked = true;
        }
        let result = reg.register(req, &make_trace(), now_epoch());
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID)
        );
    }

    #[test]
    fn adversarial_stale_attestation_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let now = now_epoch();
        let mut req = valid_request("ext-a", &sk, now);
        // Make attestation extremely old (beyond 7-day dev window)
        req.provenance.build_timestamp_epoch = now.saturating_sub(8 * 24 * 3600);
        for link in &mut req.provenance.links {
            link.issued_at_epoch = now.saturating_sub(8 * 24 * 3600);
            link.expires_at_epoch = now.saturating_sub(7 * 24 * 3600);
        }
        // Re-sign links with updated timestamps
        prov::sign_links_in_place(&mut req.provenance, &provenance_signing_keys(&sk))
            .expect("sign");
        let result = reg.register(req, &make_trace(), now);
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID)
        );
    }

    #[test]
    fn adversarial_tampered_provenance_link_signature_rejected() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.provenance.links[0].signature.push_str("00");

        let result = reg.register(req, &make_trace(), now_epoch());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID)
        );
        assert!(reg.list(None).is_empty());
    }

    // === Regression: shape-only checks no longer work ===

    #[test]
    fn regression_hex_shaped_signature_not_accepted() {
        // The old code accepted any 64+ hex chars as a valid signature.
        // Verify that hex-shaped strings are not accepted without real verification.
        let (_sk, vk) = test_keypair();
        let (sk2, _vk2) = test_keypair_2();
        let mut reg = test_registry(&vk);
        let req = valid_request("ext-a", &sk2, now_epoch());
        // Even though this is a valid signature by sk2, the key is not in the ring
        let result = reg.register(req, &make_trace(), now_epoch());
        assert!(!result.success);
    }

    #[test]
    fn regression_field_presence_not_sufficient() {
        // The old verify_provenance only checked !field.is_empty().
        // With canonical chain verification, non-empty fields alone don't pass.
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let mut req = valid_request("ext-a", &sk, now_epoch());
        // Corrupt the provenance: valid-looking but wrong output hash
        req.provenance.output_hash = "x".repeat(64);
        // Re-sign links (the link's signed_payload_hash won't match output_hash)
        prov::sign_links_in_place(&mut req.provenance, &provenance_signing_keys(&sk))
            .expect("sign");
        let result = reg.register(req, &make_trace(), now_epoch());
        // Should fail because link payload hash doesn't match attestation output hash
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_PROVENANCE_CHAIN_INVALID)
        );
    }

    // === Version management ===

    #[test]
    fn add_version_to_active_extension() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();
        let result = reg.add_version(&ext_id, valid_version("2.0.0"), &make_trace());
        assert!(result.success);
        assert_eq!(reg.version_lineage(&ext_id).unwrap().len(), 2);
    }

    #[test]
    fn add_version_rejects_equal_previous_version() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();

        let result = reg.add_version(&ext_id, valid_version("1.0.0"), &make_trace());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_INPUT)
        );
        assert!(
            result
                .detail
                .contains("must be greater than current version")
        );
        assert_eq!(reg.version_lineage(&ext_id).unwrap().len(), 1);
        assert_eq!(
            reg.audit_log().last().expect("audit").event_code,
            event_codes::SER_ERR_INVALID_INPUT
        );
    }

    #[test]
    fn add_version_rejects_lower_previous_version() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();

        let result = reg.add_version(&ext_id, valid_version("0.9.9"), &make_trace());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_INVALID_INPUT)
        );
        assert_eq!(reg.version_lineage(&ext_id).unwrap().len(), 1);
    }

    #[test]
    fn add_version_does_not_depend_on_revocation_sequence_capacity() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let now = now_epoch();
        let result = reg.register(valid_request("ext-a", &sk, now), &make_trace(), now);
        let ext_id = result.extension_id.expect("extension id");
        reg.revocation_sequence = u64::MAX;

        let add_version = reg.add_version(&ext_id, valid_version("2.0.0"), &make_trace());

        assert!(add_version.success);
        assert_eq!(reg.version_lineage(&ext_id).expect("lineage").len(), 2);
        assert_eq!(
            reg.query(&ext_id).expect("extension").status,
            ExtensionStatus::Active
        );
        assert_eq!(reg.revocation_sequence, u64::MAX);
    }

    #[test]
    fn add_version_to_revoked_extension_fails() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();
        reg.revoke(
            &ext_id,
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );
        let result = reg.add_version(&ext_id, valid_version("2.0.0"), &make_trace());
        assert!(!result.success);
    }

    #[test]
    fn add_version_to_revoked_extension_preserves_lineage() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();
        reg.revoke(
            &ext_id,
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );
        let before = reg.version_lineage(&ext_id).expect("lineage").len();

        let result = reg.add_version(&ext_id, valid_version("2.0.0"), &make_trace());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_ALREADY_REVOKED)
        );
        assert_eq!(reg.version_lineage(&ext_id).expect("lineage").len(), before);
    }

    #[test]
    fn add_version_not_found() {
        let (_, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let result = reg.add_version("nonexistent", valid_version("1.0.0"), &make_trace());
        assert!(!result.success);
    }

    #[test]
    fn add_version_missing_extension_does_not_emit_audit() {
        let (_, vk) = test_keypair();
        let mut reg = test_registry(&vk);

        let result = reg.add_version("missing", valid_version("1.0.0"), &make_trace());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_NOT_FOUND)
        );
        assert!(reg.audit_log().is_empty());
    }

    // === Deprecation ===

    #[test]
    fn deprecate_active_extension() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();
        let result = reg.deprecate(&ext_id, &make_trace());
        assert!(result.success);
        assert_eq!(
            reg.query(&ext_id).unwrap().status,
            ExtensionStatus::Deprecated
        );
    }

    #[test]
    fn deprecate_revoked_extension_fails() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();
        reg.revoke(
            &ext_id,
            RevocationReason::PolicyViolation,
            "admin",
            &make_trace(),
        );
        let result = reg.deprecate(&ext_id, &make_trace());
        assert!(!result.success);
    }

    #[test]
    fn deprecate_missing_extension_does_not_emit_mutation_audit() {
        let (_, vk) = test_keypair();
        let mut reg = test_registry(&vk);

        let result = reg.deprecate("missing-extension", &make_trace());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_NOT_FOUND)
        );
        assert!(reg.audit_log().is_empty());
    }

    #[test]
    fn deprecate_revoked_extension_preserves_terminal_status() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();
        reg.revoke(
            &ext_id,
            RevocationReason::PolicyViolation,
            "admin",
            &make_trace(),
        );

        let result = reg.deprecate(&ext_id, &make_trace());

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_ALREADY_REVOKED)
        );
        assert_eq!(
            reg.query(&ext_id).expect("extension").status,
            ExtensionStatus::Revoked
        );
    }

    // === Revocation ===

    #[test]
    fn revoke_active_extension() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();
        let result = reg.revoke(
            &ext_id,
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );
        assert!(result.success);
        assert_eq!(reg.query(&ext_id).unwrap().status, ExtensionStatus::Revoked);
    }

    #[test]
    fn revoke_already_revoked_fails() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = r.extension_id.unwrap();
        reg.revoke(
            &ext_id,
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );
        let result = reg.revoke(
            &ext_id,
            RevocationReason::PolicyViolation,
            "admin",
            &make_trace(),
        );
        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_ALREADY_REVOKED)
        );
    }

    #[test]
    fn duplicate_revocation_does_not_advance_sequence_or_append_record() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let result = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext_id = result.extension_id.expect("extension id");
        reg.revoke(
            &ext_id,
            RevocationReason::PolicyViolation,
            "admin",
            &make_trace(),
        );
        let sequence_after_first = reg.revocation_sequence;
        let records_after_first = reg.revocations().len();

        let duplicate = reg.revoke(
            &ext_id,
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );

        assert!(!duplicate.success);
        assert_eq!(
            duplicate.error_code.as_deref(),
            Some(event_codes::SER_ERR_ALREADY_REVOKED)
        );
        assert_eq!(reg.revocation_sequence, sequence_after_first);
        assert_eq!(reg.revocations().len(), records_after_first);
    }

    #[test]
    fn revoke_missing_extension_does_not_increment_sequence_or_record() {
        let (_, vk) = test_keypair();
        let mut reg = test_registry(&vk);

        let result = reg.revoke(
            "missing-extension",
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );

        assert!(!result.success);
        assert_eq!(
            result.error_code.as_deref(),
            Some(event_codes::SER_ERR_NOT_FOUND)
        );
        assert!(reg.revocations().is_empty());
        assert_eq!(reg.revocation_sequence, 0);
    }

    #[test]
    fn revocation_sequence_is_monotonic() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let now = now_epoch();
        let r1 = reg.register(valid_request("ext-a", &sk, now), &make_trace(), now);
        let r2 = reg.register(valid_request("ext-b", &sk, now), &make_trace(), now);
        reg.revoke(
            r1.extension_id.as_ref().unwrap(),
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );
        reg.revoke(
            r2.extension_id.as_ref().unwrap(),
            RevocationReason::Superseded,
            "admin",
            &make_trace(),
        );
        let revs = reg.revocations();
        assert_eq!(revs.len(), 2);
        assert!(revs[1].sequence > revs[0].sequence);
    }

    #[test]
    fn revocation_fails_closed_when_sequence_is_exhausted() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let now = now_epoch();
        let result = reg.register(valid_request("ext-a", &sk, now), &make_trace(), now);
        let ext_id = result.extension_id.expect("extension id");
        reg.revocation_sequence = u64::MAX;

        let revoke = reg.revoke(
            &ext_id,
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );

        assert!(!revoke.success);
        assert_eq!(
            revoke.error_code.as_deref(),
            Some(event_codes::SER_ERR_INTERNAL)
        );
        assert_eq!(revoke.detail, "Revocation sequence exhausted");
        assert!(reg.revocations().is_empty());
        assert_eq!(
            reg.query(&ext_id).expect("extension").status,
            ExtensionStatus::Active
        );
        assert_eq!(
            reg.audit_log().last().expect("audit").event_code,
            event_codes::SER_ERR_INTERNAL
        );
    }

    #[test]
    fn revocation_reasons() {
        let reasons = [
            RevocationReason::SecurityVulnerability,
            RevocationReason::PolicyViolation,
            RevocationReason::MaintainerRequest,
            RevocationReason::LicenseConflict,
            RevocationReason::Superseded,
        ];
        assert_eq!(reasons.len(), 5);
    }

    // === Query and listing ===

    #[test]
    fn query_existing_extension() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let r = reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let ext = reg.query(r.extension_id.as_ref().unwrap());
        assert!(ext.is_some());
        assert_eq!(ext.unwrap().name, "ext-a");
    }

    #[test]
    fn query_nonexistent_returns_none() {
        let (_, vk) = test_keypair();
        let reg = test_registry(&vk);
        assert!(reg.query("nonexistent").is_none());
    }

    #[test]
    fn list_with_status_filter() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let now = now_epoch();
        let r1 = reg.register(valid_request("ext-a", &sk, now), &make_trace(), now);
        reg.register(valid_request("ext-b", &sk, now), &make_trace(), now);
        reg.revoke(
            r1.extension_id.as_ref().unwrap(),
            RevocationReason::SecurityVulnerability,
            "admin",
            &make_trace(),
        );
        let active = reg.list(Some(ExtensionStatus::Active));
        assert_eq!(active.len(), 1);
        let revoked = reg.list(Some(ExtensionStatus::Revoked));
        assert_eq!(revoked.len(), 1);
    }

    #[test]
    fn list_all() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let now = now_epoch();
        reg.register(valid_request("ext-a", &sk, now), &make_trace(), now);
        reg.register(valid_request("ext-b", &sk, now), &make_trace(), now);
        assert_eq!(reg.list(None).len(), 2);
    }

    // === Extension status ===

    #[test]
    fn four_statuses() {
        assert_eq!(ExtensionStatus::all().len(), 4);
    }

    #[test]
    fn only_revoked_is_terminal() {
        for s in ExtensionStatus::all() {
            if *s == ExtensionStatus::Revoked {
                assert!(s.is_terminal());
            } else {
                assert!(!s.is_terminal());
            }
        }
    }

    #[test]
    fn status_labels() {
        for s in ExtensionStatus::all() {
            assert!(!s.label().is_empty());
        }
    }

    // === Audit log ===

    #[test]
    fn registration_produces_audit_entries() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        // admission evaluated + sig verified + provenance validated + registered = 4
        assert!(reg.audit_log().len() >= 4);
    }

    #[test]
    fn audit_log_has_event_codes() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let codes: Vec<&str> = reg
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::SER_SIGNATURE_VERIFIED));
        assert!(codes.contains(&event_codes::SER_EXTENSION_REGISTERED));
        assert!(codes.contains(&event_codes::SER_ADMISSION_EVALUATED));
    }

    #[test]
    fn export_jsonl() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let jsonl = reg.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(!first["event_code"].as_str().unwrap().is_empty());
    }

    // === Content hash ===

    #[test]
    fn content_hash_is_64_hex() {
        let (_, vk) = test_keypair();
        let reg = test_registry(&vk);
        let hash = reg.content_hash();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn content_hash_changes_on_mutation() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let hash1 = reg.content_hash();
        reg.register(
            valid_request("ext-a", &sk, now_epoch()),
            &make_trace(),
            now_epoch(),
        );
        let hash2 = reg.content_hash();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn content_hash_changes_on_config_policy_mutation() {
        let (_, vk) = test_keypair();
        let strict = test_registry(&vk);
        let strict_hash = strict.content_hash();

        let mut relaxed_config = RegistryConfig::default();
        relaxed_config.require_signature = false;
        let relaxed = SignedExtensionRegistry::new(relaxed_config, test_kernel(&vk));

        assert_ne!(strict_hash, relaxed.content_hash());
    }

    // === Config ===

    #[test]
    fn default_config_strict() {
        let config = RegistryConfig::default();
        assert!(config.require_provenance);
        assert!(config.require_signature);
        assert!(config.allow_self_revocation);
    }

    // === Admission kernel direct ===

    #[test]
    fn admission_kernel_evaluate_returns_receipt() {
        let (sk, vk) = test_keypair();
        let kernel = test_kernel(&vk);
        let now = now_epoch();
        let manifest = b"test-manifest";
        let sig_bytes = artifact_signing::sign_bytes(&sk, manifest);
        let key_id = KeyId::from_verifying_key(&vk);

        let receipt = kernel.evaluate(
            manifest,
            &ExtensionSignature {
                key_id: key_id.to_string(),
                algorithm: "ed25519".to_string(),
                signature_bytes: sig_bytes,
                signed_at: Utc::now().to_rfc3339(),
            },
            &valid_provenance(now),
            None,
            "test-ext",
            now,
            "trace-1",
        );
        assert!(receipt.admitted);
        assert!(receipt.witness.is_none());
    }

    #[test]
    fn admission_kernel_shared_across_flows() {
        // Verify the kernel produces consistent results when reused
        let (sk, vk) = test_keypair();
        let kernel = test_kernel(&vk);
        let now = now_epoch();

        let manifest1 = b"manifest-1";
        let manifest2 = b"manifest-2";
        let sig1 = artifact_signing::sign_bytes(&sk, manifest1);
        let sig2 = artifact_signing::sign_bytes(&sk, manifest2);
        let key_id = KeyId::from_verifying_key(&vk);

        let sig = |bytes: Vec<u8>| ExtensionSignature {
            key_id: key_id.to_string(),
            algorithm: "ed25519".to_string(),
            signature_bytes: bytes,
            signed_at: Utc::now().to_rfc3339(),
        };

        let r1 = kernel.evaluate(
            manifest1,
            &sig(sig1),
            &valid_provenance(now),
            None,
            "ext-1",
            now,
            "t1",
        );
        let r2 = kernel.evaluate(
            manifest2,
            &sig(sig2),
            &valid_provenance(now),
            None,
            "ext-2",
            now,
            "t2",
        );
        assert!(r1.admitted);
        assert!(r2.admitted);
        assert_ne!(r1.manifest_digest, r2.manifest_digest);
    }

    // === Admission digest ===

    #[test]
    fn admission_digest_deterministic() {
        let manifest = b"test-manifest";
        let prov = valid_provenance(1000);
        let d1 = compute_admission_digest(manifest, "key-1", &prov);
        let d2 = compute_admission_digest(manifest, "key-1", &prov);
        assert_eq!(d1, d2);
    }

    #[test]
    fn admission_digest_changes_with_key_id() {
        let manifest = b"test-manifest";
        let prov = valid_provenance(1000);
        let d1 = compute_admission_digest(manifest, "key-1", &prov);
        let d2 = compute_admission_digest(manifest, "key-2", &prov);
        assert_ne!(d1, d2);
    }

    #[test]
    fn admission_digest_changes_with_manifest() {
        let prov = valid_provenance(1000);
        let d1 = compute_admission_digest(b"manifest-a", "key-1", &prov);
        let d2 = compute_admission_digest(b"manifest-b", "key-1", &prov);
        assert_ne!(d1, d2);
    }

    #[test]
    fn admission_digest_changes_with_vcs_commit_tamper() {
        let mut prov = valid_provenance(1000);
        let original = compute_admission_digest(b"manifest", "key-1", &prov);
        prov.vcs_commit_sha.push_str("-tampered");
        let changed = compute_admission_digest(b"manifest", "key-1", &prov);

        assert_ne!(original, changed);
    }

    #[test]
    fn admission_digest_changes_with_build_system_tamper() {
        let mut prov = valid_provenance(1000);
        let original = compute_admission_digest(b"manifest", "key-1", &prov);
        prov.build_system_identifier = "local-shell".to_string();
        let changed = compute_admission_digest(b"manifest", "key-1", &prov);

        assert_ne!(original, changed);
    }

    #[test]
    fn admission_digest_changes_with_output_hash_tamper() {
        let mut prov = valid_provenance(1000);
        let original = compute_admission_digest(b"manifest", "key-1", &prov);
        prov.output_hash = "0".repeat(64);
        let changed = compute_admission_digest(b"manifest", "key-1", &prov);

        assert_ne!(original, changed);
    }

    #[test]
    fn admission_digest_length_prefix_blocks_field_boundary_collision() {
        let prov = valid_provenance(1000);
        let first = compute_admission_digest(b"ab", "c", &prov);
        let second = compute_admission_digest(b"a", "bc", &prov);

        assert_ne!(first, second);
    }

    // === Determinism ===

    #[test]
    fn same_operations_same_extension_count() {
        let (sk, vk) = test_keypair();
        let now = now_epoch();
        let mut r1 = test_registry(&vk);
        let mut r2 = test_registry(&vk);
        r1.register(valid_request("ext-det", &sk, now), "trace-det", now);
        r2.register(valid_request("ext-det", &sk, now), "trace-det", now);
        assert_eq!(r1.extensions.len(), r2.extensions.len());
    }

    // === Static check: no shape-only verification ===

    #[test]
    fn static_check_no_shape_shortcuts() {
        // This test exists as a static assertion that shape-only checks
        // (field presence, hex format, string length) are not used for
        // admission decisions. The old verify_signature() checked:
        //   !sig.key_id.is_empty() && sig.signature_hex.len() >= 64 && ...
        // The new code uses artifact_signing::verify_signature() which
        // performs real Ed25519 verification.
        //
        // If this test compiles, the registry has no verify_signature(&self, sig)
        // or verify_provenance(&self, prov) methods that only check shapes.
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        // A request with valid-looking but cryptographically garbage signature
        // must fail (old code would have accepted this):
        let mut req = valid_request("ext-a", &sk, now_epoch());
        req.signature.signature_bytes = vec![0xFF; 64]; // valid length, wrong content
        let result = reg.register(req, &make_trace(), now_epoch());
        assert!(!result.success, "shape-only check would have accepted this");
    }

    // === Bounded versions ===

    #[test]
    fn versions_bounded_per_extension() {
        let (sk, vk) = test_keypair();
        let mut reg = test_registry(&vk);
        let epoch = now_epoch();
        let req = valid_request("ext-bounded", &sk, epoch);
        let result = reg.register(req, &make_trace(), epoch);
        assert!(result.success);
        let ext_id = result.extension_id.unwrap();

        // Push MAX_VERSIONS_PER_EXTENSION + 10 versions — oldest should be evicted
        for i in 0..(MAX_VERSIONS_PER_EXTENSION + 10) {
            let ver = valid_version(&format!("{}.0.0", i + 2));
            let r = reg.add_version(&ext_id, ver, &make_trace());
            assert!(r.success, "version add {i} failed: {}", r.detail);
        }

        let versions = reg.version_lineage(&ext_id).expect("extension exists");
        assert!(
            versions.len() <= MAX_VERSIONS_PER_EXTENSION,
            "versions Vec must be bounded: got {} > max {}",
            versions.len(),
            MAX_VERSIONS_PER_EXTENSION,
        );
    }

    #[test]
    fn push_bounded_zero_capacity_drops_existing_and_new_items() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_overfull_input_preserves_latest_window() {
        let mut items = vec![1, 2, 3, 4, 5];

        push_bounded(&mut items, 6, 3);

        assert_eq!(items, vec![4, 5, 6]);
    }
}
