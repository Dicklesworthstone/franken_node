//! bd-3ku8: Capability-carrying extension artifact format and enforcement.
//!
//! Defines the canonical format for extension artifacts that carry explicit
//! capability contracts. Implements admission control (fail-closed) and
//! runtime envelope enforcement (no drift).
//!
//! # Artifact Format
//!
//! Each extension artifact consists of:
//! - An `ArtifactIdentity` (unique ID, author, creation timestamp).
//! - A `CapabilityEnvelope` listing the capabilities the extension requires,
//!   with justifications and a SHA-256 digest binding.
//! - A schema version for forward/backward compatibility detection.
//!
//! # Admission Protocol
//!
//! 1. Parse the artifact and validate the schema version.
//! 2. Validate the capability envelope (non-empty, all capabilities in scope).
//! 3. Verify the digest binding between envelope and artifact identity.
//! 4. If any step fails, reject the artifact (fail-closed). No silent pass-through.
//!
//! # Runtime Enforcement
//!
//! Once admitted, the `EnvelopeEnforcer` tracks which capabilities are actually
//! used at runtime. Drift detection fires if:
//! - A capability is used that was not declared in the envelope.
//! - A declared capability is revoked mid-session.
//!
//! # Invariants
//!
//! - INV-CART-FAIL-CLOSED: Admission rejects missing/invalid envelopes.
//! - INV-CART-ENVELOPE-MATCH: Runtime usage matches admitted envelope.
//! - INV-CART-SCHEMA-VERSIONED: Schema version is validated.
//! - INV-CART-DIGEST-BOUND: Envelope is SHA-256 bound to artifact identity.
//! - INV-CART-DETERMINISTIC: BTreeMap/BTreeSet for deterministic output.
//! - INV-CART-AUDIT-COMPLETE: Every decision is audited with stable codes.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current schema version for the capability artifact format.
pub const SCHEMA_VERSION: &str = "cart-v1.0";

/// All recognised schema versions for backward compatibility.
pub const KNOWN_SCHEMA_VERSIONS: &[&str] = &["cart-v1.0"];

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Artifact submitted for admission.
    pub const CART_001: &str = "CART-001";
    /// Artifact admission succeeded.
    pub const CART_002: &str = "CART-002";
    /// Artifact admission rejected (fail-closed).
    pub const CART_003: &str = "CART-003";
    /// Capability envelope validated.
    pub const CART_004: &str = "CART-004";
    /// Capability envelope validation failed.
    pub const CART_005: &str = "CART-005";
    /// Runtime enforcement check passed.
    pub const CART_006: &str = "CART-006";
    /// Runtime enforcement drift detected.
    pub const CART_007: &str = "CART-007";
    /// Artifact digest verified.
    pub const CART_008: &str = "CART-008";
    /// Artifact digest mismatch.
    pub const CART_009: &str = "CART-009";
    /// Schema version validated.
    pub const CART_010: &str = "CART-010";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    /// Artifact has no capability envelope.
    pub const ERR_CART_MISSING_ENVELOPE: &str = "ERR_CART_MISSING_ENVELOPE";
    /// Capability envelope fails schema validation.
    pub const ERR_CART_INVALID_ENVELOPE: &str = "ERR_CART_INVALID_ENVELOPE";
    /// Envelope digest does not match artifact identity.
    pub const ERR_CART_DIGEST_MISMATCH: &str = "ERR_CART_DIGEST_MISMATCH";
    /// Envelope requests capabilities beyond maximum scope.
    pub const ERR_CART_OVER_SCOPED: &str = "ERR_CART_OVER_SCOPED";
    /// Runtime capability usage does not match envelope.
    pub const ERR_CART_DRIFT_DETECTED: &str = "ERR_CART_DRIFT_DETECTED";
    /// Artifact carries an unrecognised schema version.
    pub const ERR_CART_SCHEMA_UNKNOWN: &str = "ERR_CART_SCHEMA_UNKNOWN";
    /// Envelope declares zero capabilities.
    pub const ERR_CART_EMPTY_CAPABILITIES: &str = "ERR_CART_EMPTY_CAPABILITIES";
    /// Artifact ID already admitted.
    pub const ERR_CART_DUPLICATE_ARTIFACT: &str = "ERR_CART_DUPLICATE_ARTIFACT";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_CART_FAIL_CLOSED: &str = "INV-CART-FAIL-CLOSED";
    pub const INV_CART_ENVELOPE_MATCH: &str = "INV-CART-ENVELOPE-MATCH";
    pub const INV_CART_SCHEMA_VERSIONED: &str = "INV-CART-SCHEMA-VERSIONED";
    pub const INV_CART_DIGEST_BOUND: &str = "INV-CART-DIGEST-BOUND";
    pub const INV_CART_DETERMINISTIC: &str = "INV-CART-DETERMINISTIC";
    pub const INV_CART_AUDIT_COMPLETE: &str = "INV-CART-AUDIT-COMPLETE";
}

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

fn is_reserved_artifact_id(artifact_id: &str) -> bool {
    artifact_id.trim() == RESERVED_ARTIFACT_ID
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Maximum capability scope
// ---------------------------------------------------------------------------

/// The set of capabilities that any extension is allowed to request.
/// Capabilities outside this set are considered over-scoped.
pub const ALLOWED_CAPABILITIES: &[&str] = &[
    "cap:crypto:derive",
    "cap:crypto:sign",
    "cap:crypto:verify",
    "cap:fs:read",
    "cap:fs:temp",
    "cap:fs:write",
    "cap:network:connect",
    "cap:network:listen",
    "cap:process:spawn",
    "cap:trust:read",
    "cap:trust:revoke",
    "cap:trust:write",
];

/// Return the allowed capabilities as a deterministic BTreeSet.
pub fn allowed_capability_set() -> BTreeSet<String> {
    ALLOWED_CAPABILITIES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// ArtifactIdentity
// ---------------------------------------------------------------------------

/// Unique identity for an extension artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    /// Unique artifact ID (e.g., "ext-abc-123").
    pub artifact_id: String,
    /// Author or publisher of the artifact.
    pub author: String,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
}

impl ArtifactIdentity {
    pub fn new(
        artifact_id: impl Into<String>,
        author: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            author: author.into(),
            created_at: created_at.into(),
        }
    }

    /// Produce a deterministic canonical string for digest computation.
    pub fn canonical_repr(&self) -> String {
        fn append_field(repr: &mut String, field_name: &str, value: &str) {
            if !repr.is_empty() {
                repr.push(';');
            }
            let _ = write!(
                repr,
                "{field_name}_len={};{field_name}={value}",
                value.len()
            );
        }

        let mut repr = String::new();
        // Preserve field boundaries even when values embed delimiter substrings.
        append_field(&mut repr, "artifact_id", &self.artifact_id);
        append_field(&mut repr, "author", &self.author);
        append_field(&mut repr, "created_at", &self.created_at);
        repr
    }
}

impl fmt::Display for ArtifactIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display_id = display_artifact_id(&self.artifact_id);
        write!(f, "{}@{}", display_id, self.author)
    }
}

// ---------------------------------------------------------------------------
// CapabilityRequirement
// ---------------------------------------------------------------------------

/// A single capability requirement within an envelope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    /// Capability name (e.g., "cap:fs:read").
    pub capability: String,
    /// Why the extension needs this capability.
    pub justification: String,
    /// Whether the capability is mandatory (vs. optional).
    pub mandatory: bool,
}

impl CapabilityRequirement {
    pub fn new(
        capability: impl Into<String>,
        justification: impl Into<String>,
        mandatory: bool,
    ) -> Self {
        Self {
            capability: capability.into(),
            justification: justification.into(),
            mandatory,
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityEnvelope
// ---------------------------------------------------------------------------

/// The capability contract carried by an extension artifact.
///
/// # INV-CART-DETERMINISTIC
/// Requirements stored in BTreeMap for deterministic serialization.
///
/// # INV-CART-DIGEST-BOUND
/// The `digest` field binds this envelope to the artifact identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEnvelope {
    /// Schema version of this envelope format.
    pub schema_version: String,
    /// Capability requirements, keyed by capability name.
    pub requirements: BTreeMap<String, CapabilityRequirement>,
    /// SHA-256 hex digest binding envelope to artifact identity.
    pub digest: String,
}

impl CapabilityEnvelope {
    /// Create a new envelope with the current schema version and no requirements.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            requirements: BTreeMap::new(),
            digest: String::new(),
        }
    }

    /// Add a capability requirement.
    pub fn add_requirement(&mut self, req: CapabilityRequirement) {
        self.requirements.insert(req.capability.clone(), req);
    }

    /// Number of declared capabilities.
    pub fn capability_count(&self) -> usize {
        self.requirements.len()
    }

    /// All declared capability names (sorted via BTreeMap).
    pub fn capability_names(&self) -> Vec<String> {
        self.requirements.keys().cloned().collect()
    }

    /// Compute the SHA-256 digest binding this envelope to an artifact identity.
    ///
    /// # INV-CART-DIGEST-BOUND
    pub fn compute_digest(&self, identity: &ArtifactIdentity) -> String {
        use sha2::{Digest, Sha256};

        // Deterministic canonical representation for hashing.
        let mut hasher = Sha256::new();
        hasher.update(b"capability_artifact_digest_v2:");
        let repr = identity.canonical_repr();
        hasher.update(len_to_u64(repr.len()).to_le_bytes());
        hasher.update(repr.as_bytes());
        hasher.update(len_to_u64(self.schema_version.len()).to_le_bytes());
        hasher.update(self.schema_version.as_bytes());
        hasher.update(len_to_u64(self.requirements.len()).to_le_bytes());
        for (name, req) in &self.requirements {
            hasher.update(len_to_u64(name.len()).to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.update(len_to_u64(req.justification.len()).to_le_bytes());
            hasher.update(req.justification.as_bytes());
            hasher.update([req.mandatory as u8]);
        }
        let digest = hasher.finalize();
        format!("sha256:{}", hex::encode(digest))
    }

    /// Bind this envelope to an artifact identity by computing and storing the digest.
    pub fn bind_to(&mut self, identity: &ArtifactIdentity) {
        self.digest = self.compute_digest(identity);
    }

    /// Verify that the stored digest matches the expected digest for the given identity.
    ///
    /// # INV-CART-DIGEST-BOUND
    pub fn verify_digest(&self, identity: &ArtifactIdentity) -> bool {
        !self.digest.is_empty()
            && crate::security::constant_time::ct_eq(&self.digest, &self.compute_digest(identity))
    }
}

impl Default for CapabilityEnvelope {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExtensionArtifact
// ---------------------------------------------------------------------------

/// A complete extension artifact with identity and capability envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionArtifact {
    /// Artifact identity.
    pub identity: ArtifactIdentity,
    /// Capability envelope (may be None if missing from bundle).
    pub envelope: Option<CapabilityEnvelope>,
}

impl ExtensionArtifact {
    /// Create a new artifact with identity and envelope.
    pub fn new(identity: ArtifactIdentity, envelope: Option<CapabilityEnvelope>) -> Self {
        Self { identity, envelope }
    }
}

// ---------------------------------------------------------------------------
// ArtifactError
// ---------------------------------------------------------------------------

/// Errors from capability artifact admission and enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactError {
    /// Artifact has no capability envelope.
    MissingEnvelope { artifact_id: String },
    /// Envelope fails schema validation.
    InvalidEnvelope { artifact_id: String, detail: String },
    /// Digest does not match artifact identity.
    DigestMismatch { artifact_id: String },
    /// Envelope requests capabilities beyond maximum scope.
    OverScoped {
        artifact_id: String,
        out_of_scope: Vec<String>,
    },
    /// Runtime drift detected.
    DriftDetected { artifact_id: String, detail: String },
    /// Unknown schema version.
    SchemaUnknown {
        artifact_id: String,
        version: String,
    },
    /// Envelope declares zero capabilities.
    EmptyCapabilities { artifact_id: String },
    /// Artifact ID already admitted.
    DuplicateArtifact { artifact_id: String },
}

impl ArtifactError {
    /// Return the stable error code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingEnvelope { .. } => error_codes::ERR_CART_MISSING_ENVELOPE,
            Self::InvalidEnvelope { .. } => error_codes::ERR_CART_INVALID_ENVELOPE,
            Self::DigestMismatch { .. } => error_codes::ERR_CART_DIGEST_MISMATCH,
            Self::OverScoped { .. } => error_codes::ERR_CART_OVER_SCOPED,
            Self::DriftDetected { .. } => error_codes::ERR_CART_DRIFT_DETECTED,
            Self::SchemaUnknown { .. } => error_codes::ERR_CART_SCHEMA_UNKNOWN,
            Self::EmptyCapabilities { .. } => error_codes::ERR_CART_EMPTY_CAPABILITIES,
            Self::DuplicateArtifact { .. } => error_codes::ERR_CART_DUPLICATE_ARTIFACT,
        }
    }

    pub fn artifact_id(&self) -> &str {
        match self {
            Self::MissingEnvelope { artifact_id } => artifact_id,
            Self::InvalidEnvelope { artifact_id, .. } => artifact_id,
            Self::DigestMismatch { artifact_id } => artifact_id,
            Self::OverScoped { artifact_id, .. } => artifact_id,
            Self::DriftDetected { artifact_id, .. } => artifact_id,
            Self::SchemaUnknown { artifact_id, .. } => artifact_id,
            Self::EmptyCapabilities { artifact_id } => artifact_id,
            Self::DuplicateArtifact { artifact_id } => artifact_id,
        }
    }
}

fn display_artifact_id(artifact_id: &str) -> &str {
    if artifact_id.trim().is_empty() || is_reserved_artifact_id(artifact_id) {
        RESERVED_ARTIFACT_ID
    } else {
        artifact_id
    }
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvelope { artifact_id } => {
                let display_id = display_artifact_id(artifact_id);
                write!(f, "artifact {} has no capability envelope", display_id)
            }
            Self::InvalidEnvelope {
                artifact_id,
                detail,
            } => {
                let display_id = display_artifact_id(artifact_id);
                write!(f, "artifact {} envelope invalid: {detail}", display_id)
            }
            Self::DigestMismatch { artifact_id } => {
                let display_id = display_artifact_id(artifact_id);
                write!(
                    f,
                    "artifact {} envelope digest does not match identity",
                    display_id
                )
            }
            Self::OverScoped {
                artifact_id,
                out_of_scope,
            } => {
                let display_id = display_artifact_id(artifact_id);
                write!(
                    f,
                    "artifact {} over-scoped capabilities: {out_of_scope:?}",
                    display_id
                )
            }
            Self::DriftDetected {
                artifact_id,
                detail,
            } => {
                let display_id = display_artifact_id(artifact_id);
                write!(f, "artifact {} runtime drift: {detail}", display_id)
            }
            Self::SchemaUnknown {
                artifact_id,
                version,
            } => {
                let display_id = display_artifact_id(artifact_id);
                write!(
                    f,
                    "artifact {} has unknown schema version: {version}",
                    display_id
                )
            }
            Self::EmptyCapabilities { artifact_id } => {
                let display_id = display_artifact_id(artifact_id);
                write!(
                    f,
                    "artifact {} envelope declares zero capabilities",
                    display_id
                )
            }
            Self::DuplicateArtifact { artifact_id } => {
                let display_id = display_artifact_id(artifact_id);
                write!(f, "artifact {} has duplicate artifact ID", display_id)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/// Structured audit log entry for admission and enforcement decisions.
///
/// # INV-CART-AUDIT-COMPLETE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Event code (stable, from event_codes module).
    pub event_code: String,
    /// Artifact ID this entry relates to.
    pub artifact_id: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Outcome: "admitted", "rejected", "enforced", "drift".
    pub outcome: String,
    /// Human-readable detail.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// AdmissionGate
// ---------------------------------------------------------------------------

/// Admission gate for capability-carrying extension artifacts.
///
/// # INV-CART-FAIL-CLOSED
/// Every artifact must pass all validation steps or be rejected.
///
/// # INV-CART-DETERMINISTIC
/// Admitted artifacts stored in BTreeMap.
///
/// # INV-CART-AUDIT-COMPLETE
/// Every admission decision is audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionGate {
    /// Schema version of the gate itself.
    pub schema_version: String,
    /// Admitted artifacts, keyed by artifact_id.
    pub admitted: BTreeMap<String, ExtensionArtifact>,
    /// Audit log.
    pub audit_log: Vec<AuditEntry>,
    /// Maximum allowed scope (allowed capabilities).
    pub allowed_scope: BTreeSet<String>,
}

impl AdmissionGate {
    /// Create a new admission gate with the default allowed scope.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            admitted: BTreeMap::new(),
            audit_log: Vec::new(),
            allowed_scope: allowed_capability_set(),
        }
    }

    /// Attempt to admit an artifact.
    ///
    /// # INV-CART-FAIL-CLOSED
    /// Returns `Err` if any validation step fails.
    pub fn admit(
        &mut self,
        artifact: &ExtensionArtifact,
        timestamp: &str,
    ) -> Result<(), ArtifactError> {
        let aid = &artifact.identity.artifact_id;
        let display_id = display_artifact_id(aid);

        // Log submission
        self.push_audit(AuditEntry {
            event_code: event_codes::CART_001.to_string(),
            artifact_id: display_id.to_string(),
            timestamp: timestamp.to_string(),
            outcome: "submitted".to_string(),
            detail: format!("artifact {} submitted for admission", display_id),
        });

        if aid.trim().is_empty() {
            let detail = "artifact identity artifact_id is empty".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: display_artifact_id(aid).to_string(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        if is_reserved_artifact_id(aid) {
            let detail = format!("artifact identity artifact_id is reserved: {aid:?}");
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        if aid != aid.trim() {
            let detail =
                "artifact identity artifact_id has leading or trailing whitespace".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        let author = &artifact.identity.author;
        if author.trim().is_empty() {
            let detail = "artifact identity author is empty".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        if author != author.trim() {
            let detail = "artifact identity author has leading or trailing whitespace".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        let created_at = &artifact.identity.created_at;
        if created_at.trim().is_empty() {
            let detail = "artifact identity created_at is empty".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        if created_at != created_at.trim() {
            let detail =
                "artifact identity created_at has leading or trailing whitespace".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        if chrono::DateTime::parse_from_rfc3339(created_at).is_err() {
            let detail = "artifact identity created_at is not RFC 3339".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        // Check for duplicate
        if self.admitted.contains_key(aid) {
            let detail = "duplicate artifact ID".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::DuplicateArtifact {
                artifact_id: aid.clone(),
            });
        }

        // INV-CART-FAIL-CLOSED: require envelope
        let envelope = match &artifact.envelope {
            Some(e) => e,
            None => {
                let detail = "missing capability envelope".to_string();
                self.log_rejection(aid, timestamp, &detail);
                self.push_audit(AuditEntry {
                    event_code: event_codes::CART_005.to_string(),
                    artifact_id: aid.clone(),
                    timestamp: timestamp.to_string(),
                    outcome: "rejected".to_string(),
                    detail: detail.clone(),
                });
                return Err(ArtifactError::MissingEnvelope {
                    artifact_id: aid.clone(),
                });
            }
        };

        if envelope.schema_version.trim().is_empty() {
            let detail = "schema version is empty".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        if envelope.schema_version != envelope.schema_version.trim() {
            let detail = "schema version has leading or trailing whitespace".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::InvalidEnvelope {
                artifact_id: aid.clone(),
                detail,
            });
        }

        // INV-CART-SCHEMA-VERSIONED: validate schema version
        if !KNOWN_SCHEMA_VERSIONS.contains(&envelope.schema_version.as_str()) {
            let detail = format!("unknown schema version: {}", envelope.schema_version);
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::SchemaUnknown {
                artifact_id: aid.clone(),
                version: envelope.schema_version.clone(),
            });
        }

        // Log schema validation success
        self.push_audit(AuditEntry {
            event_code: event_codes::CART_010.to_string(),
            artifact_id: aid.clone(),
            timestamp: timestamp.to_string(),
            outcome: "validated".to_string(),
            detail: format!("schema version {} validated", envelope.schema_version),
        });

        // INV-CART-FAIL-CLOSED: envelope must declare at least one capability
        if envelope.requirements.is_empty() {
            let detail = "envelope declares zero capabilities".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::EmptyCapabilities {
                artifact_id: aid.clone(),
            });
        }

        for (name, req) in &envelope.requirements {
            if name.trim().is_empty() {
                let detail = "capability requirement key is empty".to_string();
                self.log_rejection(aid, timestamp, &detail);
                self.push_audit(AuditEntry {
                    event_code: event_codes::CART_005.to_string(),
                    artifact_id: aid.clone(),
                    timestamp: timestamp.to_string(),
                    outcome: "rejected".to_string(),
                    detail: detail.clone(),
                });
                return Err(ArtifactError::InvalidEnvelope {
                    artifact_id: aid.clone(),
                    detail,
                });
            }
            if name != name.trim() {
                let detail = format!(
                    "capability requirement key '{}' has leading or trailing whitespace",
                    name
                );
                self.log_rejection(aid, timestamp, &detail);
                self.push_audit(AuditEntry {
                    event_code: event_codes::CART_005.to_string(),
                    artifact_id: aid.clone(),
                    timestamp: timestamp.to_string(),
                    outcome: "rejected".to_string(),
                    detail: detail.clone(),
                });
                return Err(ArtifactError::InvalidEnvelope {
                    artifact_id: aid.clone(),
                    detail,
                });
            }
            if req.capability.trim().is_empty() {
                let detail = "capability requirement payload is empty".to_string();
                self.log_rejection(aid, timestamp, &detail);
                self.push_audit(AuditEntry {
                    event_code: event_codes::CART_005.to_string(),
                    artifact_id: aid.clone(),
                    timestamp: timestamp.to_string(),
                    outcome: "rejected".to_string(),
                    detail: detail.clone(),
                });
                return Err(ArtifactError::InvalidEnvelope {
                    artifact_id: aid.clone(),
                    detail,
                });
            }
            if req.capability != req.capability.trim() {
                let detail = format!(
                    "capability '{}' has leading or trailing whitespace",
                    req.capability
                );
                self.log_rejection(aid, timestamp, &detail);
                self.push_audit(AuditEntry {
                    event_code: event_codes::CART_005.to_string(),
                    artifact_id: aid.clone(),
                    timestamp: timestamp.to_string(),
                    outcome: "rejected".to_string(),
                    detail: detail.clone(),
                });
                return Err(ArtifactError::InvalidEnvelope {
                    artifact_id: aid.clone(),
                    detail,
                });
            }
            if name.as_str() != req.capability.as_str() {
                let detail = format!(
                    "capability requirement key '{}' does not match payload '{}'",
                    name, req.capability
                );
                self.log_rejection(aid, timestamp, &detail);
                self.push_audit(AuditEntry {
                    event_code: event_codes::CART_005.to_string(),
                    artifact_id: aid.clone(),
                    timestamp: timestamp.to_string(),
                    outcome: "rejected".to_string(),
                    detail: detail.clone(),
                });
                return Err(ArtifactError::InvalidEnvelope {
                    artifact_id: aid.clone(),
                    detail,
                });
            }
            if req.justification.trim().is_empty() {
                let detail = format!("capability '{}' has empty justification", name);
                self.log_rejection(aid, timestamp, &detail);
                self.push_audit(AuditEntry {
                    event_code: event_codes::CART_005.to_string(),
                    artifact_id: aid.clone(),
                    timestamp: timestamp.to_string(),
                    outcome: "rejected".to_string(),
                    detail: detail.clone(),
                });
                return Err(ArtifactError::InvalidEnvelope {
                    artifact_id: aid.clone(),
                    detail,
                });
            }
            if req.justification != req.justification.trim() {
                let detail = format!(
                    "capability '{}' justification has leading or trailing whitespace",
                    name
                );
                self.log_rejection(aid, timestamp, &detail);
                self.push_audit(AuditEntry {
                    event_code: event_codes::CART_005.to_string(),
                    artifact_id: aid.clone(),
                    timestamp: timestamp.to_string(),
                    outcome: "rejected".to_string(),
                    detail: detail.clone(),
                });
                return Err(ArtifactError::InvalidEnvelope {
                    artifact_id: aid.clone(),
                    detail,
                });
            }
        }

        // Check scope: all requested capabilities must be in allowed_scope
        let requested: BTreeSet<String> = envelope.requirements.keys().cloned().collect();
        let out_of_scope: Vec<String> =
            requested.difference(&self.allowed_scope).cloned().collect();
        if !out_of_scope.is_empty() {
            let detail = format!("over-scoped capabilities: {:?}", out_of_scope);
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            return Err(ArtifactError::OverScoped {
                artifact_id: aid.clone(),
                out_of_scope,
            });
        }

        // INV-CART-DIGEST-BOUND: verify digest
        if !envelope.verify_digest(&artifact.identity) {
            let detail = "digest mismatch".to_string();
            self.log_rejection(aid, timestamp, &detail);
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_005.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: detail.clone(),
            });
            self.push_audit(AuditEntry {
                event_code: event_codes::CART_009.to_string(),
                artifact_id: aid.clone(),
                timestamp: timestamp.to_string(),
                outcome: "rejected".to_string(),
                detail: "digest mismatch".to_string(),
            });
            return Err(ArtifactError::DigestMismatch {
                artifact_id: aid.clone(),
            });
        }

        // Digest verified
        self.push_audit(AuditEntry {
            event_code: event_codes::CART_008.to_string(),
            artifact_id: aid.clone(),
            timestamp: timestamp.to_string(),
            outcome: "verified".to_string(),
            detail: format!("digest {} verified", envelope.digest),
        });

        // Envelope validated
        self.push_audit(AuditEntry {
            event_code: event_codes::CART_004.to_string(),
            artifact_id: aid.clone(),
            timestamp: timestamp.to_string(),
            outcome: "validated".to_string(),
            detail: format!(
                "envelope validated: {} capabilities",
                envelope.capability_count()
            ),
        });

        // Admit
        self.admitted.insert(aid.clone(), artifact.clone());
        self.push_audit(AuditEntry {
            event_code: event_codes::CART_002.to_string(),
            artifact_id: aid.clone(),
            timestamp: timestamp.to_string(),
            outcome: "admitted".to_string(),
            detail: format!(
                "artifact {} admitted with {} capabilities",
                display_id,
                envelope.capability_count()
            ),
        });

        Ok(())
    }

    /// Number of admitted artifacts.
    pub fn admitted_count(&self) -> usize {
        self.admitted.len()
    }

    /// Return the audit log.
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Get the admitted envelope for an artifact.
    pub fn get_envelope(&self, artifact_id: &str) -> Option<&CapabilityEnvelope> {
        self.admitted
            .get(artifact_id)
            .and_then(|a| a.envelope.as_ref())
    }

    /// Log a rejection event.
    fn log_rejection(&mut self, artifact_id: &str, timestamp: &str, detail: &str) {
        self.push_audit(AuditEntry {
            event_code: event_codes::CART_003.to_string(),
            artifact_id: display_artifact_id(artifact_id).to_string(),
            timestamp: timestamp.to_string(),
            outcome: "rejected".to_string(),
            detail: detail.to_string(),
        });
    }

    fn push_audit(&mut self, mut entry: AuditEntry) {
        entry.artifact_id = display_artifact_id(&entry.artifact_id).to_string();
        push_bounded(&mut self.audit_log, entry, MAX_AUDIT_LOG_ENTRIES);
    }
}

impl Default for AdmissionGate {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EnvelopeEnforcer
// ---------------------------------------------------------------------------

/// Runtime enforcer that checks actual capability usage against the admitted
/// envelope.
///
/// # INV-CART-ENVELOPE-MATCH
/// Detects drift between declared and actual capability usage.
///
/// # INV-CART-AUDIT-COMPLETE
/// Every enforcement decision is audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEnforcer {
    /// The artifact ID being enforced.
    pub artifact_id: String,
    /// The admitted capability set (from the envelope).
    pub admitted_capabilities: BTreeSet<String>,
    /// Capabilities actually used at runtime.
    pub used_capabilities: BTreeSet<String>,
    /// Revoked capabilities (e.g., due to policy change).
    pub revoked_capabilities: BTreeSet<String>,
    /// Enforcement audit log.
    pub enforcement_log: Vec<AuditEntry>,
}

impl EnvelopeEnforcer {
    /// Create an enforcer from an admitted envelope.
    pub fn from_envelope(artifact_id: impl Into<String>, envelope: &CapabilityEnvelope) -> Self {
        let artifact_id = artifact_id.into();
        let sanitized_id = display_artifact_id(&artifact_id).to_string();
        Self {
            artifact_id: sanitized_id,
            admitted_capabilities: envelope.requirements.keys().cloned().collect(),
            used_capabilities: BTreeSet::new(),
            revoked_capabilities: BTreeSet::new(),
            enforcement_log: Vec::new(),
        }
    }

    /// Check whether a capability is allowed at runtime.
    ///
    /// # INV-CART-ENVELOPE-MATCH
    pub fn check_capability(
        &mut self,
        capability: &str,
        timestamp: &str,
    ) -> Result<(), ArtifactError> {
        self.used_capabilities.insert(capability.to_string());
        let display_id = display_artifact_id(&self.artifact_id);

        // Check if revoked
        if self.revoked_capabilities.contains(capability) {
            self.push_enforcement_audit(AuditEntry {
                event_code: event_codes::CART_007.to_string(),
                artifact_id: self.artifact_id.clone(),
                timestamp: timestamp.to_string(),
                outcome: "drift".to_string(),
                detail: format!(
                    "capability {} was revoked but used by {}",
                    capability, display_id
                ),
            });
            return Err(ArtifactError::DriftDetected {
                artifact_id: self.artifact_id.clone(),
                detail: format!("capability {capability} revoked but used"),
            });
        }

        // Check if declared in envelope
        if !self.admitted_capabilities.contains(capability) {
            self.push_enforcement_audit(AuditEntry {
                event_code: event_codes::CART_007.to_string(),
                artifact_id: self.artifact_id.clone(),
                timestamp: timestamp.to_string(),
                outcome: "drift".to_string(),
                detail: format!(
                    "capability {} used but not declared in envelope for {}",
                    capability, display_id
                ),
            });
            return Err(ArtifactError::DriftDetected {
                artifact_id: self.artifact_id.clone(),
                detail: format!("capability {capability} not in admitted envelope"),
            });
        }

        // Enforcement passed
        self.push_enforcement_audit(AuditEntry {
            event_code: event_codes::CART_006.to_string(),
            artifact_id: self.artifact_id.clone(),
            timestamp: timestamp.to_string(),
            outcome: "enforced".to_string(),
            detail: format!("capability {} allowed for {}", capability, display_id),
        });

        Ok(())
    }

    /// Revoke a capability at runtime.
    pub fn revoke_capability(&mut self, capability: &str) {
        self.revoked_capabilities.insert(capability.to_string());
    }

    /// Return enforcement audit log.
    pub fn enforcement_log(&self) -> &[AuditEntry] {
        &self.enforcement_log
    }

    fn push_enforcement_audit(&mut self, mut entry: AuditEntry) {
        entry.artifact_id = display_artifact_id(&entry.artifact_id).to_string();
        push_bounded(&mut self.enforcement_log, entry, MAX_AUDIT_LOG_ENTRIES);
    }

    /// Check for drift: any used capability not in admitted set, or any
    /// revoked capability that was used.
    ///
    /// # INV-CART-ENVELOPE-MATCH
    pub fn detect_drift(&self) -> Vec<String> {
        let mut drifts = Vec::new();
        for cap in &self.used_capabilities {
            if !self.admitted_capabilities.contains(cap) {
                drifts.push(format!("used but undeclared: {cap}"));
            }
            if self.revoked_capabilities.contains(cap) {
                drifts.push(format!("revoked but used: {cap}"));
            }
        }
        drifts
    }
}

// ---------------------------------------------------------------------------
// AdmissionReport
// ---------------------------------------------------------------------------

/// Summary report for an admission attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReport {
    pub artifact_id: String,
    pub verdict: String,
    pub capabilities_declared: usize,
    pub detail: String,
}

impl AdmissionReport {
    pub fn pass(artifact_id: &str, capabilities: usize) -> Self {
        Self {
            artifact_id: display_artifact_id(artifact_id).to_string(),
            verdict: "PASS".to_string(),
            capabilities_declared: capabilities,
            detail: format!("artifact admitted with {capabilities} capabilities"),
        }
    }

    pub fn fail(artifact_id: &str, error: &ArtifactError) -> Self {
        let resolved_id = if artifact_id.trim().is_empty() || is_reserved_artifact_id(artifact_id) {
            error.artifact_id()
        } else {
            artifact_id
        };
        Self {
            artifact_id: display_artifact_id(resolved_id).to_string(),
            verdict: "FAIL".to_string(),
            capabilities_declared: 0,
            detail: format!("{error} ({})", error.code()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: build a valid test artifact
// ---------------------------------------------------------------------------

/// Build a well-formed extension artifact for testing/demonstration.
pub fn build_test_artifact(artifact_id: &str, capabilities: &[(&str, &str)]) -> ExtensionArtifact {
    let identity = ArtifactIdentity::new(artifact_id, "test-author", "2026-02-21T00:00:00Z");
    let mut envelope = CapabilityEnvelope::new();
    for (cap, justification) in capabilities {
        envelope.add_requirement(CapabilityRequirement::new(*cap, *justification, true));
    }
    envelope.bind_to(&identity);
    ExtensionArtifact::new(identity, Some(envelope))
}

/// Push an item to a bounded Vec, evicting oldest entries if at capacity.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max: usize) {
    if max == 0 {
        vec.clear();
        return;
    }
    if vec.len() >= max {
        let overflow = vec.len().saturating_sub(max).saturating_add(1);
        vec.drain(0..overflow);
    }
    vec.push(item);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Event codes ──────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::CART_001, "CART-001");
        assert_eq!(event_codes::CART_002, "CART-002");
        assert_eq!(event_codes::CART_003, "CART-003");
        assert_eq!(event_codes::CART_004, "CART-004");
        assert_eq!(event_codes::CART_005, "CART-005");
        assert_eq!(event_codes::CART_006, "CART-006");
        assert_eq!(event_codes::CART_007, "CART-007");
        assert_eq!(event_codes::CART_008, "CART-008");
        assert_eq!(event_codes::CART_009, "CART-009");
        assert_eq!(event_codes::CART_010, "CART-010");
    }

    // ── Error codes ──────────────────────────────────────────────────

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(
            error_codes::ERR_CART_MISSING_ENVELOPE,
            "ERR_CART_MISSING_ENVELOPE"
        );
        assert_eq!(
            error_codes::ERR_CART_INVALID_ENVELOPE,
            "ERR_CART_INVALID_ENVELOPE"
        );
        assert_eq!(
            error_codes::ERR_CART_DIGEST_MISMATCH,
            "ERR_CART_DIGEST_MISMATCH"
        );
        assert_eq!(error_codes::ERR_CART_OVER_SCOPED, "ERR_CART_OVER_SCOPED");
        assert_eq!(
            error_codes::ERR_CART_DRIFT_DETECTED,
            "ERR_CART_DRIFT_DETECTED"
        );
        assert_eq!(
            error_codes::ERR_CART_SCHEMA_UNKNOWN,
            "ERR_CART_SCHEMA_UNKNOWN"
        );
        assert_eq!(
            error_codes::ERR_CART_EMPTY_CAPABILITIES,
            "ERR_CART_EMPTY_CAPABILITIES"
        );
        assert_eq!(
            error_codes::ERR_CART_DUPLICATE_ARTIFACT,
            "ERR_CART_DUPLICATE_ARTIFACT"
        );
    }

    // ── Invariants ───────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(invariants::INV_CART_FAIL_CLOSED, "INV-CART-FAIL-CLOSED");
        assert_eq!(
            invariants::INV_CART_ENVELOPE_MATCH,
            "INV-CART-ENVELOPE-MATCH"
        );
        assert_eq!(
            invariants::INV_CART_SCHEMA_VERSIONED,
            "INV-CART-SCHEMA-VERSIONED"
        );
        assert_eq!(invariants::INV_CART_DIGEST_BOUND, "INV-CART-DIGEST-BOUND");
        assert_eq!(invariants::INV_CART_DETERMINISTIC, "INV-CART-DETERMINISTIC");
        assert_eq!(
            invariants::INV_CART_AUDIT_COMPLETE,
            "INV-CART-AUDIT-COMPLETE"
        );
    }

    // ── Schema version ───────────────────────────────────────────────

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "cart-v1.0");
        assert!(KNOWN_SCHEMA_VERSIONS.contains(&SCHEMA_VERSION));
    }

    // ── Allowed capabilities ─────────────────────────────────────────

    #[test]
    fn test_allowed_capabilities_count() {
        assert_eq!(ALLOWED_CAPABILITIES.len(), 12);
    }

    #[test]
    fn test_allowed_capability_set_deterministic() {
        let set = allowed_capability_set();
        let keys: Vec<String> = set.iter().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeSet must be sorted");
    }

    // ── ArtifactIdentity ─────────────────────────────────────────────

    #[test]
    fn test_artifact_identity_canonical_repr() {
        let id = ArtifactIdentity::new("ext-1", "alice", "2026-01-01T00:00:00Z");
        let repr = id.canonical_repr();
        assert_eq!(
            repr,
            "artifact_id_len=5;artifact_id=ext-1;author_len=5;author=alice;created_at_len=20;created_at=2026-01-01T00:00:00Z"
        );
    }

    #[test]
    fn test_artifact_identity_canonical_repr_preserves_field_boundaries() {
        let lhs = ArtifactIdentity::new("ext-1;author=alice", "bob", "2026-01-01T00:00:00Z");
        let rhs = ArtifactIdentity::new("ext-1", "alice;author=bob", "2026-01-01T00:00:00Z");

        assert_ne!(lhs, rhs);
        assert_ne!(lhs.canonical_repr(), rhs.canonical_repr());
    }

    #[test]
    fn test_artifact_identity_display() {
        let id = ArtifactIdentity::new("ext-1", "alice", "2026-01-01T00:00:00Z");
        assert_eq!(format!("{id}"), "ext-1@alice");
    }

    #[test]
    fn test_artifact_identity_display_unknown_id() {
        let id = ArtifactIdentity::new("   ", "alice", "2026-01-01T00:00:00Z");
        assert_eq!(format!("{id}"), "<unknown>@alice");
        let id = ArtifactIdentity::new(" <unknown> ", "alice", "2026-01-01T00:00:00Z");
        assert_eq!(format!("{id}"), "<unknown>@alice");
    }

    #[test]
    fn test_artifact_identity_display_preserves_whitespace() {
        let id = ArtifactIdentity::new(" ext-id ", "alice", "2026-01-01T00:00:00Z");
        assert_eq!(format!("{id}"), " ext-id @alice");
    }

    #[test]
    fn test_artifact_identity_serde() {
        let id = ArtifactIdentity::new("ext-1", "alice", "2026-01-01T00:00:00Z");
        let json = serde_json::to_string(&id).unwrap();
        let parsed: ArtifactIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    // ── CapabilityEnvelope ───────────────────────────────────────────

    #[test]
    fn test_envelope_new_defaults() {
        let env = CapabilityEnvelope::new();
        assert_eq!(env.schema_version, SCHEMA_VERSION);
        assert_eq!(env.capability_count(), 0);
        assert!(env.digest.is_empty());
    }

    #[test]
    fn test_envelope_add_requirement() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new(
            "cap:fs:read",
            "read config",
            true,
        ));
        assert_eq!(env.capability_count(), 1);
        assert!(env.capability_names().contains(&"cap:fs:read".to_string()));
    }

    #[test]
    fn test_envelope_capability_names_sorted() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:trust:write", "write", true));
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        env.add_requirement(CapabilityRequirement::new(
            "cap:network:connect",
            "connect",
            true,
        ));
        let names = env.capability_names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "BTreeMap keys must be sorted");
    }

    #[test]
    fn test_envelope_digest_binding() {
        let identity = ArtifactIdentity::new("ext-1", "alice", "2026-01-01T00:00:00Z");
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        env.bind_to(&identity);
        assert!(!env.digest.is_empty());
        assert!(env.digest.starts_with("sha256:"));
        assert!(env.verify_digest(&identity));
    }

    #[test]
    fn test_envelope_digest_fails_wrong_identity() {
        let id1 = ArtifactIdentity::new("ext-1", "alice", "2026-01-01T00:00:00Z");
        let id2 = ArtifactIdentity::new("ext-2", "bob", "2026-01-01T00:00:00Z");
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        env.bind_to(&id1);
        assert!(!env.verify_digest(&id2));
    }

    #[test]
    fn test_envelope_digest_changes_when_identity_field_boundaries_change() {
        let lhs = ArtifactIdentity::new("ext-1;author=alice", "bob", "2026-01-01T00:00:00Z");
        let rhs = ArtifactIdentity::new("ext-1", "alice;author=bob", "2026-01-01T00:00:00Z");
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));

        assert_ne!(env.compute_digest(&lhs), env.compute_digest(&rhs));
    }

    #[test]
    fn test_envelope_digest_empty_fails() {
        let identity = ArtifactIdentity::new("ext-1", "alice", "2026-01-01T00:00:00Z");
        let env = CapabilityEnvelope::new();
        assert!(!env.verify_digest(&identity));
    }

    #[test]
    fn test_envelope_serde() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let json = serde_json::to_string(&env).unwrap();
        let parsed: CapabilityEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.capability_count(), 1);
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
    }

    // ── AdmissionGate: success ──────────────────────────────────────

    #[test]
    fn test_admission_gate_new() {
        let gate = AdmissionGate::new();
        assert_eq!(gate.schema_version, SCHEMA_VERSION);
        assert_eq!(gate.admitted_count(), 0);
        assert_eq!(gate.allowed_scope.len(), 12);
    }

    #[test]
    fn test_admission_valid_artifact() {
        let mut gate = AdmissionGate::new();
        let artifact = build_test_artifact(
            "ext-1",
            &[
                ("cap:fs:read", "read config"),
                ("cap:crypto:verify", "verify sigs"),
            ],
        );
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_ok());
        assert_eq!(gate.admitted_count(), 1);
    }

    #[test]
    fn test_admission_produces_audit_entries() {
        let mut gate = AdmissionGate::new();
        let artifact = build_test_artifact("ext-1", &[("cap:fs:read", "read config")]);
        gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap();
        // At least: submission, schema-ok, digest-ok, envelope-ok, admitted
        assert_eq!(gate.audit_log().len(), 5);
        // Should include CART-002 (admitted)
        assert!(
            gate.audit_log()
                .iter()
                .any(|e| e.event_code == event_codes::CART_002)
        );
    }

    // ── AdmissionGate: fail-closed ──────────────────────────────────

    #[test]
    fn test_admission_rejects_missing_envelope() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-bad", "author", "2026-02-21T00:00:00Z");
        let artifact = ExtensionArtifact::new(identity, None);
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_MISSING_ENVELOPE
        );
        assert_eq!(gate.admitted_count(), 0);
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003
                && entry.detail.contains("missing capability envelope")
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005
                && entry.detail.contains("missing capability envelope")
        }));
    }

    #[test]
    fn test_admission_rejects_empty_artifact_id() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_001
                && entry.artifact_id == "<unknown>"
                && entry.detail.contains("<unknown>")
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003 && entry.artifact_id == "<unknown>"
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005 && entry.artifact_id == "<unknown>"
        }));
    }

    #[test]
    fn test_admission_rejects_reserved_artifact_id() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("<unknown>", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003 && entry.artifact_id == "<unknown>"
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005
                && entry.detail.contains("artifact_id is reserved")
        }));
    }

    #[test]
    fn test_admission_rejects_reserved_artifact_id_whitespace() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new(" <unknown> ", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003 && entry.artifact_id == "<unknown>"
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005
                && entry.detail.contains("artifact_id is reserved")
        }));
    }

    #[test]
    fn test_admission_rejects_identity_author_whitespace() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-author-ws", " author ", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_identity_author_empty() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-author-empty", "", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_identity_artifact_id_whitespace() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new(" ext-id ", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_001
                && entry.artifact_id == " ext-id "
                && entry.detail.contains(" ext-id ")
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003 && entry.artifact_id == " ext-id "
        }));
    }

    #[test]
    fn test_admission_rejects_identity_created_at_empty() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-created-empty", "author", "");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_identity_created_at_whitespace() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-created-ws", "author", " 2026-02-21T00:00:00Z ");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_identity_created_at_invalid_rfc3339() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-created-bad", "author", "not-a-time");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_empty_capabilities() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-empty", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_EMPTY_CAPABILITIES
        );
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003
                && entry.detail.contains("envelope declares zero capabilities")
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005
                && entry.detail.contains("envelope declares zero capabilities")
        }));
    }

    #[test]
    fn test_admission_rejects_empty_schema_version() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-empty-schema", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.schema_version.clear();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005
                && entry.detail.contains("schema version is empty")
        }));
    }

    #[test]
    fn test_admission_rejects_schema_version_whitespace() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-schema-ws", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.schema_version = format!(" {} ", SCHEMA_VERSION);
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_empty_justification() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-just-empty", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_whitespace_justification() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-just-ws", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", " read ", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_requirement_payload_whitespace() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-cap-ws", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        let req = CapabilityRequirement::new(" cap:fs:read ", "read", true);
        envelope.requirements.insert("cap:fs:read".to_string(), req);
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_requirement_key_whitespace() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-cap-key-ws", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        let req = CapabilityRequirement::new("cap:fs:read", "read", true);
        envelope
            .requirements
            .insert(" cap:fs:read ".to_string(), req);
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_requirement_payload_empty() {
        let mut gate = AdmissionGate::new();
        let identity =
            ArtifactIdentity::new("ext-cap-payload-empty", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        let req = CapabilityRequirement::new("", "read", true);
        envelope.requirements.insert("cap:fs:read".to_string(), req);
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_empty_requirement_key() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-cap-key-empty", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        let req = CapabilityRequirement::new("cap:fs:read", "read", true);
        envelope.requirements.insert(String::new(), req);
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_duplicate_artifact_id() {
        let mut gate = AdmissionGate::new();
        let artifact = build_test_artifact("ext-dup", &[("cap:fs:read", "read config")]);
        gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap();
        let result = gate.admit(&artifact, "2026-02-21T00:00:01Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_DUPLICATE_ARTIFACT
        );
        assert_eq!(gate.admitted_count(), 1);
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003
                && entry.detail.contains("duplicate artifact ID")
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005
                && entry.detail.contains("duplicate artifact ID")
        }));
    }

    #[test]
    fn test_admission_rejects_mismatched_requirement_key() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-key-mismatch", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        let req = CapabilityRequirement::new("cap:fs:write", "write", true);
        envelope.requirements.insert("cap:fs:read".to_string(), req);
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_INVALID_ENVELOPE
        );
    }

    #[test]
    fn test_admission_rejects_unknown_schema() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-schema", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.schema_version = "cart-v99.0".to_string();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_SCHEMA_UNKNOWN
        );
        assert!(
            gate.audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_003
                    && entry.detail.contains("unknown schema version"))
        );
        assert!(
            gate.audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_005
                    && entry.detail.contains("unknown schema version"))
        );
        assert!(
            !gate
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_010
                    && entry.detail.contains("validated"))
        );
    }

    #[test]
    fn test_admission_rejects_over_scoped() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-over", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new(
            "cap:forbidden:escalate",
            "evil",
            true,
        ));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CART_OVER_SCOPED);
        if let ArtifactError::OverScoped { out_of_scope, .. } = err {
            assert!(out_of_scope.contains(&"cap:forbidden:escalate".to_string()));
        } else {
            unreachable!("expected OverScoped error");
        }
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003
                && entry.detail.contains("over-scoped capabilities")
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005
                && entry.detail.contains("over-scoped capabilities")
        }));
    }

    #[test]
    fn test_admission_rejects_digest_mismatch() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-digest", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        // Deliberately bind to a different identity
        let wrong_id = ArtifactIdentity::new("ext-other", "other", "2026-01-01T00:00:00Z");
        envelope.bind_to(&wrong_id);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));
        let result = gate.admit(&artifact, "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_DIGEST_MISMATCH
        );
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_009 && entry.detail.contains("digest mismatch")
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_003 && entry.detail.contains("digest mismatch")
        }));
        assert!(gate.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::CART_005 && entry.detail.contains("digest mismatch")
        }));
    }

    #[test]
    fn test_admission_rejects_duplicate() {
        let mut gate = AdmissionGate::new();
        let artifact = build_test_artifact("ext-dup", &[("cap:fs:read", "read")]);
        gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap();
        let result = gate.admit(&artifact, "2026-02-21T00:01:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_DUPLICATE_ARTIFACT
        );
    }

    // ── EnvelopeEnforcer ─────────────────────────────────────────────

    #[test]
    fn test_enforcer_allows_declared_capability() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-1", &env);
        let result = enforcer.check_capability("cap:fs:read", "2026-02-21T00:00:00Z");
        assert!(result.is_ok());
    }

    #[test]
    fn test_enforcer_denies_undeclared_capability() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-1", &env);
        let result = enforcer.check_capability("cap:process:spawn", "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_DRIFT_DETECTED
        );
    }

    #[test]
    fn test_enforcer_denies_revoked_capability() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-1", &env);
        enforcer.revoke_capability("cap:fs:read");
        let result = enforcer.check_capability("cap:fs:read", "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            error_codes::ERR_CART_DRIFT_DETECTED
        );
    }

    #[test]
    fn test_enforcer_detect_drift() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-1", &env);
        // Force-insert an undeclared capability into used set
        enforcer
            .used_capabilities
            .insert("cap:trust:write".to_string());
        let drifts = enforcer.detect_drift();
        assert!(!drifts.is_empty());
        assert!(drifts.iter().any(|d| d.contains("undeclared")));
    }

    #[test]
    fn test_enforcer_produces_audit_entries() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-1", &env);
        let _ = enforcer.check_capability("cap:fs:read", "t1");
        let _ = enforcer.check_capability("cap:fs:write", "t2");
        assert_eq!(enforcer.enforcement_log().len(), 2);
        // One pass (CART-006), one drift (CART-007)
        assert!(
            enforcer
                .enforcement_log()
                .iter()
                .any(|e| e.event_code == event_codes::CART_006)
        );
        assert!(
            enforcer
                .enforcement_log()
                .iter()
                .any(|e| e.event_code == event_codes::CART_007)
        );
    }

    #[test]
    fn test_enforcer_sanitizes_artifact_id_in_audit() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("   ", &env);
        assert_eq!(enforcer.artifact_id, "<unknown>");
        let _ = enforcer.check_capability("cap:fs:read", "t1");
        let entry = enforcer
            .enforcement_log()
            .first()
            .expect("expected enforcement audit entry");
        assert_eq!(entry.artifact_id, "<unknown>");
        assert!(entry.detail.contains("<unknown>"));
    }

    // ── ArtifactError ────────────────────────────────────────────────

    #[test]
    fn test_error_codes_mapping() {
        assert_eq!(
            ArtifactError::MissingEnvelope {
                artifact_id: "x".into()
            }
            .code(),
            "ERR_CART_MISSING_ENVELOPE"
        );
        assert_eq!(
            ArtifactError::InvalidEnvelope {
                artifact_id: "x".into(),
                detail: "bad".into()
            }
            .code(),
            "ERR_CART_INVALID_ENVELOPE"
        );
        assert_eq!(
            ArtifactError::DigestMismatch {
                artifact_id: "x".into()
            }
            .code(),
            "ERR_CART_DIGEST_MISMATCH"
        );
        assert_eq!(
            ArtifactError::OverScoped {
                artifact_id: "x".into(),
                out_of_scope: vec![]
            }
            .code(),
            "ERR_CART_OVER_SCOPED"
        );
        assert_eq!(
            ArtifactError::DriftDetected {
                artifact_id: "x".into(),
                detail: "d".into()
            }
            .code(),
            "ERR_CART_DRIFT_DETECTED"
        );
        assert_eq!(
            ArtifactError::SchemaUnknown {
                artifact_id: "x".into(),
                version: "v".into()
            }
            .code(),
            "ERR_CART_SCHEMA_UNKNOWN"
        );
        assert_eq!(
            ArtifactError::EmptyCapabilities {
                artifact_id: "x".into()
            }
            .code(),
            "ERR_CART_EMPTY_CAPABILITIES"
        );
        assert_eq!(
            ArtifactError::DuplicateArtifact {
                artifact_id: "x".into()
            }
            .code(),
            "ERR_CART_DUPLICATE_ARTIFACT"
        );
    }

    #[test]
    fn test_error_artifact_id_accessor() {
        assert_eq!(
            ArtifactError::MissingEnvelope {
                artifact_id: "id-1".into()
            }
            .artifact_id(),
            "id-1"
        );
        assert_eq!(
            ArtifactError::InvalidEnvelope {
                artifact_id: "id-2".into(),
                detail: "bad".into()
            }
            .artifact_id(),
            "id-2"
        );
        assert_eq!(
            ArtifactError::DigestMismatch {
                artifact_id: "id-3".into()
            }
            .artifact_id(),
            "id-3"
        );
        assert_eq!(
            ArtifactError::OverScoped {
                artifact_id: "id-4".into(),
                out_of_scope: vec![]
            }
            .artifact_id(),
            "id-4"
        );
        assert_eq!(
            ArtifactError::DriftDetected {
                artifact_id: "id-5".into(),
                detail: "drift".into()
            }
            .artifact_id(),
            "id-5"
        );
        assert_eq!(
            ArtifactError::SchemaUnknown {
                artifact_id: "id-6".into(),
                version: "v1".into()
            }
            .artifact_id(),
            "id-6"
        );
        assert_eq!(
            ArtifactError::EmptyCapabilities {
                artifact_id: "id-7".into()
            }
            .artifact_id(),
            "id-7"
        );
        assert_eq!(
            ArtifactError::DuplicateArtifact {
                artifact_id: "id-8".into()
            }
            .artifact_id(),
            "id-8"
        );
    }

    #[test]
    fn test_error_display() {
        let e = ArtifactError::MissingEnvelope {
            artifact_id: "ext-1".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("ext-1"));
        assert!(s.contains("no capability envelope"));

        let e = ArtifactError::MissingEnvelope {
            artifact_id: "   ".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("<unknown>"));
        assert!(s.contains("no capability envelope"));

        let e = ArtifactError::EmptyCapabilities {
            artifact_id: "ext-2".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("ext-2"));
        assert!(s.contains("envelope declares zero capabilities"));

        let e = ArtifactError::DuplicateArtifact {
            artifact_id: "ext-dup".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("ext-dup"));
        assert!(s.contains("duplicate artifact ID"));

        let e = ArtifactError::SchemaUnknown {
            artifact_id: "ext-schema".into(),
            version: "cart-v99.0".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("ext-schema"));
        assert!(s.contains("unknown schema version"));
        assert!(s.contains("cart-v99.0"));

        let e = ArtifactError::OverScoped {
            artifact_id: "ext-over".into(),
            out_of_scope: vec!["cap:forbidden:escalate".into()],
        };
        let s = format!("{e}");
        assert!(s.contains("ext-over"));
        assert!(s.contains("over-scoped capabilities"));
        assert!(s.contains("cap:forbidden:escalate"));

        let e = ArtifactError::DigestMismatch {
            artifact_id: "ext-digest".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("ext-digest"));
        assert!(s.contains("digest does not match identity"));

        let e = ArtifactError::DriftDetected {
            artifact_id: "ext-drift".into(),
            detail: "capability cap:fs:read revoked but used".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("ext-drift"));
        assert!(s.contains("runtime drift"));
        assert!(s.contains("revoked but used"));

        let e = ArtifactError::InvalidEnvelope {
            artifact_id: "ext-bad".into(),
            detail: "schema version is empty".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("ext-bad"));
        assert!(s.contains("envelope invalid"));
        assert!(s.contains("schema version is empty"));

        let e = ArtifactError::MissingEnvelope {
            artifact_id: "   ".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("<unknown>"));

        let e = ArtifactError::MissingEnvelope {
            artifact_id: " ext-id ".into(),
        };
        let s = format!("{e}");
        assert!(s.contains(" ext-id "));
    }

    // ── AdmissionReport ──────────────────────────────────────────────

    #[test]
    fn test_admission_report_pass() {
        let report = AdmissionReport::pass("ext-1", 3);
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.capabilities_declared, 3);
        assert!(report.detail.contains("admitted"));
        let report = AdmissionReport::pass("   ", 1);
        assert_eq!(report.artifact_id, "<unknown>");
        let report = AdmissionReport::pass(" <unknown> ", 1);
        assert_eq!(report.artifact_id, "<unknown>");
        let report = AdmissionReport::pass(" ext-id ", 1);
        assert_eq!(report.artifact_id, " ext-id ");
    }

    #[test]
    fn test_admission_report_fail() {
        let err = ArtifactError::MissingEnvelope {
            artifact_id: "ext-1".into(),
        };
        let report = AdmissionReport::fail("ext-1", &err);
        assert_eq!(report.verdict, "FAIL");
        assert!(report.detail.contains("no capability envelope"));
        assert!(
            report
                .detail
                .contains(error_codes::ERR_CART_MISSING_ENVELOPE)
        );

        let report = AdmissionReport::fail("<unknown>", &err);
        assert_eq!(report.artifact_id, "ext-1");

        let report = AdmissionReport::fail(" <unknown> ", &err);
        assert_eq!(report.artifact_id, "ext-1");

        let report = AdmissionReport::fail("   ", &err);
        assert_eq!(report.artifact_id, "ext-1");

        let err = ArtifactError::MissingEnvelope {
            artifact_id: "   ".into(),
        };
        let report = AdmissionReport::fail("   ", &err);
        assert_eq!(report.artifact_id, "<unknown>");

        let err = ArtifactError::MissingEnvelope {
            artifact_id: " ext-id ".into(),
        };
        let report = AdmissionReport::fail("   ", &err);
        assert_eq!(report.artifact_id, " ext-id ");
    }

    // ── build_test_artifact helper ───────────────────────────────────

    #[test]
    fn test_build_test_artifact() {
        let artifact = build_test_artifact("test-1", &[("cap:fs:read", "read")]);
        assert_eq!(artifact.identity.artifact_id, "test-1");
        let env = artifact.envelope.as_ref().unwrap();
        assert_eq!(env.capability_count(), 1);
        assert!(env.verify_digest(&artifact.identity));
    }

    // ── Serde round-trips ────────────────────────────────────────────

    #[test]
    fn test_admission_gate_serde() {
        let mut gate = AdmissionGate::new();
        let artifact = build_test_artifact("ext-ser", &[("cap:fs:read", "read")]);
        gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap();
        let json = serde_json::to_string(&gate).unwrap();
        let parsed: AdmissionGate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.admitted_count(), 1);
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_enforcer_serde() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let enforcer = EnvelopeEnforcer::from_envelope("ext-1", &env);
        let json = serde_json::to_string(&enforcer).unwrap();
        let parsed: EnvelopeEnforcer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.artifact_id, "ext-1");
        assert!(parsed.admitted_capabilities.contains("cap:fs:read"));
    }

    // ── Determinism ──────────────────────────────────────────────────

    #[test]
    fn test_deterministic_admitted_ordering() {
        let mut gate = AdmissionGate::new();
        let a1 = build_test_artifact("ext-zz", &[("cap:fs:read", "read")]);
        let a2 = build_test_artifact("ext-aa", &[("cap:fs:write", "write")]);
        gate.admit(&a1, "t1").unwrap();
        gate.admit(&a2, "t2").unwrap();
        let keys: Vec<String> = gate.admitted.keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap keys must be sorted");
    }

    // ── Send + Sync ──────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<ArtifactIdentity>();
        assert_sync::<ArtifactIdentity>();
        assert_send::<CapabilityEnvelope>();
        assert_sync::<CapabilityEnvelope>();
        assert_send::<ExtensionArtifact>();
        assert_sync::<ExtensionArtifact>();
        assert_send::<AdmissionGate>();
        assert_sync::<AdmissionGate>();
        assert_send::<EnvelopeEnforcer>();
        assert_sync::<EnvelopeEnforcer>();
        assert_send::<ArtifactError>();
        assert_sync::<ArtifactError>();
        assert_send::<AuditEntry>();
        assert_sync::<AuditEntry>();
        assert_send::<AdmissionReport>();
        assert_sync::<AdmissionReport>();
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn test_envelope_digest_deterministic() {
        let identity = ArtifactIdentity::new("ext-det", "alice", "2026-01-01T00:00:00Z");
        let mut env1 = CapabilityEnvelope::new();
        env1.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        env1.add_requirement(CapabilityRequirement::new("cap:fs:write", "write", true));
        let d1 = env1.compute_digest(&identity);

        let mut env2 = CapabilityEnvelope::new();
        env2.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        env2.add_requirement(CapabilityRequirement::new("cap:fs:write", "write", true));
        let d2 = env2.compute_digest(&identity);

        assert_eq!(d1, d2, "same inputs must produce same digest");
    }

    #[test]
    fn test_get_envelope_for_admitted_artifact() {
        let mut gate = AdmissionGate::new();
        let artifact = build_test_artifact("ext-get", &[("cap:fs:read", "read")]);
        gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap();
        let env = gate.get_envelope("ext-get").unwrap();
        assert_eq!(env.capability_count(), 1);
    }

    #[test]
    fn test_get_envelope_returns_none_for_unadmitted() {
        let gate = AdmissionGate::new();
        assert!(gate.get_envelope("ext-missing").is_none());
    }

    #[test]
    fn test_rejection_due_to_allowed_scope_does_not_admit_or_emit_success_events() {
        let mut gate = AdmissionGate::new();
        gate.allowed_scope.clear();
        let artifact = build_test_artifact("ext-no-scope", &[("cap:fs:read", "read config")]);

        let err = gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CART_OVER_SCOPED);
        assert_eq!(gate.admitted_count(), 0);
        assert!(gate.get_envelope("ext-no-scope").is_none());
        assert!(
            gate.audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_010)
        );
        assert!(
            !gate
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_008)
        );
        assert!(
            !gate
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_004)
        );
        assert!(
            !gate
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_002)
        );
    }

    #[test]
    fn test_duplicate_artifact_does_not_replace_existing_envelope() {
        let mut gate = AdmissionGate::new();
        let original = build_test_artifact("ext-dup-stable", &[("cap:fs:read", "read config")]);
        let replacement =
            build_test_artifact("ext-dup-stable", &[("cap:crypto:sign", "sign receipts")]);
        gate.admit(&original, "2026-02-21T00:00:00Z").unwrap();

        let err = gate
            .admit(&replacement, "2026-02-21T00:00:01Z")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CART_DUPLICATE_ARTIFACT);
        assert_eq!(gate.admitted_count(), 1);
        let admitted = gate
            .get_envelope("ext-dup-stable")
            .expect("original envelope should remain admitted");
        assert!(admitted.requirements.contains_key("cap:fs:read"));
        assert!(!admitted.requirements.contains_key("cap:crypto:sign"));
        assert_eq!(
            gate.audit_log()
                .iter()
                .filter(|entry| entry.event_code == event_codes::CART_002)
                .count(),
            1
        );
    }

    #[test]
    fn test_missing_envelope_stops_before_schema_digest_and_success_audits() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-no-env", "author", "2026-02-21T00:00:00Z");
        let artifact = ExtensionArtifact::new(identity, None);

        let err = gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CART_MISSING_ENVELOPE);
        assert_eq!(gate.admitted_count(), 0);
        for forbidden in [
            event_codes::CART_010,
            event_codes::CART_008,
            event_codes::CART_004,
            event_codes::CART_002,
        ] {
            assert!(
                !gate
                    .audit_log()
                    .iter()
                    .any(|entry| entry.event_code == forbidden),
                "{forbidden} should not be emitted after missing envelope"
            );
        }
    }

    #[test]
    fn test_digest_mismatch_stops_after_schema_validation_without_admission() {
        let mut gate = AdmissionGate::new();
        let identity = ArtifactIdentity::new("ext-bad-digest", "author", "2026-02-21T00:00:00Z");
        let wrong_identity =
            ArtifactIdentity::new("ext-other-digest", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&wrong_identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));

        let err = gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CART_DIGEST_MISMATCH);
        assert_eq!(gate.admitted_count(), 0);
        assert!(
            gate.audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_010)
        );
        assert!(
            gate.audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_009)
        );
        assert!(
            !gate
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_008)
        );
        assert!(
            !gate
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_004)
        );
        assert!(
            !gate
                .audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_002)
        );
    }

    #[test]
    fn test_unknown_schema_stops_before_schema_success_and_digest_audits() {
        let mut gate = AdmissionGate::new();
        let identity =
            ArtifactIdentity::new("ext-unknown-schema", "author", "2026-02-21T00:00:00Z");
        let mut envelope = CapabilityEnvelope::new();
        envelope.schema_version = "cart-v2.0".to_string();
        envelope.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        envelope.bind_to(&identity);
        let artifact = ExtensionArtifact::new(identity, Some(envelope));

        let err = gate.admit(&artifact, "2026-02-21T00:00:00Z").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CART_SCHEMA_UNKNOWN);
        assert_eq!(gate.admitted_count(), 0);
        for forbidden in [
            event_codes::CART_010,
            event_codes::CART_008,
            event_codes::CART_004,
            event_codes::CART_002,
        ] {
            assert!(
                !gate
                    .audit_log()
                    .iter()
                    .any(|entry| entry.event_code == forbidden),
                "{forbidden} should not be emitted after unknown schema"
            );
        }
    }

    #[test]
    fn test_enforcer_empty_capability_is_drift_not_enforced() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-empty-cap", &env);

        let err = enforcer
            .check_capability("", "2026-02-21T00:00:00Z")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CART_DRIFT_DETECTED);
        assert!(enforcer.used_capabilities.contains(""));
        assert_eq!(enforcer.enforcement_log().len(), 1);
        assert_eq!(
            enforcer.enforcement_log()[0].event_code,
            event_codes::CART_007
        );
        assert!(
            !enforcer
                .enforcement_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_006)
        );
        assert!(
            enforcer
                .detect_drift()
                .iter()
                .any(|drift| drift.contains("used but undeclared"))
        );
    }

    #[test]
    fn test_revoking_unused_declared_capability_does_not_create_drift_until_use() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-revoke-unused", &env);

        enforcer.revoke_capability("cap:fs:read");

        assert!(enforcer.detect_drift().is_empty());
        assert!(enforcer.enforcement_log().is_empty());

        let err = enforcer
            .check_capability("cap:fs:read", "2026-02-21T00:00:00Z")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CART_DRIFT_DETECTED);
        assert!(
            enforcer
                .detect_drift()
                .iter()
                .any(|drift| drift.as_str() == "revoked but used: cap:fs:read")
        );
    }

    #[test]
    fn test_revoked_undeclared_capability_records_both_drift_reasons() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-revoked-undeclared", &env);

        enforcer.revoke_capability("cap:network:connect");
        let err = enforcer
            .check_capability("cap:network:connect", "2026-02-21T00:00:00Z")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CART_DRIFT_DETECTED);
        assert!(format!("{err}").contains("revoked but used"));
        let drifts = enforcer.detect_drift();
        assert!(
            drifts
                .iter()
                .any(|drift| drift.as_str() == "used but undeclared: cap:network:connect")
        );
        assert!(
            drifts
                .iter()
                .any(|drift| drift.as_str() == "revoked but used: cap:network:connect")
        );
        assert_eq!(enforcer.enforcement_log().len(), 1);
        assert_eq!(
            enforcer.enforcement_log()[0].event_code,
            event_codes::CART_007
        );
    }

    #[test]
    fn test_repeated_undeclared_uses_do_not_duplicate_used_set_but_audit_each_attempt() {
        let mut env = CapabilityEnvelope::new();
        env.add_requirement(CapabilityRequirement::new("cap:fs:read", "read", true));
        let mut enforcer = EnvelopeEnforcer::from_envelope("ext-repeat-drift", &env);

        let first = enforcer.check_capability("cap:process:spawn", "t1");
        let second = enforcer.check_capability("cap:process:spawn", "t2");

        assert!(first.is_err());
        assert!(second.is_err());
        assert_eq!(enforcer.used_capabilities.len(), 1);
        assert!(enforcer.used_capabilities.contains("cap:process:spawn"));
        assert_eq!(
            enforcer
                .enforcement_log()
                .iter()
                .filter(|entry| entry.event_code == event_codes::CART_007)
                .count(),
            2
        );
        assert!(
            !enforcer
                .enforcement_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::CART_006)
        );
    }

    #[test]
    fn negative_artifact_identity_rejects_missing_author() {
        let value = serde_json::json!({
            "artifact_id": "ext-missing-author",
            "created_at": "2026-02-21T00:00:00Z"
        });

        let err = serde_json::from_value::<ArtifactIdentity>(value).unwrap_err();

        assert!(err.to_string().contains("author"));
    }

    #[test]
    fn negative_capability_requirement_rejects_non_bool_mandatory() {
        let value = serde_json::json!({
            "capability": "cap:fs:read",
            "justification": "read manifest",
            "mandatory": "yes"
        });

        let err = serde_json::from_value::<CapabilityRequirement>(value).unwrap_err();

        assert!(err.to_string().contains("mandatory"));
    }

    #[test]
    fn negative_capability_envelope_rejects_array_requirements() {
        let value = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "requirements": [{
                "capability": "cap:fs:read",
                "justification": "read manifest",
                "mandatory": true
            }],
            "digest": "sha256:abc"
        });

        let err = serde_json::from_value::<CapabilityEnvelope>(value).unwrap_err();

        assert!(err.to_string().contains("requirements"));
    }

    #[test]
    fn negative_extension_artifact_rejects_numeric_envelope() {
        let value = serde_json::json!({
            "identity": {
                "artifact_id": "ext-bad-envelope",
                "author": "test-author",
                "created_at": "2026-02-21T00:00:00Z"
            },
            "envelope": 7
        });

        let err = serde_json::from_value::<ExtensionArtifact>(value).unwrap_err();

        assert!(err.to_string().contains("envelope"));
    }

    #[test]
    fn negative_artifact_error_rejects_missing_variant_payload() {
        let value = serde_json::json!({
            "OverScoped": {
                "artifact_id": "ext-over"
            }
        });

        let err = serde_json::from_value::<ArtifactError>(value).unwrap_err();

        assert!(err.to_string().contains("out_of_scope"));
    }

    #[test]
    fn negative_audit_entry_rejects_missing_event_code() {
        let value = serde_json::json!({
            "artifact_id": "ext-audit",
            "timestamp": "2026-02-21T00:00:00Z",
            "outcome": "rejected",
            "detail": "missing event code"
        });

        let err = serde_json::from_value::<AuditEntry>(value).unwrap_err();

        assert!(err.to_string().contains("event_code"));
    }

    #[test]
    fn negative_admission_gate_rejects_object_allowed_scope() {
        let value = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "admitted": {},
            "audit_log": [],
            "allowed_scope": {"cap:fs:read": true}
        });

        let err = serde_json::from_value::<AdmissionGate>(value).unwrap_err();

        assert!(err.to_string().contains("allowed_scope"));
    }

    #[test]
    fn negative_envelope_enforcer_rejects_numeric_admitted_capability() {
        let value = serde_json::json!({
            "artifact_id": "ext-enforcer",
            "admitted_capabilities": ["cap:fs:read", 7],
            "used_capabilities": [],
            "revoked_capabilities": [],
            "enforcement_log": []
        });

        let err = serde_json::from_value::<EnvelopeEnforcer>(value).unwrap_err();

        assert!(err.to_string().contains("admitted_capabilities"));
    }

    #[test]
    fn negative_admission_report_rejects_negative_capability_count() {
        let value = serde_json::json!({
            "artifact_id": "ext-report",
            "verdict": "FAIL",
            "capabilities_declared": -1,
            "detail": "invalid count"
        });

        let err = serde_json::from_value::<AdmissionReport>(value).unwrap_err();

        assert!(err.to_string().contains("capabilities_declared"));
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_without_inserting() {
        let mut values = vec!["old-a".to_string(), "old-b".to_string()];

        push_bounded(&mut values, "new".to_string(), 0);

        assert!(values.is_empty());
    }
}
