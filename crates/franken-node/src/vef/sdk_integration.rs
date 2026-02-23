//! bd-3pds: Integrate VEF evidence into verifier SDK replay capsules and external
//! verification APIs.
//!
//! This module bridges the VEF proof pipeline (Section 10.18) with the verifier
//! SDK (Section 10.12/10.17) by embedding VEF compliance proofs into replay
//! capsules and exposing a stable, versioned external verification API that
//! third-party verifiers can call to submit and query VEF evidence.
//!
//! # Capabilities
//!
//! - `VefCapsuleEmbed`: embeds VEF proofs into verifier SDK replay capsules
//! - `ExternalVerificationEndpoint`: API interface for VEF evidence submission/query
//! - `CapsuleEmbedding`: struct carrying format_version, proof_ref, embed_metadata
//! - `VersionNegotiator`: backward-compatible version matching for API consumers
//!
//! # Invariants
//!
//! - **INV-VSI-VERSIONED**: every capsule embedding and API response carries an
//!   explicit format version for forward/backward compatibility.
//! - **INV-VSI-BACKWARD-COMPAT**: version negotiation always selects the highest
//!   mutually supported version; unsupported versions produce classified errors.
//! - **INV-VSI-EMBED-COMPLETE**: an embedded proof in a replay capsule is
//!   self-contained: it includes the proof reference, metadata, and a binding
//!   hash that ties the proof to the capsule payload.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

// ── Schema version ──────────────────────────────────────────────────────────

/// Schema version for the VEF SDK integration format.
pub const VSI_SCHEMA_VERSION: &str = "vef-sdk-integration-v1";

/// Current format version for capsule embeddings.
pub const VSI_FORMAT_VERSION: &str = "1.0.0";

/// Minimum supported format version for backward compatibility.
pub const VSI_MIN_FORMAT_VERSION: &str = "1.0.0";

/// All format versions supported by this implementation, newest first.
pub const VSI_SUPPORTED_VERSIONS: &[&str] = &["1.0.0"];

// ── Invariant constants ─────────────────────────────────────────────────────

/// INV-VSI-VERSIONED: every embedding and API response carries format_version.
pub const INV_VSI_VERSIONED: &str = "INV-VSI-VERSIONED";

/// INV-VSI-BACKWARD-COMPAT: version negotiation selects highest mutual version.
pub const INV_VSI_BACKWARD_COMPAT: &str = "INV-VSI-BACKWARD-COMPAT";

/// INV-VSI-EMBED-COMPLETE: embedded proof is self-contained with binding hash.
pub const INV_VSI_EMBED_COMPLETE: &str = "INV-VSI-EMBED-COMPLETE";

// ── Event codes ─────────────────────────────────────────────────────────────

pub mod event_codes {
    /// VEF proof embedded into replay capsule.
    pub const VSI_001_PROOF_EMBEDDED: &str = "VSI-001";
    /// External verification request received.
    pub const VSI_002_EVIDENCE_SUBMITTED: &str = "VSI-002";
    /// External verification query completed.
    pub const VSI_003_EVIDENCE_QUERIED: &str = "VSI-003";
    /// Version negotiation completed.
    pub const VSI_004_VERSION_NEGOTIATED: &str = "VSI-004";
    /// Capsule embedding validated.
    pub const VSI_005_EMBED_VALIDATED: &str = "VSI-005";
    /// Evidence bundle exported for external consumption.
    pub const VSI_006_EVIDENCE_EXPORTED: &str = "VSI-006";
}

// ── Error codes ─────────────────────────────────────────────────────────────

pub mod error_codes {
    /// Proof reference is missing or empty.
    pub const ERR_VSI_PROOF_REF_MISSING: &str = "ERR-VSI-PROOF-REF-MISSING";
    /// Capsule payload is empty or invalid for embedding.
    pub const ERR_VSI_CAPSULE_INVALID: &str = "ERR-VSI-CAPSULE-INVALID";
    /// Requested format version is not supported.
    pub const ERR_VSI_VERSION_UNSUPPORTED: &str = "ERR-VSI-VERSION-UNSUPPORTED";
    /// Binding hash verification failed.
    pub const ERR_VSI_BINDING_MISMATCH: &str = "ERR-VSI-BINDING-MISMATCH";
    /// Evidence submission rejected (duplicate or malformed).
    pub const ERR_VSI_SUBMISSION_REJECTED: &str = "ERR-VSI-SUBMISSION-REJECTED";
    /// Internal serialization / hashing failure.
    pub const ERR_VSI_INTERNAL: &str = "ERR-VSI-INTERNAL";
}

// ── Core types ──────────────────────────────────────────────────────────────

/// Status of an evidence submission in the external verification store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Pending,
    Accepted,
    Rejected,
    Expired,
}

/// A capsule embedding that ties a VEF compliance proof into a verifier SDK
/// replay capsule. INV-VSI-EMBED-COMPLETE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleEmbedding {
    /// Format version of this embedding structure. INV-VSI-VERSIONED.
    pub format_version: String,
    /// Reference to the VEF compliance proof (e.g., proof job ID or hash).
    pub proof_ref: String,
    /// Metadata about the embedding: keys are deterministically ordered.
    pub embed_metadata: BTreeMap<String, String>,
    /// SHA-256 binding hash tying proof to capsule payload.
    pub binding_hash: String,
    /// Trace correlation ID.
    pub trace_id: String,
    /// Timestamp of embedding creation (millis since epoch).
    pub created_at_millis: u64,
}

/// Result of a version negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiationResult {
    /// The selected version (highest mutually supported).
    pub selected_version: String,
    /// All versions the client offered.
    pub client_versions: Vec<String>,
    /// All versions the server supports.
    pub server_versions: Vec<String>,
}

/// A request to submit VEF evidence to the external verification endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSubmission {
    /// Unique submission identifier.
    pub submission_id: String,
    /// VEF proof reference.
    pub proof_ref: String,
    /// Format version of the submitted evidence.
    pub format_version: String,
    /// Proof payload (serialized proof data).
    pub proof_payload: String,
    /// Metadata about this evidence (deterministic ordering).
    pub metadata: BTreeMap<String, String>,
    /// Trace correlation ID.
    pub trace_id: String,
    /// Submission timestamp.
    pub submitted_at_millis: u64,
}

/// Response to an evidence submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionResponse {
    /// Submission identifier (echo back).
    pub submission_id: String,
    /// Status after processing.
    pub status: EvidenceStatus,
    /// Server-side format version.
    pub format_version: String,
    /// Reason for status (empty on success).
    pub reason: String,
    /// Trace correlation ID.
    pub trace_id: String,
}

/// Query filter for looking up evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQuery {
    /// Filter by proof reference (exact match).
    pub proof_ref: Option<String>,
    /// Filter by status.
    pub status_filter: Option<EvidenceStatus>,
    /// Maximum number of results to return.
    pub limit: usize,
}

/// A stored evidence record returned by queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub submission_id: String,
    pub proof_ref: String,
    pub format_version: String,
    pub status: EvidenceStatus,
    pub binding_hash: String,
    pub metadata: BTreeMap<String, String>,
    pub submitted_at_millis: u64,
    pub trace_id: String,
}

/// Exported evidence bundle for external verifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedEvidenceBundle {
    pub schema_version: String,
    pub format_version: String,
    pub records: Vec<EvidenceRecord>,
    pub exported_at_millis: u64,
    pub trace_id: String,
}

/// Structured event emitted by the SDK integration layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsiEvent {
    pub event_code: String,
    pub trace_id: String,
    pub detail: String,
}

/// Classified error for the SDK integration layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsiError {
    pub code: String,
    pub event_code: String,
    pub message: String,
}

impl VsiError {
    fn proof_ref_missing(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VSI_PROOF_REF_MISSING.to_string(),
            event_code: event_codes::VSI_001_PROOF_EMBEDDED.to_string(),
            message: message.into(),
        }
    }

    fn capsule_invalid(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VSI_CAPSULE_INVALID.to_string(),
            event_code: event_codes::VSI_001_PROOF_EMBEDDED.to_string(),
            message: message.into(),
        }
    }

    fn version_unsupported(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VSI_VERSION_UNSUPPORTED.to_string(),
            event_code: event_codes::VSI_004_VERSION_NEGOTIATED.to_string(),
            message: message.into(),
        }
    }

    fn binding_mismatch(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VSI_BINDING_MISMATCH.to_string(),
            event_code: event_codes::VSI_005_EMBED_VALIDATED.to_string(),
            message: message.into(),
        }
    }

    fn submission_rejected(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VSI_SUBMISSION_REJECTED.to_string(),
            event_code: event_codes::VSI_002_EVIDENCE_SUBMITTED.to_string(),
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VSI_INTERNAL.to_string(),
            event_code: event_codes::VSI_001_PROOF_EMBEDDED.to_string(),
            message: message.into(),
        }
    }
}

impl fmt::Display for VsiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for VsiError {}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Compute SHA-256 hex digest of arbitrary input bytes.
fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest([b"vef_sdk_hash_v1:" as &[u8], data].concat());
    format!("sha256:{digest:x}")
}

/// Compute the binding hash that ties a proof_ref to a capsule payload.
/// INV-VSI-EMBED-COMPLETE: the binding is deterministic and self-contained.
fn compute_binding_hash(proof_ref: &str, capsule_payload: &str) -> Result<String, VsiError> {
    #[derive(Serialize)]
    struct BindingMaterial<'a> {
        schema_version: &'a str,
        proof_ref: &'a str,
        capsule_payload_hash: String,
    }

    let payload_hash = sha256_hex(capsule_payload.as_bytes());
    let material = BindingMaterial {
        schema_version: VSI_SCHEMA_VERSION,
        proof_ref,
        capsule_payload_hash: payload_hash,
    };
    let bytes = serde_json::to_vec(&material)
        .map_err(|e| VsiError::internal(format!("binding hash serialization failed: {e}")))?;
    Ok(sha256_hex(&bytes))
}

// ── VersionNegotiator ───────────────────────────────────────────────────────

/// Handles backward-compatible version matching between client and server.
/// INV-VSI-BACKWARD-COMPAT: selects the highest mutually supported version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionNegotiator {
    /// Versions supported by this server, newest first.
    pub supported_versions: Vec<String>,
}

impl VersionNegotiator {
    /// Create a negotiator with the default supported version set.
    pub fn new() -> Self {
        Self {
            supported_versions: VSI_SUPPORTED_VERSIONS
                .iter()
                .map(|v| v.to_string())
                .collect(),
        }
    }

    /// Create a negotiator with custom supported versions (newest first).
    pub fn with_versions(versions: Vec<String>) -> Self {
        Self {
            supported_versions: versions,
        }
    }

    /// Negotiate the best version given a set of client-offered versions.
    /// INV-VSI-BACKWARD-COMPAT: selects highest mutually supported version.
    pub fn negotiate(&self, client_versions: &[String]) -> Result<NegotiationResult, VsiError> {
        if client_versions.is_empty() {
            return Err(VsiError::version_unsupported("client offered no versions"));
        }
        if self.supported_versions.is_empty() {
            return Err(VsiError::version_unsupported("server supports no versions"));
        }

        // Find highest version that both sides support.
        // Server versions are ordered newest-first; pick the first server
        // version that appears in the client set.
        for server_ver in &self.supported_versions {
            if client_versions.iter().any(|cv| cv == server_ver) {
                return Ok(NegotiationResult {
                    selected_version: server_ver.clone(),
                    client_versions: client_versions.to_vec(),
                    server_versions: self.supported_versions.clone(),
                });
            }
        }

        Err(VsiError::version_unsupported(format!(
            "no mutual version: client={client_versions:?} server={:?}",
            self.supported_versions
        )))
    }

    /// Check whether a specific version string is supported.
    pub fn is_supported(&self, version: &str) -> bool {
        self.supported_versions.iter().any(|v| v == version)
    }
}

impl Default for VersionNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

// ── VefCapsuleEmbed ─────────────────────────────────────────────────────────

/// Embeds VEF compliance proofs into verifier SDK replay capsules.
///
/// INV-VSI-EMBED-COMPLETE: every embedding includes proof_ref, metadata,
/// and a deterministic binding hash tying the proof to the capsule payload.
///
/// INV-VSI-VERSIONED: all embeddings carry explicit format_version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VefCapsuleEmbed {
    pub schema_version: String,
    pub negotiator: VersionNegotiator,
    events: Vec<VsiEvent>,
}

impl VefCapsuleEmbed {
    /// Create a new embedder with default settings.
    pub fn new() -> Self {
        Self {
            schema_version: VSI_SCHEMA_VERSION.to_string(),
            negotiator: VersionNegotiator::new(),
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[VsiEvent] {
        &self.events
    }

    /// Embed a VEF proof into a replay capsule payload.
    ///
    /// # Errors
    /// - `ERR-VSI-PROOF-REF-MISSING` if proof_ref is empty.
    /// - `ERR-VSI-CAPSULE-INVALID` if capsule_payload is empty.
    /// - `ERR-VSI-INTERNAL` on serialization failure.
    pub fn embed(
        &mut self,
        proof_ref: &str,
        capsule_payload: &str,
        metadata: BTreeMap<String, String>,
        now_millis: u64,
        trace_id: &str,
    ) -> Result<CapsuleEmbedding, VsiError> {
        if proof_ref.is_empty() {
            return Err(VsiError::proof_ref_missing("proof_ref must not be empty"));
        }
        if capsule_payload.is_empty() {
            return Err(VsiError::capsule_invalid(
                "capsule_payload must not be empty for embedding",
            ));
        }

        let binding_hash = compute_binding_hash(proof_ref, capsule_payload)?;

        let embedding = CapsuleEmbedding {
            format_version: VSI_FORMAT_VERSION.to_string(),
            proof_ref: proof_ref.to_string(),
            embed_metadata: metadata,
            binding_hash,
            trace_id: trace_id.to_string(),
            created_at_millis: now_millis,
        };

        self.events.push(VsiEvent {
            event_code: event_codes::VSI_001_PROOF_EMBEDDED.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!(
                "proof={} binding={}",
                embedding.proof_ref, embedding.binding_hash
            ),
        });

        Ok(embedding)
    }

    /// Validate that a capsule embedding's binding hash matches the given
    /// capsule payload.
    ///
    /// INV-VSI-EMBED-COMPLETE: the binding hash must match a recomputation.
    pub fn validate_embedding(
        &mut self,
        embedding: &CapsuleEmbedding,
        capsule_payload: &str,
        trace_id: &str,
    ) -> Result<bool, VsiError> {
        let expected = compute_binding_hash(&embedding.proof_ref, capsule_payload)?;
        let valid = expected == embedding.binding_hash;

        self.events.push(VsiEvent {
            event_code: event_codes::VSI_005_EMBED_VALIDATED.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!(
                "proof={} valid={} expected={} actual={}",
                embedding.proof_ref, valid, expected, embedding.binding_hash
            ),
        });

        if !valid {
            return Err(VsiError::binding_mismatch(format!(
                "expected={expected} actual={}",
                embedding.binding_hash
            )));
        }

        Ok(valid)
    }
}

impl Default for VefCapsuleEmbed {
    fn default() -> Self {
        Self::new()
    }
}

// ── ExternalVerificationEndpoint ────────────────────────────────────────────

/// API interface for VEF evidence submission and query by external verifiers.
///
/// INV-VSI-VERSIONED: all responses carry format_version.
/// INV-VSI-BACKWARD-COMPAT: version negotiation on submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalVerificationEndpoint {
    pub schema_version: String,
    pub negotiator: VersionNegotiator,
    store: BTreeMap<String, EvidenceRecord>,
    events: Vec<VsiEvent>,
    next_seq: u64,
}

impl ExternalVerificationEndpoint {
    /// Create a new endpoint with default settings.
    pub fn new() -> Self {
        Self {
            schema_version: VSI_SCHEMA_VERSION.to_string(),
            negotiator: VersionNegotiator::new(),
            store: BTreeMap::new(),
            events: Vec::new(),
            next_seq: 0,
        }
    }

    pub fn events(&self) -> &[VsiEvent] {
        &self.events
    }

    pub fn store(&self) -> &BTreeMap<String, EvidenceRecord> {
        &self.store
    }

    /// Submit VEF evidence. The endpoint validates the submission, performs
    /// version negotiation, and stores the evidence if accepted.
    ///
    /// # Errors
    /// - `ERR-VSI-PROOF-REF-MISSING` if proof_ref is empty.
    /// - `ERR-VSI-VERSION-UNSUPPORTED` if format_version is not supported.
    /// - `ERR-VSI-SUBMISSION-REJECTED` on duplicate submission_id.
    pub fn submit(
        &mut self,
        submission: &EvidenceSubmission,
    ) -> Result<SubmissionResponse, VsiError> {
        // Validate proof reference
        if submission.proof_ref.is_empty() {
            return Err(VsiError::proof_ref_missing(
                "evidence submission proof_ref must not be empty",
            ));
        }

        // Version check
        if !self.negotiator.is_supported(&submission.format_version) {
            return Err(VsiError::version_unsupported(format!(
                "format_version '{}' is not supported",
                submission.format_version
            )));
        }

        // Duplicate check
        if self.store.contains_key(&submission.submission_id) {
            return Err(VsiError::submission_rejected(format!(
                "duplicate submission_id '{}'",
                submission.submission_id
            )));
        }

        // Compute binding hash from proof payload
        let binding_hash = sha256_hex(submission.proof_payload.as_bytes());

        let record = EvidenceRecord {
            submission_id: submission.submission_id.clone(),
            proof_ref: submission.proof_ref.clone(),
            format_version: submission.format_version.clone(),
            status: EvidenceStatus::Accepted,
            binding_hash,
            metadata: submission.metadata.clone(),
            submitted_at_millis: submission.submitted_at_millis,
            trace_id: submission.trace_id.clone(),
        };
        self.store.insert(submission.submission_id.clone(), record);

        self.next_seq = self.next_seq.wrapping_add(1);

        self.events.push(VsiEvent {
            event_code: event_codes::VSI_002_EVIDENCE_SUBMITTED.to_string(),
            trace_id: submission.trace_id.clone(),
            detail: format!(
                "submission={} proof_ref={} status=accepted",
                submission.submission_id, submission.proof_ref
            ),
        });

        Ok(SubmissionResponse {
            submission_id: submission.submission_id.clone(),
            status: EvidenceStatus::Accepted,
            format_version: VSI_FORMAT_VERSION.to_string(),
            reason: String::new(),
            trace_id: submission.trace_id.clone(),
        })
    }

    /// Query stored evidence by filters.
    pub fn query(&mut self, query: &EvidenceQuery, trace_id: &str) -> Vec<EvidenceRecord> {
        let mut results: Vec<EvidenceRecord> = self
            .store
            .values()
            .filter(|record| {
                if let Some(ref pr) = query.proof_ref {
                    if &record.proof_ref != pr {
                        return false;
                    }
                }
                if let Some(sf) = query.status_filter {
                    if record.status != sf {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        results.truncate(query.limit);

        self.events.push(VsiEvent {
            event_code: event_codes::VSI_003_EVIDENCE_QUERIED.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!("matched={} limit={}", results.len(), query.limit),
        });

        results
    }

    /// Export all accepted evidence as a bundle for external consumption.
    /// INV-VSI-VERSIONED: bundle carries schema and format version.
    pub fn export_evidence(&mut self, now_millis: u64, trace_id: &str) -> ExportedEvidenceBundle {
        let records: Vec<EvidenceRecord> = self
            .store
            .values()
            .filter(|r| r.status == EvidenceStatus::Accepted)
            .cloned()
            .collect();

        self.events.push(VsiEvent {
            event_code: event_codes::VSI_006_EVIDENCE_EXPORTED.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!("exported={} records", records.len()),
        });

        ExportedEvidenceBundle {
            schema_version: VSI_SCHEMA_VERSION.to_string(),
            format_version: VSI_FORMAT_VERSION.to_string(),
            records,
            exported_at_millis: now_millis,
            trace_id: trace_id.to_string(),
        }
    }

    /// Mark a stored evidence record's status (e.g., expire it).
    pub fn update_status(
        &mut self,
        submission_id: &str,
        new_status: EvidenceStatus,
        trace_id: &str,
    ) -> Result<(), VsiError> {
        let record = self.store.get_mut(submission_id).ok_or_else(|| {
            VsiError::submission_rejected(format!("unknown submission_id '{submission_id}'"))
        })?;
        record.status = new_status;

        self.events.push(VsiEvent {
            event_code: event_codes::VSI_002_EVIDENCE_SUBMITTED.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!("submission={submission_id} status_updated={new_status:?}"),
        });

        Ok(())
    }
}

impl Default for ExternalVerificationEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("action_class".to_string(), "network".to_string());
        m.insert("policy_hash".to_string(), "sha256:abcdef".to_string());
        m
    }

    fn sample_submission(id: &str, proof_ref: &str) -> EvidenceSubmission {
        EvidenceSubmission {
            submission_id: id.to_string(),
            proof_ref: proof_ref.to_string(),
            format_version: VSI_FORMAT_VERSION.to_string(),
            proof_payload: "proof-data-bytes".to_string(),
            metadata: sample_metadata(),
            trace_id: "trace-test".to_string(),
            submitted_at_millis: 1_700_000_000_000,
        }
    }

    // ── 1. CapsuleEmbedding carries format_version (INV-VSI-VERSIONED) ──

    #[test]
    fn embed_carries_format_version() {
        let mut embedder = VefCapsuleEmbed::new();
        let embedding = embedder
            .embed(
                "proof-001",
                "capsule-payload-data",
                sample_metadata(),
                1_000,
                "t1",
            )
            .unwrap();
        assert_eq!(embedding.format_version, VSI_FORMAT_VERSION);
    }

    // ── 2. Embedding with empty proof_ref fails ──

    #[test]
    fn embed_empty_proof_ref_fails() {
        let mut embedder = VefCapsuleEmbed::new();
        let err = embedder
            .embed("", "payload", BTreeMap::new(), 1_000, "t2")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_PROOF_REF_MISSING);
    }

    // ── 3. Embedding with empty capsule payload fails ──

    #[test]
    fn embed_empty_payload_fails() {
        let mut embedder = VefCapsuleEmbed::new();
        let err = embedder
            .embed("proof-002", "", BTreeMap::new(), 1_000, "t3")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_CAPSULE_INVALID);
    }

    // ── 4. Binding hash is deterministic (INV-VSI-EMBED-COMPLETE) ──

    #[test]
    fn binding_hash_is_deterministic() {
        let mut e1 = VefCapsuleEmbed::new();
        let mut e2 = VefCapsuleEmbed::new();
        let emb1 = e1
            .embed("proof-003", "same-payload", BTreeMap::new(), 1_000, "t4")
            .unwrap();
        let emb2 = e2
            .embed("proof-003", "same-payload", BTreeMap::new(), 1_000, "t4")
            .unwrap();
        assert_eq!(emb1.binding_hash, emb2.binding_hash);
    }

    // ── 5. Different payloads produce different binding hashes ──

    #[test]
    fn different_payloads_different_binding() {
        let mut e = VefCapsuleEmbed::new();
        let a = e
            .embed("proof-004", "payload-a", BTreeMap::new(), 1_000, "t5")
            .unwrap();
        let b = e
            .embed("proof-004", "payload-b", BTreeMap::new(), 1_000, "t5")
            .unwrap();
        assert_ne!(a.binding_hash, b.binding_hash);
    }

    // ── 6. validate_embedding succeeds for valid embedding ──

    #[test]
    fn validate_embedding_succeeds_for_valid() {
        let mut embedder = VefCapsuleEmbed::new();
        let embedding = embedder
            .embed("proof-005", "valid-payload", BTreeMap::new(), 1_000, "t6")
            .unwrap();
        let valid = embedder
            .validate_embedding(&embedding, "valid-payload", "t6-validate")
            .unwrap();
        assert!(valid);
    }

    // ── 7. validate_embedding fails for wrong payload ──

    #[test]
    fn validate_embedding_fails_for_wrong_payload() {
        let mut embedder = VefCapsuleEmbed::new();
        let embedding = embedder
            .embed(
                "proof-006",
                "original-payload",
                BTreeMap::new(),
                1_000,
                "t7",
            )
            .unwrap();
        let err = embedder
            .validate_embedding(&embedding, "tampered-payload", "t7-validate")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_BINDING_MISMATCH);
    }

    // ── 8. Embed events are emitted ──

    #[test]
    fn embed_emits_events() {
        let mut embedder = VefCapsuleEmbed::new();
        embedder
            .embed("proof-007", "payload", BTreeMap::new(), 1_000, "t8")
            .unwrap();
        assert_eq!(embedder.events().len(), 1);
        assert_eq!(
            embedder.events()[0].event_code,
            event_codes::VSI_001_PROOF_EMBEDDED
        );
    }

    // ── 9. VersionNegotiator selects highest mutual version ──

    #[test]
    fn version_negotiator_selects_highest_mutual() {
        let negotiator = VersionNegotiator::new();
        let result = negotiator.negotiate(&["1.0.0".to_string()]).unwrap();
        assert_eq!(result.selected_version, "1.0.0");
    }

    // ── 10. VersionNegotiator rejects when no mutual version ──

    #[test]
    fn version_negotiator_rejects_no_mutual() {
        let negotiator = VersionNegotiator::new();
        let err = negotiator.negotiate(&["99.99.99".to_string()]).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_VERSION_UNSUPPORTED);
    }

    // ── 11. VersionNegotiator rejects empty client versions ──

    #[test]
    fn version_negotiator_rejects_empty_client() {
        let negotiator = VersionNegotiator::new();
        let err = negotiator.negotiate(&[]).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_VERSION_UNSUPPORTED);
    }

    // ── 12. VersionNegotiator with custom versions ──

    #[test]
    fn version_negotiator_custom_versions() {
        let negotiator =
            VersionNegotiator::with_versions(vec!["2.0.0".to_string(), "1.0.0".to_string()]);
        let result = negotiator
            .negotiate(&["1.0.0".to_string(), "2.0.0".to_string()])
            .unwrap();
        // Server prefers 2.0.0 (newest first) and client supports it
        assert_eq!(result.selected_version, "2.0.0");
    }

    // ── 13. VersionNegotiator is_supported ──

    #[test]
    fn version_negotiator_is_supported() {
        let negotiator = VersionNegotiator::new();
        assert!(negotiator.is_supported("1.0.0"));
        assert!(!negotiator.is_supported("0.0.1"));
    }

    // ── 14. ExternalVerificationEndpoint submit succeeds ──

    #[test]
    fn endpoint_submit_succeeds() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        let sub = sample_submission("sub-001", "proof-a");
        let resp = endpoint.submit(&sub).unwrap();
        assert_eq!(resp.status, EvidenceStatus::Accepted);
        assert_eq!(resp.submission_id, "sub-001");
        assert!(!resp.format_version.is_empty());
    }

    // ── 15. ExternalVerificationEndpoint rejects empty proof_ref ──

    #[test]
    fn endpoint_rejects_empty_proof_ref() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        let sub = sample_submission("sub-002", "");
        let err = endpoint.submit(&sub).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_PROOF_REF_MISSING);
    }

    // ── 16. ExternalVerificationEndpoint rejects unsupported version ──

    #[test]
    fn endpoint_rejects_unsupported_version() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        let mut sub = sample_submission("sub-003", "proof-b");
        sub.format_version = "99.0.0".to_string();
        let err = endpoint.submit(&sub).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_VERSION_UNSUPPORTED);
    }

    // ── 17. ExternalVerificationEndpoint rejects duplicate ──

    #[test]
    fn endpoint_rejects_duplicate() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        let sub = sample_submission("sub-004", "proof-c");
        endpoint.submit(&sub).unwrap();
        let err = endpoint.submit(&sub).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_SUBMISSION_REJECTED);
    }

    // ── 18. Query by proof_ref ──

    #[test]
    fn query_by_proof_ref() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        endpoint
            .submit(&sample_submission("s1", "proof-x"))
            .unwrap();
        endpoint
            .submit(&sample_submission("s2", "proof-y"))
            .unwrap();

        let results = endpoint.query(
            &EvidenceQuery {
                proof_ref: Some("proof-x".to_string()),
                status_filter: None,
                limit: 100,
            },
            "t-query",
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].proof_ref, "proof-x");
    }

    // ── 19. Query by status ──

    #[test]
    fn query_by_status() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        endpoint
            .submit(&sample_submission("s3", "proof-z"))
            .unwrap();
        endpoint
            .update_status("s3", EvidenceStatus::Expired, "t-expire")
            .unwrap();

        let results = endpoint.query(
            &EvidenceQuery {
                proof_ref: None,
                status_filter: Some(EvidenceStatus::Expired),
                limit: 100,
            },
            "t-query-status",
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, EvidenceStatus::Expired);
    }

    // ── 20. Query respects limit ──

    #[test]
    fn query_respects_limit() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        for i in 0..5 {
            endpoint
                .submit(&sample_submission(&format!("s-lim-{i}"), "proof-lim"))
                .unwrap();
        }
        let results = endpoint.query(
            &EvidenceQuery {
                proof_ref: None,
                status_filter: None,
                limit: 2,
            },
            "t-limit",
        );
        assert_eq!(results.len(), 2);
    }

    // ── 21. Export evidence bundle ──

    #[test]
    fn export_evidence_bundle() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        endpoint
            .submit(&sample_submission("s-exp-1", "proof-e"))
            .unwrap();
        let bundle = endpoint.export_evidence(1_700_000_001_000, "t-export");
        assert_eq!(bundle.schema_version, VSI_SCHEMA_VERSION);
        assert_eq!(bundle.format_version, VSI_FORMAT_VERSION);
        assert_eq!(bundle.records.len(), 1);
    }

    // ── 22. Export excludes non-accepted records ──

    #[test]
    fn export_excludes_non_accepted() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        endpoint
            .submit(&sample_submission("s-exc-1", "proof-f"))
            .unwrap();
        endpoint
            .submit(&sample_submission("s-exc-2", "proof-g"))
            .unwrap();
        endpoint
            .update_status("s-exc-2", EvidenceStatus::Rejected, "t-rej")
            .unwrap();

        let bundle = endpoint.export_evidence(1_700_000_002_000, "t-exp-exc");
        assert_eq!(bundle.records.len(), 1);
        assert_eq!(bundle.records[0].submission_id, "s-exc-1");
    }

    // ── 23. Update status of unknown submission fails ──

    #[test]
    fn update_status_unknown_fails() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        let err = endpoint
            .update_status("nonexistent", EvidenceStatus::Expired, "t-bad")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_SUBMISSION_REJECTED);
    }

    // ── 24. VsiError Display includes code ──

    #[test]
    fn vsi_error_display() {
        let err = VsiError::proof_ref_missing("test message");
        let display = format!("{err}");
        assert!(display.contains(error_codes::ERR_VSI_PROOF_REF_MISSING));
        assert!(display.contains("test message"));
    }

    // ── 25. CapsuleEmbedding serde round-trip ──

    #[test]
    fn capsule_embedding_serde_roundtrip() {
        let mut embedder = VefCapsuleEmbed::new();
        let embedding = embedder
            .embed(
                "proof-serde",
                "payload-serde",
                sample_metadata(),
                2_000,
                "t-serde",
            )
            .unwrap();
        let json = serde_json::to_string(&embedding).unwrap();
        let parsed: CapsuleEmbedding = serde_json::from_str(&json).unwrap();
        assert_eq!(embedding, parsed);
    }

    // ── 26. EvidenceRecord serde round-trip ──

    #[test]
    fn evidence_record_serde_roundtrip() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        endpoint
            .submit(&sample_submission("s-serde", "proof-serde"))
            .unwrap();
        let record = endpoint.store().get("s-serde").unwrap().clone();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: EvidenceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, parsed);
    }

    // ── 27. ExportedEvidenceBundle serde round-trip ──

    #[test]
    fn exported_bundle_serde_roundtrip() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        endpoint
            .submit(&sample_submission("s-bun", "proof-bun"))
            .unwrap();
        let bundle = endpoint.export_evidence(3_000, "t-bun");
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: ExportedEvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, parsed);
    }

    // ── 28. NegotiationResult serde round-trip ──

    #[test]
    fn negotiation_result_serde_roundtrip() {
        let negotiator = VersionNegotiator::new();
        let result = negotiator.negotiate(&["1.0.0".to_string()]).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: NegotiationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    // ── 29. SubmissionResponse carries format_version (INV-VSI-VERSIONED) ──

    #[test]
    fn submission_response_carries_version() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        let resp = endpoint
            .submit(&sample_submission("s-ver", "proof-ver"))
            .unwrap();
        assert_eq!(resp.format_version, VSI_FORMAT_VERSION);
    }

    // ── 30. Events accumulate across operations ──

    #[test]
    fn events_accumulate() {
        let mut endpoint = ExternalVerificationEndpoint::new();
        endpoint
            .submit(&sample_submission("s-ev-1", "proof-ev"))
            .unwrap();
        endpoint.query(
            &EvidenceQuery {
                proof_ref: None,
                status_filter: None,
                limit: 10,
            },
            "t-ev-q",
        );
        endpoint.export_evidence(4_000, "t-ev-exp");
        // submit + query + export = 3 events
        assert_eq!(endpoint.events().len(), 3);
    }

    // ── 31. Invariant constants are correctly defined ──

    #[test]
    fn invariant_constants() {
        assert_eq!(INV_VSI_VERSIONED, "INV-VSI-VERSIONED");
        assert_eq!(INV_VSI_BACKWARD_COMPAT, "INV-VSI-BACKWARD-COMPAT");
        assert_eq!(INV_VSI_EMBED_COMPLETE, "INV-VSI-EMBED-COMPLETE");
    }

    // ── 32. Schema version constant ──

    #[test]
    fn schema_version_constant() {
        assert_eq!(VSI_SCHEMA_VERSION, "vef-sdk-integration-v1");
    }

    // ── 33. Event codes are all distinct ──

    #[test]
    fn event_codes_distinct() {
        let codes = [
            event_codes::VSI_001_PROOF_EMBEDDED,
            event_codes::VSI_002_EVIDENCE_SUBMITTED,
            event_codes::VSI_003_EVIDENCE_QUERIED,
            event_codes::VSI_004_VERSION_NEGOTIATED,
            event_codes::VSI_005_EMBED_VALIDATED,
            event_codes::VSI_006_EVIDENCE_EXPORTED,
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "all event codes must be distinct"
        );
    }

    // ── 34. Error codes are all distinct ──

    #[test]
    fn error_codes_distinct() {
        let codes = [
            error_codes::ERR_VSI_PROOF_REF_MISSING,
            error_codes::ERR_VSI_CAPSULE_INVALID,
            error_codes::ERR_VSI_VERSION_UNSUPPORTED,
            error_codes::ERR_VSI_BINDING_MISMATCH,
            error_codes::ERR_VSI_SUBMISSION_REJECTED,
            error_codes::ERR_VSI_INTERNAL,
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "all error codes must be distinct"
        );
    }

    // ── 35. EvidenceStatus serde round-trip ──

    #[test]
    fn evidence_status_serde_roundtrip() {
        for status in [
            EvidenceStatus::Pending,
            EvidenceStatus::Accepted,
            EvidenceStatus::Rejected,
            EvidenceStatus::Expired,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: EvidenceStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }

    // ── 36. Metadata in embedding uses BTreeMap (deterministic ordering) ──

    #[test]
    fn metadata_ordering_deterministic() {
        let mut m1 = BTreeMap::new();
        m1.insert("z_key".to_string(), "z_val".to_string());
        m1.insert("a_key".to_string(), "a_val".to_string());

        let mut m2 = BTreeMap::new();
        m2.insert("a_key".to_string(), "a_val".to_string());
        m2.insert("z_key".to_string(), "z_val".to_string());

        let mut e1 = VefCapsuleEmbed::new();
        let mut e2 = VefCapsuleEmbed::new();

        let emb1 = e1.embed("p", "payload", m1, 1_000, "t").unwrap();
        let emb2 = e2.embed("p", "payload", m2, 1_000, "t").unwrap();

        // BTreeMap ensures identical iteration order regardless of insertion order
        assert_eq!(
            serde_json::to_string(&emb1.embed_metadata).unwrap(),
            serde_json::to_string(&emb2.embed_metadata).unwrap()
        );
    }

    // ── 37. VersionNegotiator with empty server versions ──

    #[test]
    fn version_negotiator_empty_server() {
        let negotiator = VersionNegotiator::with_versions(vec![]);
        let err = negotiator.negotiate(&["1.0.0".to_string()]).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VSI_VERSION_UNSUPPORTED);
    }

    // ── 38. Binding hash starts with sha256: prefix ──

    #[test]
    fn binding_hash_has_sha256_prefix() {
        let mut embedder = VefCapsuleEmbed::new();
        let embedding = embedder
            .embed("proof-sha", "payload-sha", BTreeMap::new(), 1_000, "t-sha")
            .unwrap();
        assert!(
            embedding.binding_hash.starts_with("sha256:"),
            "binding hash should start with sha256: prefix"
        );
    }
}
